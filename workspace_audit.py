import argparse
import base64
import csv
import datetime as dt
import html
import json
import os
import stat
import sys
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow


SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.security",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/apps.groups.settings",
]

RISKY_SCOPE_MARKERS = [
    "mail.google.com",
    "/auth/gmail.",
    "/auth/drive",
    "/auth/cloud-platform",
    "/auth/admin.",
    "/auth/script.projects",
]

SUSPICIOUS_LOGIN_MARKERS = [
    "suspicious",
    "login_failure",
    "failed_login",
    "password",
    "challenge",
    "risky",
    "unknown",
]

EXTERNAL_SHARING_MARKERS = [
    "outside_domain",
    "external",
    "public",
    "anyone",
    "link",
    "visibility",
]

SHARING_CONTEXT_MARKERS = [
    "share",
    "sharing",
    "acl",
    "permission",
    "visibility",
]

BLOCKED_NON_DOMAIN_TLDS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "svg",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "csv",
    "md",
    "txt",
    "apk",
    "json",
    "xml",
    "yaml",
    "yml",
}

LOGO_MIME_BY_EXT = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
}

API_GET_MAX_ATTEMPTS = 5
API_GET_BASE_BACKOFF_SECONDS = 1.0
API_GET_MAX_BACKOFF_SECONDS = 16.0
API_GET_RETRY_STATUS_CODES = {429, 500, 502, 503, 504}

GRADE_THRESHOLDS = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
)


def score_grade(score):
    for min_score, grade in GRADE_THRESHOLDS:
        if score >= min_score:
            return grade
    return "F"
REPORTS_ACTIVITY_BASE_URL = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications"
REPORTS_ACTIVITY_PAGE_SIZE = 1000
TOKEN_SCAN_MAX_WORKERS = 8
TOKEN_SCAN_REQUESTS_PER_SECOND = 6.0
USER_OWNER_SCAN_MAX_WORKERS = 4
USER_OWNER_SCAN_REQUESTS_PER_SECOND = 1.5


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def to_iso(ts):
    return ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")


class CallRateLimiter:
    def __init__(self, calls_per_second):
        self.calls_per_second = max(0.0, float(calls_per_second))
        self.interval_seconds = 0.0 if self.calls_per_second <= 0 else (1.0 / self.calls_per_second)
        self.next_allowed_at = 0.0
        self.lock = threading.Lock()

    def wait_for_slot(self):
        if self.interval_seconds <= 0:
            return
        while True:
            with self.lock:
                now = time.monotonic()
                if now >= self.next_allowed_at:
                    self.next_allowed_at = now + self.interval_seconds
                    return
                wait_seconds = self.next_allowed_at - now
            time.sleep(wait_seconds)


def load_client(client_secret_path):
    with open(client_secret_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    block = data.get("installed") or data.get("web")
    if not block:
        raise ValueError("Client secret JSON must contain 'installed' or 'web'.")
    return block["client_id"], block.get("client_secret", "")


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_token_json(path, data):
    write_json(path, data)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def post_form(url, payload):
    r = requests.post(url, data=payload, timeout=60)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code} from {url}: {r.text[:1000]}")
    return r.json()


def auth_login(args):
    flow = InstalledAppFlow.from_client_secrets_file(args.client_secret, SCOPES)
    creds = flow.run_local_server(port=0, open_browser=True, access_type="offline", prompt="consent")
    token = {
        "access_token": creds.token,
        "expires_at": to_iso(creds.expiry.astimezone(dt.timezone.utc)),
    }
    if creds.refresh_token:
        token["refresh_token"] = creds.refresh_token
    write_token_json(args.token, token)
    print(f"Token saved to: {args.token}")


def is_expired(token_data):
    expiry = dt.datetime.fromisoformat(token_data["expires_at"].replace("Z", "+00:00"))
    return utc_now() >= (expiry - dt.timedelta(minutes=2))


def refresh_access_token(token_data, client_id, client_secret):
    refresh_token = token_data.get("refresh_token")
    if not refresh_token:
        return token_data
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    data = post_form("https://oauth2.googleapis.com/token", payload)
    token_data["access_token"] = data["access_token"]
    token_data["expires_at"] = to_iso(utc_now() + dt.timedelta(seconds=data.get("expires_in", 3600)))
    return token_data


def api_get(url, access_token, params=None):
    for attempt in range(1, API_GET_MAX_ATTEMPTS + 1):
        try:
            r = requests.get(
                url,
                headers={"Authorization": f"Bearer {access_token}"},
                params=params or {},
                timeout=60,
            )
        except requests.RequestException as e:
            if attempt >= API_GET_MAX_ATTEMPTS:
                raise RuntimeError(f"HTTP transport error GET {url}: {str(e)[:300]}") from e
            wait_seconds = min(API_GET_MAX_BACKOFF_SECONDS, API_GET_BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)))
            time.sleep(wait_seconds)
            continue

        if r.status_code < 400:
            return r.json()

        if r.status_code in API_GET_RETRY_STATUS_CODES and attempt < API_GET_MAX_ATTEMPTS:
            retry_after_header = (r.headers.get("Retry-After") or "").strip()
            wait_seconds = None
            if retry_after_header.isdigit():
                wait_seconds = max(0, int(retry_after_header))
            if wait_seconds is None:
                wait_seconds = min(API_GET_MAX_BACKOFF_SECONDS, API_GET_BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)))
            time.sleep(wait_seconds)
            continue

        raise RuntimeError(f"HTTP {r.status_code} GET {url}: {r.text[:1000]}")

    raise RuntimeError(f"Retries exhausted GET {url}")


def paged_get(url, item_key, access_token, params=None):
    out = []
    query = dict(params or {})
    while True:
        data = api_get(url, access_token, query)
        out.extend(data.get(item_key, []))
        token = data.get("nextPageToken")
        if not token:
            break
        query["pageToken"] = token
    return out


def paged_report_activities(application_name, access_token, start_time):
    return paged_get(
        f"{REPORTS_ACTIVITY_BASE_URL}/{application_name}",
        "items",
        access_token,
        {"startTime": start_time, "maxResults": REPORTS_ACTIVITY_PAGE_SIZE},
    )


def safe_tokens_for_user(access_token, user_email):
    user_key = urllib.parse.quote(user_email, safe="")
    url = f"https://admin.googleapis.com/admin/directory/v1/users/{user_key}/tokens"
    try:
        data = api_get(url, access_token)
    except Exception:
        return []
    return data.get("items", [])


def contains_risky_scope(scopes):
    lowered = [s.lower() for s in scopes or []]
    for s in lowered:
        for marker in RISKY_SCOPE_MARKERS:
            if marker in s:
                return True
    return False


def email_domain(value):
    if not value or "@" not in value:
        return ""
    return value.split("@", 1)[1].strip().lower()


def is_domain_like(value):
    v = (value or "").strip().lower().strip(".")
    if not v or "@" in v or "/" in v or " " in v or "." not in v:
        return False
    parts = v.split(".")
    if len(parts[-1]) < 2:
        return False
    if parts[-1] in BLOCKED_NON_DOMAIN_TLDS:
        return False
    for p in parts:
        if not p or not all(ch.isalnum() or ch == "-" for ch in p):
            return False
    return True


def normalize_domain_candidate(value):
    v = (value or "").strip().lower().strip(".")
    if not v or "." not in v:
        return v
    parts = v.split(".")
    while len(parts) > 2 and parts[-1] in BLOCKED_NON_DOMAIN_TLDS:
        parts = parts[:-1]
    return ".".join(parts)


def safe_internal_domains(access_token, users):
    domains = {email_domain(u.get("primaryEmail", "")) for u in users}
    domains.discard("")
    try:
        data = api_get(
            "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domains",
            access_token,
        )
        for d in data.get("domains", []):
            dn = (d.get("domainName") or "").lower().strip()
            if dn:
                domains.add(dn)
            for a in d.get("domainAliases", []):
                ad = (a.get("domainAliasName") or "").lower().strip()
                if ad:
                    domains.add(ad)
    except Exception:
        pass
    return domains


def safe_domain_drive_files(access_token, max_pages=60):
    files = []
    params = {
        "corpora": "domain",
        "q": "trashed=false",
        "includeItemsFromAllDrives": "true",
        "supportsAllDrives": "true",
        "pageSize": 200,
        "fields": "nextPageToken,files(id,name,mimeType,webViewLink,owners(emailAddress),permissions(type,role,domain,emailAddress,allowFileDiscovery))",
    }
    url = "https://www.googleapis.com/drive/v3/files"
    page_count = 0
    try:
        while True:
            page_count += 1
            data = api_get(url, access_token, params)
            files.extend(data.get("files", []))
            token = data.get("nextPageToken")
            if not token or page_count >= max_pages:
                break
            params["pageToken"] = token
        truncated = bool(params.get("pageToken")) and page_count >= max_pages
        return files, None, truncated
    except Exception as e:
        return files, str(e), False


def safe_list_groups(access_token):
    groups = []
    params = {"customer": "my_customer", "maxResults": 200}
    url = "https://admin.googleapis.com/admin/directory/v1/groups"
    try:
        while True:
            data = api_get(url, access_token, params)
            groups.extend(data.get("groups", []))
            token = data.get("nextPageToken")
            if not token:
                break
            params["pageToken"] = token
        return groups, None
    except Exception as e:
        return groups, str(e)


def safe_group_settings(access_token, group_email):
    gid = urllib.parse.quote(group_email, safe="")
    url = f"https://www.googleapis.com/groups/v1/groups/{gid}"
    try:
        return api_get(url, access_token, {"alt": "json"}), None
    except Exception as e:
        return None, str(e)


def delegated_access_token(service_account_key, subject, scopes):
    creds = service_account.Credentials.from_service_account_file(
        service_account_key,
        scopes=scopes,
    ).with_subject(subject)
    creds.refresh(Request())
    return creds.token


def safe_user_public_files_scan(service_account_key, user_email):
    token = delegated_access_token(
        service_account_key,
        user_email,
        ["https://www.googleapis.com/auth/drive.metadata.readonly"],
    )
    base = {
        "supportsAllDrives": "true",
        "includeItemsFromAllDrives": "true",
        "pageSize": 200,
        "fields": "nextPageToken,files(id,name,webViewLink,owners(emailAddress))",
    }
    link_params = dict(base)
    link_params["q"] = "trashed=false and 'me' in owners and visibility='anyoneWithLink'"
    public_params = dict(base)
    public_params["q"] = "trashed=false and 'me' in owners and visibility='anyoneCanFind'"
    anyone_with_link = paged_get("https://www.googleapis.com/drive/v3/files", "files", token, link_params)
    public_on_web = paged_get("https://www.googleapis.com/drive/v3/files", "files", token, public_params)
    return {"anyone_with_link": anyone_with_link, "public_on_web": public_on_web}


def parse_login_time(raw):
    if not raw:
        return None
    try:
        return dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def collect_risky_tokens_for_users(access_token, active_users):
    user_emails = [u.get("primaryEmail") for u in active_users if u.get("primaryEmail")]
    if not user_emails:
        return []

    limiter = CallRateLimiter(TOKEN_SCAN_REQUESTS_PER_SECOND)

    def scan_user_tokens(email):
        limiter.wait_for_slot()
        user_risky_tokens = []
        for t in safe_tokens_for_user(access_token, email):
            scopes = t.get("scopes", [])
            if contains_risky_scope(scopes):
                user_risky_tokens.append(
                    {
                        "user": email,
                        "app": t.get("displayText"),
                        "clientId": t.get("clientId"),
                        "anonymous": t.get("anonymous"),
                        "nativeApp": t.get("nativeApp"),
                        "scopes": scopes,
                    }
                )
        return user_risky_tokens

    risky_tokens = []
    max_workers = max(1, min(TOKEN_SCAN_MAX_WORKERS, len(user_emails)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_user_tokens, email) for email in user_emails]
        for future in as_completed(futures):
            try:
                risky_tokens.extend(future.result())
            except Exception:
                continue
    return risky_tokens


def collect_user_owner_drive_visibility(service_account_key, active_users):
    user_owner_users_scanned = 0
    user_owner_scan_errors = []
    user_owner_anyone_link_map = {}
    user_owner_public_web_map = {}
    if not service_account_key:
        return {
            "user_owner_users_scanned": user_owner_users_scanned,
            "user_owner_scan_errors": user_owner_scan_errors,
            "user_owner_anyone_link_files": list(user_owner_anyone_link_map.values()),
            "user_owner_public_web_files": list(user_owner_public_web_map.values()),
        }

    user_emails = [u.get("primaryEmail") for u in active_users if u.get("primaryEmail")]
    if not user_emails:
        return {
            "user_owner_users_scanned": user_owner_users_scanned,
            "user_owner_scan_errors": user_owner_scan_errors,
            "user_owner_anyone_link_files": list(user_owner_anyone_link_map.values()),
            "user_owner_public_web_files": list(user_owner_public_web_map.values()),
        }

    limiter = CallRateLimiter(USER_OWNER_SCAN_REQUESTS_PER_SECOND)

    def scan_user_drive(email):
        limiter.wait_for_slot()
        try:
            return email, safe_user_public_files_scan(service_account_key, email), None
        except Exception as e:
            return email, None, str(e)[:400]

    max_workers = max(1, min(USER_OWNER_SCAN_MAX_WORKERS, len(user_emails)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_email = {executor.submit(scan_user_drive, email): email for email in user_emails}
        for future in as_completed(future_to_email):
            fallback_email = future_to_email[future]
            try:
                email, scan, err = future.result()
            except Exception as e:
                user_owner_scan_errors.append({"user": fallback_email, "error": str(e)[:400]})
                continue
            if err:
                user_owner_scan_errors.append({"user": email, "error": err})
                continue

            user_owner_users_scanned += 1
            for f in scan.get("anyone_with_link", []):
                fid = f.get("id") or ""
                rec = {
                    "id": fid,
                    "name": f.get("name"),
                    "webViewLink": f.get("webViewLink"),
                    "owner": ((f.get("owners") or [{}])[0].get("emailAddress")) or email,
                }
                user_owner_anyone_link_map[fid or f"{email}:{f.get('name','')}"] = rec
            for f in scan.get("public_on_web", []):
                fid = f.get("id") or ""
                rec = {
                    "id": fid,
                    "name": f.get("name"),
                    "webViewLink": f.get("webViewLink"),
                    "owner": ((f.get("owners") or [{}])[0].get("emailAddress")) or email,
                }
                user_owner_public_web_map[fid or f"{email}:{f.get('name','')}"] = rec

    return {
        "user_owner_users_scanned": user_owner_users_scanned,
        "user_owner_scan_errors": user_owner_scan_errors,
        "user_owner_anyone_link_files": list(user_owner_anyone_link_map.values()),
        "user_owner_public_web_files": list(user_owner_public_web_map.values()),
    }


def domain_health_penalties(summary):
    active = max(1, int(summary.get("activeUsers", 0)))
    return {
        "p_2sv_enrollment": (summary.get("usersWithout2SVEnrollment", 0) / active) * 25,
        "p_2sv_enforcement": (summary.get("usersWithout2SVEnforcement", 0) / active) * 15,
        "p_oauth": min(20.0, (summary.get("riskyOAuthGrants", 0) / active) * 20),
        "p_login": min(10.0, (summary.get("suspiciousLoginEvents30d", 0) / active) * 6),
        "p_anyone_link": min(12.0, summary.get("filesAnyoneWithLink", 0) * 0.25),
        "p_public_on_web": min(12.0, summary.get("filesPublicOnWeb", 0) * 1.5),
        "p_external_domains": min(8.0, summary.get("externalSharedDomains", 0) * 0.5),
        "p_groups_anyone_join": min(10.0, summary.get("groupsAnyoneCanJoin", 0) * 2.0),
        "p_groups_anyone_view": min(10.0, summary.get("groupsAnyoneCanView", 0) * 2.0),
        "p_stale": min(8.0, (summary.get("staleAccounts90d", 0) / active) * 20),
        "p_unencrypted_mobile": min(5.0, summary.get("unencryptedMobileDevices", 0) * 1.0),
    }


def calculate_domain_health(summary):
    score = max(0, min(100, round(100.0 - sum(domain_health_penalties(summary).values()), 1)))
    return score, score_grade(score)


def compute_posture_breakdown(summary):
    penalties = {k: round(v, 1) for k, v in domain_health_penalties(summary).items()}
    p_2sv_enrollment = penalties["p_2sv_enrollment"]
    p_2sv_enforcement = penalties["p_2sv_enforcement"]
    p_oauth = penalties["p_oauth"]
    p_login = penalties["p_login"]
    p_anyone_link = penalties["p_anyone_link"]
    p_public_on_web = penalties["p_public_on_web"]
    p_external_domains = penalties["p_external_domains"]
    p_groups_anyone_join = penalties["p_groups_anyone_join"]
    p_groups_anyone_view = penalties["p_groups_anyone_view"]
    p_stale = penalties["p_stale"]
    p_unencrypted_mobile = penalties["p_unencrypted_mobile"]
    score, grade = calculate_domain_health(summary)
    total_penalty = round(100.0 - score, 1)
    return {
        "score": score,
        "grade": grade,
        "p_2sv": p_2sv_enrollment,
        "p_2sv_enrollment": p_2sv_enrollment,
        "p_2sv_enforcement": p_2sv_enforcement,
        "p_oauth": p_oauth,
        "p_login": p_login,
        "p_external_domains": p_external_domains,
        "p_anyone_link": p_anyone_link,
        "p_public_on_web": p_public_on_web,
        "p_groups_anyone_join": p_groups_anyone_join,
        "p_groups_anyone_view": p_groups_anyone_view,
        "p_stale": p_stale,
        "p_unencrypted_mobile": p_unencrypted_mobile,
        "total_penalty": total_penalty,
    }


def write_domains_csv(path, domain_rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "domain",
                "shared_files_count",
                "permission_entries",
                "sample_files",
            ],
        )
        writer.writeheader()
        for row in domain_rows:
            writer.writerow(row)


def event_parameter_values(event):
    values = []
    for _, vals in event_parameter_items(event):
        values.extend(vals)
    return values


def event_parameter_items(event):
    for p in event.get("parameters", []):
        name = (p.get("name") or "").strip().lower()
        vals = []
        for key in ("value", "boolValue", "intValue", "messageValue"):
            if key in p and p.get(key) is not None:
                vals.append(str(p.get(key)))
        mv = p.get("multiValue")
        if isinstance(mv, list):
            vals.extend(str(v) for v in mv if v is not None)
        yield name, vals


def is_external_sharing_event(event):
    name = (event.get("name") or "").lower()
    param_blob = " ".join(event_parameter_values(event)).lower()
    combined = f"{name} {param_blob}"
    has_context = any(m in combined for m in SHARING_CONTEXT_MARKERS)
    has_external_signal = any(m in combined for m in EXTERNAL_SHARING_MARKERS)
    return has_context and has_external_signal


def collect_user_inventory(access_token):
    users = paged_get(
        "https://admin.googleapis.com/admin/directory/v1/users",
        "users",
        access_token,
        {"customer": "my_customer", "projection": "full", "maxResults": 500, "orderBy": "email"},
    )
    active_users = [u for u in users if not u.get("suspended", False)]
    user_by_id = {u.get("id"): u.get("primaryEmail") for u in users if u.get("id")}
    internal_domains = safe_internal_domains(access_token, users)
    no_2sv_enrolled = [u.get("primaryEmail") for u in active_users if not u.get("isEnrolledIn2Sv", False)]
    no_2sv_enforced = [u.get("primaryEmail") for u in active_users if not u.get("isEnforcedIn2Sv", False)]

    stale_cutoff = utc_now() - dt.timedelta(days=90)
    stale_active_users = []
    never_logged_in_users = []
    for u in active_users:
        email = u.get("primaryEmail")
        last_login = parse_login_time(u.get("lastLoginTime"))
        if not email:
            continue
        if not last_login or last_login.year <= 1971:
            never_logged_in_users.append(email)
            stale_active_users.append(email)
            continue
        if last_login < stale_cutoff:
            stale_active_users.append(email)

    return {
        "users": users,
        "active_users": active_users,
        "user_by_id": user_by_id,
        "internal_domains": internal_domains,
        "no_2sv_enrolled": no_2sv_enrolled,
        "no_2sv_enforced": no_2sv_enforced,
        "stale_active_users": stale_active_users,
        "never_logged_in_users": never_logged_in_users,
    }


def collect_super_admins(access_token, user_by_id, active_users):
    roles = paged_get(
        "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roles",
        "items",
        access_token,
        {"maxResults": 100},
    )
    super_admin_role_ids = {str(r.get("roleId")) for r in roles if r.get("roleName") == "Super Admin"}
    role_assignments = paged_get(
        "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments",
        "items",
        access_token,
        {"maxResults": 100},
    )
    super_admin_user_ids = {
        str(a.get("assignedTo"))
        for a in role_assignments
        if str(a.get("roleId")) in super_admin_role_ids and a.get("assignedTo")
    }
    super_admin_emails = sorted({user_by_id.get(uid) for uid in super_admin_user_ids if user_by_id.get(uid)})
    super_admin_without_2sv = [
        email
        for email in super_admin_emails
        if any(u.get("primaryEmail") == email and not u.get("isEnforcedIn2Sv", False) for u in active_users)
    ]
    return {
        "super_admin_emails": super_admin_emails,
        "super_admin_without_2sv": super_admin_without_2sv,
    }

def collect_risky_tokens(access_token, active_users):
    risky_tokens = collect_risky_tokens_for_users(access_token, active_users)
    return risky_tokens


def collect_login_observations(access_token, start_time):
    login_activities = paged_report_activities("login", access_token, start_time)
    suspicious_logins = []
    event_counts = {}
    for activity in login_activities:
        actor = (((activity.get("actor") or {}).get("email")) or "unknown")
        for ev in activity.get("events", []):
            name = (ev.get("name") or "").lower()
            event_counts[name] = event_counts.get(name, 0) + 1
            if any(marker in name for marker in SUSPICIOUS_LOGIN_MARKERS):
                suspicious_logins.append(
                    {
                        "time": activity.get("id", {}).get("time"),
                        "actor": actor,
                        "event": ev.get("name"),
                    }
                )
    return {"suspicious_logins": suspicious_logins, "event_counts": event_counts}


def safe_collect_activity(access_token, start_time, app):
    try:
        return paged_report_activities(app, access_token, start_time)
    except Exception:
        return []


def collect_event_counts(activities):
    counts = Counter()
    for activity in activities:
        for ev in activity.get("events", []):
            counts[(ev.get("name") or "unknown")] += 1
    return counts


def collect_admin_token_groups_observations(access_token, start_time):
    admin_activities = safe_collect_activity(access_token, start_time, "admin")
    token_activities = safe_collect_activity(access_token, start_time, "token")
    groups_activities = safe_collect_activity(access_token, start_time, "groups")
    return {
        "admin_event_counts": collect_event_counts(admin_activities),
        "token_event_counts": collect_event_counts(token_activities),
        "groups_event_counts": collect_event_counts(groups_activities),
    }


def collect_drive_activity_observations(access_token, start_time, internal_domains):
    drive_activities = safe_collect_activity(access_token, start_time, "drive")
    external_sharing_events = []
    external_sharing_counts = {}
    external_domains_from_events = {}
    anyone_link_file_ids_from_events = set()
    anyone_link_file_names_from_events = set()
    for activity in drive_activities:
        actor = (((activity.get("actor") or {}).get("email")) or "unknown")
        for ev in activity.get("events", []):
            ev_name = (ev.get("name") or "unknown")
            ev_name_l = ev_name.lower()
            all_vals_l = [v.lower() for v in event_parameter_values(ev)]
            combined = " ".join([ev_name_l] + all_vals_l)
            param_pairs = list(event_parameter_items(ev))
            file_ids = set()
            file_names = set()

            for p_name, vals in param_pairs:
                if any(k in p_name for k in ("doc_id", "file_id", "item_id", "target_id", "resource_id")):
                    file_ids.update(v for v in vals if v)
                if any(k in p_name for k in ("doc_title", "file_title", "doc_name", "file_name", "title", "name")):
                    file_names.update(v for v in vals if v)
                is_domain_context_param = any(
                    k in p_name for k in ("domain", "recipient", "shared_with", "target_user", "email", "owner", "external")
                )
                for v in vals:
                    d = ""
                    if "@" in v:
                        d = normalize_domain_candidate(email_domain(v))
                    elif is_domain_context_param and is_domain_like(v):
                        d = normalize_domain_candidate(v)
                    if d and is_domain_like(d) and d not in internal_domains and len(d) >= 4:
                        external_domains_from_events[d] = external_domains_from_events.get(d, 0) + 1

            if ("anyone" in combined and "link" in combined) or "shared_publicly" in combined:
                anyone_link_file_ids_from_events.update(file_ids)
                anyone_link_file_names_from_events.update(file_names)
            if is_external_sharing_event(ev):
                external_sharing_counts[ev_name] = external_sharing_counts.get(ev_name, 0) + 1
                external_sharing_events.append(
                    {
                        "time": activity.get("id", {}).get("time"),
                        "actor": actor,
                        "event": ev_name,
                        "parameters": event_parameter_values(ev)[:10],
                    }
                )

    return {
        "external_sharing_events": external_sharing_events,
        "external_sharing_counts": external_sharing_counts,
        "external_domains_from_events": external_domains_from_events,
        "anyone_link_file_ids_from_events": anyone_link_file_ids_from_events,
        "anyone_link_file_names_from_events": anyone_link_file_names_from_events,
    }


def collect_drive_inventory(access_token, internal_domains, external_domains_from_events, domains_csv_path):
    domain_drive_files, drive_scan_error, drive_scan_truncated = safe_domain_drive_files(access_token)
    anyone_link_files = []
    public_web_files = []
    domain_to_files = {}
    domain_permission_counts = {}
    domain_file_samples = {}

    for f in domain_drive_files:
        file_id = f.get("id")
        file_name = f.get("name") or ""
        perms = f.get("permissions", []) or []
        file_domains = set()
        has_anyone_link = False
        has_public_web = False
        for p in perms:
            p_type = (p.get("type") or "").lower()
            if p_type == "anyone":
                if p.get("allowFileDiscovery") is True:
                    has_public_web = True
                else:
                    has_anyone_link = True
            elif p_type == "domain":
                d = (p.get("domain") or "").lower().strip()
                if d and d not in internal_domains:
                    file_domains.add(d)
            elif p_type in {"user", "group"}:
                d = email_domain(p.get("emailAddress", ""))
                if d and d not in internal_domains:
                    file_domains.add(d)
        if has_anyone_link:
            anyone_link_files.append(
                {
                    "id": file_id,
                    "name": file_name,
                    "webViewLink": f.get("webViewLink"),
                    "owner": ((f.get("owners") or [{}])[0].get("emailAddress")),
                }
            )
        if has_public_web:
            public_web_files.append(
                {
                    "id": file_id,
                    "name": file_name,
                    "webViewLink": f.get("webViewLink"),
                    "owner": ((f.get("owners") or [{}])[0].get("emailAddress")),
                }
            )
        for d in file_domains:
            domain_to_files.setdefault(d, set()).add(file_id)
            domain_permission_counts[d] = domain_permission_counts.get(d, 0) + 1
            domain_file_samples.setdefault(d, set()).add(file_name)

    domain_rows = []
    for d, files_set in sorted(domain_to_files.items(), key=lambda kv: len(kv[1]), reverse=True):
        samples = sorted(domain_file_samples.get(d, set()))
        domain_rows.append(
            {
                "domain": d,
                "shared_files_count": len(files_set),
                "permission_entries": domain_permission_counts.get(d, 0),
                "sample_files": " | ".join(samples[:5]),
            }
        )
    if not domain_rows and external_domains_from_events:
        for d, cnt in sorted(external_domains_from_events.items(), key=lambda kv: kv[1], reverse=True):
            domain_rows.append(
                {
                    "domain": d,
                    "shared_files_count": 0,
                    "permission_entries": cnt,
                    "sample_files": "derived from Drive activity events",
                }
            )
    if domains_csv_path:
        write_domains_csv(domains_csv_path, domain_rows)

    return {
        "domain_drive_files": domain_drive_files,
        "drive_scan_error": drive_scan_error,
        "drive_scan_truncated": drive_scan_truncated,
        "anyone_link_files": anyone_link_files,
        "public_web_files": public_web_files,
        "domain_rows": domain_rows,
    }


def collect_groups_exposure(access_token):
    groups, groups_scan_error = safe_list_groups(access_token)
    groups_anyone_can_join = []
    groups_anyone_can_view = []
    groups_settings_errors = []
    for g in groups:
        email = g.get("email")
        if not email:
            continue
        settings, err = safe_group_settings(access_token, email)
        if err:
            groups_settings_errors.append({"group": email, "error": err})
            continue
        who_can_join = (settings.get("whoCanJoin") or "").upper()
        who_can_view = (settings.get("whoCanViewGroup") or "").upper()
        if "ANYONE_CAN_JOIN" in who_can_join:
            groups_anyone_can_join.append(
                {
                    "group": email,
                    "name": g.get("name"),
                    "whoCanJoin": settings.get("whoCanJoin"),
                    "whoCanViewGroup": settings.get("whoCanViewGroup"),
                }
            )
        if "ANYONE_CAN_VIEW" in who_can_view:
            groups_anyone_can_view.append(
                {
                    "group": email,
                    "name": g.get("name"),
                    "whoCanJoin": settings.get("whoCanJoin"),
                    "whoCanViewGroup": settings.get("whoCanViewGroup"),
                }
            )
    return {
        "groups": groups,
        "groups_scan_error": groups_scan_error,
        "groups_anyone_can_join": groups_anyone_can_join,
        "groups_anyone_can_view": groups_anyone_can_view,
        "groups_settings_errors": groups_settings_errors,
    }

def collect_user_owner_drive_scan(service_account_key, active_users):
    return collect_user_owner_drive_visibility(service_account_key, active_users)

def resolve_anyone_link_evidence(
    domain_drive_files,
    drive_scan_error,
    anyone_link_files,
    user_owner_anyone_link_files,
    anyone_link_file_ids_from_events,
    anyone_link_file_names_from_events,
    user_owner_users_scanned,
):
    anyone_link_files_count = len(anyone_link_files)
    anyone_link_evidence = anyone_link_files[:200]
    anyone_link_source = "drive_inventory" if len(domain_drive_files) > 0 else "unavailable"
    if anyone_link_files_count == 0 and user_owner_anyone_link_files:
        anyone_link_files_count = len(user_owner_anyone_link_files)
        anyone_link_evidence = user_owner_anyone_link_files[:200]
        anyone_link_source = "user_owner_scan_dwd"
    if anyone_link_files_count == 0 and anyone_link_file_ids_from_events:
        anyone_link_files_count = len(anyone_link_file_ids_from_events)
        anyone_link_evidence = [{"id": fid, "name": ""} for fid in list(anyone_link_file_ids_from_events)[:200]]
        if not anyone_link_evidence and anyone_link_file_names_from_events:
            anyone_link_evidence = [{"id": "", "name": n} for n in list(anyone_link_file_names_from_events)[:200]]
        anyone_link_source = "drive_activity_events"
    if user_owner_users_scanned > 0 and anyone_link_source == "unavailable":
        anyone_link_source = "user_owner_scan_dwd"

    anyone_title = "Files accessible via 'Anyone with the link'"
    anyone_remediation = "Remove public link access for non-public assets and enforce safer default sharing settings."
    if drive_scan_error and len(domain_drive_files) == 0:
        anyone_title = "Files observed with 'Anyone with the link' access (activity-based, 30 days)"
        anyone_remediation = "Enable Drive API for exact inventory, then remove unnecessary anyone-link exposure."

    return {
        "anyone_link_files_count": anyone_link_files_count,
        "anyone_link_evidence": anyone_link_evidence,
        "anyone_link_source": anyone_link_source,
        "anyone_title": anyone_title,
        "anyone_remediation": anyone_remediation,
    }


def collect_mobile_device_observations(access_token):
    mobile_devices = paged_get(
        "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/devices/mobile",
        "mobiledevices",
        access_token,
        {"maxResults": 100},
    )
    unencrypted_mobile_devices = []
    for d in mobile_devices:
        status = str(d.get("encryptionStatus", "")).lower()
        if "unencrypted" in status or status in {"false", "not_encrypted"}:
            unencrypted_mobile_devices.append(
                {
                    "email": d.get("email"),
                    "model": d.get("model"),
                    "os": d.get("os"),
                    "status": d.get("encryptionStatus"),
                }
            )
    return {"mobile_devices": mobile_devices, "unencrypted_mobile_devices": unencrypted_mobile_devices}


def build_findings_list(
    super_admin_without_2sv,
    no_2sv_enforced,
    risky_tokens,
    suspicious_logins,
    external_sharing_events,
    anyone_link_files_count,
    anyone_link_evidence,
    anyone_title,
    anyone_remediation,
    public_web_files,
    domain_rows,
    admin_event_counts,
    token_event_counts,
    groups_anyone_can_join,
    groups_anyone_can_view,
    stale_active_users,
    drive_scan_error,
    user_owner_scan_errors,
    groups_scan_error,
    groups_settings_errors,
    unencrypted_mobile_devices,
):
    findings = []
    if super_admin_without_2sv:
        findings.append(
            {
                "severity": "critical",
                "title": "Super Admin accounts without enforced 2SV",
                "count": len(super_admin_without_2sv),
                "evidence": super_admin_without_2sv,
                "remediation": "Enforce 2-Step Verification for all Super Admins immediately.",
            }
        )
    if no_2sv_enforced:
        findings.append(
            {
                "severity": "high",
                "title": "Active users without enforced 2SV",
                "count": len(no_2sv_enforced),
                "evidence": no_2sv_enforced[:200],
                "remediation": "Turn on org-wide 2SV enforcement and move users to enforced policy.",
            }
        )
    if risky_tokens:
        findings.append(
            {
                "severity": "high",
                "title": "OAuth grants with high-impact scopes detected",
                "count": len(risky_tokens),
                "evidence": risky_tokens[:200],
                "remediation": "Review and revoke unnecessary OAuth app grants; restrict app access controls.",
            }
        )
    if suspicious_logins:
        findings.append(
            {
                "severity": "medium",
                "title": "Suspicious login-related events in last 30 days",
                "count": len(suspicious_logins),
                "evidence": suspicious_logins[:200],
                "remediation": "Investigate risky login events, impossible travel, and repeated failures.",
            }
        )
    if external_sharing_events:
        findings.append(
            {
                "severity": "high",
                "title": "Potential external sharing activity detected (Drive, 30 days)",
                "count": len(external_sharing_events),
                "evidence": external_sharing_events[:200],
                "remediation": "Review sharing events and restrict external/public sharing where not required.",
            }
        )
    if anyone_link_files_count:
        findings.append(
            {
                "severity": "high",
                "title": anyone_title,
                "count": anyone_link_files_count,
                "evidence": anyone_link_evidence,
                "remediation": anyone_remediation,
            }
        )
    if public_web_files:
        findings.append(
            {
                "severity": "critical",
                "title": "Files publicly discoverable on the web",
                "count": len(public_web_files),
                "evidence": public_web_files[:200],
                "remediation": "Immediately remove public-on-web sharing and review data exposure impact.",
            }
        )
    if domain_rows:
        findings.append(
            {
                "severity": "medium",
                "title": "Files shared with external domains",
                "count": len(domain_rows),
                "evidence": domain_rows[:100],
                "remediation": "Review trusted external domains list and remove unnecessary cross-domain sharing.",
            }
        )
    admin_change_keys = [
        "ADD_TO_TRUSTED_OAUTH2_APPS",
        "CHANGE_APP_ACCESS",
        "AUTHORIZE_API_CLIENT_ACCESS",
        "ASSIGN_ROLE",
        "USER_PUT_IN_TWO_STEP_VERIFICATION_GRACE_PERIOD",
        "CHANGE_APPLICATION_SETTING",
        "CREATE_APPLICATION_SETTING",
    ]
    admin_security_change_count = sum(admin_event_counts.get(k, 0) for k in admin_change_keys)
    if admin_security_change_count:
        findings.append(
            {
                "severity": "medium",
                "title": "Admin security/app-access changes observed (30 days)",
                "count": admin_security_change_count,
                "evidence": {k: admin_event_counts.get(k, 0) for k in admin_change_keys if admin_event_counts.get(k, 0)},
                "remediation": "Validate these admin changes against approved change-control tickets and least-privilege policy.",
            }
        )
    token_authorize_count = int(token_event_counts.get("authorize", 0))
    if token_authorize_count:
        findings.append(
            {
                "severity": "medium",
                "title": "OAuth token authorization volume (30 days)",
                "count": token_authorize_count,
                "evidence": {
                    "authorize": token_event_counts.get("authorize", 0),
                    "revoke": token_event_counts.get("revoke", 0),
                    "deny": token_event_counts.get("deny", 0),
                    "request": token_event_counts.get("request", 0),
                },
                "remediation": "Review app consent posture regularly and constrain high-risk OAuth scopes through app access controls.",
            }
        )
    if groups_anyone_can_join:
        findings.append(
            {
                "severity": "high",
                "title": "Google Groups allowing anyone to join",
                "count": len(groups_anyone_can_join),
                "evidence": groups_anyone_can_join[:200],
                "remediation": "Restrict group join permissions to invited users or domain users only.",
            }
        )
    if groups_anyone_can_view:
        findings.append(
            {
                "severity": "high",
                "title": "Google Groups allowing anyone to read",
                "count": len(groups_anyone_can_view),
                "evidence": groups_anyone_can_view[:200],
                "remediation": "Restrict group visibility to members or domain users only.",
            }
        )
    if stale_active_users:
        findings.append(
            {
                "severity": "medium",
                "title": "Stale active user accounts (no login in 90+ days)",
                "count": len(stale_active_users),
                "evidence": stale_active_users[:200],
                "remediation": "Disable or suspend stale accounts pending owner confirmation and access review.",
            }
        )
    if drive_scan_error:
        findings.append(
            {
                "severity": "low",
                "title": "Drive sharing inventory incomplete",
                "count": 1,
                "evidence": [drive_scan_error],
                "remediation": "Enable Google Drive API for the audit project, confirm scope consent, and rerun inventory collection.",
            }
        )
    if user_owner_scan_errors:
        findings.append(
            {
                "severity": "low",
                "title": "Per-user Drive visibility scan had partial errors",
                "count": len(user_owner_scan_errors),
                "evidence": user_owner_scan_errors[:100],
                "remediation": "Review failing accounts and ensure licensing/Drive access for complete user-owner visibility coverage.",
            }
        )
    if groups_scan_error or groups_settings_errors:
        details = []
        if groups_scan_error:
            details.append(groups_scan_error)
        if groups_settings_errors:
            details.extend([f"{x.get('group')}: {x.get('error')}" for x in groups_settings_errors[:30]])
        findings.append(
            {
                "severity": "low",
                "title": "Google Groups settings inventory incomplete",
                "count": len(details),
                "evidence": details,
                "remediation": "Enable Groups Settings API and ensure the auditor has groups settings read access.",
            }
        )
    if unencrypted_mobile_devices:
        findings.append(
            {
                "severity": "medium",
                "title": "Unencrypted managed mobile devices",
                "count": len(unencrypted_mobile_devices),
                "evidence": unencrypted_mobile_devices[:200],
                "remediation": "Enforce encryption and block access from non-compliant devices.",
            }
        )
    return findings


def build_findings(access_token, domains_csv_path=None, service_account_key=None):
    inventory = collect_user_inventory(access_token)
    users = inventory["users"]
    active_users = inventory["active_users"]
    user_by_id = inventory["user_by_id"]
    internal_domains = inventory["internal_domains"]
    no_2sv_enrolled = inventory["no_2sv_enrolled"]
    no_2sv_enforced = inventory["no_2sv_enforced"]
    stale_active_users = inventory["stale_active_users"]
    never_logged_in_users = inventory["never_logged_in_users"]

    super_admin_data = collect_super_admins(access_token, user_by_id, active_users)
    super_admin_emails = super_admin_data["super_admin_emails"]
    super_admin_without_2sv = super_admin_data["super_admin_without_2sv"]

    risky_tokens = collect_risky_tokens(access_token, active_users)
    start_time = to_iso(utc_now() - dt.timedelta(days=30))
    login_data = collect_login_observations(access_token, start_time)
    suspicious_logins = login_data["suspicious_logins"]
    event_counts = login_data["event_counts"]

    atg_data = collect_admin_token_groups_observations(access_token, start_time)
    admin_event_counts = atg_data["admin_event_counts"]
    token_event_counts = atg_data["token_event_counts"]
    groups_event_counts = atg_data["groups_event_counts"]

    drive_activity = collect_drive_activity_observations(access_token, start_time, internal_domains)
    external_sharing_events = drive_activity["external_sharing_events"]
    external_sharing_counts = drive_activity["external_sharing_counts"]
    external_domains_from_events = drive_activity["external_domains_from_events"]
    anyone_link_file_ids_from_events = drive_activity["anyone_link_file_ids_from_events"]
    anyone_link_file_names_from_events = drive_activity["anyone_link_file_names_from_events"]

    drive_inventory = collect_drive_inventory(access_token, internal_domains, external_domains_from_events, domains_csv_path)
    domain_drive_files = drive_inventory["domain_drive_files"]
    drive_scan_error = drive_inventory["drive_scan_error"]
    drive_scan_truncated = drive_inventory["drive_scan_truncated"]
    anyone_link_files = drive_inventory["anyone_link_files"]
    public_web_files = drive_inventory["public_web_files"]
    domain_rows = drive_inventory["domain_rows"]

    groups_data = collect_groups_exposure(access_token)
    groups = groups_data["groups"]
    groups_scan_error = groups_data["groups_scan_error"]
    groups_anyone_can_join = groups_data["groups_anyone_can_join"]
    groups_anyone_can_view = groups_data["groups_anyone_can_view"]
    groups_settings_errors = groups_data["groups_settings_errors"]

    owner_scan = collect_user_owner_drive_scan(service_account_key, active_users)
    user_owner_users_scanned = owner_scan["user_owner_users_scanned"]
    user_owner_scan_errors = owner_scan["user_owner_scan_errors"]
    user_owner_anyone_link_files = owner_scan["user_owner_anyone_link_files"]
    user_owner_public_web_files = owner_scan["user_owner_public_web_files"]
    anyone_link_owner_counts = Counter((x.get("owner") or "unknown") for x in user_owner_anyone_link_files)
    public_web_owner_counts = Counter((x.get("owner") or "unknown") for x in user_owner_public_web_files)

    anyone_link_data = resolve_anyone_link_evidence(
        domain_drive_files,
        drive_scan_error,
        anyone_link_files,
        user_owner_anyone_link_files,
        anyone_link_file_ids_from_events,
        anyone_link_file_names_from_events,
        user_owner_users_scanned,
    )
    anyone_link_files_count = anyone_link_data["anyone_link_files_count"]
    anyone_link_evidence = anyone_link_data["anyone_link_evidence"]
    anyone_link_source = anyone_link_data["anyone_link_source"]
    anyone_title = anyone_link_data["anyone_title"]
    anyone_remediation = anyone_link_data["anyone_remediation"]
    if len(public_web_files) == 0 and user_owner_public_web_files:
        public_web_files = user_owner_public_web_files

    mobile_data = collect_mobile_device_observations(access_token)
    mobile_devices = mobile_data["mobile_devices"]
    unencrypted_mobile_devices = mobile_data["unencrypted_mobile_devices"]

    findings = build_findings_list(
        super_admin_without_2sv,
        no_2sv_enforced,
        risky_tokens,
        suspicious_logins,
        external_sharing_events,
        anyone_link_files_count,
        anyone_link_evidence,
        anyone_title,
        anyone_remediation,
        public_web_files,
        domain_rows,
        admin_event_counts,
        token_event_counts,
        groups_anyone_can_join,
        groups_anyone_can_view,
        stale_active_users,
        drive_scan_error,
        user_owner_scan_errors,
        groups_scan_error,
        groups_settings_errors,
        unencrypted_mobile_devices,
    )
    admin_change_keys = [
        "ADD_TO_TRUSTED_OAUTH2_APPS",
        "CHANGE_APP_ACCESS",
        "AUTHORIZE_API_CLIENT_ACCESS",
        "ASSIGN_ROLE",
        "USER_PUT_IN_TWO_STEP_VERIFICATION_GRACE_PERIOD",
        "CHANGE_APPLICATION_SETTING",
        "CREATE_APPLICATION_SETTING",
    ]
    admin_security_change_count = sum(admin_event_counts.get(k, 0) for k in admin_change_keys)
    token_authorize_count = int(token_event_counts.get("authorize", 0))

    summary = {
        "totalUsers": len(users),
        "activeUsers": len(active_users),
        "usersWithout2SVEnrollment": len(no_2sv_enrolled),
        "usersWithout2SVEnforcement": len(no_2sv_enforced),
        "superAdmins": len(super_admin_emails),
        "superAdminsWithout2SVEnforcement": len(super_admin_without_2sv),
        "riskyOAuthGrants": len(risky_tokens),
        "suspiciousLoginEvents30d": len(suspicious_logins),
        "externalSharingEvents30d": len(external_sharing_events),
        "driveFilesScanned": len(domain_drive_files),
        "driveScanTruncated": drive_scan_truncated,
        "driveScanError": bool(drive_scan_error),
        "filesAnyoneWithLink": anyone_link_files_count,
        "filesAnyoneWithLinkSource": anyone_link_source,
        "filesPublicOnWeb": len(public_web_files),
        "externalSharedDomains": len(domain_rows),
        "externalSharedDomainsSource": "drive_inventory" if len(domain_drive_files) > 0 else ("drive_activity_events" if domain_rows else "unavailable"),
        "driveUserOwnerScanUsers": user_owner_users_scanned,
        "driveUserOwnerScanErrors": len(user_owner_scan_errors),
        "adminSecurityChangeEvents30d": admin_security_change_count,
        "tokenAuthorizeEvents30d": token_authorize_count,
        "tokenRevokeEvents30d": int(token_event_counts.get("revoke", 0)),
        "groupsTotal": len(groups),
        "groupsAnyoneCanJoin": len(groups_anyone_can_join),
        "groupsAnyoneCanView": len(groups_anyone_can_view),
        "groupsScanError": bool(groups_scan_error or groups_settings_errors),
        "staleAccounts90d": len(stale_active_users),
        "neverLoggedInActiveUsers": len(never_logged_in_users),
        "mobileDevices": len(mobile_devices),
        "unencryptedMobileDevices": len(unencrypted_mobile_devices),
    }
    score, grade = calculate_domain_health(summary)
    summary["domainHealthScore"] = score
    summary["domainHealthGrade"] = grade

    return {
        "generatedAt": to_iso(utc_now()),
        "scope": "entire_primary_domain",
        "summary": summary,
        "observations": {
            "superAdmins": super_admin_emails,
            "loginEventCounts30d": event_counts,
            "externalSharingEventCounts30d": external_sharing_counts,
            "adminEventCounts30d": dict(admin_event_counts),
            "tokenEventCounts30d": dict(token_event_counts),
            "groupsEventCounts30d": dict(groups_event_counts),
            "staleActiveUsers90d": stale_active_users[:200],
            "neverLoggedInActiveUsers": never_logged_in_users[:200],
            "driveInventory": {
                "anyoneWithLinkFilesSample": anyone_link_evidence[:100],
                "publicOnWebFilesSample": public_web_files[:100],
                "anyoneWithLinkSource": anyone_link_source,
                "topAnyoneWithLinkOwners": anyone_link_owner_counts.most_common(20),
                "topPublicWebOwners": public_web_owner_counts.most_common(20),
                "externalSharedDomains": domain_rows[:200],
                "csvPath": domains_csv_path or "",
                "scanError": drive_scan_error or "",
                "scanTruncated": drive_scan_truncated,
                "userOwnerScanUsers": user_owner_users_scanned,
                "userOwnerScanErrors": user_owner_scan_errors[:100],
            },
            "groupsExposure": {
                "groupsAnyoneCanJoin": groups_anyone_can_join[:200],
                "groupsAnyoneCanView": groups_anyone_can_view[:200],
                "groupsScanError": groups_scan_error or "",
                "groupsSettingsErrors": groups_settings_errors[:100],
            },
        },
        "findings": findings,
    }


def run_audit(args):
    access_token = None
    if args.service_account_key and args.impersonate_admin:
        creds = service_account.Credentials.from_service_account_file(
            args.service_account_key,
            scopes=SCOPES,
        ).with_subject(args.impersonate_admin)
        creds.refresh(Request())
        access_token = creds.token
    else:
        if not args.token:
            raise RuntimeError("Either --token or both --service-account-key and --impersonate-admin are required.")
        token = read_json(args.token)
        client_id = client_secret = None
        if args.client_secret and os.path.exists(args.client_secret):
            client_id, client_secret = load_client(args.client_secret)
        if is_expired(token):
            if client_id and client_secret and token.get("refresh_token"):
                token = refresh_access_token(token, client_id, client_secret)
                write_token_json(args.token, token)
            else:
                raise RuntimeError("Access token expired and no refresh path available.")
        access_token = token["access_token"]

    findings = build_findings(
        access_token,
        domains_csv_path=args.domains_csv,
        service_account_key=args.service_account_key,
    )
    write_json(args.out, findings)
    print(f"Findings written to: {args.out}")
    if args.domains_csv:
        print(f"Shared domains CSV written to: {args.domains_csv}")
    print(json.dumps(findings.get("summary", {}), indent=2))


def severity_rank(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(str(sev).lower(), 9)


def logo_file_to_data_uri(logo_path):
    if not logo_path or not os.path.exists(logo_path):
        return ""
    mime = LOGO_MIME_BY_EXT.get(os.path.splitext(logo_path)[1].lower(), "application/octet-stream")
    with open(logo_path, "rb") as f:
        encoded = base64.b64encode(f.read()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def build_recommendations(summary):
    recommendations = []
    if summary.get("usersWithout2SVEnrollment", 0) > 0:
        recommendations.append("Require 2SV enrollment for all remaining users and enforce hardware-backed MFA for privileged roles.")
    if summary.get("riskyOAuthGrants", 0) > 0:
        recommendations.append("Review and revoke high-impact OAuth grants; implement app allowlisting and least-privilege OAuth scope policy.")
    if summary.get("suspiciousLoginEvents30d", 0) > 0:
        recommendations.append("Investigate risky login events, then enable tighter context-aware access rules and alert response SLAs.")
    if summary.get("externalSharingEvents30d", 0) > 0:
        recommendations.append("Audit files shared externally, remove non-business external collaborators, and restrict public link sharing by OU.")
    if summary.get("filesAnyoneWithLink", 0) > 0:
        recommendations.append("Prioritize removal of 'anyone with link' access on sensitive files and enforce safer default sharing permissions.")
    if summary.get("groupsAnyoneCanJoin", 0) > 0:
        recommendations.append("Restrict Google Groups join policy so external/anyone-join is disabled unless explicitly justified.")
    if summary.get("groupsAnyoneCanView", 0) > 0:
        recommendations.append("Restrict Google Groups read visibility to members/domain users to prevent public information leakage.")
    if summary.get("staleAccounts90d", 0) > 0:
        recommendations.append("Suspend or validate stale active accounts (90+ days inactivity) to reduce account takeover and persistence risk.")
    if summary.get("driveScanError", False):
        recommendations.append("Drive API inventory returned errors; validate API enablement/permissions and rerun to get exact sharing state.")
    if summary.get("groupsScanError", False):
        recommendations.append("Groups settings inventory had errors; validate Groups Settings API enablement and admin permissions.")
    if summary.get("unencryptedMobileDevices", 0) > 0:
        recommendations.append("Block non-compliant mobile devices and enforce full-disk encryption in endpoint management policy.")
    if not recommendations:
        recommendations.append("Maintain current baseline and schedule monthly security telemetry reviews.")
    return recommendations


def load_optional_json(path):
    if not path or not os.path.exists(path):
        return None
    try:
        return read_json(path)
    except Exception:
        return None


def render_report_html(findings, customer, prepared_by, logo_url, findings_path="", email_health=None):
    summary = findings.get("summary", {})
    observations = findings.get("observations", {})
    drive_inventory = observations.get("driveInventory", {})
    token_counts = observations.get("tokenEventCounts30d", {})
    score_data = compute_posture_breakdown(summary)

    external_domains = [str(d.get("domain", "")).strip() for d in drive_inventory.get("externalSharedDomains", []) if d.get("domain")]
    external_domains_html = ", ".join(f"<code>{html.escape(d)}</code>" for d in external_domains) if external_domains else "No external domains observed."
    domains_csv_path = drive_inventory.get("csvPath", "")

    admin_security_change_count = int(summary.get("adminSecurityChangeEvents30d", 0))
    token_authorize_count = int(summary.get("tokenAuthorizeEvents30d", token_counts.get("authorize", 0)))
    token_revoke_count = int(summary.get("tokenRevokeEvents30d", token_counts.get("revoke", 0)))
    token_deny_count = int(token_counts.get("deny", 0))

    email_health = email_health or {}
    email_summary = email_health.get("summary", {})
    email_domains = email_health.get("domains", [])
    email_domains_checked = int(email_summary.get("domains_checked", 0))
    email_with_spf = int(email_summary.get("domains_with_spf", 0))
    email_with_dkim = int(email_summary.get("domains_with_dkim_detected", 0))
    email_with_dmarc = int(email_summary.get("domains_with_dmarc", 0))
    email_score = email_summary.get("overall_email_domain_health_score", "N/A")

    verified_scores = [int(d.get("score", 0)) for d in email_domains if d.get("verified")]
    verified_avg = round(sum(verified_scores) / len(verified_scores), 1) if verified_scores else "N/A"
    dmarc_none_domains = [d.get("domain", "") for d in email_domains if d.get("dmarc_present") and str(d.get("dmarc_policy", "")).lower() == "none"]
    alias_unprotected = [d.get("domain", "") for d in email_domains if (not d.get("verified")) and (not d.get("spf_present")) and (not d.get("dkim_present")) and (not d.get("dmarc_present"))]
    primary_gap_text = (
        ", ".join(f"<code>{html.escape(d)}</code>" for d in dmarc_none_domains) + " DMARC policy is currently <code>p=none</code> (monitor-only)."
        if dmarc_none_domains
        else "No DMARC monitor-only domains were detected."
    )
    alias_gap_text = (
        ", ".join(f"<code>{html.escape(d)}</code>" for d in alias_unprotected) + " appears unverified and has no detectable SPF/DKIM/DMARC controls."
        if alias_unprotected
        else "No unverified alias domains without SPF/DKIM/DMARC were detected."
    )

    email_rows = []
    for d in email_domains:
        domain_name = str(d.get("domain", ""))
        if d.get("source") == "alias" and not d.get("verified"):
            domain_name += " (alias, unverified)"
        spf = f"Present ({'~all' if str(d.get('spf_mode', '')).lower() == 'soft_fail' else d.get('spf_mode', '')})" if d.get("spf_present") else "Missing"
        dkim = "Present" if d.get("dkim_present") else "Missing"
        dmarc = "Present" if d.get("dmarc_present") else "Missing"
        policy = d.get("dmarc_policy", "n/a") if d.get("dmarc_present") else "n/a"
        score = d.get("score", 0)
        email_rows.append(
            f"<tr><td>{html.escape(str(domain_name))}</td><td>{html.escape(str(spf))}</td><td>{html.escape(str(dkim))}</td><td>{html.escape(str(dmarc))}</td><td>{html.escape(str(policy))}</td><td>{html.escape(str(score))}</td></tr>"
        )
    email_rows_html = "\n".join(email_rows) if email_rows else "<tr><td colspan='6'>No email domain health data provided.</td></tr>"

    identity_status = ("sev-low", "Good") if int(summary.get("usersWithout2SVEnrollment", 0)) == 0 else ("sev-medium", "Partial")
    oauth_status = ("sev-low", "Good") if int(summary.get("riskyOAuthGrants", 0)) == 0 else ("sev-high", "At Risk")
    sharing_status = ("sev-low", "Good") if int(summary.get("filesAnyoneWithLink", 0)) == 0 else ("sev-high", "At Risk")
    groups_exposed = int(summary.get("groupsAnyoneCanJoin", 0)) + int(summary.get("groupsAnyoneCanView", 0))
    groups_status = ("sev-low", "Good") if groups_exposed == 0 else ("sev-medium", "Partial")
    endpoint_status = ("sev-low", "Good") if int(summary.get("unencryptedMobileDevices", 0)) == 0 else ("sev-medium", "Partial")
    email_status = ("sev-medium", "Partial")
    if email_domains_checked > 0 and email_with_spf == email_domains_checked and email_with_dkim == email_domains_checked and email_with_dmarc == email_domains_checked and len(dmarc_none_domains) == 0:
        email_status = ("sev-low", "Good")

    static_recommendations = [
        f"Complete 2SV enrollment for the remaining {int(summary.get('usersWithout2SVEnrollment', 0))} users and enforce phishing-resistant MFA for privileged roles.",
        "Review and revoke unnecessary OAuth grants, then enforce an approved-app/least-privilege OAuth policy.",
        "Investigate risky login events per user and tighten conditional/context-aware access controls.",
        "Audit external sharing activity, remove unnecessary external collaborators, and restrict public link sharing by OU.",
        f"Reduce anyone-with-link exposure from {int(summary.get('filesAnyoneWithLink', 0))} files by enforcing internal-only defaults and exception approvals.",
        "Introduce formal admin change-control for trusted apps/app-access policy updates with monthly compliance review.",
        "Set recurring OAuth consent governance (owner + business justification + expiry) to reduce app-access sprawl.",
        "Move DMARC from monitor mode to enforcement where feasible after staged monitoring.",
        "Remove unused alias domains or fully configure SPF/DKIM/DMARC controls.",
        "Suspend or recertify stale active accounts and automatically deprovision dormant accounts after policy threshold.",
    ]
    recommendation_rows = "\n".join(f"<li>{html.escape(r)}</li>" for r in static_recommendations)

    logo_markup = (
        f"<img src='{html.escape(logo_url)}' alt='Grey Wing Security logo' style='max-height:100px;max-width:420px;object-fit:contain;' />"
        if logo_url
        else "Insert logo"
    )

    generated_at_raw = str(findings.get("generatedAt", to_iso(utc_now())))
    assessment_date = html.escape(generated_at_raw[:10])
    generated_at = html.escape(generated_at_raw)
    customer = html.escape(customer)
    prepared_by = html.escape(prepared_by)
    findings_path = html.escape(findings_path or "")
    domains_csv_path = html.escape(str(domains_csv_path or "Not provided"))
    script_path = html.escape(os.path.abspath(__file__))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Google Workspace Security Assessment Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; background: #f6f8fb; color: #1f2937; }}
    .page {{ max-width: 980px; margin: 24px auto; background: #fff; padding: 36px; box-shadow: 0 2px 10px rgba(0,0,0,.08); }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e5e7eb; padding-bottom: 16px; margin-bottom: 20px; }}
    .logo-box {{ width: 420px; min-height: 110px; display: flex; align-items: center; justify-content: center; color: #6b7280; font-size: 13px; text-align: center; border: 1px solid #e5e7eb; border-radius: 8px; background: #fff; }}
    h1 {{ margin: 0 0 6px 0; font-size: 28px; }}
    h2 {{ margin-top: 30px; font-size: 21px; border-left: 4px solid #2563eb; padding-left: 10px; }}
    h3 {{ margin-top: 20px; font-size: 17px; }}
    p, li {{ line-height: 1.5; }}
    .meta {{ font-size: 14px; color: #4b5563; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 12px; }}
    .card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; }}
    .metric {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
    .sev-critical, .sev-high, .sev-medium, .sev-low {{ font-weight: 700; }}
    .sev-critical {{ color: #b91c1c; }}
    .sev-high {{ color: #b45309; }}
    .sev-medium {{ color: #1d4ed8; }}
    .sev-low {{ color: #047857; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 10px; text-align: left; font-size: 14px; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    .small {{ font-size: 12px; color: #6b7280; }}
    .footer {{ margin-top: 28px; font-size: 12px; color: #6b7280; border-top: 1px solid #e5e7eb; padding-top: 12px; }}
    @media print {{
      body {{ background: #fff; }}
      .page {{ box-shadow: none; margin: 0; max-width: 100%; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="header">
      <div>
        <h1>Google Workspace Security Assessment</h1>
        <div class="meta"><strong>Customer:</strong> {customer}</div>
        <div class="meta"><strong>Prepared by:</strong> {prepared_by}</div>
        <div class="meta"><strong>Assessment Date:</strong> {assessment_date}</div>
      </div>
      <div class="logo-box">{logo_markup}</div>
    </div>

    <h2>1. Executive Summary</h2>
    <p>
      This report summarizes a read-only security assessment of the Google Workspace environment using Google Admin APIs across identity, authentication, OAuth access, device security, and login telemetry.
      The assessment identified several high-risk OAuth grants, repeated risky/failed login patterns, and notable external sharing activity requiring immediate review.
    </p>
    <p><strong>Overall Workspace Security Posture Score:</strong> <strong>{score_data["score"]} / 100 (Grade: {html.escape(score_data["grade"])})</strong></p>
    <p><strong>Why {score_data["score"]}:</strong> this posture score starts at 100 and is reduced by weighted risk factors across identity, OAuth, login risk, sharing, and stale accounts.</p>
    <ul>
      <li>2SV not enrolled: <strong>-{score_data["p_2sv_enrollment"]}</strong> ({int(summary.get("usersWithout2SVEnrollment", 0))}/{int(summary.get("activeUsers", 0))} active users)</li>
      <li>2SV not enforced: <strong>-{score_data["p_2sv_enforcement"]}</strong> ({int(summary.get("usersWithout2SVEnforcement", 0))}/{int(summary.get("activeUsers", 0))} active users)</li>
      <li>High-impact OAuth grants: <strong>-{score_data["p_oauth"]}</strong> ({int(summary.get("riskyOAuthGrants", 0))} grants, capped)</li>
      <li>Suspicious login events: <strong>-{score_data["p_login"]}</strong> ({int(summary.get("suspiciousLoginEvents30d", 0))} events, capped)</li>
      <li>External shared domains: <strong>-{score_data["p_external_domains"]}</strong> ({int(summary.get("externalSharedDomains", 0))} domains)</li>
      <li>Anyone-with-link files: <strong>-{score_data["p_anyone_link"]}</strong> ({int(summary.get("filesAnyoneWithLink", 0))} files, capped)</li>
      <li>Public-on-web files: <strong>-{score_data["p_public_on_web"]}</strong> ({int(summary.get("filesPublicOnWeb", 0))} files, capped)</li>
      <li>Groups anyone can join: <strong>-{score_data["p_groups_anyone_join"]}</strong> ({int(summary.get("groupsAnyoneCanJoin", 0))} groups, capped)</li>
      <li>Groups anyone can view: <strong>-{score_data["p_groups_anyone_view"]}</strong> ({int(summary.get("groupsAnyoneCanView", 0))} groups, capped)</li>
      <li>Stale active accounts: <strong>-{score_data["p_stale"]}</strong> ({int(summary.get("staleAccounts90d", 0))} accounts inactive 90+ days)</li>
      <li>Unencrypted mobile devices: <strong>-{score_data["p_unencrypted_mobile"]}</strong> ({int(summary.get("unencryptedMobileDevices", 0))} devices, capped)</li>
      <li><strong>Total penalty: -{score_data["total_penalty"]}</strong> → final score <strong>{score_data["score"]}</strong></li>
    </ul>
    <p><strong>Email Domain Health (SPF/DKIM/DMARC):</strong> <strong>{email_score} / 100 overall</strong> (<strong>{verified_avg} / 100</strong> on verified domains only).</p>

    <div class="grid">
      <div class="card"><div>Active Users</div><div class="metric">{int(summary.get("activeUsers", 0))}</div></div>
      <div class="card"><div>Users Not Enrolled in 2SV</div><div class="metric">{int(summary.get("usersWithout2SVEnrollment", 0))}</div></div>
      <div class="card"><div>High-Impact OAuth Grants</div><div class="metric">{int(summary.get("riskyOAuthGrants", 0))}</div></div>
      <div class="card"><div>Suspicious Login Events (30d)</div><div class="metric">{int(summary.get("suspiciousLoginEvents30d", 0))}</div></div>
      <div class="card"><div>External Sharing Events (30d)</div><div class="metric">{int(summary.get("externalSharingEvents30d", 0))}</div></div>
      <div class="card"><div>External Shared Domains (30d activity)</div><div class="metric">{int(summary.get("externalSharedDomains", 0))}</div></div>
      <div class="card"><div>Anyone-with-link Files (current state)</div><div class="metric">{int(summary.get("filesAnyoneWithLink", 0))}</div></div>
      <div class="card"><div>Groups Anyone Can Join</div><div class="metric">{int(summary.get("groupsAnyoneCanJoin", 0))}</div></div>
      <div class="card"><div>Groups Anyone Can Read</div><div class="metric">{int(summary.get("groupsAnyoneCanView", 0))}</div></div>
      <div class="card"><div>Stale Active Accounts (90+ days)</div><div class="metric">{int(summary.get("staleAccounts90d", 0))}</div></div>
      <div class="card"><div>Never-Logged-In Active Users</div><div class="metric">{int(summary.get("neverLoggedInActiveUsers", 0))}</div></div>
      <div class="card"><div>Email Domains Checked</div><div class="metric">{email_domains_checked if email_domains_checked else "N/A"}</div></div>
      <div class="card"><div>Domains with SPF / DKIM / DMARC</div><div class="metric">{email_with_spf}/{email_with_dkim}/{email_with_dmarc}</div></div>
      <div class="card"><div>Admin Security/App Changes (30d)</div><div class="metric">{admin_security_change_count}</div></div>
      <div class="card"><div>OAuth Token Authorizations (30d)</div><div class="metric">{token_authorize_count}</div></div>
    </div>

    <h2>2. Scope & Method</h2>
    <ul>
      <li><strong>Scope:</strong> Entire primary Google Workspace domain.</li>
      <li><strong>Access model:</strong> Domain-wide delegated service account + read-only API scopes.</li>
      <li><strong>Data sources:</strong> Directory API, Reports API, Groups Settings API, Drive API metadata queries, and DNS TXT checks (SPF/DKIM/DMARC).</li>
      <li><strong>Assessment window:</strong> Login telemetry reviewed for trailing 30 days.</li>
      <li><strong>Generated:</strong> {generated_at}</li>
    </ul>

    <h2>3. Risk Register</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Finding</th>
          <th>Impact</th>
          <th>Evidence (Count)</th>
          <th>Recommended Action</th>
        </tr>
      </thead>
      <tbody>
        <tr><td class="sev-high">High</td><td>OAuth grants with high-impact scopes</td><td>Potential broad data access (mail, drive, cloud resources) via third-party apps.</td><td>{int(summary.get("riskyOAuthGrants", 0))} grants</td><td>Review and revoke non-essential OAuth grants; enforce trusted app controls and scope restrictions.</td></tr>
        <tr><td class="sev-medium">Medium</td><td>Suspicious login-related events</td><td>Potential account takeover attempts and risky session activity.</td><td>{int(summary.get("suspiciousLoginEvents30d", 0))} events in 30 days</td><td>Investigate affected users, geolocation anomalies, repeated failures, and challenge outcomes.</td></tr>
        <tr><td class="sev-high">High</td><td>Potential external sharing activity</td><td>Possible data exposure to external collaborators or public links.</td><td>{int(summary.get("externalSharingEvents30d", 0))} events in 30 days</td><td>Review externally shared files/folders, remove unnecessary external access, and restrict public link sharing by policy.</td></tr>
        <tr><td class="sev-medium">Medium</td><td>Admin security/app-access changes observed</td><td>High volume of trust/app-access/policy changes increases misconfiguration risk without strict change control.</td><td>{admin_security_change_count} admin security-related events in 30 days</td><td>Map every change to approved tickets and enforce two-person review for high-impact admin changes.</td></tr>
        <tr><td class="sev-medium">Medium</td><td>OAuth token authorization volume</td><td>High app-authorization volume indicates app sprawl and elevated third-party access risk.</td><td>{token_authorize_count} authorize events ({token_revoke_count} revokes) in 30 days</td><td>Enforce app allowlisting, periodic consent review, and automated revocation for high-risk scopes.</td></tr>
        <tr><td class="sev-medium">Medium</td><td>Stale active accounts</td><td>Inactive accounts can be abused for persistence and unauthorized access.</td><td>{int(summary.get("staleAccounts90d", 0))} accounts inactive 90+ days ({int(summary.get("neverLoggedInActiveUsers", 0))} never logged in)</td><td>Suspend or validate stale accounts and enforce owner recertification.</td></tr>
        <tr><td class="sev-high">High</td><td>Files accessible via “anyone with link”</td><td>Large public-link footprint increases accidental exposure risk.</td><td>{int(summary.get("filesAnyoneWithLink", 0))} files (exact per-user owner scan)</td><td>Reduce link-sharing on sensitive assets, enforce internal-only defaults, and monitor exceptions.</td></tr>
        <tr><td class="sev-medium">Medium</td><td>Users not enrolled in 2SV</td><td>Increased likelihood of credential compromise.</td><td>{int(summary.get("usersWithout2SVEnrollment", 0))} active users</td><td>Complete 2SV enrollment for remaining users and verify enforcement stays at 100%.</td></tr>
      </tbody>
    </table>

    <h2>4. Detailed Findings</h2>
    <h3>4.1 OAuth Exposure</h3>
    <p>High-impact scopes were detected across several applications, including mail and cloud-platform level access.</p>
    <ul>
      <li>Examples observed: <code>https://mail.google.com/</code>, <code>https://www.googleapis.com/auth/drive</code>, <code>https://www.googleapis.com/auth/cloud-platform</code>.</li>
      <li>Total high-impact OAuth grants observed: <strong>{int(summary.get("riskyOAuthGrants", 0))}</strong>.</li>
    </ul>

    <h3>4.2 Authentication & Login Risk</h3>
    <ul>
      <li>Observed events include <code>login_failure</code>, <code>login_challenge</code>, and <code>risky_sensitive_action_allowed</code>/<code>blocked</code>.</li>
      <li>Total suspicious login events in 30-day window: <strong>{int(summary.get("suspiciousLoginEvents30d", 0))}</strong>.</li>
    </ul>

    <h3>4.3 Identity Baseline</h3>
    <ul>
      <li>2SV enforcement appears enabled for enrolled users, but <strong>{int(summary.get("usersWithout2SVEnrollment", 0))} active users</strong> are still not enrolled.</li>
      <li>No unencrypted managed mobile devices were detected in the collected dataset.</li>
      <li class="small">Note: API role assignment output may be incomplete in some tenants; validate Super Admin list directly in Admin Console.</li>
    </ul>

    <h3>4.4 External Sharing Exposure</h3>
    <ul>
      <li>Drive telemetry indicates <strong>{int(summary.get("externalSharingEvents30d", 0))} potential external sharing-related events</strong> in the 30-day review window.</li>
      <li>Observed external domains in sharing activity include: {external_domains_html}</li>
      <li>A detailed CSV of observed external domains was generated at <code>{domains_csv_path}</code>.</li>
      <li>Exact current-state count of files with “anyone with link” is available via delegated per-user scan: <strong>{int(summary.get("filesAnyoneWithLink", 0))} files</strong>.</li>
    </ul>

    <h3>4.5 Additional Issues Identified</h3>
    <ul>
      <li><strong>{int(summary.get("staleAccounts90d", 0))} stale active accounts</strong> (including <strong>{int(summary.get("neverLoggedInActiveUsers", 0))} never-logged-in accounts</strong>) should be reviewed for deprovisioning or suspension.</li>
      <li><strong>{int(summary.get("filesAnyoneWithLink", 0))} files currently use anyone-with-link visibility</strong>; prioritize remediation by data sensitivity and owner.</li>
    </ul>

    <h3>4.6 Google Groups Exposure</h3>
    <ul>
      <li>Detected groups in tenant: <strong>{int(summary.get("groupsTotal", 0))}</strong>.</li>
      <li>Confirmed groups allowing anyone to join: <strong>{int(summary.get("groupsAnyoneCanJoin", 0))}</strong>.</li>
      <li>Confirmed groups allowing anyone to read: <strong>{int(summary.get("groupsAnyoneCanView", 0))}</strong>.</li>
      <li>Groups settings check {"completed successfully" if not summary.get("groupsScanError", False) else "returned errors"} in this run.</li>
    </ul>

    <h3>4.7 Admin & API Governance</h3>
    <ul>
      <li>Admin audit logs show <strong>{admin_security_change_count} security/app-access relevant changes</strong> in the last 30 days.</li>
      <li>Token audit logs show <strong>{token_authorize_count} authorization events</strong>, <strong>{token_revoke_count} revocations</strong>, and <strong>{token_deny_count} consent denials</strong>.</li>
      <li>This pattern is common in fast-moving environments but requires stronger change control and periodic app-consent governance.</li>
    </ul>

    <h3>4.8 Control Coverage Matrix</h3>
    <table>
      <thead><tr><th>Control Area</th><th>Status</th><th>Evidence</th><th>Notes</th></tr></thead>
      <tbody>
        <tr><td>Identity & MFA</td><td class="{identity_status[0]}">{identity_status[1]}</td><td>{int(summary.get("usersWithout2SVEnrollment", 0))} users not enrolled in 2SV; enforcement present for enrolled users</td><td>Close enrollment gap and harden privileged auth</td></tr>
        <tr><td>OAuth/App Access Governance</td><td class="{oauth_status[0]}">{oauth_status[1]}</td><td>{int(summary.get("riskyOAuthGrants", 0))} high-impact grants; {token_authorize_count} token authorizations</td><td>Implement allowlisting and periodic grant recertification</td></tr>
        <tr><td>Data Sharing Controls (Drive)</td><td class="{sharing_status[0]}">{sharing_status[1]}</td><td>{int(summary.get("filesAnyoneWithLink", 0))} anyone-with-link files; {int(summary.get("externalSharingEvents30d", 0))} external sharing events</td><td>Prioritize sensitive file remediation and policy hardening</td></tr>
        <tr><td>Groups Exposure</td><td class="{groups_status[0]}">{groups_status[1]}</td><td>{groups_exposed} groups with anyone-join/read exposure</td><td>Maintain restrictive settings and continue periodic review</td></tr>
        <tr><td>Email Domain Authentication</td><td class="{email_status[0]}">{email_status[1]}</td><td>SPF/DKIM/DMARC: {email_with_spf}/{email_with_dkim}/{email_with_dmarc} domains checked</td><td>Move DMARC monitor-only domains to enforcement and clean up alias posture</td></tr>
        <tr><td>Endpoint Posture</td><td class="{endpoint_status[0]}">{endpoint_status[1]}</td><td>{int(summary.get("unencryptedMobileDevices", 0))} unencrypted managed mobile devices</td><td>Continue compliance monitoring</td></tr>
      </tbody>
    </table>

    <h3>4.9 Email Domain Authentication Health (SPF, DKIM, DMARC)</h3>
    <table>
      <thead><tr><th>Domain</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th>Policy</th><th>Score</th></tr></thead>
      <tbody>{email_rows_html}</tbody>
    </table>
    <ul>
      <li>Primary gap: {primary_gap_text}</li>
      <li>Alias risk: {alias_gap_text}</li>
    </ul>

    <h2>5. Control Baseline</h2>
    <table>
      <thead><tr><th>Baseline Domain</th><th>Target Baseline</th><th>Current State</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>Identity / MFA</td><td>100% active users enrolled in MFA; privileged users phishing-resistant</td><td>{int(summary.get("usersWithout2SVEnrollment", 0))} of {int(summary.get("activeUsers", 0))} active users not enrolled in 2SV</td><td class="{identity_status[0]}">{identity_status[1]}</td></tr>
        <tr><td>OAuth App Governance</td><td>Approved-app allowlist; high-risk scopes strictly justified</td><td>{int(summary.get("riskyOAuthGrants", 0))} high-impact grants; {token_authorize_count} authorize events in 30 days</td><td class="{oauth_status[0]}">{oauth_status[1]}</td></tr>
        <tr><td>Drive Public Sharing</td><td>No broad public-link sharing except documented exceptions</td><td>{int(summary.get("filesAnyoneWithLink", 0))} files with anyone-with-link access</td><td class="{sharing_status[0]}">{sharing_status[1]}</td></tr>
        <tr><td>External Collaboration</td><td>Allowlisted domains with periodic recertification</td><td>{int(summary.get("externalSharedDomains", 0))} external domains observed in sharing activity</td><td class="sev-medium">Partial</td></tr>
        <tr><td>Google Groups Exposure</td><td>No groups allowing anyone to join/read</td><td>{groups_exposed} groups with anyone-join/read</td><td class="{groups_status[0]}">{groups_status[1]}</td></tr>
        <tr><td>Email Authentication (SPF/DKIM/DMARC)</td><td>SPF + DKIM + DMARC enforce mode on all active domains</td><td>{email_with_spf}/{email_with_dkim}/{email_with_dmarc} protected domains</td><td class="{email_status[0]}">{email_status[1]}</td></tr>
        <tr><td>Dormant Account Hygiene</td><td>Disable or recertify accounts inactive over 90 days</td><td>{int(summary.get("staleAccounts90d", 0))} stale active accounts; {int(summary.get("neverLoggedInActiveUsers", 0))} never-logged-in accounts</td><td class="sev-medium">Partial</td></tr>
        <tr><td>Admin Change Governance</td><td>Ticketed, approved, and auditable high-impact admin changes</td><td>{admin_security_change_count} admin security/app-access changes in 30 days</td><td class="sev-medium">Partial</td></tr>
      </tbody>
    </table>

    <h2>6. Framework Mapping (CIS + NIST)</h2>
    <p>This mapping is implementation-focused and indicates control posture based on observed evidence in this assessment period.</p>
    <table>
      <thead><tr><th>Framework</th><th>Control / Category</th><th>Assessment</th><th>Evidence</th></tr></thead>
      <tbody>
        <tr><td>CIS Controls v8</td><td>5.1/5.2 Account Inventory & Lifecycle</td><td class="sev-medium">Partial</td><td>{int(summary.get("staleAccounts90d", 0))} stale active accounts, including {int(summary.get("neverLoggedInActiveUsers", 0))} never-logged-in</td></tr>
        <tr><td>CIS Controls v8</td><td>6.3 MFA for user access</td><td class="{identity_status[0]}">{identity_status[1]}</td><td>{int(summary.get("usersWithout2SVEnrollment", 0))} active users not enrolled in 2SV</td></tr>
        <tr><td>CIS Controls v8</td><td>6.7 Centralized access governance</td><td class="{oauth_status[0]}">{oauth_status[1]}</td><td>{int(summary.get("riskyOAuthGrants", 0))} high-impact OAuth grants; high token authorization volume</td></tr>
        <tr><td>CIS Controls v8</td><td>3.3 Data access control / sharing restrictions</td><td class="{sharing_status[0]}">{sharing_status[1]}</td><td>{int(summary.get("filesAnyoneWithLink", 0))} anyone-with-link files; {int(summary.get("externalSharingEvents30d", 0))} external sharing events</td></tr>
        <tr><td>CIS Controls v8</td><td>8.2 Audit log management and review</td><td class="sev-medium">Partial</td><td>Strong log coverage present; governance follow-through required</td></tr>
        <tr><td>NIST CSF 2.0</td><td>PR.AA / PR.AC (Identity, Authentication, Access Control)</td><td class="sev-medium">Partial</td><td>MFA gap remains; group exposure controls are strong</td></tr>
        <tr><td>NIST CSF 2.0</td><td>PR.DS (Data Security)</td><td class="{sharing_status[0]}">{sharing_status[1]}</td><td>Anyone-link exposure and active external sharing footprint</td></tr>
        <tr><td>NIST CSF 2.0</td><td>DE.CM / DE.AE (Continuous Monitoring / Anomalies)</td><td class="sev-medium">Partial</td><td>Telemetry exists; operational triage and SLAs need hardening</td></tr>
        <tr><td>NIST CSF 2.0</td><td>GV.RM / GV.PO (Risk Management / Policy)</td><td class="sev-medium">Partial</td><td>Policy intent present; enforcement and recertification cadence needed</td></tr>
      </tbody>
    </table>

    <h2>7. Recommended Changes</h2>
    <ul>{recommendation_rows}</ul>

    <h2>8. 30-60-90 Day Remediation Plan</h2>
    <table>
      <thead><tr><th>Timeline</th><th>Action</th><th>Owner</th><th>Success Criteria</th></tr></thead>
      <tbody>
        <tr><td>0-30 days</td><td>Review/revoke risky OAuth grants; investigate high-risk login events; close 2SV enrollment gap; triage external sharing events; reduce anyone-with-link exposure on high-risk files first; baseline admin/app-access changes against approved tickets.</td><td>[Security / IT Admin]</td><td>All non-business-critical risky grants removed; all flagged users reviewed; 2SV enrollment at 100%.</td></tr>
        <tr><td>31-60 days</td><td>Implement app allowlisting and context-aware access controls; tighten alert routing.</td><td>[Security Engineering]</td><td>Only approved OAuth apps allowed; priority alerts routed to SOC/helpdesk with SLA.</td></tr>
        <tr><td>61-90 days</td><td>Run follow-up assessment and trend comparison; formalize quarterly governance review.</td><td>[Security Governance]</td><td>Reduction in risky events and grants, documented governance cadence.</td></tr>
      </tbody>
    </table>

    <h2>9. Appendix</h2>
    <ul>
      <li><strong>Raw findings file:</strong> <code>{findings_path or "Not provided"}</code></li>
      <li><strong>External sharing domains CSV:</strong> <code>{domains_csv_path}</code></li>
      <li><strong>Collection script:</strong> <code>{script_path}</code></li>
      <li><strong>Assessment type:</strong> Read-only API review (no configuration changes made).</li>
    </ul>

    <div class="footer">Confidential - Prepared for {customer}.</div>
  </div>
</body>
</html>
"""


def build_report(args):
    findings = read_json(args.findings)
    logo_url = args.logo_url or logo_file_to_data_uri(args.logo_path)
    email_health = load_optional_json(args.email_health_json)
    html_report = render_report_html(
        findings,
        args.customer,
        args.prepared_by,
        logo_url,
        findings_path=args.findings,
        email_health=email_health,
    )
    with open(args.out_html, "w", encoding="utf-8") as f:
        f.write(html_report)
    print(f"Report written to: {args.out_html}")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_login = sub.add_parser("auth-login")
    p_login.add_argument("--client-secret", required=True)
    p_login.add_argument("--token", required=True)
    p_login.set_defaults(func=auth_login)

    p_audit = sub.add_parser("audit")
    p_audit.add_argument("--token")
    p_audit.add_argument("--out", required=True)
    p_audit.add_argument("--client-secret")
    p_audit.add_argument("--domains-csv")
    p_audit.add_argument("--service-account-key")
    p_audit.add_argument("--impersonate-admin")
    p_audit.set_defaults(func=run_audit)

    p_report = sub.add_parser("build-report")
    p_report.add_argument("--findings", required=True)
    p_report.add_argument("--out-html", required=True)
    p_report.add_argument("--customer", required=True)
    p_report.add_argument("--prepared-by", required=True)
    p_report.add_argument("--logo-url")
    p_report.add_argument("--logo-path")
    p_report.add_argument("--email-health-json")
    p_report.set_defaults(func=build_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
