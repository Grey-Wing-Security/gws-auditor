import argparse
import csv
import datetime as dt
import html
import json
import os
import sys
import urllib.parse
from collections import Counter

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


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def to_iso(ts):
    return ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    write_json(args.token, token)
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
    r = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        params=params or {},
        timeout=60,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code} GET {url}: {r.text[:1000]}")
    return r.json()


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


def calculate_domain_health(summary):
    active = max(1, int(summary.get("activeUsers", 0)))
    score = 100.0
    score -= (summary.get("usersWithout2SVEnrollment", 0) / active) * 25
    score -= (summary.get("usersWithout2SVEnforcement", 0) / active) * 15
    score -= min(20.0, (summary.get("riskyOAuthGrants", 0) / active) * 20)
    score -= min(10.0, (summary.get("suspiciousLoginEvents30d", 0) / active) * 6)
    score -= min(12.0, summary.get("filesAnyoneWithLink", 0) * 0.25)
    score -= min(12.0, summary.get("filesPublicOnWeb", 0) * 1.5)
    score -= min(8.0, summary.get("externalSharedDomains", 0) * 0.5)
    score -= min(10.0, summary.get("groupsAnyoneCanJoin", 0) * 2.0)
    score -= min(10.0, summary.get("groupsAnyoneCanView", 0) * 2.0)
    score -= min(8.0, (summary.get("staleAccounts90d", 0) / active) * 20)
    score -= min(5.0, summary.get("unencryptedMobileDevices", 0) * 1.0)
    score = max(0, min(100, round(score, 1)))
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return score, grade


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


def build_findings(access_token, domains_csv_path=None, service_account_key=None):
    users = paged_get(
        "https://admin.googleapis.com/admin/directory/v1/users",
        "users",
        access_token,
        {"customer": "my_customer", "projection": "full", "maxResults": 500, "orderBy": "email"},
    )
    active_users = [u for u in users if not u.get("suspended", False)]
    user_by_id = {u.get("id"): u.get("primaryEmail") for u in users if u.get("id")}
    internal_domains = safe_internal_domains(access_token, users)

    no_2sv_enrolled = [
        u.get("primaryEmail")
        for u in active_users
        if not u.get("isEnrolledIn2Sv", False)
    ]
    no_2sv_enforced = [
        u.get("primaryEmail")
        for u in active_users
        if not u.get("isEnforcedIn2Sv", False)
    ]

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
    super_admin_emails = sorted(
        {user_by_id.get(uid) for uid in super_admin_user_ids if user_by_id.get(uid)}
    )
    super_admin_without_2sv = [
        email
        for email in super_admin_emails
        if any(
            u.get("primaryEmail") == email and not u.get("isEnforcedIn2Sv", False)
            for u in active_users
        )
    ]

    risky_tokens = []
    for u in active_users:
        email = u.get("primaryEmail")
        if not email:
            continue
        tokens = safe_tokens_for_user(access_token, email)
        for t in tokens:
            scopes = t.get("scopes", [])
            if contains_risky_scope(scopes):
                risky_tokens.append(
                    {
                        "user": email,
                        "app": t.get("displayText"),
                        "clientId": t.get("clientId"),
                        "anonymous": t.get("anonymous"),
                        "nativeApp": t.get("nativeApp"),
                        "scopes": scopes,
                    }
                )

    start_time = to_iso(utc_now() - dt.timedelta(days=30))
    login_activities = paged_get(
        "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login",
        "items",
        access_token,
        {"startTime": start_time, "maxResults": 1000},
    )
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

    admin_activities = []
    token_activities = []
    groups_activities = []
    try:
        admin_activities = paged_get(
            "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin",
            "items",
            access_token,
            {"startTime": start_time, "maxResults": 1000},
        )
    except Exception:
        admin_activities = []
    try:
        token_activities = paged_get(
            "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token",
            "items",
            access_token,
            {"startTime": start_time, "maxResults": 1000},
        )
    except Exception:
        token_activities = []
    try:
        groups_activities = paged_get(
            "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/groups",
            "items",
            access_token,
            {"startTime": start_time, "maxResults": 1000},
        )
    except Exception:
        groups_activities = []

    admin_event_counts = Counter()
    token_event_counts = Counter()
    groups_event_counts = Counter()
    for a in admin_activities:
        for ev in a.get("events", []):
            admin_event_counts[(ev.get("name") or "unknown")] += 1
    for a in token_activities:
        for ev in a.get("events", []):
            token_event_counts[(ev.get("name") or "unknown")] += 1
    for a in groups_activities:
        for ev in a.get("events", []):
            groups_event_counts[(ev.get("name") or "unknown")] += 1

    drive_activities = []
    try:
        drive_activities = paged_get(
            "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/drive",
            "items",
            access_token,
            {"startTime": start_time, "maxResults": 1000},
        )
    except Exception:
        drive_activities = []

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
                    k in p_name
                    for k in ("domain", "recipient", "shared_with", "target_user", "email", "owner", "external")
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

    user_owner_users_scanned = 0
    user_owner_scan_errors = []
    user_owner_anyone_link_map = {}
    user_owner_public_web_map = {}
    if service_account_key:
        for u in active_users:
            email = u.get("primaryEmail")
            if not email:
                continue
            try:
                scan = safe_user_public_files_scan(service_account_key, email)
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
            except Exception as e:
                user_owner_scan_errors.append({"user": email, "error": str(e)[:400]})

    user_owner_anyone_link_files = list(user_owner_anyone_link_map.values())
    user_owner_public_web_files = list(user_owner_public_web_map.values())
    anyone_link_owner_counts = Counter((x.get("owner") or "unknown") for x in user_owner_anyone_link_files)
    public_web_owner_counts = Counter((x.get("owner") or "unknown") for x in user_owner_public_web_files)

    anyone_link_files_count = len(anyone_link_files)
    anyone_link_evidence = anyone_link_files[:200]
    anyone_link_source = "drive_inventory" if len(domain_drive_files) > 0 else "unavailable"
    if anyone_link_files_count == 0 and user_owner_anyone_link_files:
        anyone_link_files_count = len(user_owner_anyone_link_files)
        anyone_link_evidence = user_owner_anyone_link_files[:200]
        anyone_link_source = "user_owner_scan_dwd"
    if anyone_link_files_count == 0 and anyone_link_file_ids_from_events:
        anyone_link_files_count = len(anyone_link_file_ids_from_events)
        anyone_link_evidence = [
            {"id": fid, "name": ""} for fid in list(anyone_link_file_ids_from_events)[:200]
        ]
        if not anyone_link_evidence and anyone_link_file_names_from_events:
            anyone_link_evidence = [
                {"id": "", "name": n} for n in list(anyone_link_file_names_from_events)[:200]
            ]
        anyone_link_source = "drive_activity_events"
    if user_owner_users_scanned > 0 and anyone_link_source == "unavailable":
        anyone_link_source = "user_owner_scan_dwd"
    if len(public_web_files) == 0 and user_owner_public_web_files:
        public_web_files = user_owner_public_web_files

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
        anyone_title = "Files accessible via 'Anyone with the link'"
        anyone_remediation = "Remove public link access for non-public assets and enforce safer default sharing settings."
        if drive_scan_error and len(domain_drive_files) == 0:
            anyone_title = "Files observed with 'Anyone with the link' access (activity-based, 30 days)"
            anyone_remediation = "Enable Drive API for exact inventory, then remove unnecessary anyone-link exposure."
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
                write_json(args.token, token)
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


def render_report_html(findings, customer, prepared_by, logo_url):
    summary = findings.get("summary", {})
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

    rows = []
    sorted_findings = sorted(findings.get("findings", []), key=lambda x: severity_rank(x.get("severity")))
    for item in sorted_findings:
        sev = html.escape(str(item.get("severity", "unknown")).lower())
        title = html.escape(str(item.get("title", "")))
        count = html.escape(str(item.get("count", 0)))
        remediation = html.escape(str(item.get("remediation", "")))
        rows.append(
            f"<tr><td class='sev-{sev}'>{sev.title()}</td><td>{title}</td><td>{count}</td><td>{remediation}</td></tr>"
        )
    findings_rows = "\n".join(rows) if rows else "<tr><td colspan='4'>No findings.</td></tr>"
    recommendation_rows = "\n".join(f"<li>{html.escape(r)}</li>" for r in recommendations)

    logo_markup = (
        f"<img src='{html.escape(logo_url)}' alt='Logo' style='max-height:70px;max-width:220px;' />"
        if logo_url
        else "Insert logo"
    )

    generated_at = html.escape(str(findings.get("generatedAt", to_iso(utc_now()))))
    customer = html.escape(customer)
    prepared_by = html.escape(prepared_by)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Google Workspace Security Assessment</title>
  <style>
    :root {{ --gw-blue:#2563eb; --gw-navy:#2b3e6d; --gw-header:#5c5c5c; --gw-charcoal:#00090f; --gw-gray:#7d7d7d; --gw-light-gray:#acaead; }}
    body {{ font-family: Arial, sans-serif; margin: 0; background: #f6f8fb; color: var(--gw-charcoal); }}
    .page {{ max-width: 980px; margin: 24px auto; background: #fff; padding: 36px; box-shadow: 0 2px 10px rgba(0,0,0,.08); }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--gw-header); padding-bottom: 16px; margin-bottom: 20px; }}
    .logo-box {{ width: 220px; height: 70px; border: 2px dashed var(--gw-gray); display: flex; align-items: center; justify-content: center; color: var(--gw-header); font-size: 13px; text-align: center; }}
    h1 {{ margin: 0 0 6px 0; font-size: 28px; }}
    h2 {{ margin-top: 30px; font-size: 21px; border-left: 4px solid var(--gw-navy); padding-left: 10px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border: 1px solid #d1d5db; padding: 10px; text-align: left; font-size: 14px; vertical-align: top; }}
    th {{ background: #f3f4f6; color: var(--gw-charcoal); }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 12px; }}
    .card {{ background: #f9fafb; border: 1px solid #d1d5db; border-radius: 8px; padding: 12px; }}
    .metric {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
    .sev-critical {{ color: #b91c1c; font-weight: 700; }}
    .sev-high {{ color: var(--gw-navy); font-weight: 700; }}
    .sev-medium {{ color: var(--gw-blue); font-weight: 700; }}
    .sev-low {{ color: #047857; font-weight: 700; }}
  </style>
</head>
<body>
  <div class="page">
    <div class="header">
      <div>
        <h1>Google Workspace Security Assessment</h1>
        <div><strong>Customer:</strong> {customer}</div>
        <div><strong>Prepared by:</strong> {prepared_by}</div>
        <div><strong>Generated:</strong> {generated_at}</div>
      </div>
      <div class="logo-box">{logo_markup}</div>
    </div>
    <h2>Executive Summary</h2>
    <div class="grid">
      <div class="card"><div>Active Users</div><div class="metric">{summary.get("activeUsers", 0)}</div></div>
      <div class="card"><div>Users Not Enrolled in 2SV</div><div class="metric">{summary.get("usersWithout2SVEnrollment", 0)}</div></div>
      <div class="card"><div>High-Impact OAuth Grants</div><div class="metric">{summary.get("riskyOAuthGrants", 0)}</div></div>
      <div class="card"><div>Suspicious Login Events (30d)</div><div class="metric">{summary.get("suspiciousLoginEvents30d", 0)}</div></div>
      <div class="card"><div>External Sharing Events (30d)</div><div class="metric">{summary.get("externalSharingEvents30d", 0)}</div></div>
      <div class="card"><div>Files with Anyone-Link Access</div><div class="metric">{summary.get("filesAnyoneWithLink", 0)}</div></div>
      <div class="card"><div>External Shared Domains</div><div class="metric">{summary.get("externalSharedDomains", 0)}</div></div>
      <div class="card"><div>Groups Anyone Can Join</div><div class="metric">{summary.get("groupsAnyoneCanJoin", 0)}</div></div>
      <div class="card"><div>Groups Anyone Can View</div><div class="metric">{summary.get("groupsAnyoneCanView", 0)}</div></div>
      <div class="card"><div>Domain Health Score</div><div class="metric">{summary.get("domainHealthScore", 0)} ({summary.get("domainHealthGrade", "N/A")})</div></div>
    </div>
    <h2>Risk Register</h2>
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Count</th><th>Recommended Action</th></tr></thead>
      <tbody>
        {findings_rows}
      </tbody>
    </table>
    <h2>Recommended Changes</h2>
    <ul>
      {recommendation_rows}
    </ul>
  </div>
</body>
</html>
"""


def build_report(args):
    findings = read_json(args.findings)
    html_report = render_report_html(findings, args.customer, args.prepared_by, args.logo_url)
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
    p_report.set_defaults(func=build_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
