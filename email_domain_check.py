import argparse
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from statistics import mean

import dns.exception
import dns.resolver
import requests
from google.auth.transport.requests import Request
from google.oauth2 import service_account


DEFAULT_SCOPES = ["https://www.googleapis.com/auth/admin.directory.domain.readonly"]
DNS_LOOKUP_ATTEMPTS = 3
DNS_TIMEOUT_SECONDS = 6
DNS_BACKOFF_SECONDS = 1.0
DKIM_SELECTOR_PROBE_LIMIT = 80
DEFAULT_DKIM_SELECTORS = [
    "google",
    "google2",
    "selector1",
    "selector2",
    "default",
    "dkim",
    "mail",
    "smtp",
    "m1",
    "m2",
    "k1",
    "k2",
    "s1",
    "s2",
]


def utc_now():
    return datetime.now(timezone.utc)


def to_iso(ts):
    return ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def parse_iso(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def is_token_expired(token_data):
    expiry = parse_iso(token_data.get("expires_at"))
    if not expiry:
        return False
    return utc_now() >= expiry


def load_oauth_client(client_secret_path):
    data = read_json(client_secret_path)
    block = data.get("installed") or data.get("web")
    if not block:
        raise RuntimeError("Client secret JSON must contain 'installed' or 'web'.")
    return block.get("client_id"), block.get("client_secret", "")


def refresh_access_token(token_data, client_id, client_secret):
    refresh_token = token_data.get("refresh_token")
    if not refresh_token:
        raise RuntimeError("Token is expired and token file does not include refresh_token.")
    r = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=60,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Token refresh failed: HTTP {r.status_code}: {r.text[:500]}")
    data = r.json()
    token_data["access_token"] = data["access_token"]
    token_data["expires_at"] = to_iso(utc_now() + timedelta(seconds=int(data.get("expires_in", 3600))))
    return token_data


def txt(name, attempts=DNS_LOOKUP_ATTEMPTS, lifetime=DNS_TIMEOUT_SECONDS):
    retry_errors = []
    for attempt in range(1, attempts + 1):
        try:
            ans = dns.resolver.resolve(name, "TXT", lifetime=lifetime)
            out = []
            for r in ans:
                s = "".join([b.decode() if isinstance(b, bytes) else str(b) for b in r.strings])
                out.append(s)
            return out, None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], None
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as e:
            retry_errors.append(str(e))
            if attempt >= attempts:
                break
            time.sleep(DNS_BACKOFF_SECONDS * attempt)
        except Exception as e:
            retry_errors.append(str(e))
            if attempt >= attempts:
                break
            time.sleep(DNS_BACKOFF_SECONDS * attempt)
    return [], f"DNS lookup failed for {name} after {attempts} attempts: {retry_errors[-1] if retry_errors else 'unknown error'}"


def parse_spf(recs):
    spf = [r for r in recs if r.lower().startswith("v=spf1")]
    if not spf:
        return False, "none", []
    r = spf[0].lower()
    mode = "neutral"
    if " -all" in (" " + r) or r.endswith("-all"):
        mode = "hard_fail"
    elif " ~all" in (" " + r) or r.endswith("~all"):
        mode = "soft_fail"
    elif " ?all" in (" " + r) or r.endswith("?all"):
        mode = "neutral"
    elif " +all" in (" " + r) or r.endswith("+all"):
        mode = "allow_all"
    return True, mode, spf


def parse_dmarc(recs):
    d = [r for r in recs if r.lower().startswith("v=dmarc1")]
    if not d:
        return False, "none", []
    rec = d[0]
    m = re.search(r"\bp=([a-zA-Z]+)", rec, re.I)
    p = m.group(1).lower() if m else "none"
    return True, p, d


def dkim_check(domain):
    selectors = build_dkim_selectors()
    return dkim_check_with_selectors(domain, selectors, user_supplied=False)


def build_dkim_selectors(extra_selectors=None):
    generated = []
    generated.extend(DEFAULT_DKIM_SELECTORS)
    generated.extend([f"selector{i}" for i in range(1, 31)])
    generated.extend([f"s{i}" for i in range(1, 31)])
    generated.extend([f"k{i}" for i in range(1, 21)])
    if extra_selectors:
        generated.extend([str(x).strip() for x in extra_selectors if str(x).strip()])
    deduped = []
    seen = set()
    for raw in generated:
        s = raw.strip().lower()
        if not s or s in seen:
            continue
        seen.add(s)
        deduped.append(s)
    return deduped[:DKIM_SELECTOR_PROBE_LIMIT]


def dkim_check_with_selectors(domain, selectors, user_supplied=False):
    found = []
    lookup_errors = []
    for s in selectors:
        recs, err = txt(f"{s}._domainkey.{domain}")
        if err:
            lookup_errors.append({"selector": s, "error": err})
            continue
        for r in recs:
            if "v=DKIM1" in r.upper() or "k=rsa" in r.lower() or "p=" in r:
                found.append({"selector": s, "record": r[:180]})
                break
    if found:
        status = "present"
    elif lookup_errors:
        status = "unknown_dns_error"
    elif user_supplied:
        status = "not_detected_for_supplied_selectors"
    else:
        status = "unknown_selector_not_detected"
    return status, found, lookup_errors


def score_domain(spf_present, spf_mode, dkim_status, dmarc_present, dmarc_policy):
    achieved = 0.0
    possible = 0.0

    if spf_present is not None:
        possible += 30
    if spf_present:
        achieved += 20
        if spf_mode == "hard_fail":
            achieved += 10
        elif spf_mode == "soft_fail":
            achieved += 6
        elif spf_mode == "neutral":
            achieved += 2

    if dkim_status in {"present", "not_detected_for_supplied_selectors"}:
        possible += 30
        if dkim_status == "present":
            achieved += 30

    if dmarc_present is not None:
        possible += 50
    if dmarc_present:
        achieved += 20
        if dmarc_policy == "reject":
            achieved += 30
        elif dmarc_policy == "quarantine":
            achieved += 20
        elif dmarc_policy == "none":
            achieved += 8

    if possible <= 0:
        return 0
    return round((achieved / possible) * 100, 1)


def get_access_token(token_file=None, service_account_key=None, impersonate_admin=None, client_secret_path=None):
    if service_account_key and impersonate_admin:
        creds = service_account.Credentials.from_service_account_file(
            service_account_key,
            scopes=DEFAULT_SCOPES,
        ).with_subject(impersonate_admin)
        creds.refresh(Request())
        return creds.token
    if token_file:
        t = read_json(token_file)
        if is_token_expired(t):
            if client_secret_path and os.path.exists(client_secret_path):
                client_id, client_secret = load_oauth_client(client_secret_path)
                if not client_id:
                    raise RuntimeError("Client secret file is missing client_id.")
                t = refresh_access_token(t, client_id, client_secret)
                write_json(token_file, t)
            else:
                raise RuntimeError(
                    "Access token is expired. Re-run auth-login to refresh token, or pass --client-secret so this command can refresh automatically."
                )
        token = t.get("access_token")
        if not token:
            raise RuntimeError("Token file does not contain access_token.")
        return token
    raise RuntimeError("Provide --token-file or both --service-account-key and --impersonate-admin.")


def list_workspace_domains(access_token):
    h = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(
        "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domains",
        headers=h,
        timeout=60,
    )
    if r.status_code == 401:
        raise RuntimeError(
            "Google API returned 401 Unauthorized. Token may be expired or invalid. Re-run auth-login or provide --client-secret for auto-refresh."
        )
    if r.status_code >= 400:
        raise RuntimeError(f"Failed to list workspace domains: HTTP {r.status_code}: {r.text[:600]}")
    data = r.json()

    domains = []
    for d in data.get("domains", []):
        dn = (d.get("domainName") or "").lower()
        if dn:
            domains.append({"domain": dn, "source": "primary_or_secondary", "verified": d.get("verified", False)})
        for a in d.get("domainAliases", []) or []:
            an = (a.get("domainAliasName") or "").lower()
            if an:
                domains.append({"domain": an, "source": "alias", "verified": a.get("verified", False)})
    seen = set()
    uniq = []
    for d in domains:
        if d["domain"] in seen:
            continue
        seen.add(d["domain"])
        uniq.append(d)
    return uniq


def run_check(access_token, output_path, dkim_selectors=None):
    domains = list_workspace_domains(access_token)
    results = []
    selectors = build_dkim_selectors(dkim_selectors)
    for d in domains:
        dom = d["domain"]
        spf_recs, spf_err = txt(dom)
        dmarc_recs, dmarc_err = txt(f"_dmarc.{dom}")
        if spf_err:
            spf_present, spf_mode, spf_vals = None, "unknown", []
        else:
            spf_present, spf_mode, spf_vals = parse_spf(spf_recs)
        if dmarc_err:
            dmarc_present, dmarc_policy, dmarc_vals = None, "unknown", []
        else:
            dmarc_present, dmarc_policy, dmarc_vals = parse_dmarc(dmarc_recs)
        dkim_status, dkim_hits, dkim_errors = dkim_check_with_selectors(dom, selectors, user_supplied=bool(dkim_selectors))
        if dkim_status == "present":
            dkim_present = True
        elif dkim_status == "not_detected_for_supplied_selectors":
            dkim_present = False
        else:
            dkim_present = None
        sc = score_domain(spf_present, spf_mode, dkim_status, dmarc_present, dmarc_policy)
        dns_issues = []
        if spf_err:
            dns_issues.append({"control": "spf", "error": spf_err})
        if dmarc_err:
            dns_issues.append({"control": "dmarc", "error": dmarc_err})
        for err in dkim_errors[:10]:
            dns_issues.append({"control": "dkim", "selector": err["selector"], "error": err["error"]})
        results.append(
            {
                "domain": dom,
                "verified": d["verified"],
                "source": d["source"],
                "spf_present": spf_present,
                "spf_mode": spf_mode,
                "dmarc_present": dmarc_present,
                "dmarc_policy": dmarc_policy,
                "dkim_present": dkim_present,
                "dkim_status": dkim_status,
                "dkim_selectors_found": [x["selector"] for x in dkim_hits],
                "dkim_selectors_probed": selectors,
                "score": sc,
                "score_confidence": "partial" if dns_issues or dkim_status.startswith("unknown") else "high",
                "spf_record": spf_vals[0] if spf_vals else "",
                "dmarc_record": dmarc_vals[0] if dmarc_vals else "",
                "dns_issues": dns_issues,
            }
        )

    overall = round(mean([x["score"] for x in results]), 1) if results else 0
    verified = [x for x in results if x.get("verified")]
    verified_score = round(mean([x["score"] for x in verified]), 1) if verified else 0
    summary = {
        "overall_email_domain_health_score": overall,
        "verified_domains_email_health_score": verified_score,
        "domains_checked": len(results),
        "domains_with_spf": sum(1 for x in results if x["spf_present"] is True),
        "domains_with_dmarc": sum(1 for x in results if x["dmarc_present"] is True),
        "domains_with_dkim_detected": sum(1 for x in results if x["dkim_status"] == "present"),
        "domains_with_indeterminate_dkim": sum(1 for x in results if str(x.get("dkim_status", "")).startswith("unknown")),
        "domains_with_dns_issues": sum(1 for x in results if x.get("dns_issues")),
        "dmarc_reject": sum(1 for x in results if x["dmarc_policy"] == "reject"),
        "dmarc_quarantine": sum(1 for x in results if x["dmarc_policy"] == "quarantine"),
        "dmarc_none": sum(1 for x in results if x["dmarc_policy"] == "none"),
    }

    out = {"generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "summary": summary, "domains": results}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(summary, indent=2))
    print(f"Saved: {output_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token-file")
    parser.add_argument("--client-secret")
    parser.add_argument("--service-account-key")
    parser.add_argument("--impersonate-admin")
    parser.add_argument("--dkim-selector", action="append", default=[])
    parser.add_argument("--output", default="email_domain_health.json")
    args = parser.parse_args()

    token = get_access_token(
        token_file=args.token_file,
        client_secret_path=args.client_secret,
        service_account_key=args.service_account_key,
        impersonate_admin=args.impersonate_admin,
    )
    run_check(token, args.output, dkim_selectors=args.dkim_selector)


if __name__ == "__main__":
    main()
