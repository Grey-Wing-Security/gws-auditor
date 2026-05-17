import argparse
import json
import re
from datetime import datetime, timezone
from statistics import mean

import dns.resolver
import requests
from google.auth.transport.requests import Request
from google.oauth2 import service_account


DEFAULT_SCOPES = ["https://www.googleapis.com/auth/admin.directory.domain.readonly"]


def txt(name):
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=6)
        out = []
        for r in ans:
            s = "".join([b.decode() if isinstance(b, bytes) else str(b) for b in r.strings])
            out.append(s)
        return out
    except Exception:
        return []


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
    selectors = ["google", "selector1", "selector2", "google2", "k1", "s1", "s2", "default"]
    found = []
    for s in selectors:
        recs = txt(f"{s}._domainkey.{domain}")
        for r in recs:
            if "v=DKIM1" in r.upper() or "k=rsa" in r.lower() or "p=" in r:
                found.append({"selector": s, "record": r[:180]})
                break
    return (len(found) > 0), found


def score_domain(spf_present, spf_mode, dkim_present, dmarc_present, dmarc_policy):
    score = 0
    if spf_present:
        score += 20
        if spf_mode == "hard_fail":
            score += 10
        elif spf_mode == "soft_fail":
            score += 6
        elif spf_mode == "neutral":
            score += 2
    if dkim_present:
        score += 30
    if dmarc_present:
        score += 20
        if dmarc_policy == "reject":
            score += 30
        elif dmarc_policy == "quarantine":
            score += 20
        elif dmarc_policy == "none":
            score += 8
    return min(100, score)


def get_access_token(token_file=None, service_account_key=None, impersonate_admin=None):
    if service_account_key and impersonate_admin:
        creds = service_account.Credentials.from_service_account_file(
            service_account_key,
            scopes=DEFAULT_SCOPES,
        ).with_subject(impersonate_admin)
        creds.refresh(Request())
        return creds.token
    if token_file:
        with open(token_file, "r", encoding="utf-8") as f:
            t = json.load(f)
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
    r.raise_for_status()
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


def run_check(access_token, output_path):
    domains = list_workspace_domains(access_token)
    results = []
    for d in domains:
        dom = d["domain"]
        spf_recs = txt(dom)
        spf_present, spf_mode, spf_vals = parse_spf(spf_recs)
        dmarc_recs = txt(f"_dmarc.{dom}")
        dmarc_present, dmarc_policy, dmarc_vals = parse_dmarc(dmarc_recs)
        dkim_present, dkim_hits = dkim_check(dom)
        sc = score_domain(spf_present, spf_mode, dkim_present, dmarc_present, dmarc_policy)
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
                "dkim_selectors_found": [x["selector"] for x in dkim_hits],
                "score": sc,
                "spf_record": spf_vals[0] if spf_vals else "",
                "dmarc_record": dmarc_vals[0] if dmarc_vals else "",
            }
        )

    overall = round(mean([x["score"] for x in results]), 1) if results else 0
    verified = [x for x in results if x.get("verified")]
    verified_score = round(mean([x["score"] for x in verified]), 1) if verified else 0
    summary = {
        "overall_email_domain_health_score": overall,
        "verified_domains_email_health_score": verified_score,
        "domains_checked": len(results),
        "domains_with_spf": sum(1 for x in results if x["spf_present"]),
        "domains_with_dmarc": sum(1 for x in results if x["dmarc_present"]),
        "domains_with_dkim_detected": sum(1 for x in results if x["dkim_present"]),
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
    parser.add_argument("--service-account-key")
    parser.add_argument("--impersonate-admin")
    parser.add_argument("--output", default="email_domain_health.json")
    args = parser.parse_args()

    token = get_access_token(
        token_file=args.token_file,
        service_account_key=args.service_account_key,
        impersonate_admin=args.impersonate_admin,
    )
    run_check(token, args.output)


if __name__ == "__main__":
    main()
