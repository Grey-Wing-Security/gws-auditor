# Google Workspace Security Auditor

Read-only security assessment tooling for Google Workspace domains.

## What this includes

- `workspace_audit.py`
  - User/authentication posture (2SV enrollment/enforcement)
  - Risky OAuth grants and token activity
  - Login-risk and sharing telemetry from Admin Reports
  - Drive sharing posture (including anyone-with-link state via delegated per-user scan)
  - Google Groups exposure checks (anyone can join/read)
  - Mobile encryption posture
  - JSON findings + branded HTML report generation
- `email_domain_check.py`
  - DNS-based SPF / DKIM / DMARC posture scoring for Workspace domains

## Requirements

- Python 3.10+
- Google Workspace Super Admin access (or equivalent delegated permissions)
- APIs enabled in Google Cloud project:
  - Admin SDK API
  - Reports API
  - Drive API
  - Groups Settings API

Install deps:

```bash
pip install -r requirements.txt
```

## Auth options

### Option A: OAuth desktop login (quick start)

```bash
python workspace_audit.py auth-login --client-secret /path/to/client_secret.json --token ./gadmin_token.json
python workspace_audit.py audit --token ./gadmin_token.json --out ./findings.json --domains-csv ./drive_shared_domains.csv
```

### Option B: Service Account + Domain-Wide Delegation (recommended for complete sharing inventory)

1. Create Service Account in GCP and enable **Domain-wide delegation**.
2. In Google Admin: Security → API controls → Domain-wide delegation, add the service account Client ID.
3. Authorize scopes used by this tool:

```text
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.user.security
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
https://www.googleapis.com/auth/admin.directory.domain.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/drive.metadata.readonly
https://www.googleapis.com/auth/apps.groups.settings
```

4. Run:

```bash
python workspace_audit.py audit \
  --service-account-key /path/to/service-account.json \
  --impersonate-admin admin@yourdomain.com \
  --out ./findings.json \
  --domains-csv ./drive_shared_domains.csv
```

## Build customer report

```bash
python workspace_audit.py build-report \
  --findings ./findings.json \
  --out-html ./Google_Admin_Security_Report.html \
  --customer "Customer Name" \
  --prepared-by "Your Company" \
  --logo-url "https://example.com/logo.png"
```

## Email auth domain health (SPF/DKIM/DMARC)

With OAuth token:

```bash
python email_domain_check.py --token-file ./gadmin_token.json --output ./email_domain_health.json
```

With OAuth token + automatic refresh when expired:

```bash
python email_domain_check.py \
  --token-file ./gadmin_token.json \
  --client-secret /path/to/client_secret.json \
  --output ./email_domain_health.json
```

With delegated service account:

```bash
python email_domain_check.py \
  --service-account-key /path/to/service-account.json \
  --impersonate-admin admin@yourdomain.com \
  --output ./email_domain_health.json
```

Optional: include custom DKIM selectors (repeat flag):

```bash
python email_domain_check.py \
  --token-file ./gadmin_token.json \
  --dkim-selector mx1 \
  --dkim-selector outbound2026 \
  --output ./email_domain_health.json
```

Notes:
- DKIM probing now checks an expanded selector set and reports unknown/indeterminate status separately from explicit missing.
- DNS TXT queries use retry/backoff; transient DNS failures are surfaced in output (`dns_issues`) instead of silently scoring as missing controls.

## Output artifacts

- Findings JSON (`--out`)
- External sharing domains CSV (`--domains-csv`)
- Report HTML (`build-report --out-html`)
- Email auth health JSON (`email_domain_check.py --output`)

## Security notes

- This tool is designed for **read-only** collection.
- Do not commit token files, OAuth client secrets, or service account keys.
- OAuth token files written by `auth-login` are set to owner read/write permissions (`0600`-equivalent); still treat them as secrets and never share them.
- Prefer delegated service account mode for complete, repeatable tenant-wide collection.
