# Herald

Application ownership and vulnerability notifications. The first module handles **container vulnerabilities**
(server vulnerabilities come next).

Built with Django 5, PostgreSQL 16 and Bootstrap 5, and runs with Docker Compose.

## Quick start

```bash
cp .env.example .env        # optional: every value has a default
docker compose up -d --build
```

- Herald: http://localhost:8000 (change with `HERALD_PORT`)
- Mailpit (catches every email in development): http://localhost:8025

Sign in as the superadmin from `SUPERADMIN_EMAIL` / `SUPERADMIN_PASSWORD` (defaults: `admin@herald.local` /
`ChangeMe!2026`). You must choose a new password at first sign-in. **Change `DJANGO_SECRET_KEY` before real use**:
it also derives the key that encrypts the stored SMTP password (or set `HERALD_ENCRYPTION_KEY` to a Fernet key).

On first start, Settings > Email is pre-filled to send through the bundled Mailpit. Point it at your real SMTP
server in **Settings > Email Setting** and use **Send test email**.

## Roles

| Role | Can do |
|---|---|
| Superadmin | Everything, plus add users (email + temporary password), assign roles, reset passwords |
| Administrator | Manage settings, register/edit applications, assign cloud accounts, upload data, send notifications |
| Operation | View the dashboard, applications and all vulnerabilities, and assign cloud accounts to App IDs |
| User | View only App IDs where their email is the owner or an extra notification email |

Users created with a temporary password must change it at first sign-in. "Forgot password?" on the sign-in
page emails a reset link to existing accounts only, and the page never reveals whether an account exists.

## Importing scan data

Go to **Upload Data**, then upload CSV, `.xlsx` or `.xlsm` files (first worksheet; the header row can be on any of
the first 50 rows). Download the blank templates from that page. The 46 scanner columns are defined in
[`vulns/columns.py`](vulns/columns.py). Headers are matched ignoring case and spaces; `Alert ID`, `Account ID` and
`Account Name` are required. App ID is optional.

Uploads go into a single **draft import**. Add as many batch files as you need (a later file replaces an earlier
row with the same Alert ID). Then review the preview and **Finalize** or **Discard** it.

Lifecycle rules (in [`vulns/lifecycle.py`](vulns/lifecycle.py)):

- Alerts are matched across uploads by **Alert ID**.
- An open alert becomes **Remediated** only when the same **Account ID + Asset ID** has a newer **Last Scan**
  without that alert. Assets missing from an upload are untouched.
- Rows older than the stored data are **skipped**, so re-uploading an older file changes nothing.
- A remediated alert seen in a newer scan is **Reopened**.
- A rejected row never counts as evidence of a fix: nothing on its asset is remediated by that import.
- Open alerts whose asset hasn't been rescanned for *N* days (Settings > General, default 90) are flagged
  **Not seen**.
- If the data has no `SLO Date`, one is computed from first seen + the SLO days per severity (Settings > General).

Want sample files? `docker compose exec web python manage.py sample_data --out /tmp/sample` writes three scans (two CSV, one
Excel). Copy them out with `docker compose cp web:/tmp/sample .`. Add `--load` to import them into an empty database.

## Cloud accounts and App IDs

Every alert belongs to one AWS account or Azure subscription. Its application is resolved in this order:

1. The alert's own App ID.
2. Otherwise, the App ID assigned to its cloud account.
3. Otherwise, it is **Unassigned** and appears in the Cloud Accounts queue.

Several accounts can belong to one App ID. Superadmin, Administrator and Operation assign accounts on the
**Cloud Accounts** page, and every change is recorded. Unassigned alerts are not emailed until they have an owner.

## Development

```bash
docker compose exec web python manage.py test
```
