# Herald

Application ownership and vulnerability notifications. The first module handles **container vulnerabilities**
(server vulnerabilities come next).

Built with Django 5, PostgreSQL 16 and Bootstrap 5, and runs with Docker Compose.

## Quick start

```bash
cp .env.example .env
sed -i "s/^DJANGO_SECRET_KEY=.*/DJANGO_SECRET_KEY=$(openssl rand -hex 32)/; s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 32)/; s/^SUPERADMIN_PASSWORD=.*/SUPERADMIN_PASSWORD=$(openssl rand -hex 16)/" .env
docker compose up -d --build
```

`DJANGO_SECRET_KEY` and `POSTGRES_PASSWORD` are required, and Herald won't start with a missing or published value.

- Herald: http://localhost:8000 (change with `HERALD_PORT`)
- Mailpit (catches every email in development): http://localhost:8025

Sign in as the superadmin from `SUPERADMIN_EMAIL` / `SUPERADMIN_PASSWORD` in your `.env`. You must choose a new
password at first sign-in. `DJANGO_SECRET_KEY` also derives the key that encrypts the stored SMTP password (or set
`HERALD_ENCRYPTION_KEY` to a Fernet key).

**Upgrading an install that relied on the old defaults:** add these to `.env` first. Keep `POSTGRES_PASSWORD` at the
database's current password (the old default was `herald`), because changing the variable doesn't change an existing
database. A new `DJANGO_SECRET_KEY` signs everyone out and makes the stored SMTP password unreadable, so enter it
again in **Settings > Email** unless `HERALD_ENCRYPTION_KEY` is set.

On first start, Settings > Email is pre-filled to send through the bundled Mailpit. Point it at your real SMTP
server in **Settings > Email Setting** and use **Send test email**.

## Running behind HTTPS

Herald serves plain HTTP on its port. Put a reverse proxy in front that terminates TLS, keeps the original `Host`
header and **overwrites** `X-Forwarded-Proto`. Publish Herald only to that proxy, for example
`HERALD_PORT=127.0.0.1:8000`, because anyone who can reach the port directly could fake that header. Then set:

```bash
DJANGO_ALLOWED_HOSTS=herald.example.com
DJANGO_CSRF_TRUSTED_ORIGINS=https://herald.example.com
HERALD_SITE_URL=https://herald.example.com
DJANGO_SECURE_PROXY_SSL_HEADER=1
DJANGO_SESSION_COOKIE_SECURE=1
DJANGO_CSRF_COOKIE_SECURE=1
DJANGO_SECURE_SSL_REDIRECT=1
DJANGO_SECURE_HSTS_SECONDS=3600
```

Raise `DJANGO_SECURE_HSTS_SECONDS` to `31536000` once HTTPS is confirmed working, since browsers remember it.
`DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS=1` and `DJANGO_SECURE_HSTS_PRELOAD=1` also affect every subdomain, so turn them
on only if all of them serve HTTPS. `manage.py check --deploy` warns about these two while they are off.

## Roles

| Role | Can do |
|---|---|
| Superadmin | Everything, plus add users (email + temporary password), assign roles, reset passwords |
| Administrator | Manage settings, register/edit applications, assign cloud accounts, upload data, send, escalate and close notification follow-ups |
| Operation | View the dashboard, applications and all vulnerabilities, assign cloud accounts to App IDs, and record support responses and remarks |
| User | View only App IDs where their email is a support, owner or extra notification email |

Users created with a temporary password must change it at first sign-in. "Forgot password?" on the sign-in
page emails a reset link to existing accounts only, and the page never reveals whether an account exists.

## Importing scan data

Go to **Upload Data**, then upload CSV, `.xlsx` or `.xlsm` files (first worksheet; the header row can be on any of
the first 50 rows). Download the blank templates from that page. The 46 scanner columns are defined in
[`vulns/columns.py`](vulns/columns.py). Headers are matched ignoring case and spaces; `Alert ID`, `Account ID` and
`Account Name` are required. App ID is optional. A row whose App ID or Account ID contains `/` is rejected.

Excel date cells and ISO dates (`2026-05-11`) are always read exactly. For text dates such as `11/05/2026`, Herald
finds the order from a date in the same file that can only be read one way, such as `25/05/2026`, and rejects rows
that contradict it. If nothing in the file settles it, the file is refused until you choose **Date order** on upload.

Uploads go into a single **draft import**. Add as many batch files as you need (a later file replaces an earlier
row with the same Alert ID). Then review the preview and **Finalize** or **Discard** it.

Lifecycle rules (in [`vulns/lifecycle.py`](vulns/lifecycle.py)):

- Alerts are matched across uploads by **Alert ID**.
- An open alert becomes **Remediated** only when the same **Account ID + Asset ID** has a newer **Last Scan**
  without that alert. Assets missing from an upload are untouched.
- Rows older than the stored data are **skipped**, so re-uploading an older file changes nothing.
- A remediated alert seen in a newer scan is **Reopened**.
- A rejected row never counts as evidence of a fix: nothing on its asset is remediated by that import.
- A failed file blocks every remediation in that import.
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

## Notification follow-ups

1. **Send to support** emails the application's support team, copies the extra emails, and opens a follow-up.
2. Sending again while it is open adds a **reminder** to the same timeline.
3. **Record response** stores who answered, when, and what they said. Herald does not read email replies.
4. A follow-up with no response for 5 days (Settings > General) is flagged **Overdue**.
5. **Escalate** is always manual. It emails the application owner and copies support and the extra emails.
   Escalating after support has responded requires a reason.
6. An Administrator **closes** the follow-up.

Remarks are internal unless **Include in email** is ticked. A failed email is logged and never changes the status.

## Development

```bash
docker compose exec web python manage.py test
```
