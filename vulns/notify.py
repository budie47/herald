import csv
import io
import os
import tempfile
import zipfile

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.db.models import Count, Q
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

from core.models import EmailSettings

from .columns import SEVERITY_ORDER
from .models import Notification, Vulnerability
from .queries import SORT_COLUMNS, iter_vulns, vulns_for_app

EMAIL_TABLE_LIMIT = 10
ACCOUNT_LIST_LIMIT = 20

CSV_COLUMNS = [
    ("Alert ID", "alert_id"), ("Provider", "provider"), ("Account ID", "account_number"),
    ("Account Name", "account_name"), ("App ID from scan", "app_id"), ("Severity", "severity"), ("CVE ID", "cve"),
    ("Package", "package"), ("Current Version", "current_version"), ("Recommended Version", "recommended_version"),
    ("Image", "image"), ("Asset ID", "asset_id"), ("Instance", "instance"), ("Environment", "environment"),
    ("Cluster", "cluster"), ("Namespace", "namespace"), ("First Seen", "first_seen"), ("Last Scan", "last_scan"),
    ("Days Open", "days_open"), ("SLO Date", "slo_date"), ("Past SLO", "slo_overdue"),
    ("Exception", "exception"), ("Exception RITM", "ritm"), ("CVE Description", "cve_description"),
]


class NotificationNotAllowed(Exception):
    pass


def _cell(vuln, attr):
    value = getattr(vuln, attr)
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d")
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return value


def write_vulns_csv(handle, vulns, columns=CSV_COLUMNS):
    writer = csv.writer(handle)
    writer.writerow([label for label, _ in columns])
    for vuln in vulns:
        writer.writerow([_cell(vuln, attr) for _, attr in columns])


def vulns_csv(vulns, columns=CSV_COLUMNS):
    buffer = io.StringIO()
    write_vulns_csv(buffer, vulns, columns)
    return buffer.getvalue()


def stream_vulns_csv(vulns, columns):
    """Yields CSV lines one at a time for a streaming download."""

    class Echo:
        def write(self, value):
            return value

    writer = csv.writer(Echo())
    yield writer.writerow([label for label, _ in columns])
    for vuln in vulns:
        yield writer.writerow([_cell(vuln, attr) for _, attr in columns])


def attach_open_vulns(message, app, base_name):
    """Attaches all open alerts. A large file is zipped; if it is still too big, returns False to link to it instead."""
    limit = EmailSettings.load().max_attachment_mb * 1024 * 1024 * 3 // 4  # base64 grows attachments by a third
    query = vulns_for_app(app.app_id).filter(status=Vulnerability.OPEN).browse().order_by(*SORT_COLUMNS)
    with tempfile.NamedTemporaryFile("w+", newline="", suffix=".csv", encoding="utf-8") as csv_file:
        write_vulns_csv(csv_file, iter_vulns(query))
        csv_file.flush()
        size = os.path.getsize(csv_file.name)
        if size <= limit:
            csv_file.seek(0)
            message.attach(f"{base_name}.csv", csv_file.read(), "text/csv")
            return True
        with tempfile.NamedTemporaryFile(suffix=".zip") as zip_file:
            with zipfile.ZipFile(zip_file, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.write(csv_file.name, f"{base_name}.csv")
            zip_file.flush()
            if os.path.getsize(zip_file.name) > limit:
                return False
            zip_file.seek(0)
            message.attach(f"{base_name}.zip", zip_file.read(), "application/zip")
            return True


SUBJECT_PREFIX = {Notification.REMINDER: "Reminder: ", Notification.ESCALATION: "ESCALATION: "}


def send_app_notification(app, user, kind, to, cc=(), follow_up=None, remark="", escalation=None):
    """Emails the open vulnerabilities and logs the attempt, whether it worked or not."""
    if app is None:
        raise NotificationNotAllowed("This App ID is not registered.")
    if "/" in app.app_id:  # older imports could store one; its email links and follow-up page can't work
        raise NotificationNotAllowed(f"{app.app_id} contains '/'. Correct the App ID in the scan data first.")
    if not to:
        raise NotificationNotAllowed(f"{app.app_id} has no email for this notification.")

    now = timezone.now()
    open_query = vulns_for_app(app.app_id).filter(status=Vulnerability.OPEN)
    top_vulns = list(open_query.browse().order_by(*SORT_COLUMNS)[:EMAIL_TABLE_LIMIT])
    if not top_vulns:
        raise NotificationNotAllowed(f"{app.app_id} has no open vulnerabilities.")
    counts = open_query.aggregate(
        total=Count("id"),
        **{s.lower(): Count("id", filter=Q(severity=s)) for s in SEVERITY_ORDER},
        past_slo=Count("id", filter=Q(slo_date__lt=now)),
    )
    total = counts["total"]
    by_account = (
        open_query.values("cloud_account__account_name", "cloud_account__account_id")
        .annotate(n=Count("id")).order_by("-n")[:ACCOUNT_LIST_LIMIT]
    )
    to_owner = kind == Notification.ESCALATION or (follow_up is not None and follow_up.status == follow_up.ESCALATED)
    context = {
        "app": app,
        "kind": kind,
        "is_escalation": kind == Notification.ESCALATION,
        "is_reminder": kind == Notification.REMINDER,
        "greeting": (app.owner_name if to_owner else app.support_team) or ("application owner" if to_owner else "support team"),
        "remark": remark,
        "escalation": escalation,
        "to": to,
        "cc": cc,
        "total": total,
        "severity_counts": [(s, counts[s.lower()]) for s in SEVERITY_ORDER],
        "past_slo": counts["past_slo"],
        "account_counts": [
            (f"{row['cloud_account__account_name']} ({row['cloud_account__account_id']})", row["n"]) for row in by_account
        ],
        "vulns": top_vulns,
        "limit": EMAIL_TABLE_LIMIT,
        "truncated": total > EMAIL_TABLE_LIMIT,
        "download_url": f"{settings.SITE_URL}{reverse('app_export', args=[app.app_id])}?status=open",
        "site_url": settings.SITE_URL,
        "sent_at": now,
    }
    subject = (
        f"[Herald] {SUBJECT_PREFIX.get(kind, '')}{app.app_id}: {total} open container vulnerabilities "
        f"({counts['past_slo']} past SLO)"
    )
    message = EmailMultiAlternatives(subject=subject, to=list(to), cc=list(cc))
    context["attached"] = attach_open_vulns(message, app, f"{app.app_id}_open_vulnerabilities_{now:%Y%m%d}")
    message.body = render_to_string("emails/notification.txt", context)
    message.attach_alternative(render_to_string("emails/notification.html", context), "text/html")

    log = Notification(
        app_id=app.app_id,
        application=app,
        follow_up=follow_up,
        kind=kind,
        sent_by=user,
        recipients=", ".join(to),
        cc=", ".join(cc),
        subject=subject[:255],
        vuln_count=total,
        past_slo_count=counts["past_slo"],
    )
    try:
        message.send()
        log.status = Notification.SENT
    except Exception as exc:
        log.status = Notification.FAILED
        log.error = str(exc) or exc.__class__.__name__
    log.save()
    return log
