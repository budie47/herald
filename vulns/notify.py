import csv
import io

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.db.models import Count, Q
from django.template.loader import render_to_string
from django.utils import timezone

from .columns import SEVERITY_ORDER
from .models import Notification, Vulnerability
from .queries import severity_rank

EMAIL_TABLE_LIMIT = 200

CSV_COLUMNS = [
    ("Alert ID", "alert_id"), ("Severity", "severity"), ("CVE", "cve"), ("Package", "package"),
    ("Current Version", "current_version"), ("Recommended Version", "recommended_version"),
    ("Image", "image"), ("Asset ID", "asset_id"), ("Asset Name", "asset_name"), ("Environment", "environment"),
    ("Cluster", "cluster"), ("Namespace", "namespace"), ("First Seen", "first_seen"), ("Last Scan", "last_scan"),
    ("Days Open", "days_open"), ("SLO Date", "slo_date"), ("Past SLO", "slo_overdue"),
    ("Exception", "exception"), ("RITM Number", "ritm"), ("CVE Description", "cve_description"),
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


def vulns_csv(vulns, columns=CSV_COLUMNS):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([label for label, _ in columns])
    for vuln in vulns:
        writer.writerow([_cell(vuln, attr) for _, attr in columns])
    return buffer.getvalue()


def send_app_notification(app, user):
    """Emails the owner + extra emails about open vulnerabilities and logs the attempt."""
    if app is None:
        raise NotificationNotAllowed("This App ID is not registered.")
    recipients = app.recipients()
    if not recipients:
        raise NotificationNotAllowed(f"{app.app_id} has no owner or notification email.")

    now = timezone.now()
    open_vulns = list(
        Vulnerability.objects.filter(app_id=app.app_id, status=Vulnerability.OPEN)
        .annotate(sev_rank=severity_rank())
        .order_by("sev_rank", "slo_date", "alert_id")
    )
    counts = Vulnerability.objects.filter(app_id=app.app_id, status=Vulnerability.OPEN).aggregate(
        **{s.lower(): Count("id", filter=Q(severity=s)) for s in SEVERITY_ORDER},
        past_slo=Count("id", filter=Q(slo_date__lt=now)),
    )
    context = {
        "app": app,
        "total": len(open_vulns),
        "severity_counts": [(s, counts[s.lower()]) for s in SEVERITY_ORDER],
        "past_slo": counts["past_slo"],
        "vulns": open_vulns[:EMAIL_TABLE_LIMIT],
        "limit": EMAIL_TABLE_LIMIT,
        "truncated": len(open_vulns) > EMAIL_TABLE_LIMIT,
        "site_url": settings.SITE_URL,
        "sent_at": now,
    }
    subject = f"[Herald] {app.app_id}: {len(open_vulns)} open container vulnerabilities ({counts['past_slo']} past SLO)"
    message = EmailMultiAlternatives(
        subject=subject,
        body=render_to_string("emails/notification.txt", context),
        to=recipients,
    )
    message.attach_alternative(render_to_string("emails/notification.html", context), "text/html")
    message.attach(f"{app.app_id}_open_vulnerabilities_{now:%Y%m%d}.csv", vulns_csv(open_vulns), "text/csv")

    log = Notification(
        app_id=app.app_id,
        application=app,
        sent_by=user,
        recipients=", ".join(recipients),
        subject=subject[:255],
        vuln_count=len(open_vulns),
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
