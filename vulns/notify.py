import csv
import io
from collections import Counter

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.db.models import Count, Q
from django.template.loader import render_to_string
from django.utils import timezone

from .columns import SEVERITY_ORDER
from .models import Notification, Vulnerability
from .queries import severity_rank, vulns_for_app

EMAIL_TABLE_LIMIT = 200

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


def vulns_csv(vulns, columns=CSV_COLUMNS):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([label for label, _ in columns])
    for vuln in vulns:
        writer.writerow([_cell(vuln, attr) for _, attr in columns])
    return buffer.getvalue()


SUBJECT_PREFIX = {Notification.REMINDER: "Reminder: ", Notification.ESCALATION: "ESCALATION: "}


def send_app_notification(app, user, kind, to, cc=(), follow_up=None, remark="", escalation=None):
    """Emails the open vulnerabilities and logs the attempt, whether it worked or not."""
    if app is None:
        raise NotificationNotAllowed("This App ID is not registered.")
    if not to:
        raise NotificationNotAllowed(f"{app.app_id} has no email for this notification.")

    now = timezone.now()
    open_vulns = list(
        vulns_for_app(app.app_id)
        .filter(status=Vulnerability.OPEN)
        .select_related("cloud_account")
        .annotate(sev_rank=severity_rank())
        .order_by("sev_rank", "slo_date", "alert_id")
    )
    if not open_vulns:
        raise NotificationNotAllowed(f"{app.app_id} has no open vulnerabilities.")
    counts = vulns_for_app(app.app_id).filter(status=Vulnerability.OPEN).aggregate(
        **{s.lower(): Count("id", filter=Q(severity=s)) for s in SEVERITY_ORDER},
        past_slo=Count("id", filter=Q(slo_date__lt=now)),
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
        "total": len(open_vulns),
        "severity_counts": [(s, counts[s.lower()]) for s in SEVERITY_ORDER],
        "past_slo": counts["past_slo"],
        "account_counts": Counter(f"{v.account_name} ({v.account_number})" for v in open_vulns).most_common(),
        "vulns": open_vulns[:EMAIL_TABLE_LIMIT],
        "limit": EMAIL_TABLE_LIMIT,
        "truncated": len(open_vulns) > EMAIL_TABLE_LIMIT,
        "site_url": settings.SITE_URL,
        "sent_at": now,
    }
    subject = (
        f"[Herald] {SUBJECT_PREFIX.get(kind, '')}{app.app_id}: {len(open_vulns)} open container vulnerabilities "
        f"({counts['past_slo']} past SLO)"
    )
    message = EmailMultiAlternatives(
        subject=subject,
        body=render_to_string("emails/notification.txt", context),
        to=list(to),
        cc=list(cc),
    )
    message.attach_alternative(render_to_string("emails/notification.html", context), "text/html")
    message.attach(f"{app.app_id}_open_vulnerabilities_{now:%Y%m%d}.csv", vulns_csv(open_vulns), "text/csv")

    log = Notification(
        app_id=app.app_id,
        application=app,
        follow_up=follow_up,
        kind=kind,
        sent_by=user,
        recipients=", ".join(to),
        cc=", ".join(cc),
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
