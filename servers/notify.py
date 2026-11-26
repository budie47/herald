"""Server vulnerability emails. Same flow as containers: support team first, then escalation to the owner."""
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
from vulns.columns import SEVERITY_ORDER
from vulns.models import SERVERS, Notification
from vulns.notify import SUBJECT_PREFIX, NotificationNotAllowed, write_vulns_csv

from .models import ServerFinding
from .queries import SORT_COLUMNS, findings_for_app, iter_findings

EMAIL_TABLE_LIMIT = 10
SERVER_LIST_LIMIT = 20
# KEV first, then by severity and SLO date.
EMAIL_ORDER = ("-cisa_kev", "severity_rank", "slo_sort", "id")

CSV_COLUMNS = [
    ("Server", "server_name"), ("IP Address", "server_ip"), ("Environment", "server_environment"),
    ("Class", "server_class"), ("OS", "os"), ("QID", "qid"), ("Title", "title"), ("Severity", "severity"),
    ("CISA KEV", "cisa_kev"), ("CVSS 3.1", "cvss_score"), ("Non-running Kernel", "non_running_kernel"),
    ("CVEs", "cves"), ("Ports", "ports"), ("First Detected", "first_detected"), ("Last Detected", "last_detected"),
    ("Days Open", "days_open"), ("SLO Date", "slo_date"), ("Past SLO", "slo_overdue"), ("Status", "display_status"),
    ("Remediated", "remediated_at"), ("Solution", "solution"),
]


def with_server_columns(findings):
    """Adds the server's details to each finding, for CSV files."""
    for finding in findings:
        server = finding.server
        finding.server_name, finding.server_ip = server.name, server.ip_address
        finding.server_environment, finding.server_class = server.environment, server.server_class
        yield finding


def _attach(message, app, base_name):
    limit = EmailSettings.load().max_attachment_mb * 1024 * 1024 * 3 // 4
    query = findings_for_app(app.app_id).filter(status=ServerFinding.OPEN).select_related("server").order_by(*SORT_COLUMNS)
    with tempfile.NamedTemporaryFile("w+", newline="", suffix=".csv", encoding="utf-8") as csv_file:
        write_vulns_csv(csv_file, with_server_columns(iter_findings(query)), CSV_COLUMNS)
        csv_file.flush()
        if os.path.getsize(csv_file.name) <= limit:
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


def send_server_notification(app, user, kind, to, cc=(), follow_up=None, remark="", escalation=None):
    """Emails the application's open server vulnerabilities and logs the attempt, whether it worked or not."""
    if app is None:
        raise NotificationNotAllowed("This App ID is not registered.")
    if "/" in app.app_id:
        raise NotificationNotAllowed(f"{app.app_id} contains '/'. Correct the App ID in CMDB first.")
    if not to:
        raise NotificationNotAllowed(f"{app.app_id} has no email for this notification.")

    now = timezone.now()
    open_query = findings_for_app(app.app_id).filter(status=ServerFinding.OPEN)
    top = list(open_query.select_related("server").order_by(*EMAIL_ORDER)[:EMAIL_TABLE_LIMIT])
    if not top:
        raise NotificationNotAllowed(f"{app.app_id} has no open server vulnerabilities.")
    counts = open_query.aggregate(
        total=Count("id"),
        kev=Count("id", filter=Q(cisa_kev=True)),
        past_slo=Count("id", filter=Q(slo_date__lt=now)),
        **{s.lower(): Count("id", filter=Q(severity=s)) for s in SEVERITY_ORDER},
    )
    total = counts["total"]
    by_server = (
        open_query.values("server__name", "server__environment").annotate(n=Count("id")).order_by("-n", "server__name")
    )
    server_count = open_query.values("server_id").distinct().count()
    to_owner = kind == Notification.ESCALATION or (follow_up is not None and follow_up.status == follow_up.ESCALATED)
    context = {
        "app": app,
        "is_escalation": kind == Notification.ESCALATION,
        "is_reminder": kind == Notification.REMINDER,
        "greeting": (app.owner_name if to_owner else app.support_team) or ("application owner" if to_owner else "support team"),
        "remark": remark,
        "escalation": escalation,
        "to": to,
        "cc": cc,
        "total": total,
        "kev": counts["kev"],
        "severity_counts": [(s, counts[s.lower()]) for s in SEVERITY_ORDER if counts[s.lower()]],
        "past_slo": counts["past_slo"],
        "server_count": server_count,
        "server_counts": [
            (row["server__name"], row["server__environment"], row["n"]) for row in by_server[:SERVER_LIST_LIMIT]
        ],
        "more_servers": max(server_count - SERVER_LIST_LIMIT, 0),
        "findings": top,
        "truncated": total > EMAIL_TABLE_LIMIT,
        "download_url": f"{settings.SITE_URL}{reverse('app_servers_export', args=[app.app_id])}?status=open",
        "view_url": f"{settings.SITE_URL}{reverse('app_servers', args=[app.app_id])}",
        "sent_at": now,
    }
    subject = (
        f"[Herald] {SUBJECT_PREFIX.get(kind, '')}{app.app_id}: {total} open server vulnerabilities "
        f"({counts['past_slo']} past SLO{', ' + str(counts['kev']) + ' actively exploited' if counts['kev'] else ''})"
    )
    message = EmailMultiAlternatives(subject=subject, to=list(to), cc=list(cc))
    context["attached"] = _attach(message, app, f"{app.app_id}_open_server_vulnerabilities_{now:%Y%m%d}")
    message.body = render_to_string("emails/server_notification.txt", context)
    message.attach_alternative(render_to_string("emails/server_notification.html", context), "text/html")

    log = Notification(
        app_id=app.app_id, application=app, module=SERVERS, follow_up=follow_up, kind=kind, sent_by=user,
        recipients=", ".join(to), cc=", ".join(cc), subject=subject[:255], vuln_count=total,
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
