import io
from collections import Counter
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, DurationField, ExpressionWrapper, F, Q
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST
from openpyxl import Workbook
from openpyxl.styles import Font

from accounts.permissions import admin_required, can_view_app
from core.models import AppSettings

from . import lifecycle
from .columns import COLUMNS, SEVERITY_ORDER
from .forms import ApplicationForm, UploadForm
from .models import Application, ImportRun, LegacyUpload, Notification, Vulnerability
from .notify import NotificationNotAllowed, send_app_notification, vulns_csv
from .parsing import FileFormatError
from .queries import (
    OPEN, REMEDIATED, VULN_STATUSES, application_rows, environments, filter_vulns, not_seen_cutoff, paginate,
    scoped_apps, scoped_notifications, scoped_vulns,
)


def _back(request, fallback):
    target = request.POST.get("next") or request.GET.get("next")
    if target and url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        return redirect(target)
    return redirect(fallback)


# --- dashboard --------------------------------------------------------------------------


@login_required
def dashboard(request):
    now = timezone.now()
    vulns = scoped_vulns(request.user)
    open_vulns = vulns.filter(status=OPEN)
    registered_ids = set(scoped_apps(request.user).values_list("app_id", flat=True))
    open_app_ids = set(open_vulns.values_list("app_id", flat=True).distinct())
    finding_ids = set(vulns.values_list("app_id", flat=True).distinct())

    remediated = vulns.filter(status=REMEDIATED, remediated_at__isnull=False)
    recent = remediated.filter(remediated_at__gte=now - timedelta(days=30))
    avg_fix = remediated.aggregate(
        avg=Avg(ExpressionWrapper(F("remediated_at") - F("first_seen"), output_field=DurationField()))
    )["avg"]

    by_sev = dict(open_vulns.values_list("severity").annotate(n=Count("id")))
    severity_bars = [(s, by_sev.pop(s, 0)) for s in SEVERITY_ORDER] + sorted(by_sev.items())
    env_bars = [(e or "(not set)", n) for e, n in open_vulns.values_list("environment").annotate(n=Count("id")).order_by("-n")]
    recent_by_sev = dict(recent.values_list("severity").annotate(n=Count("id")))

    top = list(
        open_vulns.values("app_id")
        .annotate(
            total=Count("id"),
            past_slo=Count("id", filter=Q(slo_date__lt=now)),
            **{s.lower(): Count("id", filter=Q(severity=s)) for s in SEVERITY_ORDER},
        )
        .order_by("-total", "app_id")[:10]
    )
    for row in top:
        row["registered"] = row["app_id"] in registered_ids
        row["severities"] = [(s, row[s.lower()]) for s in SEVERITY_ORDER]

    owned = len(finding_ids & registered_ids)
    context = {
        "open_count": open_vulns.count(),
        "apps_registered": len(registered_ids),
        "apps_with_open": len(open_app_ids),
        "apps_with_open_registered": len(open_app_ids & registered_ids),
        "apps_with_open_unregistered": len(open_app_ids - registered_ids),
        "critical_high": open_vulns.filter(severity__in=["Critical", "High"]).count(),
        "past_slo": open_vulns.filter(slo_date__lt=now).count(),
        "remediated_30": recent.count(),
        "remediated_all": remediated.count(),
        "avg_fix_days": round(avg_fix.total_seconds() / 86400) if avg_fix else None,
        "severity_bars": severity_bars,
        "severity_max": max([n for _, n in severity_bars] or [0]),
        "env_bars": env_bars,
        "env_max": max([n for _, n in env_bars] or [0]),
        "finding_apps": len(finding_ids),
        "owned_apps": owned,
        "unowned_apps": len(finding_ids) - owned,
        "not_seen": open_vulns.filter(last_scan__lt=not_seen_cutoff()).count(),
        "not_seen_days": AppSettings.load().not_seen_days,
        "exceptions": open_vulns.filter(exception=True).count(),
        "notifications_sent": scoped_notifications(request.user).filter(status=Notification.SENT).count(),
        "recent_by_sev": [(s, recent_by_sev.get(s, 0)) for s in SEVERITY_ORDER if recent_by_sev.get(s)],
        "top_apps": top,
        "last_import": ImportRun.objects.filter(status=ImportRun.FINALIZED).order_by("-finalized_at").first(),
        "today": now,
    }
    return render(request, "vulns/dashboard.html", context)


# --- applications -----------------------------------------------------------------------

APP_STATUSES = [
    ("", "All"), ("with_vulns", "With vulnerabilities"), ("registered", "Registered"), ("unregistered", "Unregistered"),
    ("no_email", "No email"), ("not_rescanned", "Not rescanned"), ("all_remediated", "All remediated"),
]


@login_required
def app_list(request):
    rows = application_rows(request.user, request.GET)
    all_rows = application_rows(request.user, {})
    context = {
        **paginate(request, rows),
        "total_rows": len(rows),
        "statuses": APP_STATUSES,
        "severities": SEVERITY_ORDER,
        "environments": environments(scoped_vulns(request.user)),
        "unregistered_count": sum(1 for r in all_rows if not r["registered"]),
        "params": request.GET,
    }
    return render(request, "vulns/app_list.html", context)


def _prefill_from_scan(app_id):
    """Suggest form values for an unregistered App ID from its scan data."""
    names = Counter(
        (v.data or {}).get("app_name") for v in Vulnerability.objects.filter(app_id=app_id).only("data")[:500]
    )
    names.pop(None, None)
    names.pop("", None)
    initial = {"app_id": app_id}
    if names:
        initial["name"] = names.most_common(1)[0][0]
    return initial


@admin_required
def app_create(request):
    initial = _prefill_from_scan(request.GET["app_id"]) if request.GET.get("app_id") else {}
    form = ApplicationForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        app = form.save()
        messages.success(request, f"Application {app.app_id} registered.")
        return redirect("app_detail", app_id=app.app_id)
    return render(request, "vulns/app_form.html", {"form": form, "title": "Register application"})


@admin_required
def app_edit(request, app_id):
    app = get_object_or_404(Application, app_id=app_id)
    form = ApplicationForm(request.POST or None, instance=app)
    if request.method == "POST" and form.is_valid():
        app = form.save()
        messages.success(request, f"Application {app.app_id} updated.")
        return redirect("app_detail", app_id=app.app_id)
    return render(request, "vulns/app_form.html", {"form": form, "app": app, "title": f"Edit {app.app_id}"})


@admin_required
def app_delete(request, app_id):
    app = get_object_or_404(Application, app_id=app_id)
    if request.method == "POST":
        app.delete()
        messages.success(request, f"Application {app_id} deleted. Its vulnerability records were kept.")
        return redirect("app_list")
    count = Vulnerability.objects.filter(app_id=app_id).count()
    return render(request, "vulns/app_delete.html", {"app": app, "vuln_count": count})


def _detail_vulns(request, app_id):
    params = request.GET.copy()
    params.setdefault("status", "open")
    return filter_vulns(Vulnerability.objects.filter(app_id=app_id), params), params


@login_required
def app_detail(request, app_id):
    if not can_view_app(request.user, app_id):
        raise Http404
    app = Application.objects.filter(app_id=app_id).first()
    all_vulns = Vulnerability.objects.filter(app_id=app_id)
    if app is None and not all_vulns.exists():
        raise Http404
    now = timezone.now()
    cutoff = not_seen_cutoff()
    open_q = Q(status=OPEN)
    summary = all_vulns.aggregate(
        open=Count("id", filter=open_q),
        past_slo=Count("id", filter=open_q & Q(slo_date__lt=now)),
        not_seen=Count("id", filter=open_q & Q(last_scan__lt=cutoff)),
        reopened=Count("id", filter=open_q & Q(reopened_at__isnull=False)),
        exceptions=Count("id", filter=open_q & Q(exception=True)),
        remediated=Count("id", filter=Q(status=REMEDIATED)),
        **{s.lower(): Count("id", filter=open_q & Q(severity=s)) for s in SEVERITY_ORDER},
    )
    vulns, params = _detail_vulns(request, app_id)
    context = {
        "app": app,
        "app_id": app_id,
        "summary": summary,
        "severity_counts": [(s, summary[s.lower()]) for s in SEVERITY_ORDER],
        "notifications": Notification.objects.filter(app_id=app_id).select_related("sent_by")[:10],
        "statuses": VULN_STATUSES,
        "severities": SEVERITY_ORDER,
        "environments": environments(all_vulns),
        "params": params,
        "cutoff": cutoff,
        "now": now,
        **paginate(request, vulns),
    }
    return render(request, "vulns/app_detail.html", context)


EXPORT_COLUMNS = [
    ("Status", "export_status"), ("Severity", "severity"), ("CVE", "cve"), ("CVE Description", "cve_description"),
    ("Package", "package"), ("Current Version", "current_version"), ("Recommended Version", "recommended_version"),
    ("Image", "image"), ("Asset ID", "asset_id"), ("Asset Name", "asset_name"), ("Environment", "environment"),
    ("Cluster", "cluster"), ("Namespace", "namespace"), ("Days Open", "days_open"), ("SLO Date", "slo_date"),
    ("Past SLO", "slo_overdue"), ("Exception", "exception"), ("RITM Number", "ritm"), ("Alert ID", "alert_id"),
    ("First Seen", "first_seen"), ("Last Scan", "last_scan"), ("Remediated", "remediated_at"), ("Reopened", "reopened_at"),
]


@login_required
def app_export(request, app_id):
    if not can_view_app(request.user, app_id):
        raise Http404
    vulns, _ = _detail_vulns(request, app_id)
    cutoff = not_seen_cutoff()
    vulns = list(vulns)
    for vuln in vulns:
        vuln.export_status = vuln.display_status(cutoff)
    response = HttpResponse(vulns_csv(vulns, EXPORT_COLUMNS), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{app_id}_vulnerabilities_{timezone.now():%Y%m%d}.csv"'
    return response


# --- notifications ----------------------------------------------------------------------


@admin_required
@require_POST
def app_notify(request, app_id):
    app = Application.objects.filter(app_id=app_id).first()
    try:
        log = send_app_notification(app, request.user)
    except NotificationNotAllowed as exc:
        messages.error(request, str(exc))
    else:
        if log.status == Notification.SENT:
            messages.success(request, f"Notification for {app_id} sent to {log.recipients} ({log.vuln_count} vulnerabilities).")
        else:
            messages.error(request, f"Notification for {app_id} failed: {log.error}")
    if app:
        return _back(request, redirect("app_detail", app_id=app_id).url)
    return _back(request, "app_list")


@admin_required
@require_POST
def notify_bulk(request):
    app_ids = request.POST.getlist("app_ids")
    if not app_ids:
        messages.warning(request, "Tick at least one application to notify.")
        return _back(request, "app_list")
    apps = {a.app_id: a for a in Application.objects.filter(app_id__in=app_ids)}
    sent, failed, skipped = [], [], []
    for app_id in app_ids:
        try:
            log = send_app_notification(apps.get(app_id), request.user)
        except NotificationNotAllowed as exc:
            skipped.append(f"{app_id} ({exc})")
            continue
        if log.status == Notification.SENT:
            sent.append(app_id)
        else:
            failed.append(f"{app_id} ({log.error})")
    if sent:
        messages.success(request, f"Sent {len(sent)} notification(s): {', '.join(sent)}.")
    if failed:
        messages.error(request, f"Failed: {'; '.join(failed)}")
    if skipped:
        messages.warning(request, f"Skipped: {'; '.join(skipped)}")
    return _back(request, "app_list")


@login_required
def notification_log(request):
    logs = scoped_notifications(request.user)
    q = (request.GET.get("q") or "").strip()
    if q:
        logs = logs.filter(Q(app_id__icontains=q) | Q(recipients__icontains=q) | Q(sent_by__email__icontains=q))
    if request.GET.get("status") in (Notification.SENT, Notification.FAILED):
        logs = logs.filter(status=request.GET["status"])
    return render(request, "vulns/notification_log.html", {**paginate(request, logs), "params": request.GET})


# --- imports ----------------------------------------------------------------------------


def _store_upload(request, run_getter):
    form = UploadForm(request.POST, request.FILES)
    if not form.is_valid():
        messages.error(request, "Choose a CSV or Excel file to upload.")
        return None
    uploaded = form.cleaned_data["file"]
    if uploaded.size > settings.UPLOAD_MAX_BYTES:
        messages.error(request, f"{uploaded.name} is larger than {settings.UPLOAD_MAX_BYTES // (1024 * 1024)} MB.")
        return None
    try:
        run = run_getter()
        import_file = lifecycle.add_file(run, uploaded, request.user)
    except FileFormatError as exc:
        messages.error(request, f"{uploaded.name}: {exc}")
        return None
    level = messages.success if not import_file.rejected else messages.warning
    level(
        request,
        f"{import_file.filename}: {import_file.accepted} of {import_file.rows_read} rows added to import #{run.pk}"
        + (f" ({import_file.rejected} rejected, see below)" if import_file.rejected else "")
        + ". Add more files, or review and finalize when all batches are in.",
    )
    return run


@admin_required
def import_home(request):
    if request.method == "POST":
        run = _store_upload(request, lambda: lifecycle.get_or_create_draft(request.user))
        return redirect("import_detail", pk=run.pk) if run else redirect("import_home")
    history = ImportRun.objects.exclude(status=ImportRun.DRAFT).select_related("finalized_by")
    context = {
        "form": UploadForm(),
        "draft": ImportRun.objects.filter(status=ImportRun.DRAFT).first(),
        "history": history,
        "legacy": LegacyUpload.objects.all(),
        "columns": COLUMNS,
    }
    return render(request, "imports/home.html", context)


@admin_required
def import_detail(request, pk):
    run = get_object_or_404(ImportRun, pk=pk)
    context = {"run": run, "files": run.files.all(), "form": UploadForm()}
    if run.is_draft:
        context["plan"] = lifecycle.build_plan(run)
    else:
        context["remediated"] = run.remediated_vulns.order_by("app_id", "alert_id")[:2000]
    return render(request, "imports/detail.html", context)


@admin_required
@require_POST
def import_add_file(request, pk):
    run = get_object_or_404(ImportRun, pk=pk, status=ImportRun.DRAFT)
    _store_upload(request, lambda: run)
    return redirect("import_detail", pk=run.pk)


@admin_required
@require_POST
def import_finalize(request, pk):
    run = get_object_or_404(ImportRun, pk=pk)
    try:
        run = lifecycle.finalize(run, request.user)
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("import_detail", pk=pk)
    messages.success(
        request,
        f"Import #{run.pk} finalized: {run.new_count} new, {run.updated_count} updated, {run.reopened_count} reopened, "
        f"{run.remediated_count} remediated, {run.skipped_count} skipped.",
    )
    return redirect("import_detail", pk=run.pk)


@admin_required
@require_POST
def import_discard(request, pk):
    run = get_object_or_404(ImportRun, pk=pk)
    try:
        lifecycle.discard(run)
        messages.success(request, f"Import #{pk} discarded. Nothing was changed.")
    except ValueError as exc:
        messages.error(request, str(exc))
    return redirect("import_home")


@admin_required
def import_template(request, fmt):
    if fmt not in ("csv", "xlsx"):
        raise Http404
    headers = [label for label, _, _ in COLUMNS]
    if fmt == "csv":
        response = HttpResponse(",".join(headers) + "\r\n", content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="herald_container_template.csv"'
        return response
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Container vulnerabilities"
    sheet.append(headers)
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    sheet.freeze_panes = "A2"
    buffer = io.BytesIO()
    workbook.save(buffer)
    response = HttpResponse(
        buffer.getvalue(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    response["Content-Disposition"] = 'attachment; filename="herald_container_template.xlsx"'
    return response
