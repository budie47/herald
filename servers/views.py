import csv

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q, Sum
from django.http import Http404, JsonResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.permissions import account_assigner_required, admin_required, can_view_app
from core.models import AppSettings
from vulns import assignment as account_assignment
from vulns import followups, jobs
from vulns.columns import SEVERITY_ORDER
from vulns.forms import ContactUploadForm, ResponseForm, UploadForm
from vulns.models import SERVERS, Application, FollowUp, Job, Notification
from vulns.notify import NotificationNotAllowed, stream_vulns_csv
from vulns.queries import followup_cutoff, overdue_q, paginate, scoped_apps, scoped_followups, scoped_notifications
from vulns.views import _back, _remark, _report_send, followup_context

from . import assignment, inventory, lifecycle
from .columns import CMDB_CHANGE_LABELS, CMDB_COLUMNS, MFS12_COLUMNS, QUALYS_COLUMNS
from .models import (
    InventoryImport, InventoryRow, Server, ServerFinding, ServerImport, ServerPlannedRemediation, ServerSummary,
)
from .notify import CSV_COLUMNS, with_server_columns
from .queries import (
    FINDING_STATUSES, can_view_server, filter_findings, findings_for_app, iter_findings, module_open_counts,
    scoped_servers, scoped_summary, summary_totals,
)

REJECTED_SAMPLE = 200
SERVER_STATES = [
    ("findings", "With open vulnerabilities"), ("unassigned", "Unassigned"), ("not_in_cmdb", "Not in CMDB"), ("all", "All"),
]
APP_SERVER_LIMIT = 50


def _choices(qs, field):
    """Distinct non-blank values for a filter list. order_by() keeps the default ordering out of DISTINCT."""
    return sorted(v for v in qs.order_by().values_list(field, flat=True).distinct() if v)


def _bars(qs, field):
    rows = qs.values_list(field).annotate(n=Sum("total")).order_by("-n")
    return [(value or "(not set)", int(n)) for value, n in rows]


# --- dashboard --------------------------------------------------------------------------


@login_required
def dashboard(request):
    summary = scoped_summary(request.user)
    open_summary = summary.filter(status=ServerFinding.OPEN)
    totals = summary_totals(summary)
    unassigned = summary_totals(open_summary.filter(app_id=""))
    by_sev = dict(_bars(open_summary, "severity"))
    severity_bars = [(s, by_sev.pop(s, 0)) for s in SEVERITY_ORDER if by_sev.get(s)] + sorted(by_sev.items())
    env_bars = _bars(open_summary, "environment")
    class_bars = _bars(open_summary, "server_class")
    top = list(
        open_summary.exclude(app_id="").values("app_id").annotate(
            total_open=Sum("total"), past=Sum("past_slo"), kev=Sum("total", filter=Q(cisa_kev=True)),
            **{s.lower(): Sum("total", filter=Q(severity=s)) for s in SEVERITY_ORDER},
        ).order_by("-total_open", "app_id")[:10]
    )
    apps = scoped_apps(request.user)
    no_team = set(apps.filter(support_emails="").values_list("app_id", flat=True))
    for row in top:
        row["severities"] = [(s, row[s.lower()] or 0) for s in SEVERITY_ORDER if row[s.lower()]]
        row["no_team"] = row["app_id"] in no_team
    open_by_app = dict(open_summary.exclude(app_id="").values_list("app_id").annotate(n=Sum("total")))
    missing_support = sorted(
        ((a, int(n)) for a, n in open_by_app.items() if a in no_team), key=lambda item: (-item[1], item[0])
    )
    servers = scoped_servers(request.user)
    followups_open = scoped_followups(request.user, SERVERS).exclude(status=FollowUp.CLOSED)
    cfg = AppSettings.load()
    context = {
        "open_count": totals["open"],
        "critical": totals["critical"],
        "high": totals["high"],
        "kev": totals["kev"],
        "past_slo": totals["past_slo"],
        "remediated_30": totals["recent_remediated"],
        "remediated_all": totals["remediated"],
        "avg_fix_days": round(totals["fix_seconds"] / totals["fix_count"] / 86400) if totals["fix_count"] else None,
        "servers_with_open": servers.filter(open_count__gt=0).count(),
        "servers_total": servers.count(),
        "servers_in_cmdb": servers.filter(in_cmdb=True).count(),
        "apps_with_open": len(open_by_app),
        "unassigned_findings": unassigned["open"],
        "unassigned_servers": assignment.needs_assignment().count() if request.user.can_view_all else 0,
        "severity_bars": severity_bars,
        "severity_max": max([n for _, n in severity_bars] or [0]),
        "env_bars": env_bars,
        "env_max": max([n for _, n in env_bars] or [0]),
        "class_bars": class_bars,
        "class_max": max([n for _, n in class_bars] or [0]),
        "top_apps": top,
        "missing_support": missing_support[:5],
        "missing_support_total": len(missing_support),
        "followups_waiting": followups_open.filter(status=FollowUp.WAITING).count(),
        "followups_overdue": followups_open.filter(overdue_q(followup_cutoff())).count(),
        "followups_escalated": followups_open.filter(status=FollowUp.ESCALATED).count(),
        "followup_days": cfg.followup_overdue_days,
        "notifications_sent": scoped_notifications(request.user, SERVERS).filter(status=Notification.SENT).count(),
        "last_import": ServerImport.objects.filter(status=ServerImport.FINALIZED).order_by("-finalized_at").first(),
        "last_cmdb": InventoryImport.objects.filter(status=InventoryImport.APPLIED).order_by("-applied_at").first(),
        "today": timezone.now(),
    }
    return render(request, "servers/dashboard.html", context)


# --- servers ----------------------------------------------------------------------------


@login_required
def server_list(request):
    states = SERVER_STATES if request.user.can_assign_accounts else [s for s in SERVER_STATES if s[0] != "unassigned"]
    state = request.GET.get("state", "findings")
    if state not in dict(states):
        state = "findings"
    params = {**request.GET.dict(), "state": state}
    base = scoped_servers(request.user)
    servers = assignment.server_queryset(base, params).order_by("-kev_open", "-critical_open", "-open_count", "name_key")
    context = {
        **paginate(request, servers),
        "states": states,
        "state": state,
        "params": request.GET,
        "environments": _choices(base, "environment"),
        "classes": _choices(base, "server_class"),
        "can_assign": request.user.can_assign_accounts,
    }
    return render(request, "servers/server_list.html", context)


@account_assigner_required
def server_app_search(request):
    return JsonResponse(account_assignment.search_apps(request.GET.get("q"), [], request.user))


@account_assigner_required
@require_POST
def server_assign(request):
    choice = request.POST.get("application", "")
    if request.POST.get("select_all") == "1":
        selection = {key: request.POST.get(key, "") for key in ("state", "q", "env", "cls", "app", "kev")}
        servers = assignment.server_queryset(Server.objects.all(), selection)
    else:
        servers = Server.objects.filter(pk__in=[pk for pk in request.POST.getlist("server_ids") if pk.isdigit()])
    pks = list(servers.values_list("pk", flat=True))
    if not pks:
        messages.warning(request, "Tick at least one server.")
        return _back(request, "server_list")
    application = None if choice == "none" else Application.objects.filter(pk=choice if choice.isdigit() else None).first()
    if choice != "none" and application is None:
        messages.warning(request, "Choose an App ID to assign.")
        return _back(request, "server_list")
    changed, skipped = assignment.assign(pks, application, request.user)
    target = application.app_id if application else "Unassigned"
    text = f"{changed} server{'s' if changed != 1 else ''} moved to {target}."
    if skipped:
        text += f" {skipped} kept their CMDB App ID. Correct those in CMDB."
    messages.success(request, text)
    return _back(request, "server_list")


@login_required
def server_detail(request, pk):
    server = get_object_or_404(Server, pk=pk)
    if not can_view_server(request.user, server):
        raise Http404
    params = request.GET.copy()
    params.setdefault("status", "open")
    findings = filter_findings(server.findings.all(), params)
    context = {
        **paginate(request, findings),
        "server": server,
        "params": params,
        "statuses": FINDING_STATUSES,
        "severities": SEVERITY_ORDER,
        "history": server.assignments.select_related("changed_by")[:20],
        "remediated": server.findings.filter(status=ServerFinding.REMEDIATED).count(),
        "app": Application.objects.filter(app_id=server.app_id).first() if server.app_id else None,
    }
    return render(request, "servers/server_detail.html", context)


# --- application tab --------------------------------------------------------------------


def _app_findings(request, app_id):
    params = request.GET.copy()
    params.setdefault("status", "open")
    return filter_findings(findings_for_app(app_id), params), params


@login_required
def app_servers(request, app_id):
    if not can_view_app(request.user, app_id):
        raise Http404
    app = Application.objects.filter(app_id=app_id).first()
    if app is None and not Server.objects.filter(app_id=app_id).exists():
        raise Http404
    app_summary = ServerSummary.objects.filter(app_id=app_id)
    summary = summary_totals(app_summary)
    findings, params = _app_findings(request, app_id)
    servers = Server.objects.filter(app_id=app_id).order_by("-kev_open", "-critical_open", "-open_count", "name_key")
    follow_up, events = followup_context(request, app, SERVERS) if app else (None, [])
    context = {
        **paginate(request, findings),
        "app": app,
        "app_id": app_id,
        "module": SERVERS,
        "summary": summary,
        "severity_counts": [(s, summary[s.lower()]) for s in SEVERITY_ORDER],
        "servers": servers[:APP_SERVER_LIMIT],
        "server_total": servers.count(),
        "follow_up": follow_up,
        "follow_up_events": events,
        "response_form": ResponseForm(initial={"responded_on": timezone.localdate()}),
        "followup_days": AppSettings.load().followup_overdue_days,
        "notifications": Notification.objects.filter(app_id=app_id, module=SERVERS).select_related("sent_by")[:10],
        "notify_url": reverse("app_servers_notify", args=[app_id]),
        "tab_counts": module_open_counts(app_id),
        "statuses": FINDING_STATUSES,
        "severities": SEVERITY_ORDER,
        "environments": _choices(servers, "environment"),
        "params": params,
    }
    return render(request, "servers/app_servers.html", context)


@login_required
def app_servers_export(request, app_id):
    if not can_view_app(request.user, app_id):
        raise Http404
    findings, _ = _app_findings(request, app_id)
    rows = with_server_columns(iter_findings(findings))
    response = StreamingHttpResponse(stream_vulns_csv(rows, CSV_COLUMNS), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{app_id}_server_vulnerabilities_{timezone.now():%Y%m%d}.csv"'
    return response


@admin_required
@require_POST
def app_servers_notify(request, app_id):
    app = Application.objects.filter(app_id=app_id).first()
    remark, include = _remark(request)
    try:
        log = followups.notify_support(app, request.user, remark, include, SERVERS)
    except NotificationNotAllowed as exc:
        messages.error(request, str(exc))
    else:
        _report_send(request, app_id, log)
    if app:
        return _back(request, reverse("app_servers", args=[app_id]))
    return _back(request, "app_list")


# --- findings imports -------------------------------------------------------------------


def _store_upload(request, run_getter):
    form = UploadForm(request.POST, request.FILES)
    if not form.is_valid():
        messages.error(request, "Choose a CSV or Excel file to upload.")
        return None
    uploaded = form.cleaned_data["file"]
    if uploaded.size > settings.UPLOAD_MAX_BYTES:
        messages.error(request, f"{uploaded.name} is larger than {settings.UPLOAD_MAX_BYTES // (1024 * 1024)} MB.")
        return None
    if not uploaded.name.lower().endswith((".csv", ".xlsx", ".xlsm")):
        messages.error(request, f"{uploaded.name}: upload a .csv, .xlsx or .xlsm file.")
        return None
    run = run_getter()
    if run.phase == "finalizing":
        messages.error(request, "This import is being finalized. Upload again when it finishes.")
        return run
    import_file = lifecycle.add_file(run, uploaded, request.user, form.cleaned_data["date_order"])
    messages.success(
        request, f"{import_file.filename} added to server import #{run.pk}. Herald reads it in the background."
    )
    return run


@admin_required
def import_home(request):
    if request.method == "POST":
        run = _store_upload(request, lambda: lifecycle.get_or_create_draft(request.user))
        return redirect("server_import_detail", pk=run.pk) if run else redirect("server_import_home")
    history = ServerImport.objects.exclude(status=ServerImport.DRAFT).select_related("finalized_by")
    context = {
        **paginate(request, history),
        "form": UploadForm(),
        "draft": ServerImport.objects.filter(status=ServerImport.DRAFT).first(),
        "mfs12_columns": MFS12_COLUMNS,
        "qualys_columns": QUALYS_COLUMNS,
    }
    return render(request, "servers/import_home.html", context)


@admin_required
def import_detail(request, pk):
    run = get_object_or_404(ServerImport, pk=pk)
    files = list(run.files.all())
    for import_file in files:
        import_file.sample_errors = list(import_file.rejected_rows.all()[:REJECTED_SAMPLE])
    context = {"run": run, "files": files, "form": UploadForm(), "plan": run.plan, "confirm_word": lifecycle.CONFIRM_WORD}
    if run.is_draft:
        planned = ServerPlannedRemediation.objects.filter(run=run).select_related("finding__server").order_by("id")
        context.update(paginate(request, planned, default="50"))
        context["is_busy"] = run.is_busy
        context["blockers"] = lifecycle.finalize_blockers(run, run.plan) if run.plan_ready else []
        context["needs_confirm"] = bool(
            run.plan_ready and run.plan.get("open_total")
            and run.plan.get("remediated", 0) / run.plan["open_total"] > lifecycle.LARGE_REMEDIATION_SHARE
        )
        context["last_failure"] = (
            Job.objects.filter(kind=jobs.SERVER_FINALIZE, payload__run=run.pk, status=Job.FAILED).order_by("-id").first()
        )
    else:
        context.update(paginate(request, run.remediated_findings.select_related("server").order_by("id"), default="50"))
    return render(request, "servers/import_detail.html", context)


@admin_required
@require_POST
def import_add_file(request, pk):
    run = get_object_or_404(ServerImport, pk=pk, status=ServerImport.DRAFT)
    _store_upload(request, lambda: run)
    return redirect("server_import_detail", pk=run.pk)


@admin_required
@require_POST
def import_expected(request, pk):
    value = (request.POST.get("expected_total") or "").replace(",", "").strip()
    if value and not value.isdigit():
        messages.error(request, "Enter the Power BI total as a whole number.")
    else:
        ServerImport.objects.filter(pk=pk, status=ServerImport.DRAFT).update(expected_total=int(value) if value else None)
    return redirect("server_import_detail", pk=pk)


@admin_required
@require_POST
def import_finalize(request, pk):
    run = get_object_or_404(ServerImport, pk=pk)
    if not run.is_draft or run.is_busy or not run.plan_ready:
        messages.error(request, "Wait for the files and preview to finish before finalizing.")
        return redirect("server_import_detail", pk=pk)
    payload = {
        "run": run.pk,
        "override_reason": (request.POST.get("override_reason") or "").strip(),
        "confirm_text": request.POST.get("confirm_text") or "",
        "skip_remediation": request.POST.get("skip_remediation") == "on",
    }
    problems = lifecycle.finalize_blockers(
        run, run.plan, payload["override_reason"], payload["confirm_text"], payload["skip_remediation"]
    )
    if problems:
        messages.error(request, " ".join(problems))
        return redirect("server_import_detail", pk=pk)
    ServerImport.objects.filter(pk=pk).update(phase="finalizing")
    job = jobs.enqueue(jobs.SERVER_FINALIZE, payload, request.user)
    if job.status == Job.FAILED:
        messages.error(request, job.message)
    elif job.status == Job.DONE:
        messages.success(request, job.message)
    else:
        messages.success(request, f"Finalizing server import #{pk} in the background.")
    return redirect("server_import_detail", pk=pk)


@admin_required
@require_POST
def import_discard(request, pk):
    run = get_object_or_404(ServerImport, pk=pk)
    try:
        lifecycle.discard(run)
        messages.success(request, f"Server import #{pk} discarded. Nothing was changed.")
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("server_import_detail", pk=pk)
    return redirect("server_import_home")


class _Echo:
    def write(self, value):
        return value


@admin_required
def import_planned_export(request, pk):
    run = get_object_or_404(ServerImport, pk=pk, status=ServerImport.DRAFT)

    def rows():
        writer = csv.writer(_Echo())
        yield writer.writerow(["Server", "App ID", "Environment", "QID", "Title", "Severity", "CISA KEV", "Last Detected"])
        planned = ServerPlannedRemediation.objects.filter(run=run).select_related("finding__server").order_by("id")
        for item in planned.iterator(chunk_size=2000):
            f = item.finding
            yield writer.writerow([
                f.server.name, f.server.app_id, f.server.environment, f.qid, f.title, f.severity,
                "Yes" if f.cisa_kev else "No", f.last_detected.strftime("%Y-%m-%d") if f.last_detected else "",
            ])

    response = StreamingHttpResponse(rows(), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="server_import_{pk}_will_be_remediated.csv"'
    return response


# --- CMDB inventory ---------------------------------------------------------------------

INVENTORY_TABS = [
    ("changes", "New and updated"), ("new", "New"), ("updated", "Updated"), ("unchanged", "Unchanged"),
    ("rejected", "Rejected"),
]


@admin_required
def inventory_home(request):
    if request.method == "POST":
        form = ContactUploadForm(request.POST, request.FILES)
        if not form.is_valid():
            messages.error(request, "Choose a CSV or Excel file.")
            return redirect("inventory_home")
        upload = form.cleaned_data["file"]
        if upload.size > inventory.MAX_FILE_BYTES:
            messages.error(request, "CMDB files can be up to 100 MB.")
            return redirect("inventory_home")
        if not upload.name.lower().endswith((".csv", ".xlsx", ".xlsm")):
            messages.error(request, f"{upload.name}: upload a .csv, .xlsx or .xlsm file.")
            return redirect("inventory_home")
        created = inventory.start(upload, request.user)
        return redirect("inventory_detail", pk=created.pk)
    context = {
        **paginate(request, InventoryImport.objects.select_related("created_by", "applied_by")),
        "form": ContactUploadForm(),
        "server_count": Server.objects.filter(in_cmdb=True).count(),
        "columns": CMDB_COLUMNS,
    }
    return render(request, "servers/inventory_home.html", context)


@admin_required
def inventory_detail(request, pk):
    item = get_object_or_404(InventoryImport, pk=pk)
    default = "rejected" if not item.change_count and item.rejected_count else "changes"
    tab = request.GET.get("show", default)
    if tab not in dict(INVENTORY_TABS):
        tab = default
    rows = item.rows.all()
    if tab == "changes":
        rows = rows.filter(action__in=[InventoryRow.NEW, InventoryRow.UPDATED])
    else:
        rows = rows.filter(action=tab)
    counts = {
        "changes": item.change_count, "new": item.new_count, "updated": item.updated_count,
        "unchanged": item.unchanged_count, "rejected": item.rejected_count,
    }
    page = paginate(request, rows)
    for row in page["page"]:
        if row.action == InventoryRow.NEW:  # one line per new server keeps a large first upload readable
            parts = [f"App ID {row.cells.get('u_id')}" if row.cells.get("u_id") else "No App ID"]
            parts += [row.cells.get(key) for key in ("sys_class_name", "u_environment", "ip_address") if row.cells.get(key)]
            row.summary = " · ".join(parts)
            continue
        row.change_list = [(CMDB_CHANGE_LABELS[key], *row.changes[key]) for key in CMDB_CHANGE_LABELS if key in row.changes]
    context = {
        **page,
        "item": item,
        "tab": tab,
        "tabs": [(key, label, counts[key]) for key, label in INVENTORY_TABS],
        "last_failure": Job.objects.filter(
            kind__in=[jobs.INVENTORY_READ, jobs.INVENTORY_APPLY], payload__inventory=item.pk, status=Job.FAILED
        ).order_by("-id").first(),
    }
    return render(request, "servers/inventory_detail.html", context)


@admin_required
@require_POST
def inventory_apply(request, pk):
    item = get_object_or_404(InventoryImport, pk=pk)
    try:
        job = inventory.queue_apply(item, request.user)
    except inventory.InventoryStale as exc:
        messages.error(request, str(exc))
        return redirect("inventory_detail", pk=pk)
    if job.status == Job.FAILED:
        messages.error(request, job.message)
    elif job.status == Job.DONE:
        messages.success(request, job.message)
    else:
        messages.success(request, "Applying the CMDB file in the background.")
    return redirect("inventory_detail", pk=pk)


@admin_required
@require_POST
def inventory_discard(request, pk):
    item = get_object_or_404(InventoryImport, pk=pk, status__in=[InventoryImport.PREVIEW, InventoryImport.FAILED])
    item.delete()
    messages.info(request, "CMDB preview discarded. No servers were changed.")
    return redirect("inventory_home")


@admin_required
def inventory_rejected(request, pk):
    item = get_object_or_404(InventoryImport, pk=pk)

    def rows():
        writer = csv.writer(_Echo())
        yield "﻿" + writer.writerow(["Row", *CMDB_COLUMNS, "Reason"])
        for row in inventory.rejected_rows(item):
            yield writer.writerow([_safe(v) for v in row])

    response = StreamingHttpResponse(rows(), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="cmdb_{pk}_rejected.csv"'
    return response


def _safe(value):
    text = str(value if value is not None else "")
    return f"'{text}" if text.startswith(("=", "+", "-", "@")) else text
