import csv
import io

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Q, Sum
from django.http import Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST
from openpyxl import Workbook
from openpyxl.styles import Font

from accounts.permissions import (
    account_assigner_required, admin_required, can_view_app, response_recorder_required,
)
from core.models import AppSettings

from . import assignment, contacts, followups, jobs, lifecycle
from .columns import COLUMNS, SEVERITY_ORDER
from .forms import ApplicationForm, ContactUploadForm, ResponseForm, UploadForm
from .models import (
    AlertSummary, Application, CloudAccount, ContactImport, ContactImportRow, FollowUp, FollowUpEvent, ImportRun, Job,
    LegacyUpload, Notification, PlannedRemediation, Vulnerability,
)
from .notify import NotificationNotAllowed, stream_vulns_csv
from .parsing import FileFormatError
from .queries import (
    OPEN, REMEDIATED, VULN_STATUSES, application_rows, filter_vulns, followup_cutoff, iter_vulns, keyset_paginate,
    match_count, not_seen_cutoff, overdue_q, paginate, scoped_apps, scoped_followups, scoped_notifications,
    scoped_summary, summary_environments, summary_totals, vulns_for_app,
)

REJECTED_SAMPLE = 200


def _back(request, fallback):
    target = request.POST.get("next") or request.GET.get("next")
    if target and url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        return redirect(target)
    return redirect(fallback)


# --- dashboard --------------------------------------------------------------------------


@login_required
def dashboard(request):
    now = timezone.now()
    summary = scoped_summary(request.user)
    open_summary = summary.filter(status=OPEN)
    totals = summary_totals(summary)
    apps = scoped_apps(request.user)
    contact_ids = set(apps.filter(~Q(support_emails="") | ~Q(owner_email="")).values_list("app_id", flat=True))
    open_by_app = {
        app_id: int(n)
        for app_id, n in open_summary.exclude(owner_app_id="").values_list("owner_app_id").annotate(n=Sum("total"))
    }
    open_app_ids = set(open_by_app)
    finding_ids = set(summary.exclude(owner_app_id="").values_list("owner_app_id", flat=True).distinct())
    unassigned = summary_totals(open_summary.filter(owner_app_id=""))

    def bars(field):
        return [
            (value, int(n)) for value, n in open_summary.values_list(field).annotate(n=Sum("total")).order_by("-n")
        ]

    by_sev = dict(bars("severity"))
    severity_bars = [(s, by_sev.pop(s, 0)) for s in SEVERITY_ORDER] + sorted(by_sev.items())
    env_bars = [(e or "(not set)", n) for e, n in bars("environment")]
    provider_bars = [(p or "(not set)", n) for p, n in bars("provider")]
    recent_by_sev = dict(summary.filter(status=REMEDIATED).values_list("severity").annotate(n=Sum("recent_remediated")))

    top = list(
        open_summary.exclude(owner_app_id="").values("owner_app_id")
        .annotate(
            total_open=Sum("total"),
            past=Sum("past_slo"),
            **{s.lower(): Sum("total", filter=Q(severity=s)) for s in SEVERITY_ORDER},
        )
        .order_by("-total_open", "owner_app_id")[:10]
    )
    for row in top:
        row["app_id"] = row["owner_app_id"]
        row["total"] = row["total_open"]
        row["past_slo"] = row["past"]
        row["registered"] = row["app_id"] in contact_ids
        row["severities"] = [(s, row[s.lower()] or 0) for s in SEVERITY_ORDER]

    no_support_ids = set(apps.filter(support_emails="").values_list("app_id", flat=True))
    missing_support = sorted(
        ((app_id, n) for app_id, n in open_by_app.items() if app_id in no_support_ids), key=lambda item: (-item[1], item[0])
    )
    cfg = AppSettings.load()
    owned = len(finding_ids & contact_ids)
    open_followups = scoped_followups(request.user).exclude(status=FollowUp.CLOSED)
    context = {
        "followups_waiting": open_followups.filter(status=FollowUp.WAITING).count(),
        "followups_overdue": open_followups.filter(overdue_q(followup_cutoff())).count(),
        "followups_escalated": open_followups.filter(status=FollowUp.ESCALATED).count(),
        "followup_days": cfg.followup_overdue_days,
        "open_count": totals["open"],
        "apps_registered": len(contact_ids),
        "apps_with_open": len(open_app_ids),
        "apps_with_open_registered": len(open_app_ids & contact_ids),
        "apps_with_open_unregistered": len(open_app_ids - contact_ids),
        "critical_high": totals["critical"] + totals["high"],
        "past_slo": totals["past_slo"],
        "remediated_30": totals["recent_remediated"],
        "remediated_all": totals["remediated"],
        "avg_fix_days": round(totals["fix_seconds"] / totals["fix_count"] / 86400) if totals["fix_count"] else None,
        "severity_bars": severity_bars,
        "severity_max": max([n for _, n in severity_bars] or [0]),
        "env_bars": env_bars,
        "env_max": max([n for _, n in env_bars] or [0]),
        "provider_bars": provider_bars,
        "provider_max": max([n for _, n in provider_bars] or [0]),
        "unassigned_alerts": unassigned["open"],
        "unassigned_critical_high": unassigned["critical"] + unassigned["high"],
        "cloud_accounts": summary.values("cloud_account_id").distinct().count(),
        "finding_apps": len(finding_ids),
        "owned_apps": owned,
        "unowned_apps": len(finding_ids) - owned,
        "missing_support": missing_support[:5],
        "missing_support_total": len(missing_support),
        "not_seen": totals["not_seen"],
        "not_seen_days": cfg.not_seen_days,
        "exceptions": totals["exceptions"],
        "notifications_sent": scoped_notifications(request.user).filter(status=Notification.SENT).count(),
        "recent_by_sev": [(s, int(recent_by_sev[s])) for s in SEVERITY_ORDER if recent_by_sev.get(s)],
        "top_apps": top,
        "last_import": ImportRun.objects.filter(status=ImportRun.FINALIZED).order_by("-finalized_at").first(),
        "summaries_at": cfg.summaries_refreshed_at,
        "today": now,
    }
    return render(request, "vulns/dashboard.html", context)


# --- applications -----------------------------------------------------------------------

APP_STATUSES = [
    ("", "All"), ("with_vulns", "With vulnerabilities"), ("registered", "Contacts set"), ("unregistered", "No contacts"),
    ("no_email", "No team email"), ("not_rescanned", "Not rescanned"), ("all_remediated", "All remediated"),
]


FOLLOWUP_FILTERS = [
    ("", "Any"), ("waiting", "Awaiting response"), ("overdue", "Overdue"), ("escalated", "Escalated"),
    ("responded", "Responded"), ("none", "No open follow-up"),
]


@login_required
def app_list(request):
    rows = application_rows(request.user, request.GET)
    all_rows = application_rows(request.user, {})
    context = {
        **paginate(request, rows),
        "total_rows": len(rows),
        "statuses": APP_STATUSES,
        "followup_filters": FOLLOWUP_FILTERS,
        "severities": SEVERITY_ORDER,
        "environments": summary_environments(scoped_summary(request.user)),
        "unregistered_count": sum(1 for r in all_rows if not r["registered"]),
        "params": request.GET,
    }
    return render(request, "vulns/app_list.html", context)


def _prefill_from_scan(app_id):
    """Suggest form values for an App ID from one of its scan rows."""
    initial = {"app_id": app_id}
    vuln = Vulnerability.objects.filter(app_id=app_id, context__isnull=False).select_related("context").first()
    if vuln:
        initial.update(
            name=vuln.context.app_service, business_service=vuln.context.business_service, department=vuln.context.department
        )
    return initial


@admin_required
def app_create(request):
    initial = _prefill_from_scan(request.GET["app_id"]) if request.GET.get("app_id") else {}
    form = ApplicationForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        app = form.save()
        messages.success(request, f"Application {app.app_id} registered.")
        return _back(request, redirect("app_detail", app_id=app.app_id).url)
    next_url = request.POST.get("next") or request.GET.get("next") or ""
    return render(request, "vulns/app_form.html", {"form": form, "title": "Register application", "next": next_url})


@admin_required
def app_edit(request, app_id):
    app = get_object_or_404(Application, app_id=app_id)
    form = ApplicationForm(request.POST or None, instance=app)
    form.fields["app_id"].disabled = True  # alerts and history refer to it
    if request.method == "POST" and form.is_valid():
        app = form.save()
        messages.success(request, f"Application {app.app_id} updated.")
        return redirect("app_detail", app_id=app.app_id)
    return render(request, "vulns/app_form.html", {"form": form, "app": app, "title": f"Edit {app.app_id}"})


@admin_required
def app_delete(request, app_id):
    app = get_object_or_404(Application, app_id=app_id)
    if request.method == "POST":
        with transaction.atomic():
            assignment.assign(list(app.cloud_accounts.values_list("pk", flat=True)), None, request.user)
            followups.close_for_deleted_app(app, request.user)
            app.delete()
        messages.success(
            request, f"Application {app_id} deleted. Vulnerabilities were kept, and its accounts are unassigned."
        )
        return redirect("app_list")
    vuln_count = sum(n for n in AlertSummary.objects.filter(owner_app_id=app_id).values_list("total", flat=True))
    context = {"app": app, "vuln_count": vuln_count, "account_count": app.cloud_accounts.count()}
    return render(request, "vulns/app_delete.html", context)


# --- bulk contacts ----------------------------------------------------------------------

CONTACT_TABS = [
    ("changes", "New and updated"), ("new", "New"), ("updated", "Updated"), ("unchanged", "Unchanged"), ("rejected", "Rejected"),
]
XLSX_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _download(content, content_type, filename):
    response = HttpResponse(content, content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@admin_required
def app_contacts(request):
    if request.method == "POST":
        form = ContactUploadForm(request.POST, request.FILES)
        if not form.is_valid():
            messages.error(request, "Choose a CSV or Excel file.")
            return redirect("app_contacts")
        upload = form.cleaned_data["file"]
        if upload.size > contacts.MAX_FILE_BYTES:
            messages.error(request, "Contact files can be up to 10 MB.")
            return redirect("app_contacts")
        try:
            preview = contacts.create_preview(upload, upload.name, request.user)
        except FileFormatError as exc:
            messages.error(request, str(exc))
            return redirect("app_contacts")
        return redirect("app_contacts_detail", pk=preview.pk)
    context = {
        **paginate(request, ContactImport.objects.select_related("created_by", "applied_by")),
        "form": ContactUploadForm(),
        "missing_count": contacts.missing_team_email_count(),
        "app_count": Application.objects.count(),
        "columns": contacts.CONTACT_COLUMNS,
        "max_rows": contacts.MAX_ROWS,
    }
    return render(request, "vulns/app_contacts.html", context)


@admin_required
def app_contacts_template(request, fmt):
    scope = request.GET.get("scope", "blank")
    if fmt not in ("csv", "xlsx") or scope not in contacts.SCOPES:
        raise Http404
    rows = contacts.template_rows(scope)
    name = {"blank": "template", "missing": "missing_team_email", "all": "all"}[scope]
    if fmt == "csv":
        return _download(contacts.as_csv(rows), "text/csv", f"herald_contacts_{name}.csv")
    return _download(contacts.as_xlsx(rows), XLSX_TYPE, f"herald_contacts_{name}.xlsx")


@admin_required
def app_contacts_detail(request, pk):
    contact_import = get_object_or_404(ContactImport, pk=pk)
    default = "rejected" if not contact_import.change_count and contact_import.rejected_count else "changes"
    tab = request.GET.get("show", default)
    if tab not in dict(CONTACT_TABS):
        tab = default
    rows = contact_import.rows.all()
    if tab == "changes":
        rows = rows.filter(action__in=[ContactImportRow.NEW, ContactImportRow.UPDATED])
    else:
        rows = rows.filter(action=tab)
    counts = {
        "changes": contact_import.change_count, "new": contact_import.new_count, "updated": contact_import.updated_count,
        "unchanged": contact_import.unchanged_count, "rejected": contact_import.rejected_count,
    }
    context = {
        **paginate(request, rows),
        "contact_import": contact_import,
        "tab": tab,
        "tabs": [(key, label, counts[key]) for key, label in CONTACT_TABS],
    }
    return render(request, "vulns/app_contacts_detail.html", context)


@admin_required
@require_POST
def app_contacts_apply(request, pk):
    contact_import = get_object_or_404(ContactImport, pk=pk)
    try:
        applied = contacts.apply_import(contact_import, request.user)
    except contacts.ContactImportStale as exc:
        messages.error(request, str(exc))
        return redirect("app_contacts_detail", pk=pk)
    messages.success(request, f"Contacts saved: {applied.new_count} new, {applied.updated_count} updated.")
    return redirect("app_contacts_detail", pk=pk)


@admin_required
@require_POST
def app_contacts_discard(request, pk):
    contact_import = get_object_or_404(ContactImport, pk=pk, status=ContactImport.PREVIEW)
    contact_import.delete()
    messages.info(request, "Preview discarded. No contacts were changed.")
    return redirect("app_contacts")


@admin_required
def app_contacts_rejected(request, pk):
    contact_import = get_object_or_404(ContactImport, pk=pk)
    content = contacts.as_csv(contacts.rejected_rows(contact_import), extra_headers=["Reason"])
    return _download(content, "text/csv", f"herald_contacts_{pk}_rejected.csv")


def _detail_vulns(request, app_id):
    params = request.GET.copy()
    params.setdefault("status", "open")
    return filter_vulns(vulns_for_app(app_id), params), params


@login_required
def app_detail(request, app_id):
    if not can_view_app(request.user, app_id):
        raise Http404
    app = Application.objects.filter(app_id=app_id).first()
    app_summary = AlertSummary.objects.filter(owner_app_id=app_id)
    if app is None and not vulns_for_app(app_id).exists():
        raise Http404
    now = timezone.now()
    cutoff = not_seen_cutoff()
    summary = summary_totals(app_summary)
    vulns, params = _detail_vulns(request, app_id)
    open_by_account = {
        pk: int(n) for pk, n in app_summary.filter(status=OPEN).values_list("cloud_account_id").annotate(n=Sum("total"))
    }
    linked_pks = set(app_summary.values_list("cloud_account_id", flat=True).distinct())
    cloud_accounts = list(CloudAccount.objects.filter(Q(application__app_id=app_id) | Q(pk__in=linked_pks)))
    for account in cloud_accounts:
        account.app_open = open_by_account.get(account.pk, 0)
        account.is_assigned = bool(app and account.application_id == app.pk)
    follow_up = None
    follow_up_events = []
    if app:
        follow_up = app.follow_ups.exclude(status=FollowUp.CLOSED).first()
        if follow_up:
            follow_up.overdue = follow_up.is_overdue(followup_cutoff())
        follow_up_events = list(
            FollowUpEvent.objects.filter(follow_up__application=app).select_related("actor", "notification", "follow_up")[:30]
        )
        for event in follow_up_events:  # remarks and responses are internal unless sent in an email
            event.show_note = request.user.can_record_responses or event.include_in_email
    context = {
        "follow_up": follow_up,
        "follow_up_events": follow_up_events,
        "response_form": ResponseForm(initial={"responded_on": timezone.localdate()}),
        "followup_days": AppSettings.load().followup_overdue_days,
        "cloud_accounts": sorted(cloud_accounts, key=lambda a: (-a.app_open, a.account_name)),
        "app": app,
        "app_id": app_id,
        "summary": summary,
        "severity_counts": [(s, summary[s.lower()]) for s in SEVERITY_ORDER],
        "notifications": Notification.objects.filter(app_id=app_id).select_related("sent_by")[:10],
        "statuses": VULN_STATUSES,
        "severities": SEVERITY_ORDER,
        "environments": summary_environments(app_summary),
        "params": params,
        "cutoff": cutoff,
        "now": now,
        **keyset_paginate(request, vulns, match_count(app_summary, params)),
    }
    return render(request, "vulns/app_detail.html", context)


EXPORT_COLUMNS = [
    ("Status", "export_status"), ("Provider", "provider"), ("Account ID", "account_number"),
    ("Account Name", "account_name"), ("App ID from scan", "app_id"), ("Severity", "severity"), ("CVE ID", "cve"),
    ("CVE Description", "cve_description"), ("Package", "package"), ("Current Version", "current_version"),
    ("Recommended Version", "recommended_version"), ("Image", "image"), ("Asset ID", "asset_id"),
    ("Instance", "instance"), ("Environment", "environment"), ("Cluster", "cluster"), ("Namespace", "namespace"),
    ("Days Open", "days_open"), ("SLO Date", "slo_date"), ("Past SLO", "slo_overdue"), ("Exception", "exception"),
    ("Exception RITM", "ritm"), ("Alert ID", "alert_id"),
    ("First Seen", "first_seen"), ("Last Scan", "seen_scan"), ("Remediated", "remediated_at"), ("Reopened", "reopened_at"),
]


@login_required
def app_export(request, app_id):
    if not can_view_app(request.user, app_id):
        raise Http404
    vulns, _ = _detail_vulns(request, app_id)
    cutoff = not_seen_cutoff()

    def rows():
        for vuln in iter_vulns(vulns):
            vuln.export_status = vuln.display_status(cutoff)
            yield vuln

    response = StreamingHttpResponse(stream_vulns_csv(rows(), EXPORT_COLUMNS), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{app_id}_vulnerabilities_{timezone.now():%Y%m%d}.csv"'
    return response


# --- cloud accounts ---------------------------------------------------------------------

ACCOUNT_STATES = [
    ("needs", "Needs assignment"), ("suggested", "One clear suggestion"), ("assigned", "Assigned"),
    ("mixed", "Multiple App IDs"), ("all", "All"),
]


@account_assigner_required
def account_list(request):
    state = request.GET.get("state", "needs")
    accounts = assignment.account_queryset(request.GET).select_related("application").order_by(
        "-untagged_critical_high", "-untagged_open", "account_name", "id"
    )
    context = {
        **paginate(request, accounts),
        "states": ACCOUNT_STATES,
        "state": state,
        "providers": sorted(p for p in CloudAccount.objects.values_list("provider", flat=True).distinct() if p),
        "suggestion_count": assignment.account_queryset({"state": "suggested"}).count(),
        "params": request.GET,
    }
    return render(request, "vulns/account_list.html", context)


@account_assigner_required
def app_search(request):
    account_pks = [int(pk) for pk in request.GET.get("accounts", "").split(",") if pk.isdigit()]
    return JsonResponse(assignment.search_apps(request.GET.get("q"), account_pks, request.user))


@account_assigner_required
@require_POST
def account_assign(request):
    choice = request.POST.get("application", "")
    selection = {key: request.POST.get(key, "") for key in ("state", "q", "provider")}
    select_all = request.POST.get("select_all") == "1"
    accepted = request.POST.get("accept_suggestion", "")
    if accepted.isdigit():
        account = CloudAccount.objects.filter(pk=accepted).exclude(suggested_app_id="").first()
        suggested = Application.objects.filter(app_id=account.suggested_app_id).first() if account else None
        if suggested is None:
            messages.error(request, "That suggestion is no longer available.")
            return _back(request, "account_list")
        accounts, choice, select_all = CloudAccount.objects.filter(pk=account.pk), str(suggested.pk), False
    elif select_all:
        accounts = assignment.account_queryset(selection)
    else:
        accounts = CloudAccount.objects.filter(pk__in=[pk for pk in request.POST.getlist("account_ids") if pk.isdigit()])
    if not accounts.exists():
        messages.warning(request, "Tick at least one cloud account.")
        return _back(request, "account_list")
    if not choice:
        messages.warning(request, "Choose an App ID to assign.")
        return _back(request, "account_list")
    application = None if choice == "none" else Application.objects.filter(pk=choice if choice.isdigit() else None).first()
    if choice != "none" and application is None:
        messages.error(request, "That application no longer exists.")
        return _back(request, "account_list")
    if request.POST.get("confirm") != "1":
        context = {
            **assignment.preview(accounts, application),
            "application": application,
            "choice": choice,
            "select_all": select_all,
            "selection": selection,
            "account_pks": [] if select_all else list(accounts.values_list("pk", flat=True)),
            "next": request.POST.get("next", ""),
        }
        return render(request, "vulns/account_assign_confirm.html", context)
    changed = assignment.assign(list(accounts.values_list("pk", flat=True)), application, request.user)
    target = application.app_id if application else "Unassigned"
    messages.success(request, f"{changed} cloud account{'s' if changed != 1 else ''} moved to {target}.")
    return _back(request, "account_list")


@account_assigner_required
def account_detail(request, account_id):
    account = get_object_or_404(CloudAccount.objects.select_related("application"), account_id=account_id)
    account_summary = AlertSummary.objects.filter(cloud_account=account)
    summary = summary_totals(account_summary)
    breakdown = [
        {"app_id": owner or None, "n": int(n)}
        for owner, n in account_summary.filter(status=OPEN).values_list("owner_app_id").annotate(n=Sum("total")).order_by("-n")
    ]
    params = request.GET.copy()
    params.setdefault("status", "open")
    vulns = filter_vulns(Vulnerability.objects.filter(cloud_account=account), params)
    context = {
        "account": account,
        "summary": summary,
        "severity_counts": [(s, summary[s.lower()]) for s in SEVERITY_ORDER],
        "breakdown": breakdown,
        "history": account.assignments.select_related("changed_by")[:20],
        "statuses": VULN_STATUSES,
        "severities": SEVERITY_ORDER,
        "environments": summary_environments(account_summary),
        "params": params,
        "cutoff": not_seen_cutoff(),
        **keyset_paginate(request, vulns, match_count(account_summary, params)),
    }
    return render(request, "vulns/account_detail.html", context)


# --- notifications ----------------------------------------------------------------------


def _remark(request):
    return (request.POST.get("remark") or "").strip(), request.POST.get("include_in_email") == "on"


NOTIFICATION_LABELS = {
    Notification.SUPPORT: "Notification", Notification.REMINDER: "Reminder", Notification.ESCALATION: "Escalation",
}


def _report_send(request, app_id, log):
    label = NOTIFICATION_LABELS.get(log.kind, "Notification")
    if log.status == Notification.SENT:
        copied = f", copied to {log.cc}" if log.cc else ""
        messages.success(request, f"{label} for {app_id} sent to {log.recipients}{copied} ({log.vuln_count} vulnerabilities).")
    else:
        messages.error(request, f"{label} for {app_id} failed, so its status did not change: {log.error}")


@admin_required
@require_POST
def app_notify(request, app_id):
    app = Application.objects.filter(app_id=app_id).first()
    remark, include = _remark(request)
    try:
        log = followups.notify_support(app, request.user, remark, include)
    except NotificationNotAllowed as exc:
        messages.error(request, str(exc))
    else:
        _report_send(request, app_id, log)
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
    remark, include = _remark(request)
    jobs.enqueue(jobs.NOTIFY, {"app_ids": app_ids, "remark": remark, "include": include}, request.user)
    messages.success(
        request, f"Sending to the support teams of {len(app_ids)} application(s). Results appear in the Notification log."
    )
    return _back(request, "app_list")


@admin_required
@require_POST
def followup_escalate(request, pk):
    follow_up = get_object_or_404(FollowUp.objects.select_related("application"), pk=pk)
    remark, include = _remark(request)
    try:
        log = followups.escalate(follow_up, request.user, remark, include)
    except NotificationNotAllowed as exc:
        messages.error(request, str(exc))
    else:
        _report_send(request, follow_up.app_id, log)
    return _followup_back(follow_up)


@response_recorder_required
@require_POST
def followup_respond(request, pk):
    follow_up = get_object_or_404(FollowUp, pk=pk)
    form = ResponseForm(request.POST)
    if not form.is_valid():
        errors = "; ".join(f"{form[name].label}: {' '.join(errs)}" for name, errs in form.errors.items())
        messages.error(request, f"Response not saved. {errors}")
        return _followup_back(follow_up)
    data = form.cleaned_data
    try:
        followups.record_response(
            follow_up, request.user, data["responder"], data["responded_on"], data["response"],
            close=data["close"] and request.user.is_admin,
        )
        messages.success(request, "Response recorded.")
    except NotificationNotAllowed as exc:
        messages.error(request, str(exc))
    return _followup_back(follow_up)


@response_recorder_required
@require_POST
def followup_remark(request, pk):
    follow_up = get_object_or_404(FollowUp, pk=pk)
    remark, _ = _remark(request)
    if not remark:
        messages.warning(request, "Write a remark first.")
    else:
        followups.add_remark(follow_up, request.user, remark)
        messages.success(request, "Remark added.")
    return _followup_back(follow_up)


@admin_required
@require_POST
def followup_close(request, pk):
    follow_up = get_object_or_404(FollowUp, pk=pk)
    remark, _ = _remark(request)
    try:
        followups.close(follow_up, request.user, remark)
        messages.success(request, "Follow-up closed.")
    except NotificationNotAllowed as exc:
        messages.error(request, str(exc))
    return _followup_back(follow_up)


def _followup_back(follow_up):
    if follow_up.application_id:
        return redirect(reverse("app_detail", args=[follow_up.application.app_id]) + "#follow-up")
    return redirect("notification_log")


@login_required
def notification_log(request):
    logs = scoped_notifications(request.user)
    q = (request.GET.get("q") or "").strip()
    if q:
        logs = logs.filter(
            Q(app_id__icontains=q) | Q(recipients__icontains=q) | Q(cc__icontains=q) | Q(sent_by__email__icontains=q)
        )
    if request.GET.get("status") in (Notification.SENT, Notification.FAILED):
        logs = logs.filter(status=request.GET["status"])
    if request.GET.get("kind") in dict(Notification.KIND_CHOICES):
        logs = logs.filter(kind=request.GET["kind"])
    followup = request.GET.get("followup")
    if followup == "overdue":
        logs = logs.filter(
            follow_up__status__in=[FollowUp.WAITING, FollowUp.ESCALATED], follow_up__waiting_since__lt=followup_cutoff()
        )
    elif followup in dict(FollowUp.STATUS_CHOICES):
        logs = logs.filter(follow_up__status=followup)
    context = {
        **paginate(request, logs.select_related("follow_up")),
        "params": request.GET,
        "kinds": Notification.KIND_CHOICES,
        "followup_statuses": FollowUp.STATUS_CHOICES,
        "cutoff": followup_cutoff(),
    }
    return render(request, "vulns/notification_log.html", context)


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
    if not uploaded.name.lower().endswith((".csv", ".xlsx", ".xlsm")):
        messages.error(request, f"{uploaded.name}: upload a .csv, .xlsx or .xlsm file.")
        return None
    run = run_getter()
    if run.phase == "finalizing":
        messages.error(request, "This import is being finalized. Upload again when it finishes.")
        return run
    import_file = lifecycle.add_file(run, uploaded, request.user)
    messages.success(request, f"{import_file.filename} added to import #{run.pk}. Herald reads it in the background.")
    return run


@admin_required
def import_home(request):
    if request.method == "POST":
        run = _store_upload(request, lambda: lifecycle.get_or_create_draft(request.user))
        return redirect("import_detail", pk=run.pk) if run else redirect("import_home")
    history = ImportRun.objects.exclude(status=ImportRun.DRAFT).select_related("finalized_by")
    context = {
        **paginate(request, history),
        "form": UploadForm(),
        "draft": ImportRun.objects.filter(status=ImportRun.DRAFT).first(),
        "legacy": LegacyUpload.objects.all(),
        "columns": COLUMNS,
    }
    return render(request, "imports/home.html", context)


@admin_required
def import_detail(request, pk):
    run = get_object_or_404(ImportRun, pk=pk)
    files = list(run.files.all())
    for import_file in files:
        import_file.sample_errors = list(import_file.rejected_rows.all()[:REJECTED_SAMPLE])
    context = {"run": run, "files": files, "form": UploadForm(), "plan": run.plan, "confirm_word": lifecycle.CONFIRM_WORD}
    if run.is_draft:
        planned = PlannedRemediation.objects.filter(run=run).select_related(
            "vulnerability__cloud_account", "vulnerability__asset_ref", "vulnerability__cve_ref", "vulnerability__package_ref"
        ).order_by("id")
        context.update(paginate(request, planned, default="50"))
        context["is_busy"] = run.is_busy
        context["blockers"] = lifecycle.finalize_blockers(run, run.plan) if run.plan_ready else []
        context["needs_confirm"] = bool(
            run.plan_ready and run.plan.get("open_total")
            and run.plan.get("remediated", 0) / run.plan["open_total"] > lifecycle.LARGE_REMEDIATION_SHARE
        )
        context["last_failure"] = (
            Job.objects.filter(kind=jobs.FINALIZE, payload__run=run.pk, status=Job.FAILED).order_by("-id").first()
        )
    else:
        context.update(paginate(request, run.remediated_vulns.browse().order_by("id"), default="50"))
    return render(request, "imports/detail.html", context)


@admin_required
@require_POST
def import_add_file(request, pk):
    run = get_object_or_404(ImportRun, pk=pk, status=ImportRun.DRAFT)
    _store_upload(request, lambda: run)
    return redirect("import_detail", pk=run.pk)


@admin_required
@require_POST
def import_expected(request, pk):
    value = (request.POST.get("expected_total") or "").replace(",", "").strip()
    if value and not value.isdigit():
        messages.error(request, "Enter the Power BI total as a whole number.")
    else:
        ImportRun.objects.filter(pk=pk, status=ImportRun.DRAFT).update(expected_total=int(value) if value else None)
    return redirect("import_detail", pk=pk)


@admin_required
@require_POST
def import_finalize(request, pk):
    run = get_object_or_404(ImportRun, pk=pk)
    if not run.is_draft or run.is_busy or not run.plan_ready:
        messages.error(request, "Wait for the files and preview to finish before finalizing.")
        return redirect("import_detail", pk=pk)
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
        return redirect("import_detail", pk=pk)
    ImportRun.objects.filter(pk=pk).update(phase="finalizing")
    job = jobs.enqueue(jobs.FINALIZE, payload, request.user)
    if job.status == Job.FAILED:
        messages.error(request, job.message)
    elif job.status == Job.DONE:
        messages.success(request, job.message)
    else:
        messages.success(request, f"Finalizing import #{pk} in the background.")
    return redirect("import_detail", pk=pk)


@admin_required
@require_POST
def import_discard(request, pk):
    run = get_object_or_404(ImportRun, pk=pk)
    try:
        lifecycle.discard(run)
        messages.success(request, f"Import #{pk} discarded. Nothing was changed.")
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("import_detail", pk=pk)
    return redirect("import_home")


@admin_required
def import_planned_export(request, pk):
    run = get_object_or_404(ImportRun, pk=pk, status=ImportRun.DRAFT)

    def rows():
        writer = csv.writer(_Echo())
        yield writer.writerow(["Account", "Account ID", "App ID", "Alert ID", "Severity", "CVE", "Package", "Asset", "Old scan", "New scan"])
        last = 0
        while True:
            chunk = list(
                PlannedRemediation.objects.filter(run=run, id__gt=last).order_by("id").select_related(
                    "vulnerability__cloud_account", "vulnerability__asset_ref", "vulnerability__cve_ref",
                    "vulnerability__package_ref",
                )[:2000]
            )
            for item in chunk:
                v = item.vulnerability
                yield writer.writerow([
                    v.account_name, v.account_number, v.owner_app_id or "", v.alert_id, v.severity, v.cve, v.package,
                    v.asset_id, item.old_scan, item.new_scan,
                ])
            if len(chunk) < 2000:
                return
            last = chunk[-1].id

    response = StreamingHttpResponse(rows(), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="import_{pk}_will_be_remediated.csv"'
    return response


@admin_required
@require_POST
def archive_now(request):
    jobs.enqueue(jobs.ARCHIVE, {}, request.user)
    messages.success(request, "Archiving remediated alerts in the background.")
    return redirect("settings_general")


class _Echo:
    def write(self, value):
        return value


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
