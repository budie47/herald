import io
from collections import Counter
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Avg, Count, DurationField, ExpressionWrapper, F, Q
from django.http import Http404, HttpResponse
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

from . import assignment, followups, lifecycle
from .columns import COLUMNS, SEVERITY_ORDER
from .forms import ApplicationForm, ResponseForm, UploadForm
from .models import (
    Application, CloudAccount, FollowUp, FollowUpEvent, ImportRun, LegacyUpload, Notification, Vulnerability,
)
from .notify import NotificationNotAllowed, vulns_csv
from .parsing import FileFormatError
from .queries import (
    OPEN, REMEDIATED, VULN_STATUSES, application_rows, environments, filter_vulns, followup_cutoff, not_seen_cutoff,
    overdue_q, paginate, scoped_apps, scoped_followups, scoped_notifications, scoped_vulns, vulns_for_app,
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
    open_owned = open_vulns.filter(owner_app_id__isnull=False)
    unassigned = open_vulns.filter(owner_app_id__isnull=True)
    open_app_ids = set(open_owned.values_list("owner_app_id", flat=True).distinct())
    finding_ids = set(vulns.filter(owner_app_id__isnull=False).values_list("owner_app_id", flat=True).distinct())

    remediated = vulns.filter(status=REMEDIATED, remediated_at__isnull=False)
    recent = remediated.filter(remediated_at__gte=now - timedelta(days=30))
    avg_fix = remediated.aggregate(
        avg=Avg(ExpressionWrapper(F("remediated_at") - F("first_seen"), output_field=DurationField()))
    )["avg"]

    by_sev = dict(open_vulns.values_list("severity").annotate(n=Count("id")))
    severity_bars = [(s, by_sev.pop(s, 0)) for s in SEVERITY_ORDER] + sorted(by_sev.items())
    env_bars = [(e or "(not set)", n) for e, n in open_vulns.values_list("environment").annotate(n=Count("id")).order_by("-n")]
    provider_bars = [
        (p or "(not set)", n)
        for p, n in open_vulns.values_list("cloud_account__provider").annotate(n=Count("id")).order_by("-n")
    ]
    recent_by_sev = dict(recent.values_list("severity").annotate(n=Count("id")))

    top = list(
        open_owned.values("owner_app_id")
        .annotate(
            total=Count("id"),
            past_slo=Count("id", filter=Q(slo_date__lt=now)),
            **{s.lower(): Count("id", filter=Q(severity=s)) for s in SEVERITY_ORDER},
        )
        .order_by("-total", "owner_app_id")[:10]
    )
    for row in top:
        row["app_id"] = row["owner_app_id"]
        row["registered"] = row["app_id"] in registered_ids
        row["severities"] = [(s, row[s.lower()]) for s in SEVERITY_ORDER]

    owned = len(finding_ids & registered_ids)
    open_followups = scoped_followups(request.user).exclude(status=FollowUp.CLOSED)
    context = {
        "followups_waiting": open_followups.filter(status=FollowUp.WAITING).count(),
        "followups_overdue": open_followups.filter(overdue_q(followup_cutoff())).count(),
        "followups_escalated": open_followups.filter(status=FollowUp.ESCALATED).count(),
        "followup_days": AppSettings.load().followup_overdue_days,
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
        "provider_bars": provider_bars,
        "provider_max": max([n for _, n in provider_bars] or [0]),
        "unassigned_alerts": unassigned.count(),
        "unassigned_critical_high": unassigned.filter(severity__in=["Critical", "High"]).count(),
        "cloud_accounts": vulns.values("cloud_account").distinct().count(),
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
    ("no_email", "No support email"), ("not_rescanned", "Not rescanned"), ("all_remediated", "All remediated"),
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
        "environments": environments(scoped_vulns(request.user)),
        "unregistered_count": sum(1 for r in all_rows if not r["registered"]),
        "params": request.GET,
    }
    return render(request, "vulns/app_list.html", context)


def _prefill_from_scan(app_id):
    """Suggest form values for an unregistered App ID from its scan data."""
    rows = [v.data or {} for v in Vulnerability.objects.filter(app_id=app_id).only("data")[:500]]
    initial = {"app_id": app_id}
    for field, column in (("name", "app_service"), ("business_service", "business_service"), ("department", "department")):
        values = Counter(row.get(column) for row in rows if row.get(column))
        if values:
            initial[field] = values.most_common(1)[0][0]
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
    context = {"app": app, "vuln_count": vulns_for_app(app_id).count(), "account_count": app.cloud_accounts.count()}
    return render(request, "vulns/app_delete.html", context)


def _detail_vulns(request, app_id):
    params = request.GET.copy()
    params.setdefault("status", "open")
    return filter_vulns(vulns_for_app(app_id), params), params


@login_required
def app_detail(request, app_id):
    if not can_view_app(request.user, app_id):
        raise Http404
    app = Application.objects.filter(app_id=app_id).first()
    all_vulns = vulns_for_app(app_id)
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
    open_by_account = dict(
        all_vulns.filter(status=OPEN).values_list("cloud_account_id").annotate(n=Count("id"))
    )
    linked = CloudAccount.objects.filter(
        Q(application__app_id=app_id) | Q(pk__in=all_vulns.values("cloud_account_id"))
    ).distinct()
    cloud_accounts = list(linked)
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
        "environments": environments(all_vulns),
        "params": params,
        "cutoff": cutoff,
        "now": now,
        **paginate(request, vulns),
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


# --- cloud accounts ---------------------------------------------------------------------

ACCOUNT_STATES = [("needs", "Needs assignment"), ("assigned", "Assigned"), ("mixed", "Multiple App IDs"), ("all", "All")]


@account_assigner_required
def account_list(request):
    state = request.GET.get("state", "needs")
    accounts = CloudAccount.objects.all()
    q = (request.GET.get("q") or "").strip()
    if q:
        accounts = accounts.filter(
            Q(account_id__icontains=q) | Q(account_name__icontains=q) | Q(application__app_id__icontains=q)
        )
    if request.GET.get("provider"):
        accounts = accounts.filter(provider=request.GET["provider"])
    seen = assignment.app_ids_by_account()
    if state == "needs":
        accounts = accounts.filter(pk__in=assignment.needs_assignment().values("pk"))
    elif state == "assigned":
        accounts = accounts.filter(application__isnull=False)
    elif state == "mixed":
        accounts = accounts.filter(pk__in=[pk for pk, ids in seen.items() if len(ids) > 1])
    accounts = assignment.with_alert_counts(accounts).select_related("application")
    accounts = accounts.order_by("-untagged_critical_high", "-untagged_open", "account_name")
    pagination = paginate(request, accounts)
    for account in pagination["page"]:
        account.app_ids = seen.get(account.pk, [])
    context = {
        **pagination,
        "states": ACCOUNT_STATES,
        "state": state,
        "providers": sorted(p for p in CloudAccount.objects.values_list("provider", flat=True).distinct() if p),
        "applications": Application.objects.all(),
        "params": request.GET,
    }
    return render(request, "vulns/account_list.html", context)


@account_assigner_required
@require_POST
def account_assign(request):
    pks = [pk for pk in request.POST.getlist("account_ids") if pk.isdigit()]
    accounts = CloudAccount.objects.filter(pk__in=pks)
    choice = request.POST.get("application", "")
    if not pks or not accounts.exists():
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
            "next": request.POST.get("next", ""),
        }
        return render(request, "vulns/account_assign_confirm.html", context)
    changed = assignment.assign(pks, application, request.user)
    target = application.app_id if application else "Unassigned"
    messages.success(request, f"{changed} cloud account{'s' if changed != 1 else ''} moved to {target}.")
    return _back(request, "account_list")


@account_assigner_required
def account_detail(request, account_id):
    account = get_object_or_404(CloudAccount.objects.select_related("application"), account_id=account_id)
    vulns = account.vulnerabilities.with_owner()
    now = timezone.now()
    open_q = Q(status=OPEN)
    summary = vulns.aggregate(
        open=Count("id", filter=open_q),
        untagged=Count("id", filter=open_q & Q(app_id="")),
        past_slo=Count("id", filter=open_q & Q(slo_date__lt=now)),
        remediated=Count("id", filter=Q(status=REMEDIATED)),
        **{s.lower(): Count("id", filter=open_q & Q(severity=s)) for s in SEVERITY_ORDER},
    )
    breakdown = [
        {"app_id": row["owner_app_id"], "n": row["n"]}
        for row in vulns.filter(status=OPEN).values("owner_app_id").annotate(n=Count("id")).order_by("-n")
    ]
    params = request.GET.copy()
    params.setdefault("status", "open")
    context = {
        "account": account,
        "summary": summary,
        "severity_counts": [(s, summary[s.lower()]) for s in SEVERITY_ORDER],
        "breakdown": breakdown,
        "applications": Application.objects.all(),
        "history": account.assignments.select_related("changed_by")[:20],
        "statuses": VULN_STATUSES,
        "severities": SEVERITY_ORDER,
        "environments": environments(vulns),
        "params": params,
        "cutoff": not_seen_cutoff(),
        **paginate(request, filter_vulns(vulns, params)),
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
    apps = {a.app_id: a for a in Application.objects.filter(app_id__in=app_ids)}
    sent, failed, skipped = [], [], []
    for app_id in app_ids:
        try:
            log = followups.notify_support(apps.get(app_id), request.user, remark, include)
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
