from datetime import timedelta

from django.core.paginator import Paginator
from django.db.models import Case, Count, IntegerField, Max, Q, Value, When
from django.utils import timezone

from accounts.permissions import visible_app_ids
from core.models import AppSettings

from .columns import SEVERITY_ORDER
from .models import Application, Notification, Vulnerability

PAGE_SIZES = ["10", "25", "50", "100", "all"]
OPEN = Vulnerability.OPEN
REMEDIATED = Vulnerability.REMEDIATED


def severity_rank():
    return Case(
        *[When(severity=name, then=Value(i)) for i, name in enumerate(SEVERITY_ORDER)],
        default=Value(len(SEVERITY_ORDER)),
        output_field=IntegerField(),
    )


def not_seen_cutoff():
    return timezone.now() - timedelta(days=AppSettings.load().not_seen_days)


def scoped_vulns(user):
    qs = Vulnerability.objects.all()
    ids = visible_app_ids(user)
    return qs if ids is None else qs.filter(app_id__in=ids)


def scoped_apps(user):
    qs = Application.objects.all()
    ids = visible_app_ids(user)
    return qs if ids is None else qs.filter(app_id__in=ids)


def scoped_notifications(user):
    qs = Notification.objects.select_related("sent_by")
    ids = visible_app_ids(user)
    return qs if ids is None else qs.filter(app_id__in=ids)


def paginate(request, items, default="25"):
    per_page = request.GET.get("per_page", default)
    if per_page not in PAGE_SIZES:
        per_page = default
    total = len(items) if isinstance(items, list) else items.count()
    paginator = Paginator(items, max(total, 1) if per_page == "all" else int(per_page))
    page = paginator.get_page(request.GET.get("page"))
    return {
        "page": page,
        "per_page": per_page,
        "page_sizes": PAGE_SIZES,
        "page_range": paginator.get_elided_page_range(page.number, on_each_side=2, on_ends=1),
        "carry_params": [
            (k, v) for k in request.GET for v in request.GET.getlist(k) if k not in ("page", "per_page")
        ],
    }


# --- vulnerability table (app detail page) ----------------------------------------------

VULN_STATUSES = [
    ("open", "Open (all)"), ("reopened", "Reopened"), ("not_seen", "Not seen"), ("remediated", "Remediated"), ("all", "All"),
]


def filter_vulns(qs, params):
    now = timezone.now()
    status = params.get("status", "open")
    if status == "open":
        qs = qs.filter(status=OPEN)
    elif status == "reopened":
        qs = qs.filter(status=OPEN, reopened_at__isnull=False)
    elif status == "not_seen":
        qs = qs.filter(status=OPEN, last_scan__lt=not_seen_cutoff())
    elif status == "remediated":
        qs = qs.filter(status=REMEDIATED)
    if params.get("severity"):
        qs = qs.filter(severity=params["severity"])
    if params.get("env"):
        qs = qs.filter(environment=params["env"])
    if params.get("slo") == "past":
        qs = qs.filter(status=OPEN, slo_date__lt=now)
    elif params.get("slo") == "within":
        qs = qs.filter(Q(slo_date__gte=now) | Q(slo_date__isnull=True))
    if params.get("exception") == "yes":
        qs = qs.filter(exception=True)
    elif params.get("exception") == "no":
        qs = qs.filter(exception=False)
    q = (params.get("q") or "").strip()
    if q:
        qs = qs.filter(
            Q(cve__icontains=q) | Q(package__icontains=q) | Q(current_version__icontains=q)
            | Q(recommended_version__icontains=q) | Q(image__icontains=q) | Q(asset_id__icontains=q)
            | Q(asset_name__icontains=q) | Q(alert_id__icontains=q) | Q(cluster__icontains=q)
            | Q(namespace__icontains=q) | Q(ritm__icontains=q)
        )
    return qs.annotate(sev_rank=severity_rank()).order_by("status", "sev_rank", "slo_date", "alert_id")


def environments(qs):
    return sorted(e for e in qs.values_list("environment", flat=True).distinct() if e)


# --- applications list ------------------------------------------------------------------


def _severity_counts(prefix=""):
    now = timezone.now()
    open_q = Q(status=OPEN)
    counts = {
        "open": Count("id", filter=open_q),
        "past_slo": Count("id", filter=open_q & Q(slo_date__lt=now)),
        "not_seen": Count("id", filter=open_q & Q(last_scan__lt=not_seen_cutoff())),
        "remediated": Count("id", filter=Q(status=REMEDIATED)),
    }
    for sev in SEVERITY_ORDER:
        counts[sev.lower()] = Count("id", filter=open_q & Q(severity=sev))
    return counts


def application_rows(user, params):
    """One row per App ID that is registered or appears in scan data, with counts, filtered per params."""
    vulns = scoped_vulns(user)
    counted = vulns
    narrowed = bool(params.get("env") or params.get("exception"))
    if params.get("env"):
        counted = counted.filter(environment=params["env"])
    if params.get("exception") == "yes":
        counted = counted.filter(exception=True)
    elif params.get("exception") == "no":
        counted = counted.filter(exception=False)

    stats = {r["app_id"]: r for r in counted.values("app_id").annotate(**_severity_counts())}
    totals = {r["app_id"]: r["n"] for r in vulns.filter(status=OPEN).values("app_id").annotate(n=Count("id"))}
    seen_ids = set(vulns.values_list("app_id", flat=True).distinct())
    apps = {a.app_id: a for a in scoped_apps(user)}
    last_notified = {
        r["app_id"]: r["last"]
        for r in scoped_notifications(user).filter(status=Notification.SENT).values("app_id").annotate(last=Max("sent_at"))
    }

    empty = {k: 0 for k in ["open", "past_slo", "not_seen", "remediated"] + [s.lower() for s in SEVERITY_ORDER]}
    rows = []
    for app_id in sorted(set(apps) | seen_ids):
        app = apps.get(app_id)
        row = {**empty, **stats.get(app_id, {})}
        row.update(
            app_id=app_id,
            app=app,
            registered=app is not None,
            has_email=bool(app and app.has_email),
            total_open=totals.get(app_id, 0),
            last_notified=last_notified.get(app_id),
            narrowed=narrowed,
        )
        rows.append(row)

    q = (params.get("q") or "").strip().lower()
    if q:
        def matches(row):
            app = row["app"]
            fields = [row["app_id"]]
            if app:
                fields += [app.name, app.owner_name, app.owner_email, app.extra_emails, app.business_service, app.department]
            return any(q in (f or "").lower() for f in fields)
        rows = [r for r in rows if matches(r)]

    status = params.get("status")
    status_filters = {
        "with_vulns": lambda r: r["open"] > 0,
        "registered": lambda r: r["registered"],
        "unregistered": lambda r: not r["registered"],
        "no_email": lambda r: r["registered"] and not r["has_email"],
        "not_rescanned": lambda r: r["not_seen"] > 0,
        "all_remediated": lambda r: r["open"] == 0 and r["remediated"] > 0,
    }
    if status in status_filters:
        rows = [r for r in rows if status_filters[status](r)]
    if params.get("severity") in SEVERITY_ORDER:
        rows = [r for r in rows if r[params["severity"].lower()] > 0]
    if params.get("slo") == "past":
        rows = [r for r in rows if r["past_slo"] > 0]
    elif params.get("slo") == "none":
        rows = [r for r in rows if r["past_slo"] == 0]
    if params.get("notified") == "yes":
        rows = [r for r in rows if r["last_notified"]]
    elif params.get("notified") == "never":
        rows = [r for r in rows if not r["last_notified"]]

    rows.sort(key=lambda r: (-r["open"], r["app_id"]))
    return rows
