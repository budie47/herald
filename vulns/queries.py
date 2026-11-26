from datetime import datetime, timedelta

from django.core.paginator import Paginator
from django.db import OperationalError, connection, transaction
from django.db.models import F, Max, Q, Sum
from django.utils import timezone
from psycopg.errors import QueryCanceled

from accounts.permissions import visible_app_ids
from core.models import AppSettings

from .columns import SEVERITY_ORDER
from .models import (
    CONTAINERS, AlertSummary, Application, CloudAccount, CveRecord, FollowUp, Notification, Vulnerability,
)

PAGE_SIZES = ["10", "25", "50", "100"]
ALL_ROWS_LIMIT = 500
SEARCH_TIMEOUT_MS = 10_000
OPEN = Vulnerability.OPEN
REMEDIATED = Vulnerability.REMEDIATED


def not_seen_cutoff():
    return timezone.now() - timedelta(days=AppSettings.load().not_seen_days)


def scoped_summary(user):
    qs = AlertSummary.objects.all()
    ids = visible_app_ids(user)
    return qs if ids is None else qs.filter(owner_app_id__in=ids)


def vulns_for_app(app_id):
    """Alerts tagged with this App ID plus untagged alerts in accounts assigned to it."""
    return Vulnerability.objects.filter(owner_app_id=app_id)


def summary_totals(qs):
    """Rolls precomputed counts up to one set of numbers."""
    open_q = Q(status=OPEN)
    totals = qs.aggregate(
        open=Sum("total", filter=open_q),
        past_slo=Sum("past_slo"),
        not_seen=Sum("not_seen"),
        reopened=Sum("reopened"),
        exceptions=Sum("total", filter=open_q & Q(exception=True)),
        remediated=Sum("total", filter=Q(status=REMEDIATED)),
        untagged=Sum(F("total") - F("tagged"), filter=open_q),
        recent_remediated=Sum("recent_remediated"),
        fix_seconds=Sum("fix_seconds"),
        fix_count=Sum("fix_count"),
        **{s.lower(): Sum("total", filter=open_q & Q(severity=s)) for s in SEVERITY_ORDER},
    )
    return {key: int(value or 0) for key, value in totals.items()}


def scoped_apps(user):
    qs = Application.objects.all()
    ids = visible_app_ids(user)
    return qs if ids is None else qs.filter(app_id__in=ids)


def scoped_notifications(user, module=None):
    qs = Notification.objects.select_related("sent_by")
    if module:
        qs = qs.filter(module=module)
    ids = visible_app_ids(user)
    return qs if ids is None else qs.filter(app_id__in=ids)


def followup_cutoff():
    return timezone.now() - timedelta(days=AppSettings.load().followup_overdue_days)


def overdue_q(cutoff):
    return Q(status__in=[FollowUp.WAITING, FollowUp.ESCALATED], waiting_since__lt=cutoff)


def scoped_followups(user, module=None):
    qs = FollowUp.objects.all() if module is None else FollowUp.objects.filter(module=module)
    ids = visible_app_ids(user)
    return qs if ids is None else qs.filter(application__app_id__in=ids)


def paginate(request, items, default="25"):
    """Page-number paging for short lists. "All" is offered only while the list stays small."""
    total = len(items) if isinstance(items, list) else items.count()
    sizes = PAGE_SIZES + ["all"] if total <= ALL_ROWS_LIMIT else PAGE_SIZES
    per_page = request.GET.get("per_page", default)
    if per_page not in sizes:
        per_page = default
    paginator = Paginator(items, max(total, 1) if per_page == "all" else int(per_page))
    page = paginator.get_page(request.GET.get("page"))
    return {
        "page": page,
        "per_page": per_page,
        "page_sizes": sizes,
        "page_range": paginator.get_elided_page_range(page.number, on_each_side=2, on_ends=1),
        "carry_params": [
            (k, v) for k in request.GET for v in request.GET.getlist(k) if k not in ("page", "per_page")
        ],
    }


# --- vulnerability tables ---------------------------------------------------------------

VULN_STATUSES = [
    ("open", "Open (all)"), ("reopened", "Reopened"), ("not_seen", "Not seen"), ("remediated", "Remediated"), ("all", "All"),
]
SORT_COLUMNS = ("status", "severity_rank", "slo_sort", "id")
SORT_TUPLE = ", ".join(f"vulns_vulnerability.{column}" for column in SORT_COLUMNS)


def _search_q(q):
    """Searches are always within one application or account, so they only read that scope's rows."""
    return (
        Q(alert_id__iexact=q) | Q(ritm__iexact=q) | Q(app_id__iexact=q) | Q(cve_ref__cve__istartswith=q)
        | Q(package_ref__package__icontains=q) | Q(package_ref__current_version__icontains=q)
        | Q(package_ref__recommended_version__icontains=q) | Q(context__image__icontains=q)
        | Q(context__instance__icontains=q) | Q(context__cluster__icontains=q) | Q(context__namespace__icontains=q)
        | Q(asset_ref__asset_id__icontains=q) | Q(cloud_account__account_id__icontains=q)
        | Q(cloud_account__account_name__icontains=q)
    )


def _apply_search(qs, q):
    """CVE and exact Alert ID use indexes. Anything else scans the selected application or account."""
    if q.upper().startswith("CVE-"):
        return qs.filter(cve_ref__in=CveRecord.objects.filter(cve__istartswith=q).values("id"))
    if Vulnerability.objects.filter(alert_id=q).exists():
        return qs.filter(alert_id=q)
    return qs.filter(_search_q(q))


def filter_vulns(qs, params):
    now = timezone.now()
    status = params.get("status", "open")
    if status == "open":
        qs = qs.filter(status=OPEN)
    elif status == "reopened":
        qs = qs.filter(status=OPEN, reopened_at__isnull=False)
    elif status == "not_seen":
        cutoff = not_seen_cutoff()
        qs = qs.filter(Q(last_scan__lt=cutoff) | Q(last_scan__isnull=True), status=OPEN).filter(
            Q(asset_ref__last_scan__lt=cutoff) | (Q(asset_ref__last_scan__isnull=True) & Q(last_scan__isnull=False))
        )
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
        qs = _apply_search(qs, q)
    return qs.browse().order_by(*SORT_COLUMNS)


def match_count(summary, params):
    """How many alerts a filter matches, from the summaries. None when only a full search could tell."""
    if (params.get("q") or "").strip():
        return None
    status = params.get("status", "open")
    slo = params.get("slo")
    if slo in ("past", "within") and status in ("reopened", "not_seen"):
        return None
    if params.get("severity"):
        summary = summary.filter(severity=params["severity"])
    if params.get("env"):
        summary = summary.filter(environment=params["env"])
    if params.get("exception") in ("yes", "no"):
        summary = summary.filter(exception=params["exception"] == "yes")
    totals = summary_totals(summary)
    every = totals["open"] + totals["remediated"]
    if slo == "past":
        return 0 if status == "remediated" else totals["past_slo"]
    if slo == "within":
        return {"open": totals["open"], "remediated": totals["remediated"]}.get(status, every) - (
            0 if status == "remediated" else totals["past_slo"]
        )
    return {
        "open": totals["open"], "reopened": totals["reopened"], "not_seen": totals["not_seen"],
        "remediated": totals["remediated"],
    }.get(status, every)


def _cursor(vuln):
    return f"{vuln.status}|{vuln.severity_rank}|{vuln.slo_sort.isoformat()}|{vuln.id}"


def _parse_cursor(value):
    try:
        status, rank, slo, pk = value.split("|")
        return [status, int(rank), datetime.fromisoformat(slo), int(pk)]
    except (AttributeError, ValueError):
        return None


def _after(qs, cursor, operator=">"):
    return qs.extra(where=[f"({SORT_TUPLE}) {operator} (%s::varchar, %s::smallint, %s::timestamptz, %s::bigint)"], params=cursor)


class KeysetPage:
    """Next/previous paging that stays fast at any depth."""

    def __init__(self, rows, has_previous, has_next):
        self.rows, self.has_previous, self.has_next = rows, has_previous, has_next
        self.next_cursor = _cursor(rows[-1]) if rows and has_next else None
        self.previous_cursor = _cursor(rows[0]) if rows and has_previous else None

    def __iter__(self):
        return iter(self.rows)

    def __len__(self):
        return len(self.rows)


def _fetch(qs, searching):
    """Runs a page query. A text search that would tie up the database is stopped and returns None."""
    if not searching:
        return list(qs)
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(f"SET LOCAL statement_timeout = {int(SEARCH_TIMEOUT_MS)}")
            return list(qs)
    except OperationalError as exc:
        if isinstance(exc.__cause__, QueryCanceled):
            return None
        raise


def keyset_paginate(request, qs, count=None):
    per_page = request.GET.get("per_page", "25")
    if per_page not in PAGE_SIZES:
        per_page = "25"
    size = int(per_page)
    after, before = _parse_cursor(request.GET.get("after")), _parse_cursor(request.GET.get("before"))
    searching = bool((request.GET.get("q") or "").strip())
    if before:
        rows = _fetch(_after(qs, before, "<").order_by(*[f"-{c}" for c in SORT_COLUMNS])[: size + 1], searching)
    else:
        rows = _fetch((_after(qs, after) if after else qs)[: size + 1], searching)
    if rows is None:
        page = KeysetPage([], False, False)
    elif before:
        page = KeysetPage(list(reversed(rows[:size])), len(rows) > size, True)
    else:
        page = KeysetPage(rows[:size], bool(after), len(rows) > size)
    return {
        "page": page,
        "search_timed_out": rows is None,
        "per_page": per_page,
        "page_sizes": PAGE_SIZES,
        "match_count": count,
        "carry_params": [
            (k, v) for k in request.GET for v in request.GET.getlist(k) if k not in ("after", "before", "page", "per_page")
        ],
    }


def iter_vulns(qs, chunk=2000):
    """Walks a filtered table in small chunks, so exports use little memory and hold no long transaction."""
    cursor = None
    while True:
        rows = list((_after(qs, cursor) if cursor else qs)[:chunk])
        yield from rows
        if len(rows) < chunk:
            return
        cursor = _parse_cursor(_cursor(rows[-1]))


def summary_environments(summary):
    return sorted(e for e in summary.values_list("environment", flat=True).distinct() if e)


# --- applications list ------------------------------------------------------------------


def application_rows(user, params):
    """One row per App ID in the catalog or scan data, with precomputed counts, filtered per params."""
    summary = scoped_summary(user).exclude(owner_app_id="")
    counted = summary
    narrowed = bool(params.get("env") or params.get("exception"))
    if params.get("env"):
        counted = counted.filter(environment=params["env"])
    if params.get("exception") in ("yes", "no"):
        counted = counted.filter(exception=params["exception"] == "yes")

    open_q = Q(status=OPEN)
    stats = {
        r["owner_app_id"]: r
        for r in counted.values("owner_app_id").annotate(
            open=Sum("total", filter=open_q),
            past_slo=Sum("past_slo"),
            not_seen=Sum("not_seen"),
            remediated=Sum("total", filter=Q(status=REMEDIATED)),
            **{s.lower(): Sum("total", filter=open_q & Q(severity=s)) for s in SEVERITY_ORDER},
        )
    }
    totals = dict(summary.filter(status=OPEN).values_list("owner_app_id").annotate(n=Sum("total")))
    seen_ids = set(summary.values_list("owner_app_id", flat=True).distinct())
    apps = {a.app_id: a for a in scoped_apps(user)}
    last_notified = {
        r["app_id"]: r["last"]
        for r in scoped_notifications(user, CONTAINERS).filter(status=Notification.SENT).values("app_id")
        .annotate(last=Max("sent_at"))
    }

    from servers.models import ServerSummary  # server counts are shown, never added to container counts

    server_open = dict(
        ServerSummary.objects.filter(status=OPEN).exclude(app_id="").values_list("app_id").annotate(n=Sum("total"))
    )
    cutoff = followup_cutoff()
    open_followups = {
        f.application.app_id: f
        for f in scoped_followups(user, CONTAINERS).exclude(status=FollowUp.CLOSED).select_related("application")
    }

    count_keys = ["open", "past_slo", "not_seen", "remediated"] + [s.lower() for s in SEVERITY_ORDER]
    rows = []
    for app_id in sorted(set(apps) | seen_ids):
        app = apps.get(app_id)
        counts = stats.get(app_id, {})
        row = {key: int(counts.get(key) or 0) for key in count_keys}
        row.update(
            app_id=app_id,
            app=app,
            in_catalog=app is not None,
            registered=bool(app and app.has_contacts),
            has_email=bool(app and app.has_email),
            total_open=int(totals.get(app_id, 0)),
            last_notified=last_notified.get(app_id),
            server_open=int(server_open.get(app_id, 0)),
            followup=open_followups.get(app_id),
            followup_overdue=bool(app_id in open_followups and open_followups[app_id].is_overdue(cutoff)),
            narrowed=narrowed,
        )
        rows.append(row)

    q = (params.get("q") or "").strip().lower()
    if q:
        def matches(row):
            app = row["app"]
            fields = [row["app_id"]]
            if app:
                fields += [
                    app.name, app.owner_name, app.owner_email, app.support_team, app.support_emails, app.extra_emails,
                    app.business_service, app.department,
                ]
            return any(q in (f or "").lower() for f in fields)
        rows = [r for r in rows if matches(r)]

    status = params.get("status")
    status_filters = {
        "with_vulns": lambda r: r["open"] > 0,
        "registered": lambda r: r["registered"],
        "unregistered": lambda r: not r["registered"],
        "no_email": lambda r: not r["has_email"],
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

    followup = params.get("followup")
    if followup == "overdue":
        rows = [r for r in rows if r["followup_overdue"]]
    elif followup == "none":
        rows = [r for r in rows if not r["followup"]]
    elif followup in (FollowUp.WAITING, FollowUp.RESPONDED, FollowUp.ESCALATED):
        rows = [r for r in rows if r["followup"] and r["followup"].status == followup]

    rows.sort(key=lambda r: (-r["open"], r["app_id"]))
    return rows
