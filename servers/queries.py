from django.db.models import Count, Q, Sum
from django.utils import timezone

from accounts.permissions import visible_app_ids
from vulns.columns import SEVERITY_ORDER

from .models import Server, ServerFinding, ServerSummary

OPEN, REMEDIATED = ServerFinding.OPEN, ServerFinding.REMEDIATED
SORT_COLUMNS = ("status", "severity_rank", "slo_sort", "id")
FINDING_STATUSES = [("open", "Open (all)"), ("reopened", "Reopened"), ("remediated", "Remediated"), ("all", "All")]


def scoped_servers(user):
    qs = Server.objects.all()
    ids = visible_app_ids(user)
    return qs if ids is None else qs.filter(app_id__in=ids)


def scoped_summary(user):
    qs = ServerSummary.objects.all()
    ids = visible_app_ids(user)
    return qs if ids is None else qs.filter(app_id__in=ids)


def can_view_server(user, server):
    ids = visible_app_ids(user)
    return ids is None or (server.app_id and server.app_id in ids)


def findings_for_app(app_id):
    return ServerFinding.objects.filter(server__app_id=app_id)


def summary_totals(qs):
    open_q = Q(status=OPEN)
    totals = qs.aggregate(
        open=Sum("total", filter=open_q),
        past_slo=Sum("past_slo"),
        reopened=Sum("reopened"),
        kev=Sum("total", filter=open_q & Q(cisa_kev=True)),
        remediated=Sum("total", filter=Q(status=REMEDIATED)),
        recent_remediated=Sum("recent_remediated"),
        fix_seconds=Sum("fix_seconds"),
        fix_count=Sum("fix_count"),
        **{s.lower(): Sum("total", filter=open_q & Q(severity=s)) for s in SEVERITY_ORDER},
    )
    return {key: int(value or 0) for key, value in totals.items()}


def filter_findings(qs, params):
    status = params.get("status", "open")
    if status == "open":
        qs = qs.filter(status=OPEN)
    elif status == "reopened":
        qs = qs.filter(status=OPEN, reopened_at__isnull=False)
    elif status == "remediated":
        qs = qs.filter(status=REMEDIATED)
    if params.get("severity"):
        qs = qs.filter(severity=params["severity"])
    if params.get("kev") == "yes":
        qs = qs.filter(cisa_kev=True)
    if params.get("slo") == "past":
        qs = qs.filter(status=OPEN, slo_date__lt=timezone.now())
    if params.get("env"):
        qs = qs.filter(server__environment=params["env"])
    q = (params.get("q") or "").strip()
    if q:
        qs = qs.filter(
            Q(qid=q) | Q(title__icontains=q) | Q(server__name__icontains=q) | Q(server__ip_address=q) | Q(cves__icontains=q)
        )
    return qs.select_related("server").order_by(*SORT_COLUMNS)


def iter_findings(qs, chunk=2000):
    """Streams a filtered list in priority order, so exports use little memory."""
    return qs.iterator(chunk_size=chunk)


def module_open_counts(app_id):
    """Open vulnerabilities per module, for the application page tabs."""
    from vulns.models import AlertSummary

    containers = AlertSummary.objects.filter(owner_app_id=app_id, status=OPEN).aggregate(n=Sum("total"))["n"]
    servers = ServerSummary.objects.filter(app_id=app_id, status=OPEN).aggregate(n=Sum("total"))["n"]
    return {"containers": int(containers or 0), "servers": int(servers or 0)}


SERVER_SEVERITIES = ("Critical", "High")


def server_application_rows(user, params, module_ids=None):
    """The Servers tab of the applications list: one row per App ID with servers, filtered per params."""
    from vulns.models import SERVERS
    from vulns.queries import app_rows, filter_app_rows, module_app_ids, scoped_apps, tab_app_ids

    counted = scoped_summary(user).exclude(app_id="")
    narrowed = bool(params.get("env"))
    if narrowed:
        counted = counted.filter(environment=params["env"])
    open_q = Q(status=OPEN)
    stats = {
        r["app_id"]: r
        for r in counted.values("app_id").annotate(
            open=Sum("total", filter=open_q),
            past_slo=Sum("past_slo"),
            kev=Sum("total", filter=open_q & Q(cisa_kev=True)),
            remediated=Sum("total", filter=Q(status=REMEDIATED)),
            **{s.lower(): Sum("total", filter=open_q & Q(severity=s)) for s in SERVER_SEVERITIES},
        )
    }
    servers_qs = scoped_servers(user).exclude(app_id="")
    if narrowed:
        servers_qs = servers_qs.filter(environment=params["env"])
    server_counts = {
        r["app_id"]: r
        for r in servers_qs.values("app_id").annotate(servers=Count("id"), servers_open=Count("id", filter=Q(open_count__gt=0)))
    }
    totals = dict(scoped_summary(user).exclude(app_id="").filter(status=OPEN).values_list("app_id").annotate(n=Sum("total")))
    apps = {a.app_id: a for a in scoped_apps(user)}
    containers, servers = module_ids or module_app_ids()
    own_ids = set(scoped_servers(user).exclude(app_id="").values_list("app_id", flat=True).distinct())
    own_ids |= set(scoped_summary(user).exclude(app_id="").values_list("app_id", flat=True).distinct())

    count_keys = ["open", "past_slo", "kev", "remediated"] + [s.lower() for s in SERVER_SEVERITIES]
    rows = app_rows(user, SERVERS, tab_app_ids(apps, own_ids, containers, servers), apps, stats, count_keys, narrowed)
    for row in rows:
        counts = server_counts.get(row["app_id"], {})
        row.update(
            servers=counts.get("servers", 0), servers_open=counts.get("servers_open", 0),
            total_open=int(totals.get(row["app_id"], 0)),
        )
    return filter_app_rows(rows, params, SERVER_SEVERITIES)


def environments(user):
    """Environments with server vulnerabilities, from the small summary table."""
    return sorted(e for e in scoped_summary(user).order_by().values_list("environment", flat=True).distinct() if e)
