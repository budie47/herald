"""Giving an App ID by hand to servers that CMDB doesn't tag. CMDB's App ID always wins."""
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from . import summaries
from .models import Server, ServerAssignment


def server_queryset(qs, params):
    state = params.get("state", "findings")
    q = (params.get("q") or "").strip()
    if q:
        qs = qs.filter(
            Q(name__icontains=q) | Q(fqdn__icontains=q) | Q(ip_address__startswith=q) | Q(app_id__iexact=q)
        )
    for param, field in (("env", "environment"), ("cls", "server_class"), ("app", "app_id")):
        if params.get(param):
            qs = qs.filter(**{field: params[param]})
    if params.get("kev") == "yes":
        qs = qs.filter(kev_open__gt=0)
    if state == "findings":
        qs = qs.filter(open_count__gt=0)
    elif state == "unassigned":
        qs = qs.filter(app_id="", open_count__gt=0)
    elif state == "not_in_cmdb":
        qs = qs.filter(in_cmdb=False)
    return qs


@transaction.atomic
def assign(server_pks, application, user):
    """Returns (changed, skipped). Servers with a CMDB App ID are skipped: correct those in CMDB."""
    target = application.app_id if application else ""
    servers = list(Server.objects.select_for_update().filter(pk__in=server_pks))
    skipped = [s for s in servers if s.cmdb_app_id]
    changing = [s for s in servers if not s.cmdb_app_id and s.app_id != target]
    if not changing:
        return 0, len(skipped)
    now = timezone.now()
    ServerAssignment.objects.bulk_create([
        ServerAssignment(server=s, old_app_id=s.app_id, new_app_id=target, open_count=s.open_count, changed_by=user)
        for s in changing
    ], batch_size=1000)
    Server.objects.filter(pk__in=[s.pk for s in changing]).update(
        manual_app_id=target, app_id=target, assigned_by=user if application else None,
        assigned_at=now if application else None, updated_at=now,
    )
    summaries.refresh()
    return len(changing), len(skipped)


def needs_assignment():
    return Server.objects.filter(app_id="", open_count__gt=0)
