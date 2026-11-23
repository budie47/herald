"""Assigning cloud accounts to App IDs. Alerts with their own App ID are never affected."""
from django.db import connection, transaction
from django.db.models import Q, Sum
from django.utils import timezone

from . import jobs, summaries
from .models import AccountAssignment, Application, CloudAccount

INLINE_ALERT_LIMIT = 20_000
SEARCH_LIMIT = 20


def needs_assignment():
    """Accounts with open alerts that have no App ID and no assigned application."""
    return CloudAccount.objects.filter(application__isnull=True, untagged_open__gt=0)


def account_queryset(params):
    state = params.get("state", "needs")
    accounts = CloudAccount.objects.all()
    q = (params.get("q") or "").strip()
    if q:
        accounts = accounts.filter(
            Q(account_id__icontains=q) | Q(account_name__icontains=q) | Q(application__app_id__icontains=q)
        )
    if params.get("provider"):
        accounts = accounts.filter(provider=params["provider"])
    if state == "needs":
        accounts = accounts.filter(application__isnull=True, untagged_open__gt=0)
    elif state == "suggested":
        accounts = accounts.filter(application__isnull=True, untagged_open__gt=0).exclude(suggested_app_id="")
    elif state == "assigned":
        accounts = accounts.filter(application__isnull=False)
    elif state == "mixed":
        accounts = accounts.filter(seen_app_count__gt=1)
    return accounts


def preview(accounts, application, limit=50):
    """What assigning these accounts would do, including accounts that already carry other App IDs."""
    target = application.app_id if application else None
    target_pk = application.pk if application else None
    total = accounts.count()
    mixed_q = Q(seen_app_count__gt=1)
    if target:
        mixed_q |= Q(seen_app_count=1) & ~Q(suggested_app_id=target)
    mixed = accounts.filter(mixed_q)
    replacing = accounts.filter(application__isnull=False).exclude(application_id=target_pk).select_related("application")
    return {
        "accounts": list(accounts.select_related("application").order_by("-untagged_open", "account_name")[:limit]),
        "account_total": total,
        "hidden_accounts": max(total - limit, 0),
        "untagged_total": accounts.aggregate(n=Sum("untagged_open"))["n"] or 0,
        "mixed": list(mixed[:limit]),
        "mixed_total": mixed.count(),
        "replacing": list(replacing[:limit]),
        "replacing_total": replacing.count(),
    }


def apply_owners(account_pks):
    """Makes untagged alerts follow their account's assignment, one account per transaction."""
    for pk in account_pks:
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                """UPDATE vulns_vulnerability v SET owner_app_id = app.app_id
                   FROM vulns_cloudaccount c LEFT JOIN vulns_application app ON app.id = c.application_id
                   WHERE c.id = %s AND v.cloud_account_id = c.id AND v.app_id = ''
                     AND v.owner_app_id IS DISTINCT FROM app.app_id""",
                [pk],
            )
    summaries.refresh(account_pks)


@transaction.atomic
def assign(account_pks, application, user):
    """Sets (or clears, with application=None) the App ID. Returns how many accounts changed."""
    target_pk = application.pk if application else None
    locked = CloudAccount.objects.select_for_update().filter(pk__in=account_pks)
    accounts = [a for a in locked if a.application_id != target_pk]
    if not accounts:
        return 0
    old_app_ids = dict(
        Application.objects.filter(pk__in={a.application_id for a in accounts if a.application_id}).values_list("pk", "app_id")
    )
    now = timezone.now()
    AccountAssignment.objects.bulk_create([
        AccountAssignment(
            cloud_account=account,
            old_app_id=old_app_ids.get(account.application_id, ""),
            new_app_id=application.app_id if application else "",
            untagged_open=account.untagged_open,
            changed_by=user,
        )
        for account in accounts
    ], batch_size=1000)
    pks = [a.pk for a in accounts]
    CloudAccount.objects.filter(pk__in=pks).update(
        application=application, assigned_by=user if application else None, assigned_at=now if application else None,
        updated_at=now,
    )
    if sum(a.untagged_open for a in accounts) <= INLINE_ALERT_LIMIT:
        apply_owners(pks)
    else:
        transaction.on_commit(lambda: jobs.enqueue(jobs.ASSIGN, {"accounts": pks}, user))
    return len(accounts)


def search_apps(q, account_pks, user):
    """Picker results: clear suggestions and recent choices first, then up to 20 matches from the App ID catalog."""
    q = (q or "").strip()
    results = {"suggested": [], "recent": [], "matches": [], "more": False}
    seen = {}
    if account_pks:
        for account in CloudAccount.objects.filter(pk__in=account_pks[:200]).only("seen_app_ids", "open_count", "account_name"):
            for item in account.seen_app_ids:
                seen.setdefault(item["app_id"], []).append((account.account_name, item["tagged"], account.open_count))
    if not q:
        ranked = sorted(seen, key=lambda app_id: -sum(t for _, t, _ in seen[app_id]))[:5]
        apps = Application.objects.in_bulk(ranked, field_name="app_id")
        for app_id in ranked:
            if app_id in apps:
                evidence = seen[app_id]
                note = (
                    f"{evidence[0][1]} of {evidence[0][2]} alerts in {evidence[0][0]} are tagged" if len(evidence) == 1
                    else f"Tagged in {len(evidence)} selected accounts"
                )
                results["suggested"].append(_app_item(apps[app_id], note))
        recent_ids = []
        for app_id in AccountAssignment.objects.filter(changed_by=user).exclude(new_app_id="").order_by("-id").values_list(
            "new_app_id", flat=True
        )[:50]:
            if app_id not in recent_ids and app_id not in ranked:
                recent_ids.append(app_id)
            if len(recent_ids) == 3:
                break
        recent = Application.objects.in_bulk(recent_ids, field_name="app_id")
        results["recent"] = [_app_item(recent[a]) for a in recent_ids if a in recent]
    apps = Application.objects.all()
    if q:
        apps = apps.filter(
            Q(app_id__icontains=q) | Q(name__icontains=q) | Q(business_service__icontains=q) | Q(department__icontains=q)
            | Q(owner_name__icontains=q) | Q(owner_email__icontains=q) | Q(support_team__icontains=q)
            | Q(support_emails__icontains=q)
        )
    upper = q.upper()
    rows = sorted(
        apps.order_by("app_id")[:500],
        key=lambda a: (a.app_id != upper, not a.app_id.startswith(upper), a.app_id),
    ) if q else list(apps.order_by("app_id")[:SEARCH_LIMIT + 1])
    results["matches"] = [_app_item(a) for a in rows[:SEARCH_LIMIT]]
    results["more"] = len(rows) > SEARCH_LIMIT
    return results


def _app_item(app, note=""):
    return {
        "id": app.pk, "app_id": app.app_id, "name": app.name, "has_support": app.has_email, "has_contacts": app.has_contacts,
        "conflict": app.scan_conflict, "note": note,
    }
