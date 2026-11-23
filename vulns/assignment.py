"""Assigning cloud accounts to App IDs. Alerts with their own App ID are never affected."""
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone

from .models import AccountAssignment, CloudAccount, Vulnerability

OPEN = Vulnerability.OPEN
UNTAGGED_OPEN = Q(vulnerabilities__status=OPEN, vulnerabilities__app_id="")


def needs_assignment():
    """Accounts with open alerts that have no App ID and no assigned application."""
    return CloudAccount.objects.filter(UNTAGGED_OPEN, application__isnull=True).distinct()


def app_ids_by_account(account_pks=None):
    """{account pk: sorted App IDs seen on its open alerts}."""
    qs = Vulnerability.objects.filter(status=OPEN).exclude(app_id="")
    if account_pks is not None:
        qs = qs.filter(cloud_account_id__in=account_pks)
    result = {}
    for pk, app_id in qs.values_list("cloud_account_id", "app_id").distinct():
        result.setdefault(pk, []).append(app_id)
    return {pk: sorted(ids) for pk, ids in result.items()}


def with_alert_counts(accounts):
    now = timezone.now()
    open_q = Q(vulnerabilities__status=OPEN)
    return accounts.annotate(
        open_count=Count("vulnerabilities", filter=open_q),
        untagged_open=Count("vulnerabilities", filter=UNTAGGED_OPEN),
        untagged_critical_high=Count(
            "vulnerabilities", filter=UNTAGGED_OPEN & Q(vulnerabilities__severity__in=["Critical", "High"])
        ),
        untagged_past_slo=Count("vulnerabilities", filter=UNTAGGED_OPEN & Q(vulnerabilities__slo_date__lt=now)),
    )


def preview(accounts, application):
    """What assigning these accounts would do, including accounts that already carry other App IDs."""
    rows = list(with_alert_counts(accounts).select_related("application"))
    seen = app_ids_by_account([a.pk for a in rows])
    target = application.app_id if application else None
    for account in rows:
        account.app_ids = seen.get(account.pk, [])
        account.other_app_ids = [a for a in account.app_ids if a != target]
        account.is_mixed = len(account.app_ids) > 1 or bool(target and account.other_app_ids)
    return {
        "accounts": rows,
        "untagged_total": sum(a.untagged_open for a in rows),
        "mixed": [a for a in rows if a.is_mixed],
        "replacing": [a for a in rows if a.application_id and a.application_id != (application.pk if application else None)],
    }


@transaction.atomic
def assign(account_pks, application, user):
    """Sets (or clears, with application=None) the App ID. Returns how many accounts changed."""
    target_pk = application.pk if application else None
    locked = CloudAccount.objects.select_for_update().filter(pk__in=account_pks)
    accounts = [a for a in locked if a.application_id != target_pk]
    untagged = dict(
        Vulnerability.objects.filter(cloud_account__in=accounts, status=OPEN, app_id="")
        .values_list("cloud_account_id")
        .annotate(n=Count("id"))
    )
    now = timezone.now()
    for account in accounts:
        AccountAssignment.objects.create(
            cloud_account=account,
            old_app_id=account.application.app_id if account.application else "",
            new_app_id=application.app_id if application else "",
            untagged_open=untagged.get(account.pk, 0),
            changed_by=user,
        )
        account.application = application
        account.assigned_by = user if application else None
        account.assigned_at = now if application else None
        account.save(update_fields=["application", "assigned_by", "assigned_at", "updated_at"])
    return len(accounts)
