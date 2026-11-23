"""Precomputed counts behind the dashboard and lists, rebuilt after imports, assignments and each new day."""
from datetime import timedelta

from django.db import connection, transaction
from django.utils import timezone

from core.models import AppSettings


@transaction.atomic
def refresh(account_pks=None):
    """Rebuilds all summaries, or only those of the given accounts. Readers keep the old numbers until commit."""
    cfg = AppSettings.load()
    now = timezone.now()
    params = {
        "now": now, "cutoff": now - timedelta(days=cfg.not_seen_days), "recent": now - timedelta(days=30),
        "accounts": list(account_pks) if account_pks is not None else None,
    }
    scope = "" if account_pks is None else "WHERE v.cloud_account_id = ANY(%(accounts)s)"
    with connection.cursor() as cursor:
        if account_pks is None:
            cursor.execute("DELETE FROM vulns_alertsummary")
        else:
            cursor.execute("DELETE FROM vulns_alertsummary WHERE cloud_account_id = ANY(%(accounts)s)", params)
        cursor.execute(f"""
            INSERT INTO vulns_alertsummary (owner_app_id, cloud_account_id, provider, environment, severity, exception,
              status, total, tagged, past_slo, untagged_past_slo, not_seen, reopened, recent_remediated, fix_seconds, fix_count)
            SELECT COALESCE(v.owner_app_id, ''), v.cloud_account_id, c.provider, v.environment, v.severity, v.exception,
              v.status, count(*),
              count(*) FILTER (WHERE v.app_id <> ''),
              count(*) FILTER (WHERE v.status = 'open' AND v.slo_date < %(now)s),
              count(*) FILTER (WHERE v.status = 'open' AND v.slo_date < %(now)s AND v.app_id = ''),
              count(*) FILTER (WHERE v.status = 'open' AND GREATEST(v.last_scan, a.last_scan) < %(cutoff)s),
              count(*) FILTER (WHERE v.status = 'open' AND v.reopened_at IS NOT NULL),
              count(*) FILTER (WHERE v.status = 'remediated' AND v.remediated_at >= %(recent)s),
              COALESCE(sum(extract(epoch FROM v.remediated_at - v.first_seen))
                       FILTER (WHERE v.status = 'remediated' AND v.remediated_at IS NOT NULL), 0)::bigint,
              count(*) FILTER (WHERE v.status = 'remediated' AND v.remediated_at IS NOT NULL)
            FROM vulns_vulnerability v
            JOIN vulns_cloudaccount c ON c.id = v.cloud_account_id
            LEFT JOIN vulns_asset a ON a.id = v.asset_ref_id
            {scope}
            GROUP BY 1, 2, 3, 4, 5, 6, 7""", params)
        account_scope = "" if account_pks is None else "WHERE c.id = ANY(%(accounts)s)"
        cursor.execute(f"""
            UPDATE vulns_cloudaccount c SET
              open_count = COALESCE(x.open_count, 0),
              untagged_open = COALESCE(x.untagged_open, 0),
              untagged_critical_high = COALESCE(x.untagged_critical_high, 0),
              untagged_past_slo = COALESCE(x.untagged_past_slo, 0),
              seen_app_ids = COALESCE(t.items, '[]'::jsonb),
              seen_app_count = COALESCE(t.n, 0),
              suggested_app_id = CASE WHEN t.n = 1 THEN t.only_app ELSE '' END
            FROM vulns_cloudaccount base
            LEFT JOIN (
              SELECT cloud_account_id,
                sum(total) AS open_count, sum(total - tagged) AS untagged_open,
                sum(total - tagged) FILTER (WHERE severity IN ('Critical', 'High')) AS untagged_critical_high,
                sum(untagged_past_slo) AS untagged_past_slo
              FROM vulns_alertsummary WHERE status = 'open' GROUP BY cloud_account_id
            ) x ON x.cloud_account_id = base.id
            LEFT JOIN (
              SELECT cloud_account_id, count(*) AS n, min(owner_app_id) AS only_app,
                jsonb_agg(jsonb_build_object('app_id', owner_app_id, 'tagged', tagged) ORDER BY tagged DESC, owner_app_id) AS items
              FROM (SELECT cloud_account_id, owner_app_id, sum(tagged)::bigint AS tagged FROM vulns_alertsummary
                    WHERE status = 'open' AND tagged > 0 GROUP BY 1, 2) by_app
              GROUP BY cloud_account_id
            ) t ON t.cloud_account_id = base.id
            WHERE c.id = base.id {account_scope.replace('WHERE', 'AND')}""", params)
    if account_pks is None:
        AppSettings.objects.filter(pk=cfg.pk).update(summaries_refreshed_at=now)
