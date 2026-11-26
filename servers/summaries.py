"""Precomputed server counts, rebuilt after imports, CMDB changes, assignments and each new day."""
from datetime import timedelta

from django.db import connection, transaction
from django.utils import timezone


@transaction.atomic
def refresh():
    now = timezone.now()
    params = {"now": now, "recent": now - timedelta(days=30)}
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM servers_serversummary")
        cursor.execute("""
            INSERT INTO servers_serversummary (app_id, environment, server_class, severity, cisa_kev, status, total,
              past_slo, reopened, recent_remediated, fix_seconds, fix_count)
            SELECT s.app_id, s.environment, s.server_class, f.severity, f.cisa_kev, f.status, count(*),
              count(*) FILTER (WHERE f.status = 'open' AND f.slo_date < %(now)s),
              count(*) FILTER (WHERE f.status = 'open' AND f.reopened_at IS NOT NULL),
              count(*) FILTER (WHERE f.status = 'remediated' AND f.remediated_at >= %(recent)s),
              COALESCE(sum(extract(epoch FROM f.remediated_at - COALESCE(f.first_detected, f.first_seen)))
                       FILTER (WHERE f.status = 'remediated' AND f.remediated_at IS NOT NULL), 0)::bigint,
              count(*) FILTER (WHERE f.status = 'remediated' AND f.remediated_at IS NOT NULL)
            FROM servers_serverfinding f JOIN servers_server s ON s.id = f.server_id
            GROUP BY 1, 2, 3, 4, 5, 6""", params)
        cursor.execute("""
            UPDATE servers_server s SET open_count = x.open_count, critical_open = x.critical_open,
              high_open = x.high_open, kev_open = x.kev_open, past_slo_open = x.past_slo_open
            FROM (
              SELECT base.id,
                count(f.id) AS open_count,
                count(f.id) FILTER (WHERE f.severity = 'Critical') AS critical_open,
                count(f.id) FILTER (WHERE f.severity = 'High') AS high_open,
                count(f.id) FILTER (WHERE f.cisa_kev) AS kev_open,
                count(f.id) FILTER (WHERE f.slo_date < %(now)s) AS past_slo_open
              FROM servers_server base
              LEFT JOIN servers_serverfinding f ON f.server_id = base.id AND f.status = 'open'
              GROUP BY base.id
            ) x
            WHERE s.id = x.id AND (s.open_count, s.critical_open, s.high_open, s.kev_open, s.past_slo_open)
              IS DISTINCT FROM (x.open_count, x.critical_open, x.high_open, x.kev_open, x.past_slo_open)""", params)
