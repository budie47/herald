"""Retention: after the configured days, a remediated alert keeps a compact record without its scan details."""
from datetime import timedelta

from django.db import connection, transaction
from django.utils import timezone

from core.models import AppSettings

from . import summaries
from .models import Vulnerability


def eligible():
    cutoff = timezone.now() - timedelta(days=AppSettings.load().retention_days)
    return Vulnerability.objects.filter(
        status=Vulnerability.REMEDIATED, remediated_at__lt=cutoff, archived_at__isnull=True
    )


def remove_unused_details():
    """Deletes shared context rows that no alert or draft uses any more."""
    with connection.cursor() as cursor:
        cursor.execute("""
            DELETE FROM vulns_alertcontext c WHERE NOT EXISTS (SELECT 1 FROM vulns_vulnerability v WHERE v.context_id = c.id)
              AND NOT EXISTS (SELECT 1 FROM vulns_stagedalert s WHERE s.context_id = c.id)""")
        return cursor.rowcount


def run_archive():
    cutoff = timezone.now() - timedelta(days=AppSettings.load().retention_days)
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            """UPDATE vulns_vulnerability SET context_id = NULL, archived_at = %s
               WHERE status = 'remediated' AND remediated_at < %s AND archived_at IS NULL""",
            [timezone.now(), cutoff],
        )
        archived = cursor.rowcount
    removed = remove_unused_details() if archived else 0
    summaries.refresh()
    return f"Archived {archived} remediated alerts and removed {removed} unused detail records."
