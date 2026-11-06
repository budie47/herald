"""Draft imports: staging uploaded rows, previewing what finalizing will do, and applying it.

Rules
- Vulnerabilities are matched across uploads by Alert ID.
- An open alert is marked remediated only when the same Asset ID has a newer Last Scan without that alert.
  Assets missing from an upload are left untouched.
- Rows older than what is stored are skipped, so re-uploading an older file changes nothing.
- A remediated alert that appears in a scan newer than the one that proved the fix is reopened.
- A rejected (unreadable) row never counts as evidence of a fix: its asset is excluded from remediation.
"""
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from core.models import AppSettings

from .columns import MODEL_FIELDS, TYPES, DATE
from .models import ImportFile, ImportRun, StagedRow, Vulnerability
from .parsing import parse_file

CHUNK = 2000
UPDATE_FIELDS = MODEL_FIELDS + [
    "data", "status", "last_seen", "remediated_at", "remediated_import", "reopened_at", "updated_import", "updated_at",
]


def chunks(items, size=CHUNK):
    items = list(items)
    for start in range(0, len(items), size):
        yield items[start:start + size]


def parse_dt(value):
    return datetime.fromisoformat(value) if value else None


# --- staging ----------------------------------------------------------------------------


def get_or_create_draft(user):
    draft = ImportRun.objects.filter(status=ImportRun.DRAFT).first()
    if draft:
        return draft
    try:
        with transaction.atomic():
            return ImportRun.objects.create(created_by=user)
    except IntegrityError:  # another admin created it at the same moment
        return ImportRun.objects.get(status=ImportRun.DRAFT)


@transaction.atomic
def add_file(run, uploaded, user):
    """Parses one upload into the draft. Raises FileFormatError if the file can't be read at all."""
    result = parse_file(uploaded, uploaded.name)
    import_file = ImportFile.objects.create(
        run=run,
        filename=uploaded.name[:255],
        uploaded_by=user,
        header_row=result.header_row,
        rows_read=result.rows_read,
        accepted=len(result.rows),
        rejected=len(result.errors),
        errors=result.errors,
        unknown_columns=result.unknown_columns,
        missing_columns=result.missing_columns,
    )
    latest = {}
    for record in result.rows:  # within a file the last row for an Alert ID wins
        latest[record["alert_id"]] = record
    for alert_ids in chunks(latest):
        StagedRow.objects.filter(run=run, alert_id__in=alert_ids).delete()
    StagedRow.objects.bulk_create(
        [
            StagedRow(
                run=run,
                file=import_file,
                row_number=record.pop("_row"),
                alert_id=alert_id,
                app_id=record["app_id"],
                asset_id=record.get("asset_id") or "",
                last_scan=parse_dt(record.get("last_scan")),
                data=record,
            )
            for alert_id, record in latest.items()
        ],
        batch_size=1000,
    )
    run.files_count = run.files.count()
    run.save(update_fields=["files_count"])
    return import_file


@transaction.atomic
def discard(run):
    run = ImportRun.objects.select_for_update().get(pk=run.pk)
    if run.status != ImportRun.DRAFT:
        raise ValueError("Only a draft import can be discarded.")
    run.staged_rows.all().delete()
    run.status = ImportRun.DISCARDED
    run.save(update_fields=["status"])


# --- planning ---------------------------------------------------------------------------


@dataclass
class Plan:
    new: list = field(default_factory=list)  # [StagedRow]
    updated: list = field(default_factory=list)  # [(StagedRow, Vulnerability)]
    reopened: list = field(default_factory=list)  # [(StagedRow, Vulnerability)]
    skipped: list = field(default_factory=list)  # [(StagedRow, Vulnerability)]
    remediated: list = field(default_factory=list)  # [(Vulnerability, new_scan_datetime)]
    assets: int = 0
    protected_assets: set = field(default_factory=set)

    @property
    def remediated_by_app(self):
        return Counter(v.app_id for v, _ in self.remediated).most_common()


def build_plan(run):
    plan = Plan()
    staged = {row.alert_id: row for row in run.staged_rows.all()}

    protected_alerts = set()
    for import_file in run.files.all():
        for error in import_file.errors:
            if error.get("asset_id"):
                plan.protected_assets.add(error["asset_id"])
            if error.get("alert_id"):
                protected_alerts.add(error["alert_id"])

    asset_scan = {}
    for row in staged.values():
        if row.asset_id and row.last_scan and (row.asset_id not in asset_scan or row.last_scan > asset_scan[row.asset_id]):
            asset_scan[row.asset_id] = row.last_scan
    plan.assets = len({row.asset_id for row in staged.values() if row.asset_id})

    existing = {}
    for alert_ids in chunks(staged):
        for vuln in Vulnerability.objects.filter(alert_id__in=alert_ids):
            existing[vuln.alert_id] = vuln

    for alert_id, row in staged.items():
        vuln = existing.get(alert_id)
        if vuln is None:
            plan.new.append(row)
        elif vuln.status == Vulnerability.REMEDIATED:
            fixed_as_of = vuln.remediated_at or vuln.last_scan
            if row.last_scan and (fixed_as_of is None or row.last_scan > fixed_as_of):
                plan.reopened.append((row, vuln))
            else:
                plan.skipped.append((row, vuln))
        elif vuln.last_scan and (row.last_scan is None or row.last_scan < vuln.last_scan):
            plan.skipped.append((row, vuln))
        else:
            plan.updated.append((row, vuln))

    for asset_ids in chunks(asset_scan):
        candidates = Vulnerability.objects.filter(status=Vulnerability.OPEN, asset_id__in=asset_ids)
        for vuln in candidates:
            if vuln.alert_id in staged or vuln.alert_id in protected_alerts or vuln.asset_id in plan.protected_assets:
                continue
            new_scan = asset_scan[vuln.asset_id]
            if vuln.last_scan and new_scan > vuln.last_scan:
                plan.remediated.append((vuln, new_scan))
    plan.remediated.sort(key=lambda item: (item[0].app_id, item[0].alert_id))
    return plan


# --- applying ---------------------------------------------------------------------------


def _apply_row(vuln, row, settings):
    data = row.data
    for key in MODEL_FIELDS:
        value = data.get(key)
        if TYPES[key] == DATE:
            value = parse_dt(value)
        elif value is None:
            value = False if key == "exception" else ""
        if key == "slo_date" and value is None:
            value = vuln.slo_date or _default_slo(vuln.first_seen, data.get("severity"), settings)
        setattr(vuln, key, value)
    vuln.data = data
    vuln.last_seen = row.last_scan or vuln.last_seen


def _default_slo(first_seen, severity, settings):
    days = settings.slo_days(severity)
    return first_seen + timedelta(days=days) if days is not None and first_seen else None


def _new_vuln(row, run, settings, now):
    first_seen = parse_dt(row.data.get("first_detected")) or row.last_scan or now
    vuln = Vulnerability(alert_id=row.alert_id, first_seen=first_seen, last_seen=row.last_scan or now, created_import=run)
    _apply_row(vuln, row, settings)
    vuln.updated_import = run
    return vuln


@transaction.atomic
def finalize(run, user):
    run = ImportRun.objects.select_for_update().get(pk=run.pk)
    if run.status != ImportRun.DRAFT:
        raise ValueError("Only a draft import can be finalized.")
    plan = build_plan(run)
    settings = AppSettings.load()
    now = timezone.now()

    Vulnerability.objects.bulk_create([_new_vuln(row, run, settings, now) for row in plan.new], batch_size=1000)

    changed = []
    for row, vuln in plan.updated:
        _apply_row(vuln, row, settings)
        vuln.updated_import, vuln.updated_at = run, now
        changed.append(vuln)
    for row, vuln in plan.reopened:
        _apply_row(vuln, row, settings)
        vuln.status = Vulnerability.OPEN
        vuln.reopened_at = row.last_scan or now
        vuln.remediated_at = None
        vuln.remediated_import = None
        vuln.updated_import, vuln.updated_at = run, now
        changed.append(vuln)
    for vuln, new_scan in plan.remediated:
        vuln.status = Vulnerability.REMEDIATED
        vuln.remediated_at = new_scan
        vuln.remediated_import = run
        vuln.updated_at = now
        changed.append(vuln)
    Vulnerability.objects.bulk_update(changed, UPDATE_FIELDS, batch_size=500)

    run.status = ImportRun.FINALIZED
    run.finalized_at = now
    run.finalized_by = user
    run.files_count = run.files.count()
    run.assets_count = plan.assets
    run.new_count = len(plan.new)
    run.updated_count = len(plan.updated)
    run.reopened_count = len(plan.reopened)
    run.remediated_count = len(plan.remediated)
    run.skipped_count = len(plan.skipped)
    run.save()
    run.staged_rows.all().delete()
    return run
