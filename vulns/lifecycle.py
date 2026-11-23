"""Draft imports: staging uploaded batches, previewing what finalizing will do, and applying it.

Rules
- Vulnerabilities are matched across uploads by Alert ID. Within a draft the newest Last Scan wins.
- An open alert is marked remediated only when the same account + Asset ID has a newer Last Scan without that alert.
  Assets missing from an upload are left untouched.
- Rows older than what is stored are skipped, so re-uploading an older file changes nothing.
- A remediated alert that appears in a scan newer than the one that proved the fix is reopened.
- A rejected (unreadable) row or failed file never counts as evidence of a fix.
- An unchanged alert is not rewritten: its asset records the newer scan.
"""
import hashlib
import os
import uuid
from datetime import datetime

from django.conf import settings
from django.db import IntegrityError, connection, transaction
from django.db.models import Sum
from django.utils import timezone

from core.models import AppSettings

from . import jobs
from .columns import CONTEXT_COLUMNS, OTHER_SEVERITY_RANK, PACKAGE_COLUMNS, SEVERITY_RANKS
from .models import (
    AlertContext, CveRecord, FAR_FUTURE, ImportFile, ImportRun, PackageRecord, PlannedRemediation, RejectedRow,
    StagedAlert,
)
from .parsing import FileFormatError, StreamParser

BATCH_SIZE = 5000
CACHE_LIMIT = 200_000
SEPARATOR = "\x1f"
LARGE_REMEDIATION_SHARE = 0.20
CONFIRM_WORD = "REMEDIATE"
STAGE_COLUMNS = [
    "run_id", "file_id", "row_number", "alert_id", "csb_id", "account_id", "account_name", "provider", "asset_id",
    "app_id", "environment", "severity", "severity_rank", "exception", "ritm", "alert_opened", "slo_date", "last_scan",
    "cve_ref_id", "package_ref_id", "context_id", "fingerprint",
]


def parse_dt(value):
    return datetime.fromisoformat(value) if value else None


def content_key(values):
    return uuid.UUID(hashlib.md5(SEPARATOR.join(values).encode()).hexdigest())


def _epoch(value):
    return str(int(value.timestamp())) if value else ""


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


def add_file(run, uploaded, user):
    """Stores an upload and queues it. The worker reads it in the background."""
    upload_dir = settings.HERALD_UPLOAD_DIR
    os.makedirs(upload_dir, exist_ok=True)
    import_file = ImportFile.objects.create(
        run=run, filename=uploaded.name[:255], uploaded_by=user, status=ImportFile.QUEUED, size_bytes=uploaded.size
    )
    extension = os.path.splitext(uploaded.name)[1].lower()
    path = os.path.join(upload_dir, f"import-{import_file.pk}{extension}")
    with open(path, "wb") as target:
        for chunk in uploaded.chunks():
            target.write(chunk)
    ImportFile.objects.filter(pk=import_file.pk).update(stored_path=path)
    ImportRun.objects.filter(pk=run.pk).update(
        files_count=run.files.count(), plan_ready=False
    )
    jobs.enqueue(jobs.PARSE, {"file": import_file.pk}, user)
    import_file.refresh_from_db()
    return import_file


class CatalogCache:
    """Resolves repeated CVE, package and context values to shared rows."""

    def __init__(self):
        self.cves, self.packages, self.contexts = {}, {}, {}

    def _ensure(self, model, cache, rows):
        missing = [key for key in rows if key not in cache]
        if not missing:
            return
        if len(cache) > CACHE_LIMIT:
            cache.clear()
        model.objects.bulk_create([model(key=key, **rows[key]) for key in missing], batch_size=1000, ignore_conflicts=True)
        cache.update(model.objects.filter(key__in=missing).values_list("key", "id"))

    def _ensure_cves(self, rows):
        missing = {cve: info for cve, info in rows.items() if cve not in self.cves}
        if not missing:
            return
        if len(self.cves) > CACHE_LIMIT:
            self.cves.clear()
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO vulns_cverecord (cve, description, link) VALUES (%s, %s, %s)
                   ON CONFLICT (cve) DO UPDATE SET
                     description = COALESCE(NULLIF(EXCLUDED.description, ''), vulns_cverecord.description),
                     link = COALESCE(NULLIF(EXCLUDED.link, ''), vulns_cverecord.link)
                   WHERE (NULLIF(EXCLUDED.description, '') IS NOT NULL
                          AND EXCLUDED.description <> vulns_cverecord.description)
                      OR (NULLIF(EXCLUDED.link, '') IS NOT NULL AND EXCLUDED.link <> vulns_cverecord.link)""",
                [(cve, description, link) for cve, (description, link) in missing.items()],
            )
        self.cves.update(CveRecord.objects.filter(cve__in=list(missing)).values_list("cve", "id"))

    def resolve(self, records):
        packages, contexts, cves = {}, {}, {}
        for record in records:
            package = {column: record.get(column) or "" for column in PACKAGE_COLUMNS}
            context = {column: record.get(column) or "" for column in CONTEXT_COLUMNS}
            record["_package_key"] = content_key(package.values())
            record["_context_key"] = content_key(context.values())
            packages[record["_package_key"]] = package
            contexts[record["_context_key"]] = context
            if record.get("cve"):
                cves[record["cve"]] = (record.get("cve_description") or "", record.get("cve_link") or "")
        self._ensure(PackageRecord, self.packages, packages)
        self._ensure(AlertContext, self.contexts, contexts)
        self._ensure_cves(cves)


def _stage_values(run_id, file_id, record, catalog):
    opened, slo, scan = (parse_dt(record.get(key)) for key in ("alert_opened", "slo_date", "last_scan"))
    severity = record.get("severity") or ""
    cve_id = catalog.cves.get(record["cve"]) if record.get("cve") else None
    package_id = catalog.packages[record["_package_key"]]
    context_id = catalog.contexts[record["_context_key"]]
    exception = bool(record.get("exception"))
    fingerprint = content_key([
        record.get("csb_id") or "", record["account_id"], record.get("asset_id") or "", record.get("app_id") or "",
        record.get("environment") or "", severity, "1" if exception else "0", record.get("ritm") or "", _epoch(opened),
        _epoch(slo), str(cve_id or ""), str(package_id), str(context_id),
    ])
    return (
        run_id, file_id, record["_row"], record["alert_id"], record.get("csb_id") or "", record["account_id"],
        record["account_name"], record.get("provider") or "", record.get("asset_id") or "", record.get("app_id") or "",
        record.get("environment") or "", severity, SEVERITY_RANKS.get(severity, OTHER_SEVERITY_RANK), exception,
        record.get("ritm") or "", opened, slo, scan, cve_id, package_id, context_id, fingerprint,
    )


@transaction.atomic
def _stage_batch(run, import_file, records, errors, catalog):
    """Returns how many rows were duplicates of an Alert ID already in this draft."""
    if errors:
        RejectedRow.objects.bulk_create(
            [RejectedRow(run=run, file=import_file, **error) for error in errors], batch_size=1000
        )
    if not records:
        return 0
    catalog.resolve(records)
    columns = ", ".join(STAGE_COLUMNS)
    updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in STAGE_COLUMNS if c not in ("run_id", "alert_id"))
    with connection.cursor() as cursor:
        cursor.execute("DROP TABLE IF EXISTS _incoming")
        cursor.execute(f"CREATE TEMP TABLE _incoming ON COMMIT DROP AS SELECT {columns} FROM vulns_stagedalert WITH NO DATA")
        with cursor.copy(f"COPY _incoming ({columns}) FROM STDIN") as copy:
            for record in records:
                copy.write_row(_stage_values(run.pk, import_file.pk, record, catalog))
        cursor.execute(f"""
            WITH newest AS (
                SELECT DISTINCT ON (alert_id) * FROM _incoming
                ORDER BY alert_id, last_scan DESC NULLS LAST, row_number DESC
            ), written AS (
                INSERT INTO vulns_stagedalert ({columns}) SELECT {columns} FROM newest
                ON CONFLICT (run_id, alert_id) DO UPDATE SET {updates}
                WHERE EXCLUDED.last_scan >= vulns_stagedalert.last_scan OR vulns_stagedalert.last_scan IS NULL
                RETURNING (xmax = 0) AS fresh
            )
            SELECT count(*) FILTER (WHERE fresh) FROM written""")
        fresh = cursor.fetchone()[0]
        cursor.execute("DROP TABLE _incoming")
    return len(records) - fresh


def process_file(file_id):
    import_file = ImportFile.objects.select_related("run").get(pk=file_id)
    run = import_file.run
    if run.status != ImportRun.DRAFT:
        _remove_stored(import_file)
        return "The import is no longer a draft."
    ImportFile.objects.filter(pk=file_id).update(status=ImportFile.PROCESSING, error="")
    RejectedRow.objects.filter(file=import_file).delete()
    StagedAlert.objects.filter(file=import_file).delete()
    accepted = rejected = duplicates = 0
    try:
        with open(import_file.stored_path, "rb") as handle:
            parser = StreamParser(handle, import_file.filename)
            ImportFile.objects.filter(pk=file_id).update(
                header_row=parser.header_row, unknown_columns=parser.unknown_columns,
                missing_columns=parser.missing_columns,
            )
            catalog = CatalogCache()
            for records, errors in parser.batches(BATCH_SIZE):
                duplicates += _stage_batch(run, import_file, records, errors, catalog)
                accepted += len(records)
                rejected += len(errors)
                ImportFile.objects.filter(pk=file_id).update(
                    rows_read=parser.rows_read, accepted=accepted, rejected=rejected, duplicates=duplicates
                )
        ImportFile.objects.filter(pk=file_id).update(status=ImportFile.DONE)
        message = f"{import_file.filename}: {accepted} of {parser.rows_read} rows accepted."
    except FileFormatError as exc:
        ImportFile.objects.filter(pk=file_id).update(status=ImportFile.FAILED, error=str(exc))
        message = str(exc)
    except Exception as exc:
        StagedAlert.objects.filter(file=import_file).delete()
        ImportFile.objects.filter(pk=file_id).update(
            status=ImportFile.FAILED, error=f"Could not finish reading this file: {exc}"
        )
        message = str(exc)
    _remove_stored(import_file)
    _refresh_run_counts(run)
    if not run.files.filter(status__in=[ImportFile.QUEUED, ImportFile.PROCESSING]).exists():
        ImportRun.objects.filter(pk=run.pk).update(phase="planning", plan_ready=False)
        jobs.enqueue(jobs.PLAN, {"run": run.pk})
    return message


def _remove_stored(import_file):
    path = ImportFile.objects.values_list("stored_path", flat=True).get(pk=import_file.pk)
    if path and os.path.exists(path):
        os.remove(path)
    ImportFile.objects.filter(pk=import_file.pk).update(stored_path="")


def _refresh_run_counts(run):
    ImportRun.objects.filter(pk=run.pk).update(
        files_count=run.files.count(),
        unique_rows=StagedAlert.objects.filter(run=run).count(),
        duplicates_count=run.files.aggregate(n=Sum("duplicates"))["n"] or 0,
    )


def _clear_staging():
    # Only one draft can exist, so these tables hold nothing else.
    with connection.cursor() as cursor:
        cursor.execute("TRUNCATE vulns_stagedalert, vulns_plannedremediation")


@transaction.atomic
def discard(run):
    run = ImportRun.objects.select_for_update().get(pk=run.pk)
    if run.status != ImportRun.DRAFT:
        raise ValueError("Only a draft import can be discarded.")
    if run.is_busy:
        raise ValueError("Wait for the current step to finish, then discard.")
    _clear_staging()
    run.status = ImportRun.DISCARDED
    run.save(update_fields=["status"])


# --- planning ---------------------------------------------------------------------------


def _prepare(cursor, run, skip_remediation=False):
    """Builds temp tables that classify every staged row and list what would be remediated."""
    params = {"run": run.pk}
    cursor.execute("""SELECT EXISTS (SELECT 1 FROM vulns_rejectedrow WHERE run_id = %(run)s AND account_id = '' AND asset_id = '')
                          OR EXISTS (SELECT 1 FROM vulns_importfile WHERE run_id = %(run)s AND status = 'failed')""", params)
    protect_all = cursor.fetchone()[0] or skip_remediation
    params["protect_all"] = protect_all
    for table in ("_plan", "_scan", "_rem"):
        cursor.execute(f"DROP TABLE IF EXISTS {table}")
    cursor.execute("""
        CREATE TEMP TABLE _plan ON COMMIT DROP AS
        SELECT s.id AS staged_id, v.id AS vuln_id,
          CASE
            WHEN v.id IS NULL THEN 'new'
            WHEN v.status = 'remediated' THEN
              CASE WHEN s.last_scan IS NOT NULL AND (COALESCE(v.remediated_at, v.last_scan) IS NULL
                        OR s.last_scan > COALESCE(v.remediated_at, v.last_scan)) THEN 'reopened' ELSE 'skipped' END
            WHEN GREATEST(v.last_scan, a.last_scan) IS NOT NULL
                 AND (s.last_scan IS NULL OR s.last_scan < GREATEST(v.last_scan, a.last_scan)) THEN 'skipped'
            ELSE 'updated'
          END AS kind,
          COALESCE(v.fingerprint = s.fingerprint, false) AS unchanged
        FROM vulns_stagedalert s
        LEFT JOIN vulns_vulnerability v ON v.alert_id = s.alert_id
        LEFT JOIN vulns_asset a ON a.id = v.asset_ref_id
        WHERE s.run_id = %(run)s""", params)
    cursor.execute("""
        CREATE TEMP TABLE _scan ON COMMIT DROP AS
        SELECT s.account_id, s.asset_id, max(s.last_scan) AS scan,
          %(protect_all)s OR EXISTS (
            SELECT 1 FROM vulns_rejectedrow r WHERE r.run_id = %(run)s AND r.account_id = s.account_id
              AND (r.asset_id = s.asset_id OR r.asset_id = '')
          ) OR EXISTS (
            SELECT 1 FROM vulns_rejectedrow r WHERE r.run_id = %(run)s AND r.account_id = '' AND r.asset_id = s.asset_id
          ) AS protected
        FROM vulns_stagedalert s
        WHERE s.run_id = %(run)s AND s.asset_id <> '' AND s.last_scan IS NOT NULL
        GROUP BY s.account_id, s.asset_id""", params)
    cursor.execute("""
        CREATE TEMP TABLE _rem ON COMMIT DROP AS
        SELECT v.id AS vuln_id, c.id AS account_pk, GREATEST(v.last_scan, a.last_scan) AS old_scan, sc.scan AS new_scan
        FROM _scan sc
        JOIN vulns_cloudaccount c ON c.account_id = sc.account_id
        JOIN vulns_asset a ON a.cloud_account_id = c.id AND a.asset_id = sc.asset_id
        JOIN vulns_vulnerability v ON v.asset_ref_id = a.id AND v.status = 'open'
        WHERE NOT sc.protected
          AND sc.scan > COALESCE(a.last_scan, '-infinity'::timestamptz)
          AND v.last_scan IS NOT NULL AND sc.scan > v.last_scan
          AND NOT EXISTS (SELECT 1 FROM vulns_stagedalert x WHERE x.run_id = %(run)s AND x.alert_id = v.alert_id)
          AND NOT EXISTS (SELECT 1 FROM vulns_rejectedrow r WHERE r.run_id = %(run)s AND r.alert_id = v.alert_id)""", params)
    return protect_all


def _plan_counts(cursor, protect_all):
    cursor.execute("SELECT kind, count(*), count(*) FILTER (WHERE unchanged) FROM _plan GROUP BY kind")
    kinds = {kind: (total, unchanged) for kind, total, unchanged in cursor.fetchall()}
    cursor.execute("SELECT count(*), count(*) FILTER (WHERE protected) FROM _scan")
    assets, protected = cursor.fetchone()
    cursor.execute("SELECT count(*) FROM _rem")
    remediated = cursor.fetchone()[0]
    cursor.execute("SELECT COALESCE(sum(total), 0) FROM vulns_alertsummary WHERE status = 'open'")
    open_total = int(cursor.fetchone()[0])
    cursor.execute("""SELECT c.account_name, count(*) FROM _rem r JOIN vulns_cloudaccount c ON c.id = r.account_pk
                      GROUP BY c.account_name ORDER BY count(*) DESC, c.account_name LIMIT 20""")
    by_account = [[name, n] for name, n in cursor.fetchall()]
    return {
        "new": kinds.get("new", (0, 0))[0],
        "updated": kinds.get("updated", (0, 0))[0],
        "unchanged": kinds.get("updated", (0, 0))[1],
        "reopened": kinds.get("reopened", (0, 0))[0],
        "skipped": kinds.get("skipped", (0, 0))[0],
        "remediated": remediated,
        "assets": assets,
        "protected": protected,
        "protect_all": protect_all,
        "open_total": open_total,
        "remediated_pct": round(100 * remediated / open_total, 1) if open_total else 0,
        "by_account": by_account,
    }


@transaction.atomic
def build_plan(run):
    """Computes and stores the preview that the draft page shows."""
    with connection.cursor() as cursor:
        protect_all = _prepare(cursor, run)
        plan = _plan_counts(cursor, protect_all)
        cursor.execute("TRUNCATE vulns_plannedremediation")
        cursor.execute(
            """INSERT INTO vulns_plannedremediation (run_id, vulnerability_id, old_scan, new_scan)
               SELECT %s, vuln_id, old_scan, new_scan FROM _rem ORDER BY account_pk, vuln_id""",
            [run.pk],
        )
    ImportRun.objects.filter(pk=run.pk).update(plan=plan, plan_ready=True, phase="")
    return plan


def finalize_blockers(run, plan, override_reason="", confirm_text="", skip_remediation=False):
    """Reasons this draft must not be applied yet. Only a remediation can be blocked."""
    if skip_remediation or not plan.get("remediated"):
        return []
    problems = []
    if not run.count_matches and not override_reason.strip():
        if run.expected_total is None:
            problems.append("Enter the Power BI total, or give a reason to continue without it.")
        else:
            problems.append(
                f"Herald has {run.unique_rows:,} unique alerts but Power BI shows {run.expected_total:,}. "
                "Upload the missing batches, or give a reason to continue."
            )
    if plan.get("open_total") and plan["remediated"] / plan["open_total"] > LARGE_REMEDIATION_SHARE:
        if confirm_text.strip() != CONFIRM_WORD:
            problems.append(
                f"This would remediate {plan['remediated_pct']}% of open alerts. Type {CONFIRM_WORD} to confirm."
            )
    return problems


# --- applying ---------------------------------------------------------------------------

APPLIED = "JOIN _plan p ON p.staged_id = s.id AND p.kind <> 'skipped'"


def _default_slo_sql(base):
    return (
        f"{base} + make_interval(days => CASE s.severity WHEN 'Critical' THEN %(slo_critical)s "
        "WHEN 'High' THEN %(slo_high)s WHEN 'Medium' THEN %(slo_medium)s WHEN 'Low' THEN %(slo_low)s END)"
    )


def _sync_app_catalog(cursor, now):
    """Adds new App IDs from this import. Values an admin entered are never overwritten."""
    cursor.execute(f"""
        WITH seen AS (
            SELECT DISTINCT s.app_id, s.context_id FROM vulns_stagedalert s {APPLIED} WHERE s.app_id <> ''
        ), named AS (
            SELECT seen.app_id,
              COALESCE(mode() WITHIN GROUP (ORDER BY NULLIF(c.app_service, '')), '') AS name,
              COALESCE(mode() WITHIN GROUP (ORDER BY NULLIF(c.business_service, '')), '') AS business_service,
              COALESCE(mode() WITHIN GROUP (ORDER BY NULLIF(c.department, '')), '') AS department,
              count(DISTINCT NULLIF(c.app_service, '')) > 1 AS conflict
            FROM seen LEFT JOIN vulns_alertcontext c ON c.id = seen.context_id
            GROUP BY seen.app_id
        )
        INSERT INTO vulns_application (app_id, name, support_team, support_emails, owner_name, owner_email, extra_emails,
                                       business_service, department, notes, source, scan_conflict, created_at, updated_at)
        SELECT app_id, left(name, 200), '', '', '', '', '', left(business_service, 200), left(department, 200), '',
               'scan', conflict, %(now)s, %(now)s
        FROM named
        ON CONFLICT (app_id) DO UPDATE SET
          name = COALESCE(NULLIF(vulns_application.name, ''), EXCLUDED.name),
          business_service = COALESCE(NULLIF(vulns_application.business_service, ''), EXCLUDED.business_service),
          department = COALESCE(NULLIF(vulns_application.department, ''), EXCLUDED.department),
          scan_conflict = EXCLUDED.scan_conflict,
          updated_at = %(now)s
        WHERE vulns_application.name = '' OR vulns_application.business_service = ''
           OR vulns_application.department = '' OR vulns_application.scan_conflict <> EXCLUDED.scan_conflict""",
        {"now": now})


@transaction.atomic
def finalize(run, user, override_reason="", confirm_text="", skip_remediation=False):
    run = ImportRun.objects.select_for_update().get(pk=run.pk)
    if run.status != ImportRun.DRAFT:
        raise ValueError("Only a draft import can be finalized.")
    cfg = AppSettings.load()
    now = timezone.now()
    params = {
        "run": run.pk, "now": now, "far": FAR_FUTURE, "slo_critical": cfg.slo_critical_days, "slo_high": cfg.slo_high_days,
        "slo_medium": cfg.slo_medium_days, "slo_low": cfg.slo_low_days,
    }
    with connection.cursor() as cursor:
        protect_all = _prepare(cursor, run, skip_remediation)
        plan = _plan_counts(cursor, protect_all)
        problems = finalize_blockers(run, plan, override_reason, confirm_text, skip_remediation)
        if problems:
            raise ValueError(" ".join(problems))
        cursor.execute(f"""
            INSERT INTO vulns_cloudaccount (account_id, account_name, provider, open_count, untagged_open,
              untagged_critical_high, untagged_past_slo, seen_app_ids, seen_app_count, suggested_app_id, created_at, updated_at)
            SELECT DISTINCT ON (s.account_id) s.account_id, s.account_name, s.provider, 0, 0, 0, 0, '[]'::jsonb, 0, '',
                   %(now)s, %(now)s
            FROM vulns_stagedalert s {APPLIED}
            ORDER BY s.account_id, s.last_scan DESC NULLS LAST
            ON CONFLICT (account_id) DO UPDATE SET
              account_name = EXCLUDED.account_name,
              provider = COALESCE(NULLIF(EXCLUDED.provider, ''), vulns_cloudaccount.provider),
              updated_at = %(now)s
            WHERE vulns_cloudaccount.account_name <> EXCLUDED.account_name
               OR (EXCLUDED.provider <> '' AND vulns_cloudaccount.provider <> EXCLUDED.provider)""", params)
        cursor.execute(f"""
            INSERT INTO vulns_asset (cloud_account_id, asset_id)
            SELECT DISTINCT c.id, s.asset_id FROM vulns_stagedalert s {APPLIED}
            JOIN vulns_cloudaccount c ON c.account_id = s.account_id
            WHERE s.asset_id <> '' ON CONFLICT DO NOTHING""")
        new_slo = f"COALESCE(s.slo_date, {_default_slo_sql('COALESCE(s.alert_opened, s.last_scan, %(now)s)')})"
        cursor.execute(f"""
            INSERT INTO vulns_vulnerability (alert_id, csb_id, cloud_account_id, asset_ref_id, cve_ref_id, package_ref_id,
              context_id, app_id, owner_app_id, environment, severity, severity_rank, exception, ritm, slo_date, slo_sort,
              last_scan, status, first_seen, fingerprint, created_at, updated_at)
            SELECT s.alert_id, s.csb_id, c.id, a.id, s.cve_ref_id, s.package_ref_id, s.context_id, s.app_id,
              COALESCE(NULLIF(s.app_id, ''), app.app_id), s.environment, s.severity, s.severity_rank, s.exception, s.ritm,
              {new_slo}, COALESCE({new_slo}, %(far)s), s.last_scan, 'open', COALESCE(s.alert_opened, s.last_scan, %(now)s),
              s.fingerprint, %(now)s, %(now)s
            FROM vulns_stagedalert s
            JOIN _plan p ON p.staged_id = s.id AND p.kind = 'new'
            JOIN vulns_cloudaccount c ON c.account_id = s.account_id
            LEFT JOIN vulns_application app ON app.id = c.application_id
            LEFT JOIN vulns_asset a ON a.cloud_account_id = c.id AND a.asset_id = s.asset_id""", params)
        changed_slo = (
            f"COALESCE(s.slo_date, v.slo_date, {_default_slo_sql('v.first_seen')})"
        )
        cursor.execute(f"""
            UPDATE vulns_vulnerability v SET
              csb_id = s.csb_id, cloud_account_id = c.id, asset_ref_id = a.id, cve_ref_id = s.cve_ref_id,
              package_ref_id = s.package_ref_id, context_id = s.context_id, app_id = s.app_id,
              owner_app_id = COALESCE(NULLIF(s.app_id, ''), app.app_id), environment = s.environment,
              severity = s.severity, severity_rank = s.severity_rank, exception = s.exception, ritm = s.ritm,
              slo_date = {changed_slo}, slo_sort = COALESCE({changed_slo}, %(far)s), last_scan = s.last_scan,
              status = 'open', archived_at = NULL,
              reopened_at = CASE WHEN p.kind = 'reopened' THEN COALESCE(s.last_scan, %(now)s) ELSE v.reopened_at END,
              remediated_at = NULL, remediated_import_id = NULL, fingerprint = s.fingerprint, updated_at = %(now)s
            FROM vulns_stagedalert s
            JOIN _plan p ON p.staged_id = s.id
            JOIN vulns_cloudaccount c ON c.account_id = s.account_id
            LEFT JOIN vulns_application app ON app.id = c.application_id
            LEFT JOIN vulns_asset a ON a.cloud_account_id = c.id AND a.asset_id = s.asset_id
            WHERE v.id = p.vuln_id AND (p.kind = 'reopened' OR (p.kind = 'updated' AND NOT p.unchanged))""", params)
        # Unchanged alerts rely on their asset for the newer scan, unless that asset can't advance.
        cursor.execute("""
            UPDATE vulns_vulnerability v SET last_scan = s.last_scan
            FROM vulns_stagedalert s
            JOIN _plan p ON p.staged_id = s.id AND p.kind = 'updated' AND p.unchanged
            LEFT JOIN _scan sc ON sc.account_id = s.account_id AND sc.asset_id = s.asset_id
            WHERE v.id = p.vuln_id AND s.last_scan > COALESCE(v.last_scan, '-infinity'::timestamptz)
              AND (s.asset_id = '' OR sc.protected IS NOT FALSE)""")
        cursor.execute("""
            UPDATE vulns_vulnerability v SET status = 'remediated', remediated_at = r.new_scan,
              remediated_import_id = %(run)s, last_scan = r.old_scan, updated_at = %(now)s
            FROM _rem r WHERE v.id = r.vuln_id""", params)
        cursor.execute("""
            UPDATE vulns_asset a SET last_scan = sc.scan
            FROM _scan sc JOIN vulns_cloudaccount c ON c.account_id = sc.account_id
            WHERE a.cloud_account_id = c.id AND a.asset_id = sc.asset_id AND NOT sc.protected
              AND sc.scan > COALESCE(a.last_scan, '-infinity'::timestamptz)""")
        _sync_app_catalog(cursor, now)
        for table in ("_plan", "_scan", "_rem"):
            cursor.execute(f"DROP TABLE IF EXISTS {table}")
        _clear_staging()
    run.status = ImportRun.FINALIZED
    run.finalized_at = now
    run.finalized_by = user
    run.files_count = run.files.count()
    run.assets_count = plan["assets"]
    run.new_count = plan["new"]
    run.updated_count = plan["updated"]
    run.reopened_count = plan["reopened"]
    run.remediated_count = plan["remediated"]
    run.skipped_count = plan["skipped"]
    run.override_reason = override_reason.strip()
    run.remediation_skipped = skip_remediation
    run.phase = ""
    run.plan = plan
    run.save()
    return run
