"""Server findings imports: stage MFS12 and Qualys files in a draft, preview the changes, then apply them.

Rules
- A finding is one server + QID. Within a draft, the newest Last Detected wins for a repeated server + QID.
- MFS12 is the complete current list. When applied, an open finding missing from it is marked remediated,
  including every finding of a server that is missing from the upload altogether.
- That is guarded: a failed MFS12 file, or a rejected row with no server, stops all remediation, and a
  rejected row stops it on its own server. Remediating also needs the Power BI total to match, or a reason.
- A remediated finding that is listed again is reopened.
- Qualys only adds Solution, Results, ports and CVEs to findings in the same draft, matched on server + QID.
"""
import os
from datetime import datetime

from django.conf import settings
from django.db import IntegrityError, connection, transaction
from django.db.models import Sum
from django.utils import timezone

from core.models import AppSettings
from vulns import jobs
from vulns.models import FAR_FUTURE
from vulns.parsing import FileFormatError

from .columns import MFS12
from .matching import AMBIGUOUS, HOW_LABELS, SCANNED, Resolver
from .models import (
    Server, ServerImport, ServerImportFile, ServerRejectedRow, StagedQualysRow, StagedServerFinding, short_key,
)
from .parsing import PARSERS, detect_kind

BATCH_SIZE = 5000
LARGE_REMEDIATION_SHARE = 0.20
CONFIRM_WORD = "REMEDIATE"
FINDING_COLUMNS = [
    "run_id", "file_id", "row_number", "asset_name", "asset_key", "qid", "title", "os", "severity", "severity_rank",
    "cisa_kev", "non_running_kernel", "cvss_score", "cvss_vector", "first_detected", "last_detected",
]
QUALYS_COLUMNS = ["run_id", "file_id", "row_number", "asset_key", "qid", "solution", "results", "port", "protocol", "cve"]


def _dt(value):
    return datetime.fromisoformat(value) if value else None


# --- staging ----------------------------------------------------------------------------


def get_or_create_draft(user):
    draft = ServerImport.objects.filter(status=ServerImport.DRAFT).first()
    if draft:
        return draft
    try:
        with transaction.atomic():
            return ServerImport.objects.create(created_by=user)
    except IntegrityError:
        return ServerImport.objects.get(status=ServerImport.DRAFT)


def add_file(run, uploaded, user, date_order=""):
    os.makedirs(settings.HERALD_UPLOAD_DIR, exist_ok=True)
    import_file = ServerImportFile.objects.create(
        run=run, filename=uploaded.name[:255], uploaded_by=user, size_bytes=uploaded.size, date_order=date_order,
    )
    path = os.path.join(
        settings.HERALD_UPLOAD_DIR, f"server-import-{import_file.pk}{os.path.splitext(uploaded.name)[1].lower()}"
    )
    with open(path, "wb") as target:
        for chunk in uploaded.chunks():
            target.write(chunk)
    ServerImportFile.objects.filter(pk=import_file.pk).update(stored_path=path)
    ServerImport.objects.filter(pk=run.pk).update(files_count=run.files.count(), plan_ready=False)
    jobs.enqueue(jobs.SERVER_PARSE, {"file": import_file.pk}, user)
    import_file.refresh_from_db()
    return import_file


def _copy(cursor, table, columns, rows):
    cursor.execute("DROP TABLE IF EXISTS _incoming")
    cursor.execute(f"CREATE TEMP TABLE _incoming ON COMMIT DROP AS SELECT {', '.join(columns)} FROM {table} WITH NO DATA")
    with cursor.copy(f"COPY _incoming ({', '.join(columns)}) FROM STDIN") as copy:
        for row in rows:
            copy.write_row(row)


@transaction.atomic
def _stage_findings(run, import_file, records, errors):
    """Returns how many rows repeated a server + QID already in this draft."""
    _stage_errors(run, import_file, errors)
    if not records:
        return 0
    columns = ", ".join(FINDING_COLUMNS)
    updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in FINDING_COLUMNS if c not in ("run_id", "asset_key", "qid"))
    with connection.cursor() as cursor:
        _copy(cursor, "servers_stagedserverfinding", FINDING_COLUMNS, (
            (run.pk, import_file.pk, r["_row"], r["asset_name"], r["asset_key"], r["qid"], r["title"], r["os"],
             r["severity"], r["severity_rank"], bool(r.get("cisa_kev")), bool(r.get("non_running_kernel")),
             r["cvss_score"], r["cvss_vector"], _dt(r.get("first_detected")), _dt(r.get("last_detected")))
            for r in records
        ))
        cursor.execute(f"""
            WITH newest AS (
                SELECT DISTINCT ON (asset_key, qid) * FROM _incoming
                ORDER BY asset_key, qid, last_detected DESC NULLS LAST, row_number DESC
            ), written AS (
                INSERT INTO servers_stagedserverfinding ({columns}) SELECT {columns} FROM newest
                ON CONFLICT (run_id, asset_key, qid) DO UPDATE SET {updates}
                WHERE EXCLUDED.last_detected >= servers_stagedserverfinding.last_detected
                   OR servers_stagedserverfinding.last_detected IS NULL
                RETURNING (xmax = 0) AS fresh
            )
            SELECT count(*) FILTER (WHERE fresh) FROM written""")
        fresh = cursor.fetchone()[0]
        cursor.execute("DROP TABLE _incoming")
    return len(records) - fresh


@transaction.atomic
def _stage_qualys(run, import_file, records, errors):
    _stage_errors(run, import_file, errors)
    if records:
        with connection.cursor() as cursor:
            with cursor.copy(f"COPY servers_stagedqualysrow ({', '.join(QUALYS_COLUMNS)}) FROM STDIN") as copy:
                for r in records:
                    copy.write_row((
                        run.pk, import_file.pk, r["_row"], r["asset_key"], r["qid"], r["solution"], r["results"],
                        r["port"], r["protocol"], r["cve"],
                    ))
    return 0


def _stage_errors(run, import_file, errors):
    if errors:
        ServerRejectedRow.objects.bulk_create(
            [ServerRejectedRow(run=run, file=import_file, **error) for error in errors], batch_size=1000
        )


def process_file(file_id):
    import_file = ServerImportFile.objects.select_related("run").get(pk=file_id)
    run = import_file.run
    if run.status != ServerImport.DRAFT:
        _remove_stored(import_file)
        return "The import is no longer a draft."
    ServerImportFile.objects.filter(pk=file_id).update(status=ServerImportFile.PROCESSING, error="")
    _clear_file_rows(file_id)
    accepted = rejected = duplicates = 0
    try:
        with open(import_file.stored_path, "rb") as handle:
            kind = detect_kind(handle, import_file.filename)
            parser = PARSERS[kind](handle, import_file.filename, import_file.date_order)
            ServerImportFile.objects.filter(pk=file_id).update(
                kind=kind, header_row=parser.header_row, unknown_columns=parser.unknown_columns,
                missing_columns=parser.missing_columns,
            )
            stage = _stage_findings if kind == MFS12 else _stage_qualys
            for records, errors in parser.batches(BATCH_SIZE):
                duplicates += stage(run, import_file, records, errors)
                accepted += len(records)
                rejected += len(errors)
                ServerImportFile.objects.filter(pk=file_id).update(
                    rows_read=parser.rows_read, accepted=accepted, rejected=rejected, duplicates=duplicates
                )
        ServerImportFile.objects.filter(pk=file_id).update(status=ServerImportFile.DONE)
        message = f"{import_file.filename}: {accepted} of {parser.rows_read} rows accepted."
    except FileFormatError as exc:
        _mark_failed(file_id, str(exc))
        message = str(exc)
    except Exception as exc:
        _mark_failed(file_id, f"Could not finish reading this file: {exc}")
        message = str(exc)
    _remove_stored(import_file)
    _refresh_run_counts(run)
    _plan_when_all_read(run)
    return message


def fail_file(file_id, message):
    """A parse job died. Its file must not stay in progress, or the draft could never be finalized or discarded."""
    import_file = ServerImportFile.objects.select_related("run").filter(pk=file_id).first()
    if import_file is None:
        return
    if import_file.status in (ServerImportFile.QUEUED, ServerImportFile.PROCESSING):
        _mark_failed(file_id, f"Could not finish reading this file: {message}")
    _remove_stored(import_file)
    _refresh_run_counts(import_file.run)
    if import_file.run.status == ServerImport.DRAFT:
        _plan_when_all_read(import_file.run)


def _clear_file_rows(file_id):
    ServerRejectedRow.objects.filter(file_id=file_id).delete()
    StagedServerFinding.objects.filter(file_id=file_id).delete()
    StagedQualysRow.objects.filter(file_id=file_id).delete()


def _mark_failed(file_id, error):
    """A failed MFS12 file keeps none of its rows and stops all remediation for the import."""
    StagedServerFinding.objects.filter(file_id=file_id).delete()
    StagedQualysRow.objects.filter(file_id=file_id).delete()
    ServerImportFile.objects.filter(pk=file_id).update(
        status=ServerImportFile.FAILED, error=error, accepted=0, duplicates=0
    )


def _plan_when_all_read(run):
    if not run.files.filter(status__in=[ServerImportFile.QUEUED, ServerImportFile.PROCESSING]).exists():
        ServerImport.objects.filter(pk=run.pk).update(phase="planning", plan_ready=False)
        jobs.enqueue(jobs.SERVER_PLAN, {"run": run.pk})


def _remove_stored(import_file):
    path = ServerImportFile.objects.values_list("stored_path", flat=True).get(pk=import_file.pk)
    if path and os.path.exists(path):
        os.remove(path)
    ServerImportFile.objects.filter(pk=import_file.pk).update(stored_path="")


def _refresh_run_counts(run):
    ServerImport.objects.filter(pk=run.pk).update(
        files_count=run.files.count(),
        unique_rows=StagedServerFinding.objects.filter(run=run).count(),
        duplicates_count=run.files.aggregate(n=Sum("duplicates"))["n"] or 0,
    )


def _clear_staging():
    # Only one draft can exist, so these tables hold nothing else.
    with connection.cursor() as cursor:
        cursor.execute(
            "TRUNCATE servers_stagedserverfinding, servers_stagedqualysrow, servers_serverplannedremediation"
        )


@transaction.atomic
def discard(run):
    run = ServerImport.objects.select_for_update().get(pk=run.pk)
    if run.status != ServerImport.DRAFT:
        raise ValueError("Only a draft import can be discarded.")
    if run.is_busy:
        raise ValueError("Wait for the current step to finish, then discard.")
    _clear_staging()
    run.status = ServerImport.DISCARDED
    run.save(update_fields=["status"])


# --- matching servers -------------------------------------------------------------------


def _asset_names(run):
    """Every server name in the draft, with how it was written in the first row that named it."""
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT DISTINCT ON (asset_key) asset_key, asset_name FROM (
              SELECT asset_key, asset_name, 0 AS source, row_number FROM servers_stagedserverfinding WHERE run_id = %(run)s
              UNION ALL SELECT asset_key, asset_name, 1, row FROM servers_serverrejectedrow
                WHERE run_id = %(run)s AND asset_key <> ''
              UNION ALL SELECT asset_key, asset_key, 2, row_number FROM servers_stagedqualysrow WHERE run_id = %(run)s
            ) names ORDER BY asset_key, source, row_number""", {"run": run.pk})
        return dict(cursor.fetchall())


def _staged_keys(run):
    return set(StagedServerFinding.objects.filter(run=run).values_list("asset_key", flat=True).distinct())


def _resolve(run, create=False):
    """[(asset key, server pk or None, how, note)]. With create=True, unmatched MFS12 servers are added."""
    resolver, names = Resolver(), _asset_names(run)
    resolved = [(key, *resolver.resolve(key)) for key in names]
    if create:
        findings = _staged_keys(run)
        new = [(key, how, note) for key, pk, how, note in resolved if pk is None and key in findings]
        Server.objects.bulk_create([
            Server(name=names[key], name_key=key, short_key=short_key(key), match_note=note)
            for key, how, note in new
        ], batch_size=1000, ignore_conflicts=True)
        created = dict(Server.objects.filter(name_key__in=[key for key, _, _ in new]).values_list("name_key", "pk"))
        resolved = [(key, pk or created.get(key), how, note) for key, pk, how, note in resolved]
        notes = [(pk, note) for key, pk, how, note in resolved if pk and how == SCANNED and note]
        for pk, note in notes:  # a scanned server that now matches several CMDB servers says so
            Server.objects.filter(pk=pk).exclude(match_note=note).update(match_note=note)
    return resolved


# --- planning ---------------------------------------------------------------------------


def _prepare(cursor, run, resolved, skip_remediation=False):
    """Temp tables: _assets (name -> server), _eff (one row per server + QID), _q (Qualys details), _rem."""
    params = {"run": run.pk, "mfs12": MFS12}
    for table in ("_assets", "_eff", "_q", "_protected", "_rem"):
        cursor.execute(f"DROP TABLE IF EXISTS {table}")
    cursor.execute("CREATE TEMP TABLE _assets (asset_key text PRIMARY KEY, server_id bigint, how text) ON COMMIT DROP")
    with cursor.copy("COPY _assets (asset_key, server_id, how) FROM STDIN") as copy:
        for key, pk, how, _ in resolved:
            copy.write_row((key, pk, how))
    cursor.execute("ANALYZE _assets")
    cursor.execute("""
        CREATE TEMP TABLE _eff ON COMMIT DROP AS
        SELECT x.*, f.id AS finding_id,
          CASE WHEN f.id IS NULL THEN 'new' WHEN f.status = 'remediated' THEN 'reopened' ELSE 'updated' END AS kind
        FROM (
          SELECT DISTINCT ON (t.target, t.qid) t.* FROM (
            SELECT s.*, a.server_id, a.how, COALESCE(a.server_id::text, 'new:' || s.asset_key) AS target
            FROM servers_stagedserverfinding s JOIN _assets a ON a.asset_key = s.asset_key
            WHERE s.run_id = %(run)s
          ) t ORDER BY t.target, t.qid, t.last_detected DESC NULLS LAST, t.row_number DESC
        ) x
        LEFT JOIN servers_serverfinding f ON f.server_id = x.server_id AND f.qid = x.qid""", params)
    cursor.execute("CREATE INDEX ON _eff (server_id, qid)")
    cursor.execute("""
        CREATE TEMP TABLE _q ON COMMIT DROP AS
        SELECT COALESCE(a.server_id::text, 'new:' || q.asset_key) AS target, q.qid,
          COALESCE((array_agg(q.solution ORDER BY q.row_number) FILTER (WHERE q.solution <> ''))[1], '') AS solution,
          COALESCE((array_agg(q.results ORDER BY q.row_number) FILTER (WHERE q.results <> ''))[1], '') AS results,
          left(COALESCE(string_agg(DISTINCT NULLIF(concat_ws('/', NULLIF(q.port, ''), NULLIF(q.protocol, '')), ''), ', '), ''), 500)
            AS ports,
          COALESCE(string_agg(DISTINCT NULLIF(q.cve, ''), ', '), '') AS cves
        FROM servers_stagedqualysrow q JOIN _assets a ON a.asset_key = q.asset_key
        WHERE q.run_id = %(run)s GROUP BY 1, 2""", params)
    cursor.execute("CREATE INDEX ON _q (target, qid)")
    cursor.execute("""
        SELECT NOT EXISTS (SELECT 1 FROM servers_serverimportfile WHERE run_id = %(run)s AND kind = %(mfs12)s AND status = 'done')
          OR EXISTS (SELECT 1 FROM servers_serverimportfile WHERE run_id = %(run)s AND status = 'failed' AND kind <> 'qualys')
          OR EXISTS (SELECT 1 FROM servers_serverrejectedrow r JOIN servers_serverimportfile f ON f.id = r.file_id
                     WHERE r.run_id = %(run)s AND r.asset_key = '' AND f.kind = %(mfs12)s)""", params)
    protect_all = cursor.fetchone()[0] or skip_remediation
    params["protect_all"] = protect_all
    cursor.execute("""
        CREATE TEMP TABLE _protected ON COMMIT DROP AS
        SELECT DISTINCT a.server_id FROM servers_serverrejectedrow r
        JOIN servers_serverimportfile f ON f.id = r.file_id AND f.kind = %(mfs12)s
        JOIN _assets a ON a.asset_key = r.asset_key
        WHERE r.run_id = %(run)s AND a.server_id IS NOT NULL""", params)
    cursor.execute("""
        CREATE TEMP TABLE _rem ON COMMIT DROP AS
        SELECT f.id AS finding_id, f.server_id FROM servers_serverfinding f
        WHERE NOT %(protect_all)s AND f.status = 'open'
          AND NOT EXISTS (SELECT 1 FROM _eff e WHERE e.server_id = f.server_id AND e.qid = f.qid)
          AND NOT EXISTS (SELECT 1 FROM _protected p WHERE p.server_id = f.server_id)""", params)
    return protect_all


def _plan_counts(cursor, run, resolved, protect_all):
    cursor.execute("SELECT kind, count(*) FROM _eff GROUP BY kind")
    kinds = dict(cursor.fetchall())
    cursor.execute("SELECT count(DISTINCT target), max(last_detected) FROM _eff")
    servers, newest = cursor.fetchone()
    cursor.execute("SELECT count(*), count(DISTINCT server_id) FROM _rem")
    remediated, remediated_servers = cursor.fetchone()
    cursor.execute("""SELECT count(DISTINCT r.server_id) FROM _rem r
                      WHERE NOT EXISTS (SELECT 1 FROM _eff e WHERE e.server_id = r.server_id)""")
    missing_servers = cursor.fetchone()[0]
    cursor.execute("SELECT count(*) FROM _protected")
    protected = cursor.fetchone()[0]
    cursor.execute("SELECT count(*), max(last_detected) FROM servers_serverfinding WHERE status = 'open'")
    open_total, _ = cursor.fetchone()
    cursor.execute("SELECT max(last_detected) FROM servers_serverfinding")
    live_newest = cursor.fetchone()[0]
    cursor.execute("""SELECT COALESCE(NULLIF(s.app_id, ''), '(no App ID)'), count(*) FROM _rem r
                      JOIN servers_server s ON s.id = r.server_id GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 20""")
    by_app = [[app_id, n] for app_id, n in cursor.fetchall()]
    cursor.execute("SELECT count(*) FROM servers_stagedqualysrow WHERE run_id = %s", [run.pk])
    qualys_rows = cursor.fetchone()[0]
    cursor.execute("SELECT count(*) FROM _eff e JOIN _q q ON q.target = e.target AND q.qid = e.qid")
    qualys_matched = cursor.fetchone()[0]
    cursor.execute("""SELECT count(*) FROM _q q
                      WHERE NOT EXISTS (SELECT 1 FROM _eff e WHERE e.target = q.target AND e.qid = q.qid)""")
    qualys_unmatched = cursor.fetchone()[0]
    findings = _staged_keys(run)
    how = {}
    for key, _, way, _ in resolved:
        if key in findings:
            how[way] = how.get(way, 0) + 1
    ambiguous = sorted(
        [key, note] for key, _, way, note in resolved if key in findings and (way == AMBIGUOUS or (way == SCANNED and note))
    )[:20]
    older = bool(newest and live_newest and newest < live_newest)
    return {
        "new": kinds.get("new", 0),
        "updated": kinds.get("updated", 0),
        "reopened": kinds.get("reopened", 0),
        "remediated": remediated,
        "remediated_servers": remediated_servers,
        "missing_servers": missing_servers,
        "servers": servers or 0,
        "protected": protected,
        "protect_all": protect_all,
        "has_findings": run.has_findings_file,
        "open_total": open_total,
        "remediated_pct": round(100 * remediated / open_total, 1) if open_total else 0,
        "by_app": by_app,
        "how": [[HOW_LABELS[way], how[way]] for way in HOW_LABELS if how.get(way)],
        "unmatched": how.get("unmatched", 0) + how.get("ambiguous", 0),
        "ambiguous": ambiguous,
        "qualys_rows": qualys_rows,
        "qualys_matched": qualys_matched,
        "qualys_unmatched": qualys_unmatched,
        "newest": newest.isoformat() if newest else None,
        "live_newest": live_newest.isoformat() if live_newest else None,
        "older": older,
    }


@transaction.atomic
def build_plan(run):
    resolved = _resolve(run)
    with connection.cursor() as cursor:
        protect_all = _prepare(cursor, run, resolved)
        plan = _plan_counts(cursor, run, resolved, protect_all)
        cursor.execute("TRUNCATE servers_serverplannedremediation")
        cursor.execute("""INSERT INTO servers_serverplannedremediation (run_id, finding_id)
                          SELECT %s, finding_id FROM _rem ORDER BY server_id, finding_id""", [run.pk])
    ServerImport.objects.filter(pk=run.pk).update(plan=plan, plan_ready=True, phase="")
    return plan


def finalize_blockers(run, plan, override_reason="", confirm_text="", skip_remediation=False):
    """Reasons this draft must not be applied yet."""
    if not plan.get("has_findings"):
        return ["Upload at least one MFS12 file. A Qualys file only adds details to MFS12 findings."]
    if skip_remediation or not plan.get("remediated"):
        return []
    problems = []
    reason_given = bool(override_reason.strip())
    if not run.count_matches and not reason_given:
        if run.expected_total is None:
            problems.append("Enter the Power BI total, or give a reason to continue without it.")
        else:
            problems.append(
                f"Herald has {run.unique_rows:,} unique findings but Power BI shows {run.expected_total:,}. "
                "Upload the missing batches, or give a reason to continue."
            )
    if plan.get("older") and not reason_given:
        problems.append(
            f"The newest Last Detected in this upload ({plan['newest'][:10]}) is older than in Herald "
            f"({plan['live_newest'][:10]}). Check that this is the latest MFS12 export, or give a reason to continue."
        )
    if plan.get("open_total") and plan["remediated"] / plan["open_total"] > LARGE_REMEDIATION_SHARE:
        if confirm_text.strip() != CONFIRM_WORD:
            problems.append(
                f"This would remediate {plan['remediated_pct']}% of open findings. Type {CONFIRM_WORD} to confirm."
            )
    return problems


# --- applying ---------------------------------------------------------------------------


def _slo_sql(base):
    return (
        f"{base} + make_interval(days => CASE e.severity WHEN 'Critical' THEN %(slo_critical)s "
        "WHEN 'High' THEN %(slo_high)s WHEN 'Medium' THEN %(slo_medium)s WHEN 'Low' THEN %(slo_low)s END)"
    )


@transaction.atomic
def finalize(run, user, override_reason="", confirm_text="", skip_remediation=False):
    run = ServerImport.objects.select_for_update().get(pk=run.pk)
    if run.status != ServerImport.DRAFT:
        raise ValueError("Only a draft import can be finalized.")
    cfg = AppSettings.load()
    now = timezone.now()
    params = {
        "run": run.pk, "now": now, "far": FAR_FUTURE, "slo_critical": cfg.slo_critical_days,
        "slo_high": cfg.slo_high_days, "slo_medium": cfg.slo_medium_days, "slo_low": cfg.slo_low_days,
    }
    resolved = _resolve(run, create=True)
    with connection.cursor() as cursor:
        protect_all = _prepare(cursor, run, resolved, skip_remediation)
        plan = _plan_counts(cursor, run, resolved, protect_all)
        problems = finalize_blockers(run, plan, override_reason, confirm_text, skip_remediation)
        if problems:
            raise ValueError(" ".join(problems))
        cursor.execute("""
            UPDATE servers_server s SET scan_os = x.os, last_detected = GREATEST(s.last_detected, x.last_detected)
            FROM (SELECT server_id, max(os) AS os, max(last_detected) AS last_detected FROM _eff GROUP BY server_id) x
            WHERE s.id = x.server_id""")
        slo = _slo_sql("COALESCE(e.first_detected, e.last_detected, %(now)s)")
        cursor.execute(f"""
            INSERT INTO servers_serverfinding (server_id, qid, title, os, severity, severity_rank, cisa_kev,
              non_running_kernel, cvss_score, cvss_vector, first_detected, last_detected, slo_date, slo_sort, status,
              first_seen, solution, results, ports, cves, created_at, updated_at)
            SELECT e.server_id, e.qid, e.title, e.os, e.severity, e.severity_rank, e.cisa_kev, e.non_running_kernel,
              e.cvss_score, e.cvss_vector, e.first_detected, e.last_detected, {slo}, COALESCE({slo}, %(far)s), 'open',
              COALESCE(e.first_detected, e.last_detected, %(now)s), COALESCE(q.solution, ''), COALESCE(q.results, ''),
              COALESCE(q.ports, ''), COALESCE(q.cves, ''), %(now)s, %(now)s
            FROM _eff e LEFT JOIN _q q ON q.target = e.target AND q.qid = e.qid
            WHERE e.kind = 'new'""", params)
        changed_slo = _slo_sql("COALESCE(e.first_detected, f.first_detected, f.first_seen)")
        cursor.execute(f"""
            UPDATE servers_serverfinding f SET
              title = e.title, os = e.os, severity = e.severity, severity_rank = e.severity_rank, cisa_kev = e.cisa_kev,
              non_running_kernel = e.non_running_kernel, cvss_score = e.cvss_score, cvss_vector = e.cvss_vector,
              first_detected = COALESCE(e.first_detected, f.first_detected),
              last_detected = GREATEST(f.last_detected, e.last_detected),
              slo_date = {changed_slo}, slo_sort = COALESCE({changed_slo}, %(far)s), status = 'open',
              reopened_at = CASE WHEN e.kind = 'reopened' THEN %(now)s ELSE f.reopened_at END,
              remediated_at = NULL, remediated_import_id = NULL,
              solution = COALESCE(NULLIF(q.solution, ''), f.solution), results = COALESCE(NULLIF(q.results, ''), f.results),
              ports = COALESCE(NULLIF(q.ports, ''), f.ports), cves = COALESCE(NULLIF(q.cves, ''), f.cves),
              updated_at = %(now)s
            FROM _eff e LEFT JOIN _q q ON q.target = e.target AND q.qid = e.qid
            WHERE f.id = e.finding_id""", params)
        cursor.execute("""
            UPDATE servers_serverfinding f SET status = 'remediated', remediated_at = %(now)s,
              remediated_import_id = %(run)s, updated_at = %(now)s
            FROM _rem r WHERE f.id = r.finding_id""", params)
        for table in ("_assets", "_eff", "_q", "_protected", "_rem"):
            cursor.execute(f"DROP TABLE IF EXISTS {table}")
        _clear_staging()
    run.status = ServerImport.FINALIZED
    run.finalized_at = now
    run.finalized_by = user
    run.files_count = run.files.count()
    run.servers_count = plan["servers"]
    run.new_count = plan["new"]
    run.updated_count = plan["updated"]
    run.reopened_count = plan["reopened"]
    run.remediated_count = plan["remediated"]
    run.override_reason = override_reason.strip()
    run.remediation_skipped = skip_remediation
    run.phase = ""
    run.plan = plan
    run.save()
    return run
