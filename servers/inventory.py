"""CMDB inventory: read the ServiceNow server report, preview every change, then apply it.

- A server is identified by its CMDB name, ignoring capitals.
- Servers missing from the file are left as they are, so a partial file is safe.
- The same name twice is counted once if both rows are identical. If they differ, both rows are rejected.
- CMDB's App ID (u_id) always wins. A server with no u_id keeps any App ID given to it by hand.
- When applied, a server first found in a scan is merged into the CMDB server its name now matches.
"""
import hashlib
import json
import os
from collections import defaultdict

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from vulns import jobs
from vulns.models import Application

from . import summaries
from .columns import CMDB_FIELDS
from .matching import Resolver
from .models import InventoryImport, InventoryRow, Server, name_key, short_key
from .parsing import check_cmdb_row, read_cmdb

MAX_FILE_BYTES = 100 * 1024 * 1024
WRITE_BATCH = 1000
TRACKED = ["u_id", *CMDB_FIELDS]


class InventoryStale(Exception):
    pass


def _hash(cells):
    return hashlib.md5(json.dumps(cells, sort_keys=True).encode()).hexdigest()


def start(uploaded, user):
    """Stores the file and lets the worker read it."""
    os.makedirs(settings.HERALD_UPLOAD_DIR, exist_ok=True)
    inventory = InventoryImport.objects.create(filename=uploaded.name[:255], size_bytes=uploaded.size, created_by=user)
    path = os.path.join(settings.HERALD_UPLOAD_DIR, f"cmdb-{inventory.pk}{os.path.splitext(uploaded.name)[1].lower()}")
    with open(path, "wb") as target:
        for chunk in uploaded.chunks():
            target.write(chunk)
    InventoryImport.objects.filter(pk=inventory.pk).update(stored_path=path)
    jobs.enqueue(jobs.INVENTORY_READ, {"inventory": inventory.pk}, user)
    inventory.refresh_from_db()
    return inventory


def _remove_file(inventory):
    path = InventoryImport.objects.values_list("stored_path", flat=True).get(pk=inventory.pk)
    if path and os.path.exists(path):
        os.remove(path)
    InventoryImport.objects.filter(pk=inventory.pk).update(stored_path="")


def fail(inventory_id, message):
    inventory = InventoryImport.objects.filter(pk=inventory_id).first()
    if inventory is None:
        return
    if inventory.status == InventoryImport.READING:
        InventoryImport.objects.filter(pk=inventory.pk).update(status=InventoryImport.FAILED, error=message[:2000])
        _remove_file(inventory)
    elif inventory.status == InventoryImport.APPLYING:  # nothing was saved, so the preview can be applied again
        InventoryImport.objects.filter(pk=inventory.pk).update(status=InventoryImport.PREVIEW, error=message[:2000])


# --- preview ----------------------------------------------------------------------------


def _first_pass(path, filename):
    """Groups rows by server name, keeping only row numbers and hashes so a large file stays small in memory."""
    groups, reasons = defaultdict(list), {}
    with open(path, "rb") as handle:
        for number, cells, _ in read_cmdb(handle, filename):
            problems = check_cmdb_row(cells)
            if problems:
                reasons[number] = problems
                continue
            # Rows that differ only in the name's capitals are the same server, so they count once.
            groups[name_key(cells["name"])].append((number, _hash({**cells, "name": name_key(cells["name"])})))
    keep, duplicates = {}, 0
    for key, rows in groups.items():
        if len({digest for _, digest in rows}) == 1:
            keep[rows[0][0]] = key
            duplicates += len(rows) - 1
            continue
        numbers = ", ".join(str(n) for n, _ in rows)
        for number, _ in rows:
            reasons[number] = [f"The name '{key}' is on rows {numbers} with different values. Correct it in CMDB."]
    return keep, reasons, duplicates, set(groups)


def _changes(old, cells):
    return {key: [old.get(key, ""), cells.get(key, "")] for key in TRACKED if old.get(key, "") != cells.get(key, "")}


def read(inventory_id):
    inventory = InventoryImport.objects.get(pk=inventory_id)
    if inventory.status != InventoryImport.READING:
        return "Already read."
    InventoryRow.objects.filter(inventory=inventory).delete()
    path = inventory.stored_path
    keep, reasons, duplicates, names = _first_pass(path, inventory.filename)
    fields = ["cmdb_app_id", *CMDB_FIELDS.values()]
    current = {}
    for key, in_cmdb, digest, app_id, *values in Server.objects.values_list(
        "name_key", "in_cmdb", "cmdb_hash", "app_id", *fields
    ).iterator(chunk_size=2000):
        current[key] = (in_cmdb, digest, dict(zip(TRACKED, values)), app_id)
    registered = set(Application.objects.values_list("app_id", flat=True))
    counts, new_app_ids, batch, unknown = defaultdict(int), set(), [], []
    with open(path, "rb") as handle:
        for number, cells, unknown in read_cmdb(handle, inventory.filename):
            if number in reasons:
                check_cmdb_row(cells)
                row = InventoryRow(action=InventoryRow.REJECTED, cells=cells, reason=" ".join(reasons[number]))
            elif number in keep:
                check_cmdb_row(cells)
                key = keep[number]
                in_cmdb, digest, old, app_id = current.get(key, (False, "", {}, ""))
                if not in_cmdb:
                    row = InventoryRow(action=InventoryRow.NEW, cells=cells, changes=_changes({}, cells))
                    if key in current:
                        row.reason = "Already found in a scan. It will be linked to this CMDB record."
                elif digest == _hash(cells):
                    row = InventoryRow(action=InventoryRow.UNCHANGED)
                else:
                    row = InventoryRow(action=InventoryRow.UPDATED, cells=cells, changes=_changes(old, cells))
                    if not row.changes:
                        row.reason = "Only columns that Herald shows on the server's page changed."
                if cells["u_id"] and cells["u_id"] != app_id:
                    counts["app_changed"] += 1
                if cells["u_id"] and cells["u_id"] not in registered:
                    new_app_ids.add(cells["u_id"])
            else:
                continue  # an identical repeat of a row already kept
            row.inventory, row.row_number = inventory, number
            row.name = (cells.get("name") or "")[:255]
            row.name_key = name_key(row.name)
            counts[row.action] += 1
            batch.append(row)
            if len(batch) >= WRITE_BATCH:
                InventoryRow.objects.bulk_create(batch)
                batch = []
    InventoryRow.objects.bulk_create(batch)
    not_in_file = sum(1 for key, (in_cmdb, *_) in current.items() if in_cmdb and key not in names)
    InventoryImport.objects.filter(pk=inventory.pk).update(
        status=InventoryImport.PREVIEW, rows_read=len(keep) + len(reasons) + duplicates,
        new_count=counts[InventoryRow.NEW], updated_count=counts[InventoryRow.UPDATED],
        unchanged_count=counts[InventoryRow.UNCHANGED], rejected_count=counts[InventoryRow.REJECTED],
        duplicate_count=duplicates, app_changed_count=counts["app_changed"], new_app_ids_count=len(new_app_ids),
        not_in_file_count=not_in_file, unknown_columns=unknown,
    )
    _remove_file(inventory)
    return f"{inventory.filename}: {counts[InventoryRow.NEW]} new, {counts[InventoryRow.UPDATED]} updated."


# --- apply ------------------------------------------------------------------------------


def queue_apply(inventory, user):
    with transaction.atomic():
        locked = InventoryImport.objects.select_for_update().get(pk=inventory.pk)
        _check_current(locked)
        locked.status = InventoryImport.APPLYING
        locked.error = ""
        locked.save(update_fields=["status", "error"])
    return jobs.enqueue(jobs.INVENTORY_APPLY, {"inventory": inventory.pk}, user)


def _check_current(inventory):
    if inventory.status not in (InventoryImport.PREVIEW, InventoryImport.APPLYING):
        raise InventoryStale("Only a preview can be applied.")
    newer = InventoryImport.objects.filter(status=InventoryImport.APPLIED, applied_at__gt=inventory.created_at)
    if newer.exists():
        raise InventoryStale("Another CMDB file was applied after this preview was made. Upload this file again.")
    if InventoryImport.objects.filter(status=InventoryImport.APPLYING).exclude(pk=inventory.pk).exists():
        raise InventoryStale("Another CMDB file is being applied. Try again when it finishes.")


def _server_values(cells, now):
    name = cells["name"]
    key = name_key(name)
    values = {
        "name": name, "short_key": short_key(key), "fqdn_key": name_key(cells.get("fqdn")), "in_cmdb": True,
        "cmdb_app_id": cells.get("u_id", ""), "match_note": "", "cmdb": cells, "cmdb_hash": _hash(cells),
        "cmdb_changed_at": now,
    }
    for column, field in CMDB_FIELDS.items():
        values[field] = (cells.get(column) or "")[:255]
    return key, values


def _register_app_ids(app_ids, now):
    existing = set(Application.objects.filter(app_id__in=app_ids).values_list("app_id", flat=True))
    Application.objects.bulk_create(
        [Application(app_id=app_id, source="cmdb") for app_id in sorted(set(app_ids) - existing)],
        batch_size=1000, ignore_conflicts=True,
    )


def _merge_scanned_servers():
    """Moves findings from servers first seen in a scan to the CMDB server their name now matches."""
    resolver, merged = Resolver(), 0
    for scanned in Server.objects.filter(in_cmdb=False).only("pk", "name_key", "manual_app_id", "assigned_by"):
        target_pk = resolver.cmdb_match(scanned.name_key)
        if target_pk is None:
            continue
        with connection.cursor() as cursor:
            # A QID already on the CMDB server keeps that finding; the duplicate is removed.
            cursor.execute(
                """DELETE FROM servers_serverfinding f USING servers_serverfinding t
                   WHERE f.server_id = %s AND t.server_id = %s AND t.qid = f.qid""",
                [scanned.pk, target_pk],
            )
            cursor.execute("UPDATE servers_serverfinding SET server_id = %s WHERE server_id = %s", [target_pk, scanned.pk])
        target = Server.objects.get(pk=target_pk)
        if not target.cmdb_app_id and not target.manual_app_id and scanned.manual_app_id:
            target.manual_app_id = scanned.manual_app_id
            target.assigned_by_id, target.assigned_at = scanned.assigned_by_id, timezone.now()
            target.save(update_fields=["manual_app_id", "assigned_by", "assigned_at"])
        scanned.assignments.update(server=target)
        scanned.delete()
        merged += 1
    return merged


def apply(inventory_id, user):
    with transaction.atomic():
        inventory = InventoryImport.objects.select_for_update().get(pk=inventory_id)
        _check_current(inventory)
        now = timezone.now()
        rows = inventory.rows.filter(action__in=[InventoryRow.NEW, InventoryRow.UPDATED]).values_list("cells", flat=True)
        app_ids, pending = set(), {}
        for cells in rows.iterator(chunk_size=WRITE_BATCH):
            key, values = _server_values(cells, now)
            pending[key] = values
            if values["cmdb_app_id"]:
                app_ids.add(values["cmdb_app_id"])
            if len(pending) >= WRITE_BATCH:
                _save_servers(pending)
                pending = {}
        _save_servers(pending)
        _register_app_ids(app_ids, now)
        with connection.cursor() as cursor:  # CMDB's App ID wins; without one, a manual App ID stays
            cursor.execute("""UPDATE servers_server SET app_id = COALESCE(NULLIF(cmdb_app_id, ''), manual_app_id)
                              WHERE app_id IS DISTINCT FROM COALESCE(NULLIF(cmdb_app_id, ''), manual_app_id)""")
        merged = _merge_scanned_servers()
        inventory.status, inventory.applied_by, inventory.applied_at = InventoryImport.APPLIED, user, now
        inventory.merged_count = merged
        inventory.save(update_fields=["status", "applied_by", "applied_at", "merged_count"])
    summaries.refresh()
    return f"CMDB applied: {inventory.new_count} new, {inventory.updated_count} updated, {merged} scanned servers linked."


def _save_servers(pending):
    if not pending:
        return
    existing = {s.name_key: s for s in Server.objects.filter(name_key__in=list(pending))}
    created, updated = [], []
    for key, values in pending.items():
        server = existing.get(key)
        if server is None:
            created.append(Server(name_key=key, **values))
            continue
        for field, value in values.items():
            setattr(server, field, value)
        updated.append(server)
    Server.objects.bulk_create(created, batch_size=500)
    if updated:
        fields = sorted(next(iter(pending.values())).keys())
        Server.objects.bulk_update(updated, fields, batch_size=500)


def rejected_rows(inventory):
    from .columns import CMDB_COLUMNS

    rows = inventory.rows.filter(action=InventoryRow.REJECTED).values_list("row_number", "cells", "reason")
    for number, cells, reason in rows.iterator(chunk_size=1000):
        yield [number, *[cells.get(key, "") for key in CMDB_COLUMNS], reason]
