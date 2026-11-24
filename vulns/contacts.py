"""Bulk import of application contacts: read the template, preview every change, then apply it."""
import csv
import io
from collections import defaultdict
from itertools import chain, islice

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone
from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Font

from .columns import CONTACT_COLUMNS, CONTACT_FIELDS, CONTACT_HEADER_MAP, CONTACT_LABELS, normalize_header
from .models import AlertSummary, Application, ContactImport, ContactImportRow, split_emails, unique_emails
from .parsing import BLANKS, HEADER_SCAN_ROWS, FileFormatError, read_rows, to_text

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_ROWS = 20000
CLEAR_WORD = "CLEAR"
SCOPES = ("blank", "missing", "all")
EMAIL_FIELDS = ("support_emails", "owner_email", "extra_emails")
TEXT_LIMITS = {
    "name": 200, "support_team": 200, "owner_name": 200, "business_service": 200, "department": 200, "notes": 5000,
}
FORMULA_START = ("=", "+", "-", "@")
NO_TEAM_EMAIL = Q(support_emails__regex=r"^[,;\s]*$")
STALE_MESSAGE = "Some of these contacts changed after this preview was made. Upload the file again to see the latest changes."


class ContactImportStale(Exception):
    pass


# --- reading ----------------------------------------------------------------------------


def find_contact_header(rows):
    for position, (_, values) in enumerate(rows[:HEADER_SCAN_ROWS]):
        if "app_id" in {CONTACT_HEADER_MAP.get(normalize_header(v)) for v in values if v is not None}:
            return position, values
    return None, None


def _cell_text(raw):
    text = to_text(raw)
    if text[:1] == "'" and text[1:2] in FORMULA_START:  # the protective quote added to Herald's own downloads
        text = text[1:]
    return "" if text.lower() in BLANKS else text


def _clean_emails(text, label, single=False):
    emails, errors = unique_emails(split_emails(text)), []
    for email in emails:
        try:
            validate_email(email)
        except ValidationError:
            errors.append(f"{label}: '{email}' is not a valid email.")
    if single and len(emails) > 1:
        errors.append(f"{label}: enter one address only.")
    return ", ".join(emails), errors


def _clean_row(cells):
    """A missing key means keep the current value. An empty string means CLEAR."""
    app_id, values, reasons = cells["app_id"].upper(), {}, []
    if not app_id:
        reasons.append("APP ID is required.")
    elif len(app_id) > 100:
        reasons.append("APP ID is longer than 100 characters.")
    elif "/" in app_id:
        reasons.append("APP ID can't contain '/'.")
    for key in CONTACT_FIELDS[1:]:
        text = cells[key]
        if not text:
            continue
        if text.upper() == CLEAR_WORD:
            values[key] = ""
        elif key in EMAIL_FIELDS:
            values[key], errors = _clean_emails(text, CONTACT_LABELS[key], single=key == "owner_email")
            reasons += errors
        elif len(text) > TEXT_LIMITS[key]:
            reasons.append(f"{CONTACT_LABELS[key]} is longer than {TEXT_LIMITS[key]} characters.")
        else:
            values[key] = text
    return app_id, values, reasons


def read_contacts(fileobj, filename):
    rows = read_rows(fileobj, filename, finder=find_contact_header)
    try:
        head = list(islice(rows, HEADER_SCAN_ROWS))
        position, header = find_contact_header(head)
        if position is None:
            raise FileFormatError("No header row found. Use the Herald contacts template.")
        keys = [CONTACT_HEADER_MAP.get(normalize_header(v)) for v in header]
        found = [key for key in keys if key]
        missing = [label for label, key in CONTACT_COLUMNS if key not in found]
        if missing:
            raise FileFormatError(f"Missing column(s): {', '.join(missing)}. Use the Herald contacts template.")
        if len(found) != len(set(found)):
            raise FileFormatError("The file has the same column more than once.")
        records = []
        for number, values in chain(head[position + 1:], rows):
            cells = dict.fromkeys(CONTACT_FIELDS, "")
            for key, raw in zip(keys, values):
                if key:
                    cells[key] = _cell_text(raw)
            if not any(cells.values()):
                continue
            if len(records) >= MAX_ROWS:
                raise FileFormatError(f"The file has more than {MAX_ROWS:,} rows.")
            app_id, cleaned, reasons = _clean_row(cells)
            records.append({"row": number, "cells": cells, "app_id": app_id, "values": cleaned, "reasons": reasons})
    except csv.Error as exc:
        raise FileFormatError(f"Could not read the CSV file: {exc}") from None
    return records


def _resolve_duplicates(records):
    """Exact repeats count once. An App ID with different values is rejected, because neither row can be trusted."""
    groups, keep, duplicates = defaultdict(list), [], 0
    for record in records:
        if record["app_id"]:
            groups[record["app_id"]].append(record)
        else:
            keep.append(record)
    for group in groups.values():
        first = group[0]
        if all(r["values"] == first["values"] and r["reasons"] == first["reasons"] for r in group):
            keep.append(first)
            duplicates += len(group) - 1
            continue
        numbers = ", ".join(str(r["row"]) for r in group)
        for record in group:
            record["reasons"] = [f"APP ID appears on rows {numbers} with different values.", *record["reasons"]]
        keep.extend(group)
    keep.sort(key=lambda r: r["row"])
    return keep, duplicates


def _same(key, old, new):
    if key in EMAIL_FIELDS:
        return sorted(e.lower() for e in split_emails(old)) == sorted(e.lower() for e in split_emails(new))
    return old == new


def _scanned_app_ids():
    return set(AlertSummary.objects.exclude(owner_app_id="").values_list("owner_app_id", flat=True).distinct())


# --- preview ----------------------------------------------------------------------------


def create_preview(fileobj, filename, user):
    records, duplicates = _resolve_duplicates(read_contacts(fileobj, filename))
    current = {app["app_id"]: app for app in Application.objects.values(*CONTACT_FIELDS)}
    variants = {app_id.upper(): app_id for app_id in current}
    scanned = _scanned_app_ids()
    counts, rows = defaultdict(int), []
    for record in records:
        app_id, values, reasons = record["app_id"], record["values"], record["reasons"]
        app, changes, unseen = current.get(app_id), {}, False
        if not reasons and app is None and app_id in variants:
            reasons = [f"Already registered as '{variants[app_id]}'."]
        if reasons:
            action = ContactImportRow.REJECTED
        elif app is None:
            action = ContactImportRow.NEW
            changes = {key: ["", value] for key, value in values.items() if value}
            unseen = app_id not in scanned
        else:
            changes = {key: [app[key], value] for key, value in values.items() if not _same(key, app[key], value)}
            action = ContactImportRow.UPDATED if changes else ContactImportRow.UNCHANGED
        counts[action] += 1
        counts["unseen"] += unseen
        counts["team_removed"] += bool(changes.get("support_emails", [None, None])[1] == "" and app)
        rows.append(ContactImportRow(
            row_number=record["row"], app_id=app_id[:100], action=action, changes=changes,
            cells=record["cells"] if reasons else {}, reason=" ".join(reasons), not_in_scans=unseen,
        ))
    with transaction.atomic():
        ContactImport.objects.filter(status=ContactImport.PREVIEW, created_by=user).delete()
        preview = ContactImport.objects.create(
            filename=filename[:255], created_by=user, new_count=counts[ContactImportRow.NEW],
            updated_count=counts[ContactImportRow.UPDATED], unchanged_count=counts[ContactImportRow.UNCHANGED],
            rejected_count=counts[ContactImportRow.REJECTED], duplicate_count=duplicates,
            not_in_scans_count=counts["unseen"], team_email_removed_count=counts["team_removed"],
        )
        for row in rows:
            row.contact_import = preview
        ContactImportRow.objects.bulk_create(rows, batch_size=1000)
    return preview


# --- apply ------------------------------------------------------------------------------


def _apply(pk, user):
    preview = ContactImport.objects.select_for_update().get(pk=pk)
    if not preview.is_preview:
        raise ContactImportStale("This import has already been applied.")
    rows = list(
        preview.rows.filter(action__in=[ContactImportRow.NEW, ContactImportRow.UPDATED])
        .values("app_id", "action", "changes")
    )
    current = {
        app.app_id: app for app in Application.objects.select_for_update().filter(app_id__in=[r["app_id"] for r in rows])
    }
    now, created, updated, fields = timezone.now(), [], [], {"updated_at"}
    for row in rows:
        app = current.get(row["app_id"])
        if row["action"] == ContactImportRow.NEW:
            if app is not None:
                raise ContactImportStale(STALE_MESSAGE)
            created.append(Application(
                app_id=row["app_id"], source="manual", **{key: new for key, (_, new) in row["changes"].items()}
            ))
            continue
        if app is None or any(getattr(app, key) != old for key, (old, _) in row["changes"].items()):
            raise ContactImportStale(STALE_MESSAGE)
        for key, (_, new) in row["changes"].items():
            setattr(app, key, new)
            fields.add(key)
        app.updated_at = now
        updated.append(app)
    Application.objects.bulk_create(created, batch_size=500)
    if updated:
        Application.objects.bulk_update(updated, sorted(fields), batch_size=500)
    preview.status, preview.applied_by, preview.applied_at = ContactImport.APPLIED, user, now
    preview.save(update_fields=["status", "applied_by", "applied_at"])
    return preview


def apply_import(contact_import, user):
    try:
        with transaction.atomic():
            return _apply(contact_import.pk, user)
    except IntegrityError:  # a weekly import registered one of the new App IDs at the same moment
        raise ContactImportStale(STALE_MESSAGE) from None


# --- downloads --------------------------------------------------------------------------


def _unregistered_app_ids():
    return _scanned_app_ids() - set(Application.objects.values_list("app_id", flat=True))


def missing_team_email_count():
    return Application.objects.filter(NO_TEAM_EMAIL).count() + len(_unregistered_app_ids())


def template_rows(scope):
    if scope == "blank":
        return []
    apps = Application.objects.filter(NO_TEAM_EMAIL) if scope == "missing" else Application.objects.all()
    rows = [list(row) for row in apps.values_list(*CONTACT_FIELDS).iterator(chunk_size=1000)]
    rows += [[app_id] + [""] * (len(CONTACT_FIELDS) - 1) for app_id in _unregistered_app_ids()]
    rows.sort(key=lambda row: row[0])
    return rows


def rejected_rows(contact_import):
    rows = contact_import.rows.filter(action=ContactImportRow.REJECTED).values_list("cells", "reason")
    return [[cells.get(key, "") for key in CONTACT_FIELDS] + [reason] for cells, reason in rows.iterator(chunk_size=1000)]


def _safe(value):
    """Spreadsheets must show these values as text, never run them as formulas."""
    text = ILLEGAL_CHARACTERS_RE.sub("", str(value or ""))
    return f"'{text}" if text.startswith(FORMULA_START) else text


def as_csv(rows, extra_headers=()):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow([label for label, _ in CONTACT_COLUMNS] + list(extra_headers))
    writer.writerows([_safe(value) for value in row] for row in rows)
    return buffer.getvalue().encode("utf-8-sig")


def as_xlsx(rows):
    workbook = Workbook(write_only=True)
    sheet = workbook.create_sheet("Application contacts")
    sheet.freeze_panes = "A2"
    for column in "ABCDEFGHIJ":
        sheet.column_dimensions[column].width = 24
    header = []
    for label, _ in CONTACT_COLUMNS:
        cell = WriteOnlyCell(sheet, value=label)
        cell.font = Font(bold=True)
        header.append(cell)
    sheet.append(header)
    for row in rows:
        sheet.append([_safe(value) for value in row])
    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()
