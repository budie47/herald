"""Reads the MFS12, Qualys and CMDB reports. Built on the container reader, so files of any size stream in batches."""
import csv
import re
from itertools import chain, islice

from vulns.columns import SEVERITY_RANKS, OTHER_SEVERITY_RANK, normalize_header
from vulns.parsing import BLANKS, HEADER_SCAN_ROWS, FileFormatError, StreamParser, normalize_severity, read_rows, to_text

from .columns import (
    CMDB_FIELD_LIMITS, CMDB_HEADER_MAP, MFS12, MFS12_COLUMNS, MFS12_HEADER_MAP, MFS12_REQUIRED, QUALYS, QUALYS_COLUMNS,
    QUALYS_HEADER_MAP, QUALYS_REQUIRED, RESULTS_LIMIT, SOLUTION_LIMIT,
)
from .models import name_key

CVSS = re.compile(r"\s*(\d+(?:[.,]\d+)?)\s*(?:\((.*)\))?\s*")
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def split_cvss(text):
    """'9.1 (AV:N/AC:L/...)' -> (9.1, 'AV:N/AC:L/...')."""
    match = CVSS.fullmatch(text or "")
    if not match:
        return None, (text or "")[:255]
    return float(match[1].replace(",", ".")), (match[2] or "").strip()[:255]


def _key_values(record, problems):
    asset_name = (record.get("asset_name") or "").strip()
    qid = (record.get("qid") or "").strip()
    if not asset_name:
        problems.insert(0, "Asset Name is missing")
    elif len(asset_name) > 255:
        problems.append("Asset Name is longer than 255 characters")
    if not qid:
        problems.insert(0, "QID is missing")
    elif len(qid) > 30:
        problems.append("QID is longer than 30 characters")
    return asset_name[:255], qid[:30]


class _ServerParser(StreamParser):
    def _parse(self, row_number, values):
        record, problems = self._cells(values)
        asset_name, qid = _key_values(record, problems)
        record.update(asset_name=asset_name, asset_key=name_key(asset_name), qid=qid, _row=row_number)
        if problems:
            return None, {
                "row": row_number, "reason": "; ".join(problems), "asset_name": asset_name,
                "asset_key": record["asset_key"], "qid": qid,
            }
        return self._finish(record), None


class MFS12Parser(_ServerParser):
    header_map = MFS12_HEADER_MAP
    labels = {key: label for label, key, _ in MFS12_COLUMNS}
    types = {key: kind for _, key, kind in MFS12_COLUMNS}
    required = MFS12_REQUIRED
    missing_header = "No header row with 'Asset Name', 'QID' and 'Severity' was found"

    def _finish(self, record):
        record["severity"] = normalize_severity(record.get("severity") or "")
        record["severity_rank"] = SEVERITY_RANKS.get(record["severity"], OTHER_SEVERITY_RANK)
        record["cvss_score"], record["cvss_vector"] = split_cvss(record.get("cvss"))
        record["title"] = record.get("title") or ""
        record["os"] = (record.get("os") or "")[:255]
        return record


class QualysParser(_ServerParser):
    header_map = QUALYS_HEADER_MAP
    labels = {key: label for label, key, _ in QUALYS_COLUMNS}
    types = {key: kind for _, key, kind in QUALYS_COLUMNS}
    required = QUALYS_REQUIRED
    missing_header = "No header row with 'Asset Name', 'QID' and 'Solution' was found"

    def _finish(self, record):
        record["solution"] = (record.get("solution") or "")[:SOLUTION_LIMIT]
        record["results"] = (record.get("results") or "")[:RESULTS_LIMIT]
        record["port"] = (record.get("port") or "")[:100]
        record["protocol"] = (record.get("protocol") or "")[:30]
        record["cve"] = ", ".join(dict.fromkeys(c.upper() for c in CVE.findall(record.get("cve") or "")))
        return record


PARSERS = {MFS12: MFS12Parser, QUALYS: QualysParser}


def detect_kind(fileobj, filename):
    """MFS12 or Qualys, from the header row. Qualys exports have a Solution column; MFS12 exports don't."""
    fileobj = getattr(fileobj, "file", fileobj)
    try:
        for kind in (QUALYS, MFS12):
            fileobj.seek(0)
            rows = read_rows(fileobj, filename, PARSERS[kind].find_header)
            try:
                if PARSERS[kind].find_header(list(islice(rows, HEADER_SCAN_ROWS)))[0] is not None:
                    return kind
            finally:
                rows.close()
    finally:
        fileobj.seek(0)
    raise FileFormatError(
        "This isn't an MFS12 or Qualys report. MFS12 needs 'Asset Name', 'QID' and 'Severity' columns, and Qualys "
        "needs 'Asset Name', 'QID' and 'Solution'."
    )


# --- CMDB -------------------------------------------------------------------------------


def find_cmdb_header(rows):
    for position, (_, values) in enumerate(rows[:HEADER_SCAN_ROWS]):
        keys = {CMDB_HEADER_MAP.get(normalize_header(v)) for v in values if v is not None}
        if "name" in keys and ("u_id" in keys or "sys_class_name" in keys):
            return position, values
    return None, None


def _cmdb_text(raw):
    text = to_text(raw)
    return "" if text.lower() in BLANKS else text


def read_cmdb(fileobj, filename):
    """Yields (row number, {column: text}, unknown columns). Every value is kept as text, as exported."""
    rows = read_rows(fileobj, filename, finder=find_cmdb_header)
    head = list(islice(rows, HEADER_SCAN_ROWS))
    position, header = find_cmdb_header(head)
    if position is None:
        raise FileFormatError("No header row with 'name' and 'u_id' was found. Upload the CMDB server report.")
    keys, unknown, seen = [], [], set()
    for title in header:
        key = CMDB_HEADER_MAP.get(normalize_header(title))
        if key in seen:
            raise FileFormatError(f"The file has the column '{title}' more than once.")
        if key:
            seen.add(key)
        elif title is not None and str(title).strip():
            unknown.append(str(title).strip())
        keys.append(key)
    try:
        for number, values in chain(head[position + 1:], rows):
            cells = {key: _cmdb_text(raw) for key, raw in zip(keys, values) if key}
            if any(cells.values()):
                yield number, cells, unknown
    except csv.Error as exc:
        raise FileFormatError(f"Could not read the CSV file: {exc}") from None


def check_cmdb_row(cells):
    """Cleans the row in place and returns the reasons it can't be used."""
    reasons = []
    cells["u_id"] = (cells.get("u_id") or "").upper()
    if not cells.get("name"):
        reasons.append("name is missing.")
    if "/" in cells["u_id"]:
        reasons.append(f"u_id '{cells['u_id']}' can't contain '/'.")
    if "," in cells["u_id"] or ";" in cells["u_id"]:
        reasons.append(f"u_id '{cells['u_id']}' has more than one App ID. A server can have only one.")
    for key, limit in CMDB_FIELD_LIMITS.items():
        if len(cells.get(key) or "") > limit:
            reasons.append(f"{key} is longer than {limit} characters.")
    for key, value in cells.items():
        if len(value) > 2000:
            cells[key] = value[:2000]
    return reasons
