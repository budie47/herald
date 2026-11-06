"""Reads scanner exports (CSV / Excel) into normalized rows plus a list of rejected rows."""
import csv
import io
import re
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone

from dateutil import parser as dateparser
from openpyxl import load_workbook

from .columns import BOOL, DATE, HEADER_MAP, LABELS, NUMBER, REQUIRED, SEVERITY_ALIASES, TYPES, normalize_header

HEADER_SCAN_ROWS = 50
BLANKS = {"", "-", "n/a", "na", "none", "null", "nan"}
FALSE_WORDS = BLANKS | {"no", "n", "false", "0", "f"}
EXCEL_EPOCH = datetime(1899, 12, 30)
DATE_FORMATS = [
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%Y/%m/%d",
    "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y",
    "%d-%m-%Y %H:%M:%S", "%d-%m-%Y %H:%M", "%d-%m-%Y", "%d.%m.%Y",
    "%d %b %Y", "%d %B %Y", "%d-%b-%Y", "%d-%b-%Y %H:%M:%S", "%d-%b-%y",
    "%b %d, %Y", "%B %d, %Y", "%b %d %Y",
    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y",
]


class FileFormatError(Exception):
    pass


@dataclass
class ParseResult:
    rows: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    rows_read: int = 0
    header_row: int = 0
    unknown_columns: list = field(default_factory=list)
    missing_columns: list = field(default_factory=list)


# --- value conversion -------------------------------------------------------------------


def _is_blank(value):
    return value is None or (isinstance(value, str) and value.strip().lower() in BLANKS)


def _from_excel_serial(number, label):
    if not 1 <= number < 2958466:
        raise ValueError(f"{label}: '{number}' is not a valid date")
    return EXCEL_EPOCH + timedelta(days=float(number))


def to_datetime(raw, label):
    if _is_blank(raw):
        return None
    if isinstance(raw, datetime):
        value = raw
    elif isinstance(raw, date):
        value = datetime.combine(raw, time())
    elif isinstance(raw, (int, float)) and not isinstance(raw, bool):
        value = _from_excel_serial(raw, label)
    else:
        text = str(raw).strip()
        value = None
        if re.fullmatch(r"(19|20)\d{6}", text):
            value = datetime.strptime(text, "%Y%m%d")
        elif re.fullmatch(r"\d+(\.\d+)?", text):
            value = _from_excel_serial(float(text), label)
        if value is None:
            try:
                value = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                pass
        if value is None:
            for fmt in DATE_FORMATS:
                try:
                    value = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
        if value is None:
            try:
                value = dateparser.parse(text, dayfirst=True)
            except (ValueError, OverflowError):
                raise ValueError(f"{label}: '{text}' is not a valid date") from None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_number(raw, label):
    if _is_blank(raw):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw).strip().replace(" ", "").rstrip("%")
    if re.fullmatch(r"-?\d+,\d{1,2}", text):  # decimal comma, e.g. 7,5
        text = text.replace(",", ".")
    text = text.replace(",", "")
    try:
        return float(text)
    except ValueError:
        raise ValueError(f"{label}: '{raw}' is not a number") from None


def to_bool(raw):
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return raw != 0
    return str(raw).strip().lower() not in FALSE_WORDS


def to_text(raw):
    if raw is None:
        return ""
    if isinstance(raw, bool):
        return "Yes" if raw else "No"
    if isinstance(raw, float) and raw.is_integer():
        return str(int(raw))
    if isinstance(raw, (datetime, date)):
        return raw.isoformat()
    return str(raw).strip()


def normalize_severity(text):
    if not text:
        return ""
    return SEVERITY_ALIASES.get(text.strip().lower(), text.strip().title())


def convert(key, raw):
    """Returns a JSON-friendly value: dates become ISO strings in UTC."""
    kind = TYPES[key]
    label = LABELS[key]
    if kind == DATE:
        value = to_datetime(raw, label)
        return value.isoformat() if value else None
    if kind == NUMBER:
        return to_number(raw, label)
    if kind == BOOL:
        return to_bool(raw)
    text = to_text(raw)
    return normalize_severity(text) if key == "severity" else text


# --- reading files ----------------------------------------------------------------------


def _read_excel(fileobj):
    try:
        workbook = load_workbook(fileobj, read_only=True, data_only=True)
    except Exception as exc:
        raise FileFormatError(f"Could not open the Excel file: {exc}") from None
    try:
        sheet = workbook.worksheets[0]
        return [(i, list(row)) for i, row in enumerate(sheet.iter_rows(values_only=True), start=1)]
    finally:
        workbook.close()


def _decode(raw):
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def _read_csv(fileobj):
    text = _decode(fileobj.read())
    # Try the common delimiters and keep the first one that yields a recognizable header row.
    first_rows = None
    for delimiter in (",", ";", "\t", "|"):
        rows = [(i, row) for i, row in enumerate(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter), start=1)]
        if first_rows is None:
            first_rows = rows
        if find_header(rows)[0] is not None:
            return rows
    return first_rows or []


def read_rows(fileobj, filename):
    name = filename.lower()
    if name.endswith((".xlsx", ".xlsm")):
        return _read_excel(fileobj)
    if name.endswith(".csv"):
        return _read_csv(fileobj)
    raise FileFormatError("Unsupported file type. Upload a .csv, .xlsx or .xlsm file.")


def find_header(rows):
    """Headers can start on any row: the first row (within the first 50) that has both Alert ID and App ID."""
    for position, (_, values) in enumerate(rows[:HEADER_SCAN_ROWS]):
        keys = {HEADER_MAP.get(normalize_header(v)) for v in values if v is not None}
        if all(required in keys for required in REQUIRED):
            return position, values
    return None, None


def parse_file(fileobj, filename):
    rows = read_rows(fileobj, filename)
    position, header = find_header(rows)
    if position is None:
        raise FileFormatError(
            f"No header row with both 'Alert ID' and 'App ID' was found in the first {HEADER_SCAN_ROWS} rows."
        )

    result = ParseResult(header_row=rows[position][0])
    mapping = []
    seen_keys = set()
    for index, title in enumerate(header):
        if title is None or str(title).strip() == "":
            continue
        key = HEADER_MAP.get(normalize_header(title))
        if key and key not in seen_keys:
            seen_keys.add(key)
            mapping.append((index, key))
        else:
            result.unknown_columns.append(str(title).strip())
    result.missing_columns = [LABELS[key] for key in LABELS if key not in seen_keys]

    for row_number, values in rows[position + 1:]:
        if all(_is_blank(v) or (isinstance(v, str) and not v.strip()) for v in values):
            continue
        result.rows_read += 1
        record, problems = {}, []
        for index, key in mapping:
            raw = values[index] if index < len(values) else None
            try:
                record[key] = convert(key, raw)
            except ValueError as exc:
                record[key] = None
                problems.append(str(exc))
        if not record.get("app_id"):
            problems.insert(0, "App ID is missing")
        if not record.get("alert_id"):
            problems.insert(0, "Alert ID is missing")
        if problems:
            result.errors.append(
                {
                    "row": row_number,
                    "reason": "; ".join(problems),
                    "alert_id": record.get("alert_id") or "",
                    "asset_id": record.get("asset_id") or "",
                }
            )
        else:
            record["_row"] = row_number
            result.rows.append(record)
    return result
