"""Reads scanner exports (CSV / Excel) into normalized rows plus a list of rejected rows."""
import codecs
import csv
import io
import re
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from itertools import chain, islice

from dateutil import parser as dateparser
from openpyxl import load_workbook

from .columns import (
    BOOL, DATE, HEADER_MAP, LABELS, NUMBER, PROVIDER_ALIASES, REQUIRED, SEVERITY_ALIASES, TYPES, normalize_header,
)

HEADER_SCAN_ROWS = 50
FIELD_LIMITS = {
    "alert_id": 200, "csb_id": 100, "account_id": 100, "account_name": 255, "provider": 30, "asset_id": 500,
    "app_id": 100, "environment": 100, "severity": 30, "ritm": 100, "cve": 100, "cve_link": 500,
}
BLANKS = {"", "-", "n/a", "na", "none", "null", "nan", "unknown"}
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
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
    return str(raw).replace("\x00", "").strip()


def normalize_severity(text):
    if not text:
        return ""
    return SEVERITY_ALIASES.get(text.strip().lower(), text.strip().title())


def normalize_provider(text, account_id):
    """Uses the Provider column, or recognizes an AWS account number / Azure subscription GUID when it is blank."""
    cleaned = (text or "").strip()
    if cleaned:
        return PROVIDER_ALIASES.get(re.sub(r"[\s_-]+", "", cleaned).lower(), cleaned)
    if GUID.fullmatch(account_id or ""):
        return "Azure"
    if re.fullmatch(r"\d{1,12}", account_id or ""):
        return "AWS"
    return ""


def normalize_account_id(text, provider):
    """Azure GUIDs are lower-cased; AWS numbers get back the leading zeros Excel removes."""
    value = (text or "").strip()
    if re.fullmatch(r"\d+(\.\d+)?[eE]\+?\d+", value):
        raise ValueError(f"Account ID: '{value}' was rounded by Excel; export the column as text")
    if GUID.fullmatch(value):
        return value.lower()
    if provider == "AWS" and re.fullmatch(r"\d{1,12}", value):
        return value.zfill(12)
    return value


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


def _excel_rows(fileobj):
    try:
        workbook = load_workbook(fileobj, read_only=True, data_only=True)
    except Exception as exc:
        raise FileFormatError(f"Could not open the Excel file: {exc}") from None
    sheet = workbook.worksheets[0]
    sheet.reset_dimensions()  # some exporters write a wrong sheet size

    def rows():
        try:
            for number, row in enumerate(sheet.iter_rows(values_only=True), start=1):
                yield number, list(row)
        finally:
            workbook.close()

    return rows()


def _detect_encoding(sample):
    try:
        codecs.getincrementaldecoder("utf-8-sig")().decode(sample, final=False)
        return "utf-8-sig"
    except UnicodeDecodeError:
        return "cp1252"


def _csv_rows(fileobj):
    csv.field_size_limit(16 * 1024 * 1024)
    sample = fileobj.read(1024 * 1024)
    fileobj.seek(0)
    encoding = _detect_encoding(sample)
    text = sample.decode(encoding, errors="ignore")
    delimiter = ","
    for candidate in (",", ";", "\t", "|"):  # keep the first delimiter that yields a recognizable header row
        head = list(islice(csv.reader(io.StringIO(text, newline=""), delimiter=candidate), HEADER_SCAN_ROWS))
        if find_header(list(enumerate(head, start=1)))[0] is not None:
            delimiter = candidate
            break
    stream = io.TextIOWrapper(fileobj, encoding=encoding, errors="replace", newline="")
    return enumerate(csv.reader(stream, delimiter=delimiter), start=1)


def read_rows(fileobj, filename):
    """Yields (row number, values) without loading the file into memory."""
    fileobj = getattr(fileobj, "file", fileobj)
    name = filename.lower()
    if name.endswith((".xlsx", ".xlsm")):
        return _excel_rows(fileobj)
    if name.endswith(".csv"):
        return _csv_rows(fileobj)
    raise FileFormatError("Unsupported file type. Upload a .csv, .xlsx or .xlsm file.")


def find_header(rows):
    """Headers can start on any row: the first row (within the first 50) that has every required column."""
    for position, (_, values) in enumerate(rows[:HEADER_SCAN_ROWS]):
        keys = {HEADER_MAP.get(normalize_header(v)) for v in values if v is not None}
        if all(required in keys for required in REQUIRED):
            return position, values
    return None, None


class StreamParser:
    """Parses a file in batches. Each batch is (accepted records, rejected rows)."""

    def __init__(self, fileobj, filename):
        self.rows_read = 0
        self.unknown_columns = []
        rows = read_rows(fileobj, filename)
        head = list(islice(rows, HEADER_SCAN_ROWS))
        position, header = find_header(head)
        if position is None:
            raise FileFormatError(
                f"No header row with 'Alert ID', 'Account ID' and 'Account Name' was found in the first "
                f"{HEADER_SCAN_ROWS} rows."
            )
        self.header_row = head[position][0]
        self._rows = chain(head[position + 1:], rows)
        self._mapping = []
        seen_keys = set()
        for index, title in enumerate(header):
            if title is None or str(title).strip() == "":
                continue
            key = HEADER_MAP.get(normalize_header(title))
            if key and key not in seen_keys:
                seen_keys.add(key)
                self._mapping.append((index, key))
            else:
                self.unknown_columns.append(str(title).strip())
        self.missing_columns = [LABELS[key] for key in LABELS if key not in seen_keys]

    def _parse(self, row_number, values):
        record, problems = {}, []
        for index, key in self._mapping:
            raw = values[index] if index < len(values) else None
            try:
                record[key] = convert(key, raw)
            except ValueError as exc:
                record[key] = None
                problems.append(str(exc))
        record["app_id"] = (record.get("app_id") or "").upper()
        record["provider"] = normalize_provider(record.get("provider"), record.get("account_id"))
        try:
            record["account_id"] = normalize_account_id(record.get("account_id"), record["provider"])
        except ValueError as exc:
            record["account_id"] = ""
            problems.append(str(exc))
        else:
            if not record["account_id"]:
                problems.insert(0, "Account ID is missing")
        if not record.get("account_name"):
            problems.insert(0, "Account Name is missing")
        if not record.get("alert_id"):
            problems.insert(0, "Alert ID is missing")
        for key, limit in FIELD_LIMITS.items():
            if len(record.get(key) or "") > limit:
                problems.append(f"{LABELS[key]} is longer than {limit} characters")
        if problems:
            return None, {
                "row": row_number,
                "reason": "; ".join(problems),
                "alert_id": (record.get("alert_id") or "")[:200],
                "account_id": (record.get("account_id") or "")[:100],
                "asset_id": (record.get("asset_id") or "")[:500],
            }
        record["_row"] = row_number
        return record, None

    def batches(self, size=5000):
        accepted, rejected = [], []
        for row_number, values in self._rows:
            if all(_is_blank(v) or (isinstance(v, str) and not v.strip()) for v in values):
                continue
            self.rows_read += 1
            record, error = self._parse(row_number, values)
            if error:
                rejected.append(error)
            else:
                accepted.append(record)
            if len(accepted) + len(rejected) >= size:
                yield accepted, rejected
                accepted, rejected = [], []
        if accepted or rejected:
            yield accepted, rejected


def parse_file(fileobj, filename):
    """Reads a whole file. Imports use StreamParser directly so they stay within memory limits."""
    parser = StreamParser(fileobj, filename)
    result = ParseResult(
        header_row=parser.header_row, unknown_columns=parser.unknown_columns, missing_columns=parser.missing_columns
    )
    for accepted, rejected in parser.batches():
        result.rows.extend(accepted)
        result.errors.extend(rejected)
    result.rows_read = parser.rows_read
    return result
