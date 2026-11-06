"""The 44 scanner columns accepted by the container import.

Headers are matched ignoring case, spaces and underscores. Edit this list to match your scanner export.
"""
import re

TEXT, DATE, NUMBER, BOOL = "text", "date", "number", "bool"

COLUMNS = [
    ("Alert ID", "alert_id", TEXT),
    ("App ID", "app_id", TEXT),
    ("App Name", "app_name", TEXT),
    ("Asset ID", "asset_id", TEXT),
    ("Asset Name", "asset_name", TEXT),
    ("Asset Type", "asset_type", TEXT),
    ("Image", "image", TEXT),
    ("Image Tag", "image_tag", TEXT),
    ("Image Digest", "image_digest", TEXT),
    ("Registry", "registry", TEXT),
    ("Repository", "repository", TEXT),
    ("Cluster", "cluster", TEXT),
    ("Namespace", "namespace", TEXT),
    ("Container", "container", TEXT),
    ("Host", "host", TEXT),
    ("Environment", "environment", TEXT),
    ("Cloud Provider", "cloud_provider", TEXT),
    ("Account ID", "account_id", TEXT),
    ("Region", "region", TEXT),
    ("OS", "os", TEXT),
    ("OS Version", "os_version", TEXT),
    ("CVE", "cve", TEXT),
    ("CVE Description", "cve_description", TEXT),
    ("CVE Link", "cve_link", TEXT),
    ("Severity", "severity", TEXT),
    ("CVSS Score", "cvss_score", NUMBER),
    ("CVSS Vector", "cvss_vector", TEXT),
    ("EPSS Score", "epss_score", NUMBER),
    ("Exploit Available", "exploit_available", BOOL),
    ("Package", "package", TEXT),
    ("Package Type", "package_type", TEXT),
    ("Package Path", "package_path", TEXT),
    ("Current Version", "current_version", TEXT),
    ("Recommended Version", "recommended_version", TEXT),
    ("Fix Status", "fix_status", TEXT),
    ("Published Date", "published_date", DATE),
    ("First Detected", "first_detected", DATE),
    ("Last Scan", "last_scan", DATE),
    ("SLO Date", "slo_date", DATE),
    ("Exception", "exception", BOOL),
    ("Exception Reason", "exception_reason", TEXT),
    ("Exception Expiry", "exception_expiry", DATE),
    ("RITM Number", "ritm", TEXT),
    ("Risk Factors", "risk_factors", TEXT),
]
assert len(COLUMNS) == 44

REQUIRED = ("alert_id", "app_id")
LABELS = {key: label for label, key, _ in COLUMNS}
TYPES = {key: kind for _, key, kind in COLUMNS}

# Alternative spellings seen in real exports.
ALIASES = {
    "enviroment": "environment",
    "env": "environment",
    "ritm": "ritm",
    "cveid": "cve",
    "fixedversion": "recommended_version",
    "fixversion": "recommended_version",
    "installedversion": "current_version",
    "packageversion": "current_version",
    "lastscanned": "last_scan",
    "lastscandate": "last_scan",
    "firstseen": "first_detected",
}


def normalize_header(value):
    return re.sub(r"[\s_]+", "", str(value or "")).lower()


HEADER_MAP = {normalize_header(label): key for label, key, _ in COLUMNS}
HEADER_MAP.update(ALIASES)

# Scanner columns stored as real database columns (for filtering/searching); everything is also kept in `data`.
MODEL_FIELDS = [
    "app_id", "asset_id", "asset_name", "image", "cluster", "namespace", "environment", "cve",
    "cve_description", "cve_link", "severity", "package", "current_version", "recommended_version",
    "exception", "exception_reason", "ritm", "slo_date", "last_scan",
]

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_ALIASES = {
    "critical": "Critical", "crit": "Critical", "urgent": "Critical",
    "high": "High", "important": "High",
    "medium": "Medium", "moderate": "Medium", "med": "Medium",
    "low": "Low", "minor": "Low",
    "info": "Informational", "informational": "Informational", "negligible": "Informational",
}
