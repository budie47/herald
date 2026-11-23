"""The 46 scanner columns accepted by the container import, in export order.

Headers are matched ignoring case, spaces and underscores.
"""
import re

TEXT, DATE, NUMBER, BOOL = "text", "date", "number", "bool"

COLUMNS = [
    ("CSB ID", "csb_id", TEXT),
    ("Alert ID", "alert_id", TEXT),
    ("Last Scan", "last_scan", DATE),
    ("Severity", "severity", TEXT),
    ("Alert Opened", "alert_opened", DATE),
    ("Days Open", "days_open", NUMBER),
    ("SLO Date", "slo_date", DATE),
    ("Exception", "exception", BOOL),
    ("Exception RITM", "ritm", TEXT),
    ("Account ID", "account_id", TEXT),
    ("Account Name", "account_name", TEXT),
    ("Provider", "provider", TEXT),
    ("Enviroment", "environment", TEXT),
    ("Asset ID", "asset_id", TEXT),
    ("Asset Type", "asset_type", TEXT),
    ("CVE ID", "cve", TEXT),
    ("CVE Description", "cve_description", TEXT),
    ("CVE Link", "cve_link", TEXT),
    ("Cluster", "cluster", TEXT),
    ("Namespace", "namespace", TEXT),
    ("Instance", "instance", TEXT),
    ("Repository", "repository", TEXT),
    ("Registry", "registry", TEXT),
    ("Image", "image", TEXT),
    ("Image Tag", "image_tag", TEXT),
    ("Image Created", "image_created", DATE),
    ("Package", "package", TEXT),
    ("Current Version", "current_version", TEXT),
    ("Recommended Version", "recommended_version", TEXT),
    ("Package Path", "package_path", TEXT),
    ("Layer ID", "layer_id", TEXT),
    ("Layer Instruction", "layer_instruction", TEXT),
    ("OS", "os", TEXT),
    ("OS Version", "os_version", TEXT),
    ("OS End of Life", "os_end_of_life", DATE),
    ("Participating Firm", "participating_firm", TEXT),
    ("Country", "country", TEXT),
    ("CMS", "cms", TEXT),
    ("Function", "function", TEXT),
    ("App ID", "app_id", TEXT),
    ("App Service", "app_service", TEXT),
    ("Business Service", "business_service", TEXT),
    ("Department", "department", TEXT),
    ("Service Line", "service_line", TEXT),
    ("Data Classification", "data_classification", TEXT),
    ("Data Qualification", "data_qualification", TEXT),
]
assert len(COLUMNS) == 46

REQUIRED = ("alert_id", "account_id", "account_name")
LABELS = {key: label for label, key, _ in COLUMNS}
TYPES = {key: kind for _, key, kind in COLUMNS}

# Alternative spellings seen in real exports.
ALIASES = {
    "environment": "environment",
    "cve": "cve",
    "ritm": "ritm",
    "ritmnumber": "ritm",
    "subscriptionid": "account_id",
    "subscriptionname": "account_name",
    "cloudprovider": "provider",
}


def normalize_header(value):
    return re.sub(r"[\s_]+", "", str(value or "")).lower()


HEADER_MAP = {normalize_header(label): key for label, key, _ in COLUMNS}
HEADER_MAP.update(ALIASES)

# Repeated values live once in shared tables, and each alert points at them.
PACKAGE_COLUMNS = ["package", "current_version", "recommended_version", "package_path", "layer_id", "layer_instruction"]
CONTEXT_COLUMNS = [
    "asset_type", "instance", "cluster", "namespace", "repository", "registry", "image", "image_tag", "image_created",
    "os", "os_version", "os_end_of_life", "participating_firm", "country", "cms", "function", "app_service",
    "business_service", "department", "service_line", "data_classification", "data_qualification",
]

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_ALIASES = {
    "critical": "Critical", "crit": "Critical", "urgent": "Critical",
    "high": "High", "important": "High",
    "medium": "Medium", "moderate": "Medium", "med": "Medium",
    "low": "Low", "minor": "Low",
    "info": "Informational", "informational": "Informational", "negligible": "Informational",
}
SEVERITY_RANKS = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}
OTHER_SEVERITY_RANK = len(SEVERITY_ORDER)
PROVIDER_ALIASES = {
    "aws": "AWS", "amazon": "AWS", "amazonwebservices": "AWS",
    "azure": "Azure", "microsoftazure": "Azure", "msazure": "Azure",
}
