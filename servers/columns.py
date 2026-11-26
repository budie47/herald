"""Columns of the three server reports. Headers are matched ignoring case, spaces and underscores.

- MFS12 (Power BI, fed by Qualys): one row per server + QID. The weekly findings upload.
- Qualys: optional. Adds the Solution and Results to MFS12 findings, matched on server + QID.
- CMDB (ServiceNow): the server inventory, with each server's App ID.
"""
from vulns.columns import BOOL, DATE, TEXT, normalize_header

MFS12, QUALYS = "mfs12", "qualys"

MFS12_COLUMNS = [
    ("Asset Name", "asset_name", TEXT),
    ("QID", "qid", TEXT),
    ("OS", "os", TEXT),
    ("Title", "title", TEXT),
    ("CISA_KEV", "cisa_kev", BOOL),
    ("First Detected", "first_detected", DATE),
    ("Last Detected", "last_detected", DATE),
    ("CVSS3.1 Base", "cvss", TEXT),
    ("Non-running Kernel", "non_running_kernel", BOOL),
    ("Severity", "severity", TEXT),
]
MFS12_REQUIRED = ("asset_name", "qid", "severity")

# Only these Qualys columns are read. Every other column in the export is ignored.
QUALYS_COLUMNS = [
    ("Asset Name", "asset_name", TEXT),
    ("QID", "qid", TEXT),
    ("Title", "title", TEXT),
    ("Solution", "solution", TEXT),
    ("Results", "results", TEXT),
    ("Port", "port", TEXT),
    ("Protocol", "protocol", TEXT),
    ("CVE", "cve", TEXT),
]
QUALYS_REQUIRED = ("asset_name", "qid", "solution")

SERVER_ALIASES = {"hostname": "asset_name", "hostnames": "asset_name", "cveid": "cve", "cves": "cve"}


def _header_map(columns):
    mapping = {normalize_header(label): key for label, key, _ in columns}
    mapping.update({alias: key for alias, key in SERVER_ALIASES.items() if key in {k for _, k, _ in columns}})
    return mapping


MFS12_HEADER_MAP = _header_map(MFS12_COLUMNS)
QUALYS_HEADER_MAP = _header_map(QUALYS_COLUMNS)

# The ServiceNow CMDB export, in its own column order. Every column is kept and shown on the server's page.
CMDB_COLUMNS = [
    "name", "sys_class_name", "location", "os_domain", "u_dttl_it_customer", "os", "os_version", "ip_address",
    "u_environment", "u_id", "operational_status", "u_dttl_it_server_role", "install_status", "company", "asset",
    "asset_tag", "serial_number", "owned_by", "managed_by", "short_description", "sys_created_on", "discovery_source",
    "fqdn", "assignment_group", "sys_updated_on", "last_discovered", "gl_account", "u_patch_slot_primary",
    "u_patch_priority", "u_patch_slot_secondary", "u_patch_with_reboot", "support_group", "supported_by", "cpu_count",
    "cpu_core_count", "cpu_core_thread", "cpu_name", "ram", "disk_space", "model_id", "model_number", "u_hosting_model",
    "u_ci_global_id",
]
CMDB_LABELS = {
    "name": "Name", "sys_class_name": "Class", "location": "Location", "os_domain": "OS domain",
    "u_dttl_it_customer": "IT customer", "os": "OS", "os_version": "OS version", "ip_address": "IP address",
    "u_environment": "Environment", "u_id": "App ID", "operational_status": "Operational status",
    "u_dttl_it_server_role": "Server role", "install_status": "Install status", "company": "Company", "asset": "Asset",
    "asset_tag": "Asset tag", "serial_number": "Serial number", "owned_by": "Owned by", "managed_by": "Managed by",
    "short_description": "Description", "sys_created_on": "Created in CMDB", "discovery_source": "Discovery source",
    "fqdn": "FQDN", "assignment_group": "Assignment group", "sys_updated_on": "Updated in CMDB",
    "last_discovered": "Last discovered", "gl_account": "GL account", "u_patch_slot_primary": "Patch slot (primary)",
    "u_patch_priority": "Patch priority", "u_patch_slot_secondary": "Patch slot (secondary)",
    "u_patch_with_reboot": "Patch with reboot", "support_group": "Support group", "supported_by": "Supported by",
    "cpu_count": "CPU count", "cpu_core_count": "CPU cores", "cpu_core_thread": "CPU threads", "cpu_name": "CPU",
    "ram": "RAM", "disk_space": "Disk space", "model_id": "Model", "model_number": "Model number",
    "u_hosting_model": "Hosting model", "u_ci_global_id": "CI global ID",
}
CMDB_HEADER_MAP = {normalize_header(key): key for key in CMDB_COLUMNS}
CMDB_HEADER_MAP.update({
    "assetname": "name", "servername": "name", "environment": "u_environment", "appid": "u_id",
    "class": "sys_class_name",
})

# CMDB columns copied onto Server, so lists can filter and sort on them. The rest stay in Server.cmdb.
CMDB_FIELDS = {
    "sys_class_name": "server_class", "u_environment": "environment", "os": "os", "os_version": "os_version",
    "ip_address": "ip_address", "operational_status": "operational_status", "owned_by": "owned_by",
    "managed_by": "managed_by", "company": "company", "asset": "asset", "location": "location",
    "support_group": "support_group", "fqdn": "fqdn",
}
CMDB_FIELD_LIMITS = {"name": 255, "u_id": 100, "fqdn": 255}
CMDB_CHANGE_LABELS = {"u_id": "App ID", **{key: CMDB_LABELS[key] for key in CMDB_FIELDS}}

RESULTS_LIMIT = 4000
SOLUTION_LIMIT = 8000
