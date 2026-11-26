from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from vulns.columns import OTHER_SEVERITY_RANK
from vulns.models import FAR_FUTURE

from .columns import CMDB_COLUMNS, CMDB_LABELS, MFS12, QUALYS


def name_key(name):
    return (name or "").strip().lower()


def short_key(key):
    """srv01.corp.local -> srv01. An IP address is kept whole."""
    if key.replace(".", "").isdigit():
        return key
    return key.split(".", 1)[0]


class Server(models.Model):
    """A server from CMDB, or one found in a scan that CMDB doesn't have yet.

    It belongs to CMDB's App ID (u_id). Only a server without one can be assigned by hand.
    """

    name = models.CharField(max_length=255)
    name_key = models.CharField(max_length=255, unique=True)  # lower-case name
    short_key = models.CharField(max_length=255, db_index=True)  # name before the first dot
    fqdn_key = models.CharField(max_length=255, blank=True, db_index=True)
    in_cmdb = models.BooleanField(default=False)
    cmdb_app_id = models.CharField(max_length=100, blank=True)
    manual_app_id = models.CharField(max_length=100, blank=True)
    app_id = models.CharField("App ID", max_length=100, blank=True, db_index=True)  # CMDB's, else the manual one
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    assigned_at = models.DateTimeField(null=True, blank=True)
    match_note = models.CharField(max_length=500, blank=True)  # why a scanned name didn't match one CMDB server
    server_class = models.CharField("Class", max_length=255, blank=True)
    environment = models.CharField(max_length=255, blank=True)
    os = models.CharField("OS", max_length=255, blank=True)
    os_version = models.CharField("OS version", max_length=255, blank=True)
    ip_address = models.CharField("IP address", max_length=255, blank=True)
    operational_status = models.CharField(max_length=255, blank=True)
    owned_by = models.CharField(max_length=255, blank=True)
    managed_by = models.CharField(max_length=255, blank=True)
    company = models.CharField(max_length=255, blank=True)
    asset = models.CharField(max_length=255, blank=True)
    location = models.CharField(max_length=255, blank=True)
    support_group = models.CharField(max_length=255, blank=True)
    fqdn = models.CharField("FQDN", max_length=255, blank=True)
    scan_os = models.CharField("OS in scan", max_length=255, blank=True)
    cmdb = models.JSONField(default=dict, blank=True)  # every CMDB column, as exported
    cmdb_hash = models.CharField(max_length=32, blank=True)
    cmdb_changed_at = models.DateTimeField(null=True, blank=True)
    last_detected = models.DateTimeField(null=True, blank=True)
    open_count = models.PositiveIntegerField(default=0)
    critical_open = models.PositiveIntegerField(default=0)
    high_open = models.PositiveIntegerField(default=0)
    kev_open = models.PositiveIntegerField(default=0)
    past_slo_open = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name_key"]
        indexes = [models.Index(fields=["app_id", "open_count"], name="server_app_open")]

    def __str__(self):
        return self.name

    @property
    def os_label(self):
        return " ".join(v for v in (self.os, self.os_version) if v) or self.scan_os

    def cmdb_rows(self):
        return [(CMDB_LABELS[key], self.cmdb.get(key, "")) for key in CMDB_COLUMNS if self.cmdb.get(key)]


class ServerAssignment(models.Model):
    """Audit trail of App IDs given to servers by hand."""

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="assignments")
    old_app_id = models.CharField(max_length=100, blank=True)
    new_app_id = models.CharField(max_length=100, blank=True)
    open_count = models.PositiveIntegerField(default=0)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-changed_at", "-id"]


# --- weekly findings imports ------------------------------------------------------------


class ServerImport(models.Model):
    DRAFT, FINALIZED, DISCARDED = "draft", "finalized", "discarded"
    STATUS_CHOICES = [(DRAFT, "Draft"), (FINALIZED, "Finalized"), (DISCARDED, "Discarded")]

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=DRAFT)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    finalized_at = models.DateTimeField(null=True, blank=True)
    finalized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    files_count = models.PositiveIntegerField(default=0)
    servers_count = models.PositiveIntegerField(default=0)
    new_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    reopened_count = models.PositiveIntegerField(default=0)
    remediated_count = models.PositiveIntegerField(default=0)
    duplicates_count = models.PositiveIntegerField(default=0)
    unique_rows = models.PositiveIntegerField(default=0)
    expected_total = models.PositiveIntegerField(null=True, blank=True, help_text="Total rows shown in Power BI.")
    override_reason = models.TextField(blank=True)
    remediation_skipped = models.BooleanField(default=False)
    phase = models.CharField(max_length=12, blank=True)  # "", planning, finalizing
    plan = models.JSONField(default=dict, blank=True)
    plan_ready = models.BooleanField(default=False)

    class Meta:
        ordering = ["-id"]
        constraints = [
            models.UniqueConstraint(fields=["status"], condition=Q(status="draft"), name="single_draft_server_import"),
        ]

    def __str__(self):
        return f"Server import #{self.pk}"

    @property
    def is_draft(self):
        return self.status == self.DRAFT

    @property
    def is_busy(self):
        busy = [ServerImportFile.QUEUED, ServerImportFile.PROCESSING]
        return bool(self.phase) or self.files.filter(status__in=busy).exists()

    @property
    def count_matches(self):
        return self.expected_total is not None and self.expected_total == self.unique_rows

    @property
    def has_findings_file(self):
        return self.files.filter(kind=MFS12, status=ServerImportFile.DONE).exists()


class ServerImportFile(models.Model):
    QUEUED, PROCESSING, DONE, FAILED = "queued", "processing", "done", "failed"
    STATUS_CHOICES = [(QUEUED, "Queued"), (PROCESSING, "Reading"), (DONE, "Done"), (FAILED, "Failed")]
    KIND_CHOICES = [(MFS12, "MFS12"), (QUALYS, "Qualys")]

    run = models.ForeignKey(ServerImport, on_delete=models.CASCADE, related_name="files")
    kind = models.CharField(max_length=10, choices=KIND_CHOICES, blank=True)  # detected from the header
    filename = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=QUEUED)
    stored_path = models.CharField(max_length=500, blank=True)
    size_bytes = models.BigIntegerField(default=0)
    error = models.TextField(blank=True)
    header_row = models.PositiveIntegerField(default=1)
    rows_read = models.PositiveIntegerField(default=0)
    accepted = models.PositiveIntegerField(default=0)
    rejected = models.PositiveIntegerField(default=0)
    duplicates = models.PositiveIntegerField(default=0)
    unknown_columns = models.JSONField(default=list, blank=True)
    missing_columns = models.JSONField(default=list, blank=True)
    date_order = models.CharField(max_length=3, blank=True, default="")

    class Meta:
        ordering = ["id"]


class ServerRejectedRow(models.Model):
    """A row that could not be read. It blocks remediation on its server, or everywhere if it names none."""

    run = models.ForeignKey(ServerImport, on_delete=models.CASCADE, related_name="rejected_rows")
    file = models.ForeignKey(ServerImportFile, on_delete=models.CASCADE, related_name="rejected_rows")
    row = models.PositiveIntegerField()
    reason = models.TextField()
    asset_name = models.CharField(max_length=255, blank=True)
    asset_key = models.CharField(max_length=255, blank=True)
    qid = models.CharField(max_length=30, blank=True)

    class Meta:
        ordering = ["file_id", "row"]
        indexes = [models.Index(fields=["run", "asset_key"], name="server_rejected_asset")]


class StagedServerFinding(models.Model):
    """An MFS12 row waiting in a draft. For a repeated server + QID, the newest Last Detected wins."""

    run = models.ForeignKey(ServerImport, on_delete=models.DO_NOTHING, db_constraint=False, related_name="+")
    file = models.ForeignKey(ServerImportFile, on_delete=models.DO_NOTHING, db_constraint=False, related_name="+")
    row_number = models.PositiveIntegerField()
    asset_name = models.CharField(max_length=255)
    asset_key = models.CharField(max_length=255)
    qid = models.CharField(max_length=30)
    title = models.TextField(blank=True)
    os = models.CharField(max_length=255, blank=True)
    severity = models.CharField(max_length=30, blank=True)
    severity_rank = models.SmallIntegerField(default=OTHER_SEVERITY_RANK)
    cisa_kev = models.BooleanField(default=False)
    non_running_kernel = models.BooleanField(default=False)
    cvss_score = models.FloatField(null=True)
    cvss_vector = models.CharField(max_length=255, blank=True)
    first_detected = models.DateTimeField(null=True)
    last_detected = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["run", "asset_key", "qid"], name="unique_staged_server_finding"),
        ]


class StagedQualysRow(models.Model):
    """A Qualys row. Several rows for one server + QID (one per port) are combined when applied."""

    run = models.ForeignKey(ServerImport, on_delete=models.DO_NOTHING, db_constraint=False, related_name="+")
    file = models.ForeignKey(ServerImportFile, on_delete=models.DO_NOTHING, db_constraint=False, related_name="+")
    row_number = models.PositiveIntegerField()
    asset_key = models.CharField(max_length=255)
    qid = models.CharField(max_length=30)
    solution = models.TextField(blank=True)
    results = models.TextField(blank=True)
    port = models.CharField(max_length=100, blank=True)
    protocol = models.CharField(max_length=30, blank=True)
    cve = models.TextField(blank=True)

    class Meta:
        indexes = [models.Index(fields=["run", "asset_key", "qid"], name="staged_qualys_key")]


class ServerFinding(models.Model):
    """One vulnerability (QID) on one server."""

    OPEN, REMEDIATED = "open", "remediated"
    STATUS_CHOICES = [(OPEN, "Open"), (REMEDIATED, "Remediated")]

    server = models.ForeignKey(Server, on_delete=models.PROTECT, related_name="findings")
    qid = models.CharField("QID", max_length=30)
    title = models.TextField(blank=True)
    os = models.CharField("OS", max_length=255, blank=True)
    severity = models.CharField(max_length=30, blank=True)
    severity_rank = models.SmallIntegerField(default=OTHER_SEVERITY_RANK)
    cisa_kev = models.BooleanField("CISA KEV", default=False)
    non_running_kernel = models.BooleanField(default=False)
    cvss_score = models.FloatField("CVSS 3.1", null=True, blank=True)
    cvss_vector = models.CharField(max_length=255, blank=True)
    first_detected = models.DateTimeField(null=True, blank=True)
    last_detected = models.DateTimeField(null=True, blank=True)
    slo_date = models.DateTimeField(null=True, blank=True)
    slo_sort = models.DateTimeField(default=FAR_FUTURE)
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=OPEN)
    first_seen = models.DateTimeField()
    remediated_at = models.DateTimeField(null=True, blank=True)
    remediated_import = models.ForeignKey(
        ServerImport, null=True, blank=True, on_delete=models.SET_NULL, related_name="remediated_findings"
    )
    reopened_at = models.DateTimeField(null=True, blank=True)
    solution = models.TextField(blank=True)
    results = models.TextField(blank=True)
    ports = models.CharField(max_length=500, blank=True)
    cves = models.TextField("CVEs", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["server", "qid"], name="unique_server_qid")]
        indexes = [
            models.Index(fields=["server", "status", "severity_rank", "slo_sort", "id"], name="finding_server_browse"),
            models.Index(fields=["status", "severity_rank", "slo_sort", "id"], name="finding_browse"),
        ]

    def __str__(self):
        return f"{self.server_id}:{self.qid}"

    @property
    def is_open(self):
        return self.status == self.OPEN

    @property
    def slo_overdue(self):
        return self.is_open and self.slo_date is not None and self.slo_date < timezone.now()

    @property
    def days_open(self):
        start = self.first_detected or self.first_seen
        end = self.remediated_at if self.status == self.REMEDIATED and self.remediated_at else timezone.now()
        return max((end - start).days, 0)

    @property
    def display_status(self):
        if self.status == self.REMEDIATED:
            return "Remediated"
        return "Reopened" if self.reopened_at else "Open"

    @property
    def cve_list(self):
        return [c for c in self.cves.split(", ") if c]


class ServerPlannedRemediation(models.Model):
    """The preview list of findings a draft would mark remediated."""

    run = models.ForeignKey(ServerImport, on_delete=models.DO_NOTHING, db_constraint=False, related_name="+")
    finding = models.ForeignKey(ServerFinding, on_delete=models.DO_NOTHING, db_constraint=False, related_name="+")

    class Meta:
        indexes = [models.Index(fields=["run", "id"], name="server_planned_run")]


class ServerSummary(models.Model):
    """Precomputed counts for the dashboard and application pages. app_id is blank for unassigned servers."""

    app_id = models.CharField(max_length=100, blank=True)
    environment = models.CharField(max_length=255, blank=True)
    server_class = models.CharField(max_length=255, blank=True)
    severity = models.CharField(max_length=30, blank=True)
    cisa_kev = models.BooleanField(default=False)
    status = models.CharField(max_length=12)
    total = models.BigIntegerField(default=0)
    past_slo = models.BigIntegerField(default=0)
    reopened = models.BigIntegerField(default=0)
    recent_remediated = models.BigIntegerField(default=0)
    fix_seconds = models.BigIntegerField(default=0)
    fix_count = models.BigIntegerField(default=0)

    class Meta:
        indexes = [models.Index(fields=["app_id", "status"], name="server_summary_app")]


# --- CMDB inventory ---------------------------------------------------------------------


class InventoryImport(models.Model):
    """One CMDB file. Servers change only when its preview is applied."""

    READING, PREVIEW, APPLYING, APPLIED, FAILED = "reading", "preview", "applying", "applied", "failed"
    STATUS_CHOICES = [
        (READING, "Reading"), (PREVIEW, "Preview"), (APPLYING, "Applying"), (APPLIED, "Applied"), (FAILED, "Failed"),
    ]

    filename = models.CharField(max_length=255)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=READING)
    stored_path = models.CharField(max_length=500, blank=True)
    size_bytes = models.BigIntegerField(default=0)
    error = models.TextField(blank=True)
    rows_read = models.PositiveIntegerField(default=0)
    new_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    unchanged_count = models.PositiveIntegerField(default=0)
    rejected_count = models.PositiveIntegerField(default=0)
    duplicate_count = models.PositiveIntegerField(default=0)
    app_changed_count = models.PositiveIntegerField(default=0)
    new_app_ids_count = models.PositiveIntegerField(default=0)  # App IDs Herald doesn't have yet
    not_in_file_count = models.PositiveIntegerField(default=0)
    merged_count = models.PositiveIntegerField(default=0)  # scanned servers matched to CMDB when applied
    unknown_columns = models.JSONField(default=list, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    applied_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    applied_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    @property
    def is_preview(self):
        return self.status == self.PREVIEW

    @property
    def is_busy(self):
        return self.status in (self.READING, self.APPLYING)

    @property
    def change_count(self):
        return self.new_count + self.updated_count


class InventoryRow(models.Model):
    NEW, UPDATED, UNCHANGED, REJECTED = "new", "updated", "unchanged", "rejected"

    inventory = models.ForeignKey(InventoryImport, on_delete=models.CASCADE, related_name="rows")
    row_number = models.PositiveIntegerField()
    name = models.CharField(max_length=255, blank=True)
    name_key = models.CharField(max_length=255, blank=True)
    action = models.CharField(max_length=10)
    changes = models.JSONField(default=dict, blank=True)  # {column: [old, new]} for the columns copied onto Server
    cells = models.JSONField(default=dict, blank=True)  # the row as exported
    reason = models.TextField(blank=True)

    class Meta:
        ordering = ["row_number", "id"]
        indexes = [models.Index(fields=["inventory", "action", "row_number"], name="inventory_row_browse")]
