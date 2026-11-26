import re
from datetime import datetime, timezone as dt_timezone
from urllib.parse import urlsplit

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from .columns import CONTACT_FIELDS, CONTACT_LABELS, OTHER_SEVERITY_RANK


def split_emails(value):
    return [e for e in re.split(r"[,;\s]+", value or "") if e]


def safe_web_url(value):
    """A scanner-supplied link, only if it is a plain http(s) URL, so it can't run as a script from an href."""
    text = (value or "").strip()
    if re.search(r"[\x00-\x20\x7f\\]", text):
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    return text if parts.scheme.lower() in ("http", "https") and parts.netloc else ""


def unique_emails(emails, exclude=()):
    """Duplicates removed (case-insensitive), order kept."""
    seen, result = {e.lower() for e in exclude}, []
    for email in emails:
        email = (email or "").strip()
        if email and email.lower() not in seen:
            seen.add(email.lower())
            result.append(email)
    return result


class Application(models.Model):
    app_id = models.CharField("App ID", max_length=100, unique=True)
    name = models.CharField(max_length=200, blank=True)
    support_team = models.CharField("Support team name", max_length=200, blank=True)
    support_emails = models.TextField(
        blank=True, help_text="First contact for notifications. Separate with commas, semicolons or new lines."
    )
    owner_name = models.CharField("Application owner name", max_length=200, blank=True)
    owner_email = models.EmailField("Application owner email", blank=True, help_text="Receives escalations.")
    extra_emails = models.TextField(
        "Extra notification emails", blank=True,
        help_text="Copied on every email. Separate with commas, semicolons or new lines.",
    )
    business_service = models.CharField(max_length=200, blank=True)
    department = models.CharField(max_length=200, blank=True)
    notes = models.TextField(blank=True)
    source = models.CharField(max_length=10, default="manual")  # "scan" when added automatically from an import
    scan_conflict = models.BooleanField(default=False, help_text="The scan data has more than one name for this App ID.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["app_id"]

    def __str__(self):
        return self.app_id

    def extra_email_list(self):
        return split_emails(self.extra_emails)

    def support_email_list(self):
        return unique_emails(split_emails(self.support_emails))

    def contact_emails(self):
        """Everyone tied to this application: support, owner and extra emails."""
        return unique_emails([*self.support_email_list(), self.owner_email, *self.extra_email_list()])

    @property
    def has_contacts(self):
        return bool(self.support_email_list() or self.owner_email)

    @property
    def has_email(self):
        """Notifications start with the support team, so a support email is required to send."""
        return bool(self.support_email_list())


class CloudAccount(models.Model):
    """An AWS account or Azure subscription. Alerts with no App ID inherit the application assigned here."""

    account_id = models.CharField("Account ID", max_length=100, unique=True)
    account_name = models.CharField(max_length=255)
    provider = models.CharField(max_length=30, blank=True, db_index=True)
    application = models.ForeignKey(
        Application, null=True, blank=True, on_delete=models.SET_NULL, related_name="cloud_accounts"
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    assigned_at = models.DateTimeField(null=True, blank=True)
    open_count = models.BigIntegerField(default=0)
    untagged_open = models.BigIntegerField(default=0)
    untagged_critical_high = models.BigIntegerField(default=0)
    untagged_past_slo = models.BigIntegerField(default=0)
    seen_app_ids = models.JSONField(default=list, blank=True)  # [{"app_id": ..., "tagged": n}], most alerts first
    seen_app_count = models.PositiveIntegerField(default=0)
    suggested_app_id = models.CharField(max_length=100, blank=True)  # set only when one App ID is clear
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["account_name", "account_id"]
        indexes = [models.Index(fields=["application", "untagged_open"], name="account_needs_assignment")]

    @property
    def app_ids(self):
        return [item["app_id"] for item in self.seen_app_ids]

    def __str__(self):
        return f"{self.account_name} ({self.account_id})"


class AccountAssignment(models.Model):
    """Audit trail: who changed which App ID an account's untagged alerts belong to."""

    cloud_account = models.ForeignKey(CloudAccount, on_delete=models.CASCADE, related_name="assignments")
    old_app_id = models.CharField(max_length=100, blank=True)
    new_app_id = models.CharField(max_length=100, blank=True)
    untagged_open = models.PositiveIntegerField(default=0)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-changed_at", "-id"]


class ImportRun(models.Model):
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
    assets_count = models.PositiveIntegerField(default=0)
    new_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    reopened_count = models.PositiveIntegerField(default=0)
    remediated_count = models.PositiveIntegerField(default=0)
    skipped_count = models.PositiveIntegerField(default=0)
    duplicates_count = models.PositiveIntegerField(default=0)
    unique_rows = models.PositiveIntegerField(default=0)
    expected_total = models.PositiveIntegerField(null=True, blank=True, help_text="Total alerts shown in Power BI.")
    override_reason = models.TextField(blank=True)
    remediation_skipped = models.BooleanField(default=False)
    phase = models.CharField(max_length=12, blank=True)  # "", planning, finalizing
    plan = models.JSONField(default=dict, blank=True)
    plan_ready = models.BooleanField(default=False)

    class Meta:
        ordering = ["-id"]
        constraints = [
            models.UniqueConstraint(fields=["status"], condition=Q(status="draft"), name="single_draft_import"),
        ]

    def __str__(self):
        return f"Import #{self.pk}"

    @property
    def is_draft(self):
        return self.status == self.DRAFT

    @property
    def is_busy(self):
        return bool(self.phase) or self.files.filter(status__in=[ImportFile.QUEUED, ImportFile.PROCESSING]).exists()

    @property
    def count_matches(self):
        return self.expected_total is not None and self.expected_total == self.unique_rows


class ImportFile(models.Model):
    QUEUED, PROCESSING, DONE, FAILED = "queued", "processing", "done", "failed"
    STATUS_CHOICES = [(QUEUED, "Queued"), (PROCESSING, "Reading"), (DONE, "Done"), (FAILED, "Failed")]
    DATE_ORDER_CHOICES = [
        ("", "Detect from the file"), ("dmy", "Day first (31/12/2026)"), ("mdy", "Month first (12/31/2026)"),
    ]

    run = models.ForeignKey(ImportRun, on_delete=models.CASCADE, related_name="files")
    filename = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=DONE)
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
    date_order = models.CharField(max_length=3, choices=DATE_ORDER_CHOICES, blank=True, default="")

    class Meta:
        ordering = ["id"]


class RejectedRow(models.Model):
    """A row that could not be read. It is listed for the user and blocks remediation on what it may belong to."""

    run = models.ForeignKey(ImportRun, on_delete=models.CASCADE, related_name="rejected_rows")
    file = models.ForeignKey(ImportFile, on_delete=models.CASCADE, related_name="rejected_rows")
    row = models.PositiveIntegerField()
    reason = models.TextField()
    alert_id = models.CharField(max_length=200, blank=True)
    account_id = models.CharField(max_length=100, blank=True)
    asset_id = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["file_id", "row"]
        indexes = [
            models.Index(fields=["run", "account_id", "asset_id"], name="rejected_scope"),
            models.Index(fields=["run", "asset_id"], name="rejected_asset"),
            models.Index(fields=["run", "alert_id"], name="rejected_alert"),
        ]


class CveRecord(models.Model):
    """One row per CVE, shared by every alert with that CVE."""

    cve = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    link = models.CharField(max_length=500, blank=True)


class PackageRecord(models.Model):
    key = models.UUIDField(unique=True)
    package = models.TextField(blank=True)
    current_version = models.TextField(blank=True)
    recommended_version = models.TextField(blank=True)
    package_path = models.TextField(blank=True)
    layer_id = models.TextField(blank=True)
    layer_instruction = models.TextField(blank=True)


class AlertContext(models.Model):
    """The image, runtime and business details shared by the alerts of one workload."""

    key = models.UUIDField(unique=True)
    asset_type = models.TextField(blank=True)
    instance = models.TextField(blank=True)
    cluster = models.TextField(blank=True)
    namespace = models.TextField(blank=True)
    repository = models.TextField(blank=True)
    registry = models.TextField(blank=True)
    image = models.TextField(blank=True)
    image_tag = models.TextField(blank=True)
    image_created = models.TextField(blank=True)
    os = models.TextField(blank=True)
    os_version = models.TextField(blank=True)
    os_end_of_life = models.TextField(blank=True)
    participating_firm = models.TextField(blank=True)
    country = models.TextField(blank=True)
    cms = models.TextField(blank=True)
    function = models.TextField(blank=True)
    app_service = models.TextField(blank=True)
    business_service = models.TextField(blank=True)
    department = models.TextField(blank=True)
    service_line = models.TextField(blank=True)
    data_classification = models.TextField(blank=True)
    data_qualification = models.TextField(blank=True)


class Asset(models.Model):
    """Tracks the newest scan per account + Asset ID, so an unchanged alert is not rewritten every week."""

    cloud_account = models.ForeignKey(CloudAccount, on_delete=models.CASCADE, related_name="assets")
    asset_id = models.CharField(max_length=500)
    last_scan = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["cloud_account", "asset_id"], name="unique_account_asset")]


class StagedAlert(models.Model):
    """A row waiting in a draft. The newest Last Scan wins for an Alert ID, and a later file wins a tie."""

    run = models.ForeignKey(ImportRun, on_delete=models.DO_NOTHING, db_constraint=False, related_name="staged_alerts")
    file = models.ForeignKey(ImportFile, on_delete=models.DO_NOTHING, db_constraint=False, related_name="+")
    row_number = models.PositiveIntegerField()
    alert_id = models.CharField(max_length=200)
    csb_id = models.CharField(max_length=100, blank=True)
    account_id = models.CharField(max_length=100)
    account_name = models.CharField(max_length=255)
    provider = models.CharField(max_length=30, blank=True)
    asset_id = models.CharField(max_length=500, blank=True)
    app_id = models.CharField(max_length=100, blank=True)
    environment = models.CharField(max_length=100, blank=True)
    severity = models.CharField(max_length=30, blank=True)
    severity_rank = models.SmallIntegerField(default=OTHER_SEVERITY_RANK)
    exception = models.BooleanField(default=False)
    ritm = models.CharField(max_length=100, blank=True)
    alert_opened = models.DateTimeField(null=True)
    slo_date = models.DateTimeField(null=True)
    last_scan = models.DateTimeField(null=True)
    cve_ref_id = models.BigIntegerField(null=True)
    package_ref_id = models.BigIntegerField(null=True)
    context_id = models.BigIntegerField(null=True)
    fingerprint = models.UUIDField()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["run", "alert_id"], name="unique_staged_alert_id")]


class PlannedRemediation(models.Model):
    """The preview list of alerts a draft would mark remediated."""

    run = models.ForeignKey(ImportRun, on_delete=models.DO_NOTHING, db_constraint=False, related_name="+")
    vulnerability = models.ForeignKey(
        "Vulnerability", on_delete=models.DO_NOTHING, db_constraint=False, related_name="+"
    )
    old_scan = models.DateTimeField(null=True)
    new_scan = models.DateTimeField()

    class Meta:
        indexes = [models.Index(fields=["run", "id"], name="planned_run")]


class VulnerabilityQuerySet(models.QuerySet):
    def browse(self):
        return self.select_related("cloud_account", "asset_ref", "cve_ref", "package_ref", "context")


FAR_FUTURE = datetime(9999, 1, 1, tzinfo=dt_timezone.utc)


class Vulnerability(models.Model):
    OPEN, REMEDIATED = "open", "remediated"
    STATUS_CHOICES = [(OPEN, "Open"), (REMEDIATED, "Remediated")]

    alert_id = models.CharField(max_length=200, unique=True)
    csb_id = models.CharField(max_length=100, blank=True)
    cloud_account = models.ForeignKey(
        CloudAccount, on_delete=models.PROTECT, db_index=False, related_name="vulnerabilities"
    )
    asset_ref = models.ForeignKey(Asset, null=True, blank=True, on_delete=models.PROTECT, db_index=False, related_name="+")
    cve_ref = models.ForeignKey(
        CveRecord, null=True, blank=True, on_delete=models.DO_NOTHING, db_constraint=False, db_index=False, related_name="+"
    )
    package_ref = models.ForeignKey(
        PackageRecord, null=True, blank=True, on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
        related_name="+",
    )
    context = models.ForeignKey(
        AlertContext, null=True, blank=True, on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
        related_name="+",
    )
    app_id = models.CharField("App ID from scan", max_length=100, blank=True, help_text="Blank when the scanner has none.")
    owner_app_id = models.CharField(max_length=100, null=True, blank=True)  # own App ID, else the account's assignment
    environment = models.CharField(max_length=100, blank=True)
    severity = models.CharField(max_length=30, blank=True)
    severity_rank = models.SmallIntegerField(default=OTHER_SEVERITY_RANK)
    exception = models.BooleanField(default=False)
    ritm = models.CharField("RITM number", max_length=100, blank=True)
    slo_date = models.DateTimeField(null=True, blank=True)
    slo_sort = models.DateTimeField(default=FAR_FUTURE)  # slo_date without NULLs, for stable paging
    last_scan = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=OPEN)
    first_seen = models.DateTimeField()
    remediated_at = models.DateTimeField(null=True, blank=True)
    remediated_import = models.ForeignKey(
        ImportRun, null=True, blank=True, on_delete=models.SET_NULL, db_index=False, related_name="remediated_vulns"
    )
    reopened_at = models.DateTimeField(null=True, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    fingerprint = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(default=timezone.now)

    objects = VulnerabilityQuerySet.as_manager()

    class Meta:
        indexes = [
            models.Index(fields=["owner_app_id", "status", "severity_rank", "slo_sort", "id"], name="vuln_owner_browse"),
            models.Index(fields=["cloud_account", "status", "severity_rank", "slo_sort", "id"], name="vuln_account_browse"),
            models.Index(fields=["asset_ref"], condition=Q(status="open"), name="vuln_open_asset"),
            models.Index(fields=["cve_ref", "status"], name="vuln_cve_status"),
            models.Index(
                fields=["remediated_import"], condition=Q(remediated_import__isnull=False), name="vuln_remediated_import"
            ),
        ]

    def __str__(self):
        return self.alert_id

    def _detail(self, relation, field):
        return getattr(relation, field, "") if relation is not None else ""

    @property
    def account_number(self):
        return self.cloud_account.account_id

    @property
    def account_name(self):
        return self.cloud_account.account_name

    @property
    def provider(self):
        return self.cloud_account.provider

    @property
    def asset_id(self):
        return self._detail(self.asset_ref, "asset_id")

    @property
    def cve(self):
        return self._detail(self.cve_ref, "cve")

    @property
    def cve_description(self):
        return self._detail(self.cve_ref, "description")

    @property
    def cve_link(self):
        return self._detail(self.cve_ref, "link")

    @property
    def package(self):
        return self._detail(self.package_ref, "package")

    @property
    def current_version(self):
        return self._detail(self.package_ref, "current_version")

    @property
    def recommended_version(self):
        return self._detail(self.package_ref, "recommended_version")

    @property
    def image(self):
        return self._detail(self.context, "image")

    @property
    def instance(self):
        return self._detail(self.context, "instance")

    @property
    def cluster(self):
        return self._detail(self.context, "cluster")

    @property
    def namespace(self):
        return self._detail(self.context, "namespace")

    @property
    def seen_scan(self):
        """An unchanged alert keeps its old last_scan; its asset holds the newest scan that still included it."""
        asset_scan = self.asset_ref.last_scan if self.asset_ref_id else None
        if self.status == self.OPEN and asset_scan and (not self.last_scan or asset_scan > self.last_scan):
            return asset_scan
        return self.last_scan

    @property
    def is_open(self):
        return self.status == self.OPEN

    @property
    def cve_url(self):
        link = safe_web_url(self.cve_link)
        if link:
            return link
        if self.cve.upper().startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{self.cve}"
        return ""

    @property
    def days_open(self):
        end = self.remediated_at if self.status == self.REMEDIATED and self.remediated_at else timezone.now()
        return max((end - self.first_seen).days, 0)

    @property
    def slo_overdue(self):
        return self.is_open and self.slo_date is not None and self.slo_date < timezone.now()

    def display_status(self, not_seen_cutoff):
        if self.status == self.REMEDIATED:
            return "Remediated"
        seen = self.seen_scan
        if seen and seen < not_seen_cutoff:
            return "Not seen"
        if self.reopened_at:
            return "Reopened"
        return "Open"


class AlertSummary(models.Model):
    """Precomputed counts, so pages never count millions of alerts. owner_app_id is blank when unassigned."""

    owner_app_id = models.CharField(max_length=100, blank=True)
    cloud_account = models.ForeignKey(
        CloudAccount, on_delete=models.DO_NOTHING, db_constraint=False, related_name="summaries"
    )
    provider = models.CharField(max_length=30, blank=True)
    environment = models.CharField(max_length=100, blank=True)
    severity = models.CharField(max_length=30, blank=True)
    exception = models.BooleanField(default=False)
    status = models.CharField(max_length=12)
    total = models.BigIntegerField(default=0)
    tagged = models.BigIntegerField(default=0)
    past_slo = models.BigIntegerField(default=0)
    untagged_past_slo = models.BigIntegerField(default=0)
    not_seen = models.BigIntegerField(default=0)
    reopened = models.BigIntegerField(default=0)
    recent_remediated = models.BigIntegerField(default=0)
    fix_seconds = models.BigIntegerField(default=0)
    fix_count = models.BigIntegerField(default=0)

    class Meta:
        indexes = [models.Index(fields=["owner_app_id", "status"], name="summary_owner")]


class Job(models.Model):
    """Background work run by the worker service: imports, summaries, large assignments and bulk emails."""

    QUEUED, RUNNING, DONE, FAILED = "queued", "running", "done", "failed"
    STATUS_CHOICES = [(QUEUED, "Queued"), (RUNNING, "Running"), (DONE, "Done"), (FAILED, "Failed")]

    kind = models.CharField(max_length=20)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=QUEUED)
    payload = models.JSONField(default=dict, blank=True)
    message = models.TextField(blank=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["id"]
        indexes = [models.Index(fields=["status", "id"], name="job_queue")]


CONTAINERS, SERVERS = "containers", "servers"
MODULE_CHOICES = [(CONTAINERS, "Containers"), (SERVERS, "Servers")]


class FollowUp(models.Model):
    """One notification cycle for an application: support first, then escalation to the owner if needed.

    Container and server vulnerabilities each have their own follow-up.
    """

    WAITING, RESPONDED, ESCALATED, CLOSED = "waiting", "responded", "escalated", "closed"
    STATUS_CHOICES = [
        (WAITING, "Awaiting response"), (RESPONDED, "Responded"), (ESCALATED, "Escalated"), (CLOSED, "Closed"),
    ]

    application = models.ForeignKey(
        Application, null=True, blank=True, on_delete=models.SET_NULL, related_name="follow_ups"
    )
    app_id = models.CharField(max_length=100, db_index=True)
    module = models.CharField(max_length=10, choices=MODULE_CHOICES, default=CONTAINERS, db_default=CONTAINERS)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=WAITING, db_index=True)
    opened_at = models.DateTimeField(default=timezone.now)
    opened_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    waiting_since = models.DateTimeField(default=timezone.now, help_text="Reminders do not reset this.")
    first_vuln_count = models.PositiveIntegerField(default=0)
    reminder_count = models.PositiveIntegerField(default=0)
    escalated_at = models.DateTimeField(null=True, blank=True)
    escalated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    closed_at = models.DateTimeField(null=True, blank=True)
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        ordering = ["-opened_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["application", "module"], condition=~Q(status="closed"), name="one_open_follow_up_per_module"
            ),
        ]

    def __str__(self):
        return f"Follow-up #{self.pk} ({self.app_id})"

    @property
    def is_open(self):
        return self.status != self.CLOSED

    @property
    def is_waiting(self):
        return self.status in (self.WAITING, self.ESCALATED)

    def is_overdue(self, cutoff):
        return self.is_waiting and self.waiting_since < cutoff

    @property
    def is_servers(self):
        return self.module == SERVERS


class Notification(models.Model):
    SENT, FAILED = "sent", "failed"
    STATUS_CHOICES = [(SENT, "Sent"), (FAILED, "Failed")]
    DIRECT, SUPPORT, REMINDER, ESCALATION = "direct", "support", "reminder", "escalation"
    KIND_CHOICES = [
        (DIRECT, "Direct"), (SUPPORT, "To support"), (REMINDER, "Reminder"), (ESCALATION, "Escalation"),
    ]

    app_id = models.CharField(max_length=100, db_index=True)
    application = models.ForeignKey(Application, null=True, blank=True, on_delete=models.SET_NULL)
    module = models.CharField(max_length=10, choices=MODULE_CHOICES, default=CONTAINERS, db_default=CONTAINERS)
    sent_at = models.DateTimeField(auto_now_add=True)
    sent_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    follow_up = models.ForeignKey(
        FollowUp, null=True, blank=True, on_delete=models.SET_NULL, related_name="notifications"
    )
    kind = models.CharField(max_length=10, choices=KIND_CHOICES, default=DIRECT)
    recipients = models.TextField(blank=True)
    cc = models.TextField(blank=True)
    subject = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    error = models.TextField(blank=True)
    vuln_count = models.PositiveIntegerField(default=0)
    past_slo_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-sent_at"]


class FollowUpEvent(models.Model):
    SENT, REMINDER, ESCALATED, RESPONSE, REMARK, CLOSED = "sent", "reminder", "escalated", "response", "remark", "closed"
    KIND_CHOICES = [
        (SENT, "Sent to support"), (REMINDER, "Reminder sent"), (ESCALATED, "Escalated to owner"),
        (RESPONSE, "Response recorded"), (REMARK, "Remark"), (CLOSED, "Closed"),
    ]

    follow_up = models.ForeignKey(FollowUp, on_delete=models.CASCADE, related_name="events")
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    remark = models.TextField(blank=True)
    include_in_email = models.BooleanField(default=False)
    notification = models.ForeignKey(Notification, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    responder = models.CharField(max_length=200, blank=True)
    responded_on = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]


class LegacyUpload(models.Model):
    """Uploads recorded before import runs existed (kept for history only)."""

    filename = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField()
    uploaded_by = models.CharField(max_length=255, blank=True)
    rows = models.PositiveIntegerField(default=0)
    note = models.TextField(blank=True)

    class Meta:
        ordering = ["-uploaded_at"]


class ContactImport(models.Model):
    """One uploaded contacts file. Nothing reaches Application until the preview is applied."""

    PREVIEW, APPLIED = "preview", "applied"

    filename = models.CharField(max_length=255)
    status = models.CharField(max_length=10, default=PREVIEW)
    new_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    unchanged_count = models.PositiveIntegerField(default=0)
    rejected_count = models.PositiveIntegerField(default=0)
    duplicate_count = models.PositiveIntegerField(default=0)
    not_in_scans_count = models.PositiveIntegerField(default=0)
    team_email_removed_count = models.PositiveIntegerField(default=0)
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
    def change_count(self):
        return self.new_count + self.updated_count


class ContactImportRow(models.Model):
    NEW, UPDATED, UNCHANGED, REJECTED = "new", "updated", "unchanged", "rejected"

    contact_import = models.ForeignKey(ContactImport, on_delete=models.CASCADE, related_name="rows")
    row_number = models.PositiveIntegerField()
    app_id = models.CharField(max_length=100, blank=True)
    action = models.CharField(max_length=10)
    changes = models.JSONField(default=dict, blank=True)  # {field: [old, new]}
    cells = models.JSONField(default=dict, blank=True)  # the original cells, kept for rejected rows
    reason = models.TextField(blank=True)
    not_in_scans = models.BooleanField(default=False)

    class Meta:
        ordering = ["row_number", "id"]
        indexes = [models.Index(fields=["contact_import", "action", "row_number"], name="contact_row_browse")]

    def change_list(self):
        return [(CONTACT_LABELS[key], *self.changes[key]) for key in CONTACT_FIELDS if key in self.changes]
