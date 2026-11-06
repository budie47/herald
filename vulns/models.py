import re

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone


class Application(models.Model):
    app_id = models.CharField("App ID", max_length=100, unique=True)
    name = models.CharField(max_length=200, blank=True)
    owner_name = models.CharField(max_length=200, blank=True)
    owner_email = models.EmailField(blank=True)
    extra_emails = models.TextField(
        "Extra notification emails", blank=True, help_text="Separate with commas, semicolons or new lines."
    )
    business_service = models.CharField(max_length=200, blank=True)
    department = models.CharField(max_length=200, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["app_id"]

    def __str__(self):
        return self.app_id

    def extra_email_list(self):
        return [e for e in re.split(r"[,;\s]+", self.extra_emails or "") if e]

    def recipients(self):
        """Owner plus extra emails, duplicates removed (case-insensitive), order kept."""
        seen, result = set(), []
        for email in [self.owner_email, *self.extra_email_list()]:
            email = (email or "").strip()
            if email and email.lower() not in seen:
                seen.add(email.lower())
                result.append(email)
        return result

    @property
    def has_email(self):
        return bool(self.recipients())


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


class ImportFile(models.Model):
    run = models.ForeignKey(ImportRun, on_delete=models.CASCADE, related_name="files")
    filename = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    header_row = models.PositiveIntegerField(default=1)
    rows_read = models.PositiveIntegerField(default=0)
    accepted = models.PositiveIntegerField(default=0)
    rejected = models.PositiveIntegerField(default=0)
    errors = models.JSONField(default=list, blank=True)  # [{"row", "reason", "alert_id", "asset_id"}]
    unknown_columns = models.JSONField(default=list, blank=True)
    missing_columns = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["id"]


class StagedRow(models.Model):
    """A row waiting in a draft import. A later file replaces an earlier row with the same Alert ID."""

    run = models.ForeignKey(ImportRun, on_delete=models.CASCADE, related_name="staged_rows")
    file = models.ForeignKey(ImportFile, on_delete=models.CASCADE, related_name="staged_rows")
    row_number = models.PositiveIntegerField()
    alert_id = models.CharField(max_length=200)
    app_id = models.CharField(max_length=100)
    asset_id = models.CharField(max_length=500, blank=True)
    last_scan = models.DateTimeField(null=True, blank=True)
    data = models.JSONField(default=dict)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["run", "alert_id"], name="unique_staged_alert")]


class Vulnerability(models.Model):
    OPEN, REMEDIATED = "open", "remediated"
    STATUS_CHOICES = [(OPEN, "Open"), (REMEDIATED, "Remediated")]

    alert_id = models.CharField(max_length=200, unique=True)
    app_id = models.CharField(max_length=100, db_index=True)
    asset_id = models.CharField(max_length=500, blank=True, db_index=True)
    asset_name = models.CharField(max_length=500, blank=True)
    image = models.CharField(max_length=500, blank=True)
    cluster = models.CharField(max_length=255, blank=True)
    namespace = models.CharField(max_length=255, blank=True)
    environment = models.CharField(max_length=100, blank=True, db_index=True)
    cve = models.CharField(max_length=100, blank=True, db_index=True)
    cve_description = models.TextField(blank=True)
    cve_link = models.CharField(max_length=500, blank=True)
    severity = models.CharField(max_length=30, blank=True, db_index=True)
    package = models.CharField(max_length=255, blank=True)
    current_version = models.CharField(max_length=255, blank=True)
    recommended_version = models.CharField(max_length=255, blank=True)
    exception = models.BooleanField(default=False)
    exception_reason = models.TextField(blank=True)
    ritm = models.CharField("RITM number", max_length=100, blank=True)
    slo_date = models.DateTimeField(null=True, blank=True)
    last_scan = models.DateTimeField(null=True, blank=True)
    data = models.JSONField(default=dict, blank=True)

    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=OPEN, db_index=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    remediated_at = models.DateTimeField(null=True, blank=True)
    remediated_import = models.ForeignKey(
        ImportRun, null=True, blank=True, on_delete=models.SET_NULL, related_name="remediated_vulns"
    )
    reopened_at = models.DateTimeField(null=True, blank=True)
    created_import = models.ForeignKey(ImportRun, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    updated_import = models.ForeignKey(ImportRun, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [models.Index(fields=["app_id", "status"])]

    def __str__(self):
        return self.alert_id

    @property
    def is_open(self):
        return self.status == self.OPEN

    @property
    def cve_url(self):
        if self.cve_link:
            return self.cve_link
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
        if self.last_scan and self.last_scan < not_seen_cutoff:
            return "Not seen"
        if self.reopened_at:
            return "Reopened"
        return "Open"


class Notification(models.Model):
    SENT, FAILED = "sent", "failed"
    STATUS_CHOICES = [(SENT, "Sent"), (FAILED, "Failed")]

    app_id = models.CharField(max_length=100, db_index=True)
    application = models.ForeignKey(Application, null=True, blank=True, on_delete=models.SET_NULL)
    sent_at = models.DateTimeField(auto_now_add=True)
    sent_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    recipients = models.TextField(blank=True)
    subject = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    error = models.TextField(blank=True)
    vuln_count = models.PositiveIntegerField(default=0)
    past_slo_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-sent_at"]


class LegacyUpload(models.Model):
    """Uploads recorded before import runs existed (kept for history only)."""

    filename = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField()
    uploaded_by = models.CharField(max_length=255, blank=True)
    rows = models.PositiveIntegerField(default=0)
    note = models.TextField(blank=True)

    class Meta:
        ordering = ["-uploaded_at"]
