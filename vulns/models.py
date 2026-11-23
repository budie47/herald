import re

from django.conf import settings
from django.db import models
from django.db.models import CharField, F, Q, Value
from django.db.models.functions import Coalesce, NullIf
from django.utils import timezone


def split_emails(value):
    return [e for e in re.split(r"[,;\s]+", value or "") if e]


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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["account_name", "account_id"]

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
    app_id = models.CharField(max_length=100, blank=True)
    asset_id = models.CharField(max_length=500, blank=True)
    last_scan = models.DateTimeField(null=True, blank=True)
    data = models.JSONField(default=dict)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["run", "alert_id"], name="unique_staged_alert")]

    @property
    def account_id(self):
        return self.data["account_id"]


class VulnerabilityQuerySet(models.QuerySet):
    def with_owner(self):
        """owner_app_id: the alert's own App ID, else its account's assigned App ID, else NULL (unassigned)."""
        return self.annotate(
            owner_app_id=Coalesce(
                NullIf("app_id", Value("")), F("cloud_account__application__app_id"), output_field=CharField()
            )
        )


class Vulnerability(models.Model):
    OPEN, REMEDIATED = "open", "remediated"
    STATUS_CHOICES = [(OPEN, "Open"), (REMEDIATED, "Remediated")]

    alert_id = models.CharField(max_length=200, unique=True)
    cloud_account = models.ForeignKey(CloudAccount, on_delete=models.PROTECT, related_name="vulnerabilities")
    app_id = models.CharField(
        "App ID from scan", max_length=100, blank=True, db_index=True, help_text="Blank when the scanner has no App ID."
    )
    asset_id = models.CharField(max_length=500, blank=True, db_index=True)
    instance = models.CharField(max_length=255, blank=True)
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

    objects = VulnerabilityQuerySet.as_manager()

    class Meta:
        indexes = [models.Index(fields=["app_id", "status"])]

    def __str__(self):
        return self.alert_id

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


class FollowUp(models.Model):
    """One notification cycle for an application: support first, then escalation to the owner if needed."""

    WAITING, RESPONDED, ESCALATED, CLOSED = "waiting", "responded", "escalated", "closed"
    STATUS_CHOICES = [
        (WAITING, "Awaiting response"), (RESPONDED, "Responded"), (ESCALATED, "Escalated"), (CLOSED, "Closed"),
    ]

    application = models.ForeignKey(
        Application, null=True, blank=True, on_delete=models.SET_NULL, related_name="follow_ups"
    )
    app_id = models.CharField(max_length=100, db_index=True)
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
                fields=["application"], condition=~Q(status="closed"), name="one_open_follow_up_per_application"
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


class Notification(models.Model):
    SENT, FAILED = "sent", "failed"
    STATUS_CHOICES = [(SENT, "Sent"), (FAILED, "Failed")]
    DIRECT, SUPPORT, REMINDER, ESCALATION = "direct", "support", "reminder", "escalation"
    KIND_CHOICES = [
        (DIRECT, "Direct"), (SUPPORT, "To support"), (REMINDER, "Reminder"), (ESCALATION, "Escalation"),
    ]

    app_id = models.CharField(max_length=100, db_index=True)
    application = models.ForeignKey(Application, null=True, blank=True, on_delete=models.SET_NULL)
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
