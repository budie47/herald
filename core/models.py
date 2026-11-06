from django.db import models

from .crypto import decrypt, encrypt


class SingletonModel(models.Model):
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class AppSettings(SingletonModel):
    not_seen_days = models.PositiveIntegerField(
        default=90, help_text="Open vulnerabilities whose asset has not been rescanned for this many days are flagged Not seen."
    )
    slo_critical_days = models.PositiveIntegerField(default=15, verbose_name="SLO days: Critical")
    slo_high_days = models.PositiveIntegerField(default=30, verbose_name="SLO days: High")
    slo_medium_days = models.PositiveIntegerField(default=90, verbose_name="SLO days: Medium")
    slo_low_days = models.PositiveIntegerField(default=180, verbose_name="SLO days: Low")

    def slo_days(self, severity):
        """Used only when the scan data has no SLO Date."""
        return {
            "Critical": self.slo_critical_days,
            "High": self.slo_high_days,
            "Medium": self.slo_medium_days,
            "Low": self.slo_low_days,
        }.get(severity)


class EmailSettings(SingletonModel):
    STARTTLS = "starttls"
    SSL = "ssl"
    NONE = "none"
    SECURITY_CHOICES = [(STARTTLS, "STARTTLS"), (SSL, "SSL/TLS"), (NONE, "None")]

    host = models.CharField("SMTP server", max_length=255, blank=True)
    port = models.PositiveIntegerField(default=587)
    security = models.CharField(max_length=10, choices=SECURITY_CHOICES, default=STARTTLS)
    username = models.CharField(max_length=255, blank=True)
    password_encrypted = models.TextField(blank=True)
    sender = models.CharField(max_length=255, blank=True, help_text='e.g. "Herald <herald@example.com>"')
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_configured(self):
        return bool(self.host and self.sender)

    @property
    def has_password(self):
        return bool(self.password_encrypted)

    def set_password(self, raw):
        self.password_encrypted = encrypt(raw)

    def get_password(self):
        return decrypt(self.password_encrypted)
