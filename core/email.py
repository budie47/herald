from django.conf import settings
from django.core.mail.backends.smtp import EmailBackend


class EmailNotConfigured(Exception):
    pass


class DatabaseEmailBackend(EmailBackend):
    """SMTP backend that reads its configuration from Settings > Email."""

    def __init__(self, fail_silently=False, **kwargs):
        from core.models import EmailSettings

        self.config = EmailSettings.load()
        cfg = self.config
        super().__init__(
            host=cfg.host or "localhost",
            port=cfg.port,
            username=cfg.username or "",
            password=cfg.get_password(),
            use_tls=cfg.security == EmailSettings.STARTTLS,
            use_ssl=cfg.security == EmailSettings.SSL,
            timeout=30,
            fail_silently=fail_silently,
            **kwargs,
        )

    def send_messages(self, email_messages):
        if not self.config.is_configured:
            if self.fail_silently:
                return 0
            raise EmailNotConfigured("The SMTP server is not configured (Settings > Email).")
        for message in email_messages:
            if not message.from_email or message.from_email == settings.DEFAULT_FROM_EMAIL:
                message.from_email = self.config.sender
        return super().send_messages(email_messages)
