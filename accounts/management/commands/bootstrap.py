import os

from django.core.management.base import BaseCommand

from accounts.models import Role, User
from core.models import AppSettings, EmailSettings


class Command(BaseCommand):
    help = "Create default roles, settings and the first superadmin account (idempotent)."

    def handle(self, *args, **options):
        Role.ensure_defaults()
        AppSettings.load()
        self._seed_email_settings()

        email = os.environ.get("SUPERADMIN_EMAIL", "").strip().lower()
        password = os.environ.get("SUPERADMIN_PASSWORD", "")
        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write("Superadmin already exists.")
            return
        if not (email and password):
            self.stdout.write(self.style.WARNING("No superadmin yet: set SUPERADMIN_EMAIL and SUPERADMIN_PASSWORD."))
            return
        User.objects.create_superuser(
            email=email,
            password=password,
            full_name="Super Admin",
            role=Role.objects.get(key=Role.ADMINISTRATOR),
            must_change_password=True,
        )
        self.stdout.write(self.style.SUCCESS(f"Superadmin {email} created (password change required at first login)."))

    def _seed_email_settings(self):
        cfg = EmailSettings.load()
        host = os.environ.get("HERALD_SMTP_HOST", "").strip()
        if cfg.host or not host:
            return
        cfg.host = host
        cfg.port = int(os.environ.get("HERALD_SMTP_PORT", "587"))
        security = os.environ.get("HERALD_SMTP_SECURITY", EmailSettings.STARTTLS)
        cfg.security = security if security in dict(EmailSettings.SECURITY_CHOICES) else EmailSettings.STARTTLS
        cfg.sender = os.environ.get("HERALD_SMTP_SENDER", "")
        cfg.save()
        self.stdout.write(f"Email settings pre-filled with SMTP host {host}.")
