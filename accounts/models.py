from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class Role(models.Model):
    ADMINISTRATOR = "administrator"
    OPERATION = "operation"
    USER = "user"

    DEFAULTS = [
        (
            ADMINISTRATOR,
            "Administrator",
            "Can manage all the settings, update application details, upload the data and send email notifications.",
        ),
        (
            OPERATION,
            "Operation",
            "Can only view the dashboard, application details and the vulnerabilities of each application / App ID.",
        ),
        (
            USER,
            "User",
            "Can only view the applications / App IDs tied to their email, including their vulnerabilities. "
            "The dashboard shows only their applications.",
        ),
    ]

    key = models.SlugField(unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        return self.name

    @classmethod
    def ensure_defaults(cls):
        for key, name, description in cls.DEFAULTS:
            cls.objects.update_or_create(key=key, defaults={"name": name, "description": description})


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra):
        if not email:
            raise ValueError("An email address is required")
        user = self.model(email=self.normalize_email(email).lower(), **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra):
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra)

    def create_superuser(self, email, password=None, **extra):
        extra["is_staff"] = True
        extra["is_superuser"] = True
        return self._create_user(email, password, **extra)

    def get_by_natural_key(self, username):
        return self.get(email__iexact=username)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=150, blank=True)
    role = models.ForeignKey(Role, null=True, blank=True, on_delete=models.SET_NULL, related_name="users")
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    must_change_password = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    objects = UserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        ordering = ["email"]

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        self.email = (self.email or "").strip().lower()
        super().save(*args, **kwargs)

    def get_full_name(self):
        return self.full_name or self.email

    def get_short_name(self):
        return self.full_name or self.email

    @property
    def display_name(self):
        return self.full_name or self.email

    @property
    def role_key(self):
        return self.role.key if self.role_id else None

    @property
    def is_superadmin(self):
        return self.is_superuser

    @property
    def is_admin(self):
        return self.is_superuser or self.role_key == Role.ADMINISTRATOR

    @property
    def can_view_all(self):
        """Administrators and Operation see every App ID; the User role sees only its own apps."""
        return self.is_admin or self.role_key == Role.OPERATION
