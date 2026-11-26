import os
import sys
import tempfile
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env_list(name, default=""):
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]


def env_flag(name):
    return os.environ.get(name, "0").strip().lower() in ("1", "true", "yes", "on")


# Defaults this project has published. They are not secrets, so production refuses them.
KNOWN_SECRET_KEYS = {"dev-insecure-change-me", "change-me-in-production", "replace-with-a-long-random-string"}

DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not DEBUG and "test" not in sys.argv and (not SECRET_KEY.strip() or SECRET_KEY in KNOWN_SECRET_KEYS):
    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY is missing or still a published placeholder. Set it to a long random value in .env, "
        "for example the output of: openssl rand -hex 32"
    )
SECRET_KEY = SECRET_KEY or "dev-insecure-change-me"
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")
SITE_URL = os.environ.get("HERALD_SITE_URL", "http://localhost:8000").rstrip("/")

# HTTPS. Everything is off by default so a plain-HTTP install keeps working (see "Running behind HTTPS" in the README).
if env_flag("DJANGO_SECURE_PROXY_SSL_HEADER"):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_SECURE = env_flag("DJANGO_SESSION_COOKIE_SECURE")
CSRF_COOKIE_SECURE = env_flag("DJANGO_CSRF_COOKIE_SECURE")
SECURE_SSL_REDIRECT = env_flag("DJANGO_SECURE_SSL_REDIRECT")
SECURE_HSTS_SECONDS = int(os.environ.get("DJANGO_SECURE_HSTS_SECONDS") or 0)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_flag("DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS")
SECURE_HSTS_PRELOAD = env_flag("DJANGO_SECURE_HSTS_PRELOAD")
if SECURE_SSL_REDIRECT and not env_flag("DJANGO_SECURE_PROXY_SSL_HEADER"):
    # Herald itself serves plain HTTP, so without the proxy header every request would redirect forever.
    raise ImproperlyConfigured("DJANGO_SECURE_SSL_REDIRECT needs DJANGO_SECURE_PROXY_SSL_HEADER=1.")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "accounts",
    "core",
    "vulns",
    "servers",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "accounts.middleware.ForcePasswordChangeMiddleware",
]

ROOT_URLCONF = "herald.urls"
WSGI_APPLICATION = "herald.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "core.context_processors.herald",
            ],
        },
    },
]

if os.environ.get("POSTGRES_HOST"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "HOST": os.environ["POSTGRES_HOST"],
            "PORT": os.environ.get("POSTGRES_PORT", "5432"),
            "NAME": os.environ.get("POSTGRES_DB", "herald"),
            "USER": os.environ.get("POSTGRES_USER", "herald"),
            "PASSWORD": os.environ.get("POSTGRES_PASSWORD", ""),
        }
    }
else:
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"
PASSWORD_RESET_TIMEOUT = 60 * 60 * 24

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Outgoing mail uses the SMTP server configured in Settings > Email (stored in the database).
EMAIL_BACKEND = "core.email.DatabaseEmailBackend"
DEFAULT_FROM_EMAIL = "herald@localhost"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

MESSAGE_STORAGE = "django.contrib.messages.storage.session.SessionStorage"
UPLOAD_MAX_BYTES = 512 * 1024 * 1024
HERALD_UPLOAD_DIR = os.environ.get("HERALD_UPLOAD_DIR", str(Path(tempfile.gettempdir()) / "herald-uploads"))
FILE_UPLOAD_TEMP_DIR = os.environ.get("HERALD_UPLOAD_DIR") or None
HERALD_JOBS_EAGER = "test" in sys.argv  # tests run background jobs inline

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
