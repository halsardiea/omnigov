# ---
# LOCATION : omnigov/settings/base.py
# PURPOSE  : Shared configuration that every environment (development, production,
#            container) inherits. Anything that must be consistent across all
#            deployments lives here. Environment-specific overrides go in
#            development.py or production.py.
#
# CONNECTS TO:
#   - omnigov/settings/development.py  → imports everything from here via 'from .base import *'
#                                         and overrides DATABASE, CHANNEL_LAYERS, LOGGING
#   - omnigov/settings/production.py   → same pattern; adds HTTPS/HSTS settings and
#                                         replaces ALLOWED_HOSTS with an env-driven list
#   - omnigov/asgi.py                  → ASGI_APPLICATION points to the Channels router
#   - omnigov/celery.py                → reads CELERY_* settings from this module
#   - omnigov/middleware.py            → registered in MIDDLEWARE list here
#   - apps/accounts/models.py          → AUTH_USER_MODEL = 'accounts.User' set here
#   - apps/interceptor/correlation.py  → ANTHROPIC_API_KEY and AI_CORRELATION_* read here
#   - apps/scanner/gvm_client.py       → GVM_* settings read here
# ---
import os
from pathlib import Path
from decouple import config, Csv
from django.core.exceptions import ImproperlyConfigured


def _require_env(var_name):
    """Read a required environment variable — crash at startup if it is missing.

    This prevents the server from ever starting with a dangerously weak default.
    Failing loudly at boot is safer than silently running with broken credentials.
    """
    value = config(var_name, default='')
    if not value:
        raise ImproperlyConfigured(
            f"Required environment variable '{var_name}' is not set. "
            "Add it to your .env file before starting the server."
        )
    return value

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Security

# No default allowed — a weak secret key breaks session signing, CSRF tokens,
# and password reset links. The server must not start without an explicit value.
SECRET_KEY = _require_env('DJANGO_SECRET_KEY')

# Safe default is OFF — a developer must explicitly set DJANGO_DEBUG=True in .env.
# Accidentally running DEBUG=True in production exposes stack traces and DB queries.
DEBUG = config('DJANGO_DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=Csv())

# Application definition
INSTALLED_APPS = [
    # Django built-in
    'daphne',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third-party
    'rest_framework',
    'channels',
    'django_celery_results',
    # Local apps
    'apps.accounts',
    'apps.scanner',
    'apps.interceptor',
    'apps.compliance',
    'apps.reports',
    'apps.dashboard',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'omnigov.middleware.NoStoreAuthenticatedPagesMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'omnigov.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'omnigov.wsgi.application'
ASGI_APPLICATION = 'omnigov.asgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME', default='omnigov'),
        'USER': config('DB_USER', default='omnigov'),
        # No default — PostgreSQL will refuse to connect with a blank password,
        # which is intentional. Never silently connect with a known default credential.
        'PASSWORD': config('DB_PASSWORD', default=''),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
    }
}

# Custom User Model
AUTH_USER_MODEL = 'accounts.User'

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Authentication
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/accounts/login/'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# Session expires after 1 hour — reduces the attack window if a session token is stolen
SESSION_COOKIE_AGE = 3600

# Session ends when the browser closes — prevents reuse on shared or borrowed computers
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

CSRF_COOKIE_SAMESITE = 'Lax'

# CSRF cookie is not readable by JavaScript — prevents token theft via XSS injection
CSRF_COOKIE_HTTPONLY = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Amman'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default auto field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ============================================================
# Django Channels (WebSocket)
# ============================================================
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [config('REDIS_URL', default='redis://localhost:6379/0')],
        },
    },
}

# ============================================================
# Celery Configuration
# ============================================================
CELERY_BROKER_URL = config('REDIS_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = 'django-db'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# ============================================================
# Django REST Framework
# ============================================================
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

# ============================================================
# Redis Cache
# ============================================================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': config('REDIS_URL', default='redis://localhost:6379/0'),
    }
}

# ============================================================
# OmniGov Custom Settings
# ============================================================

# GVM / OpenVAS
GVM_HOST = config('GVM_HOST', default='localhost')
GVM_PORT = config('GVM_PORT', default=9390, cast=int)
# Unix socket path — used on Linux (Kali/Debian GVM package default).
# Set to empty string '' to force TCP connection instead.
GVM_SOCKET_PATH = config('GVM_SOCKET_PATH', default='/run/gvmd/gvmd.sock')
# No defaults — GVM authentication will fail loudly if these are blank.
# This forces explicit credential management instead of leaving GVM at the
# factory-default 'admin/admin' that every attacker knows.
GVM_ADMIN_USER = config('GVM_ADMIN_USER', default='')
GVM_ADMIN_PASSWORD = config('GVM_ADMIN_PASSWORD', default='')
GVM_USE_MOCK = config('GVM_USE_MOCK', default=True, cast=bool)


# Site
SITE_DOMAIN = config('SITE_DOMAIN', default='localhost:8000')
SITE_NAME = config('SITE_NAME', default='OmniGov')

# Scan settings
MAX_CONCURRENT_SCANS = 3
SCAN_POLL_INTERVAL = 10  # seconds

# Correlation / AI enrichment (Claude via Anthropic API)
# Set ANTHROPIC_API_KEY to activate AI-backed refinement; leave blank for deterministic heuristic-only mode.
ANTHROPIC_API_KEY = config('ANTHROPIC_API_KEY', default='')
AI_CORRELATION_MODEL = config('AI_CORRELATION_MODEL', default='claude-3-5-haiku-20241022')
AI_CORRELATION_MAX_CANDIDATES = config('AI_CORRELATION_MAX_CANDIDATES', default=8, cast=int)
AI_CORRELATION_TOP_MATCHES = config('AI_CORRELATION_TOP_MATCHES', default=3, cast=int)

# ============================================================
# Audit Logging
# ============================================================
# Create the logs directories at startup so file handlers never fail on first write.
os.makedirs(BASE_DIR / 'logs', exist_ok=True)
os.makedirs(BASE_DIR / 'logs' / 'ai', exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{asctime} {levelname} {name} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        # Security events (failed logins, rejected WebSocket connections, scan audit)
        # are written to a dedicated rotating file so they can be reviewed independently
        # of the general application log or shipped to a SIEM.
        'security_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'security.log',
            'maxBytes': 10 * 1024 * 1024,  # rotate at 10 MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        # AI correlation events (Claude API calls, heuristic scoring, framework alignment)
        # are isolated here so they can be audited separately from app and security logs.
        'ai_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'ai' / 'correlation.log',
            'maxBytes': 10 * 1024 * 1024,  # rotate at 10 MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'apps': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        # django.security captures Django's own security events (CSRF failures,
        # SuspiciousOperation, etc.) plus our custom security_logger entries.
        'django.security': {
            'handlers': ['console', 'security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        # AI/Claude correlation module — logs separately so every API call,
        # heuristic match, and scoring decision is traceable in logs/ai/.
        'apps.interceptor.correlation': {
            'handlers': ['console', 'ai_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
