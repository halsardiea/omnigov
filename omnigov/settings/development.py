# ---
# LOCATION : omnigov/settings/development.py
# PURPOSE  : Overrides for local development — swaps out every component that
#            requires infrastructure (PostgreSQL → SQLite, Redis → in-memory,
#            Celery async → synchronous eager mode) so the project runs on a
#            single laptop without Docker.
#            This file must NEVER be used in production.
#
# CONNECTS TO:
#   - omnigov/settings/base.py     → 'from .base import *' pulls in all shared settings
#   - omnigov/asgi.py              → reads DJANGO_SETTINGS_MODULE at startup
#   - apps/scanner/gvm_client.py   → GVM_USE_MOCK (defined in base.py, default True)
#                                    controls whether mock or real GVM is used
# ---
"""
Development settings — overrides base.py for local development.

Runs entirely without Docker:
- SQLite instead of PostgreSQL
- In-memory channel layer instead of Redis
- Locmem cache instead of Redis cache
- Celery eager mode (tasks run synchronously)
"""
from pathlib import Path
from .base import *  # noqa: F401,F403

DEBUG = True

# Allow ngrok tunnels for sharing local dev builds — development environments ONLY.
# This setting must never appear in production.py or base.py.
CSRF_TRUSTED_ORIGINS = ['https://*.ngrok-free.app', 'https://*.ngrok.io']
ALLOWED_HOSTS = ['*']

# Explicitly disable HTTPS redirect in development — prevents redirect loops
# when running over plain HTTP on localhost.
SECURE_SSL_REDIRECT = False

# ============================================================
# SQLite — no Docker / PostgreSQL needed for local dev
# ============================================================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ============================================================
# In-memory channel layer — no Redis needed
# ============================================================
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    },
}

# ============================================================
# Locmem cache — no Redis needed
# ============================================================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'omnigov-dev',
    }
}

# ============================================================
# Celery — eager mode, tasks execute synchronously
# ============================================================
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = 'memory://'
CELERY_RESULT_BACKEND = 'cache+memory://'

# AI correlation uses the key from .env — real Claude calls enabled

# Explicit local placeholders: direct password auth, no OTP.
# Verbose logging
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
        'security_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'security.log',
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'ai_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'ai' / 'correlation.log',
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'apps': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        # Security events go to both console and security.log in development
        # so failed login attempts and rejections are visible during testing.
        'django.security': {
            'handlers': ['console', 'security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        # AI correlation events are mirrored to console in dev for easy inspection.
        'apps.interceptor.correlation': {
            'handlers': ['console', 'ai_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
