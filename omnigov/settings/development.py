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

# Allow ngrok tunnels for public sharing
CSRF_TRUSTED_ORIGINS = ['https://*.ngrok-free.app', 'https://*.ngrok.io']
ALLOWED_HOSTS = ['*']

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

# Use console email backend in dev (prints OTP to terminal instead of sending)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

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
    },
}
