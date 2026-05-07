"""
Container settings — used when running inside Docker.

Inherits everything from base.py and overrides only what
changes when running inside a container (no SSL, host DB/Redis,
real GVM via socket, etc.).
"""

from .base import *  # noqa: F401, F403

# ── Security ────────────────────────────────────────────────
# DEBUG=True so Django serves static files directly (no nginx)
DEBUG = True
ALLOWED_HOSTS = ['*']

# Allow the browser to reach the app over plain HTTP
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0

CSRF_TRUSTED_ORIGINS = [
    'http://localhost:8000',
    'http://127.0.0.1:8000',
]

# ── GVM ─────────────────────────────────────────────────────
# Always use real GVM in Docker (socket is provided by gvmd container)
GVM_USE_MOCK = False


# ── Logging ─────────────────────────────────────────────────
# Everything goes to stdout so `docker compose logs` works
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
            'level': 'INFO',
            'propagate': False,
        },
    },
}
