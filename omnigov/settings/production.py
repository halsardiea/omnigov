# ---
# LOCATION : omnigov/settings/production.py
# PURPOSE  : Production-only hardening that is never active during development.
#            Enables HTTPS-only cookies, HSTS preloading, ALLOWED_HOSTS enforcement,
#            and routes all logs to rotating file handlers.
#            All sensitive values (ALLOWED_HOSTS, CSRF origins) are read from
#            environment variables — no hardcoded strings here.
#
# CONNECTS TO:
#   - omnigov/settings/base.py     → 'from .base import *' pulls in all shared settings
#   - docker/                      → Docker Compose sets the environment variables
#                                    consumed here (ALLOWED_HOSTS, REDIS_URL, etc.)
#   - nginx/                       → Nginx terminates TLS and proxies to Daphne;
#                                    SECURE_SSL_REDIRECT works because Nginx sets
#                                    X-Forwarded-Proto: https
# ---
"""
Production settings — overrides base.py for deployment.
"""
from .base import *  # noqa: F401,F403

DEBUG = False

# Explicitly restrict which external origins Django trusts for CSRF.
# This overrides any development setting that might allow wildcard tunnel domains.
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in config('CSRF_TRUSTED_ORIGINS', default='').split(',')
    if origin.strip()
]

# No default — config() raises UndefinedValueError if ALLOWED_HOSTS is not in .env,
# which prevents accidental deployment where the app silently restricts to localhost.
ALLOWED_HOSTS = [host.strip() for host in config('ALLOWED_HOSTS').split(',')]

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
X_FRAME_OPTIONS = 'DENY'

# GVM is real in production
GVM_USE_MOCK = False

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
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'omnigov.log',  # noqa: F405
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 10,
            'formatter': 'verbose',
        },
        # Security events are isolated in their own file so they can be shipped
        # to a SIEM, reviewed by a security team, or monitored for alerting.
        'security_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'security.log',  # noqa: F405
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 10,
            'formatter': 'verbose',
        },
        # AI correlation events (Claude API calls, framework scoring) are written
        # to their own rotating file for auditability and cost tracking.
        'ai_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'ai' / 'correlation.log',  # noqa: F405
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 10,
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'WARNING',
    },
    'loggers': {
        'apps': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        # django.security captures Django's own security events and our custom
        # security_logger entries — all written to the dedicated security log.
        'django.security': {
            'handlers': ['console', 'file', 'security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        # AI correlation logs go to their own file in production — useful for
        # monitoring Claude API usage and debugging alignment scoring.
        'apps.interceptor.correlation': {
            'handlers': ['console', 'file', 'ai_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
