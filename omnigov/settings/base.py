import os
from pathlib import Path
from decouple import config, Csv

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Security
SECRET_KEY = config('DJANGO_SECRET_KEY', default='django-insecure-change-me-in-production')
DEBUG = config('DJANGO_DEBUG', default=True, cast=bool)
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
    'django_otp',
    'django_otp.plugins.otp_email',
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
    'django_otp.middleware.OTPMiddleware',
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
        'PASSWORD': config('DB_PASSWORD', default='omnigov_dev_password'),
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
# Email (OTP delivery)
# ============================================================
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('EMAIL_HOST_USER', default='noreply@omnigov.net')

# ============================================================
# OmniGov Custom Settings
# ============================================================

# GVM / OpenVAS
GVM_HOST = config('GVM_HOST', default='localhost')
GVM_PORT = config('GVM_PORT', default=9390, cast=int)
# Unix socket path — used on Linux (Kali/Debian GVM package default).
# Set to empty string '' to force TCP connection instead.
GVM_SOCKET_PATH = config('GVM_SOCKET_PATH', default='/run/gvmd/gvmd.sock')
GVM_ADMIN_USER = config('GVM_ADMIN_USER', default='admin')
GVM_ADMIN_PASSWORD = config('GVM_ADMIN_PASSWORD', default='admin')
GVM_USE_MOCK = config('GVM_USE_MOCK', default=True, cast=bool)

# Site
SITE_DOMAIN = config('SITE_DOMAIN', default='localhost:8000')
SITE_NAME = config('SITE_NAME', default='OmniGov')

# Scan settings
MAX_CONCURRENT_SCANS = 3
SCAN_POLL_INTERVAL = 10  # seconds

# OTP settings
OTP_EMAIL_SENDER = DEFAULT_FROM_EMAIL
OTP_EMAIL_TOKEN_VALIDITY = 300  # 5 minutes
