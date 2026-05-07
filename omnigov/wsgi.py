# ---
# LOCATION : omnigov/wsgi.py
# PURPOSE  : WSGI fallback entry point for synchronous HTTP servers (e.g. Gunicorn).
#            In production this project uses Daphne (ASGI) instead, making this
#            file mostly relevant for deployment environments or CI that do not
#            need WebSocket support.
#
# CONNECTS TO:
#   - omnigov/asgi.py                  → the preferred async entry point that handles
#                                        both HTTP and WebSocket traffic
#   - omnigov/settings/development.py  → default settings loaded here
# ---
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'omnigov.settings.development')

application = get_wsgi_application()
