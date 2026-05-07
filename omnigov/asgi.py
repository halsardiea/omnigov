# ---
# LOCATION : omnigov/asgi.py
# PURPOSE  : ASGI entry point — the single object Daphne calls to handle every
#            incoming connection, whether it is a normal HTTP page request or a
#            WebSocket connection for live scan progress.
#
# CONNECTS TO:
#   - omnigov/settings/development.py   → default settings loaded here
#   - apps/scanner/routing.py           → supplies the websocket_urlpatterns list that
#                                         maps ws/scan/<id>/ to ScanProgressConsumer
#   - apps/scanner/consumers.py         → the WebSocket handler that receives messages
#                                         pushed by scanner/tasks.py during a scan
#   - omnigov/wsgi.py                   → the synchronous HTTP fallback (not used by Daphne)
# ---
import os
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'omnigov.settings.development')

# Initialise Django's standard HTTP handler first — must happen before any
# app-level imports so models and settings are fully loaded.
django_asgi_app = get_asgi_application()

# Imported after get_asgi_application() because apps must be initialised before
# their URL patterns can be imported.
from apps.scanner.routing import websocket_urlpatterns  # noqa: E402

# This is the top-level ASGI application object.
# ProtocolTypeRouter splits incoming traffic by protocol:
#   - "http"      → normal Django views, templates, and DRF endpoints
#   - "websocket" → real-time scan progress updates via Django Channels
#
# AllowedHostsOriginValidator enforces the ALLOWED_HOSTS whitelist on WebSocket
# upgrade requests, blocking cross-origin hijacking attempts.
#
# AuthMiddlewareStack populates scope['user'] from the session cookie so that
# ScanProgressConsumer can identify and authorise the connected user.
application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(websocket_urlpatterns)
        )
    ),
})


