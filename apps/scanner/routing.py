# ---
# LOCATION : apps/scanner/routing.py
# PURPOSE  : WebSocket URL table for the scanner app.
#            This is the Channels equivalent of urls.py — it maps WebSocket
#            connection paths to their consumer handler.
#            Imported by omnigov/asgi.py to wire into the ASGI application.
#
# CONNECTS TO:
#   - omnigov/asgi.py              → imports websocket_urlpatterns and passes it
#                                    to URLRouter inside the ProtocolTypeRouter
#   - apps/scanner/consumers.py    → ScanProgressConsumer handles the connection,
#                                    pushes live progress events to the browser
# ---
from django.urls import re_path
from . import consumers

# Maps ws://host/ws/scan/<integer id>/ to the ScanProgressConsumer.
# The numeric scan_id in the URL is used inside the consumer to look up
# ownership and join the correct channel group for that specific scan job.
websocket_urlpatterns = [
    re_path(r'ws/scan/(?P<scan_id>\d+)/$', consumers.ScanProgressConsumer.as_asgi()),
]
