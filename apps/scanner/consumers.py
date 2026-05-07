# ---
# LOCATION : apps/scanner/consumers.py
# PURPOSE  : Handles the WebSocket connection for live scan progress updates.
#            When a user opens the scan detail page, JavaScript opens a WebSocket
#            to ws/scan/<id>/. This consumer accepts that connection, joins a
#            channel group named 'scan_<id>', and relays any progress/complete/error
#            messages pushed by scanner/tasks.py to the browser in real time.
#
# CONNECTS TO:
#   - apps/scanner/routing.py     → maps ws/scan/<id>/ to this consumer
#   - apps/scanner/tasks.py       → _send_ws_update() sends channel group messages
#                                    that this consumer's handler methods relay to JS
#   - apps/scanner/models.py      → _user_owns_scan() queries ScanTask to verify
#                                    the connecting user created this scan
#   - omnigov/asgi.py             → AuthMiddlewareStack populates scope['user'] so
#                                    the connect() method can identify the user
#   - omnigov/settings/development.py → InMemoryChannelLayer used in dev (no Redis)
#   - omnigov/settings/base.py    → RedisChannelLayer used in production
# ---
"""
WebSocket consumer for real-time scan progress updates.
"""
import json
import logging

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer

from .models import ScanTask

logger = logging.getLogger(__name__)


class ScanProgressConsumer(AsyncWebsocketConsumer):
    """Pushes scan progress updates to connected WebSocket clients."""

    async def connect(self):
        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.group_name = f'scan_{self.scan_id}'

        # Step 1 — Reject unauthenticated connections immediately.
        user = self.scope.get('user')
        if not user or user.is_anonymous:
            await self.close()
            return

        # Step 2 — Verify this user actually owns the scan they are connecting to.
        # Without this check, any logged-in user could subscribe to any scan ID
        # and receive live findings and error messages that belong to someone else.
        user_owns_this_scan = await self._user_owns_scan(user, self.scan_id)
        if not user_owns_this_scan:
            logger.warning(
                'WS rejected: user %s attempted to subscribe to scan %s they do not own',
                user.id, self.scan_id,
            )
            await self.close()
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.debug('WS connected: %s by user %s', self.group_name, user)

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        # The browser does not send commands — it only listens.
        # This method exists to satisfy the AsyncWebsocketConsumer interface.
        pass

    # ---- Handler methods (called by channel_layer.group_send) ----
    # Django Channels calls these automatically based on the 'type' field in the
    # group_send payload. For example, a message with type='scan.progress' triggers
    # scan_progress() — dots are converted to underscores by the framework.

    async def scan_progress(self, event):
        """Send progress update."""
        await self.send(text_data=json.dumps({
            'type': 'progress',
            'progress': event.get('progress', 0),
            'status': event.get('status', 'running'),
            'message': event.get('message', ''),
        }))

    async def scan_complete(self, event):
        """Send scan completion notification."""
        await self.send(text_data=json.dumps({
            'type': 'complete',
            'status': event.get('status', 'completed'),
            'message': event.get('message', 'Scan analysis complete.'),
            'report_id': event.get('report_id'),
        }))

    async def scan_error(self, event):
        """Send error notification."""
        await self.send(text_data=json.dumps({
            'type': 'error',
            'status': 'failed',
            'message': event.get('message', 'An error occurred.'),
        }))

    @database_sync_to_async
    def _user_owns_scan(self, user, scan_id):
        """Check the database to confirm this user created the scan they are connecting to.

        Uses the ORM (not raw SQL) so Django handles parameterisation safely.
        Returns True only if a matching scan exists for this exact user.
        """
        return ScanTask.objects.filter(pk=scan_id, created_by=user).exists()
