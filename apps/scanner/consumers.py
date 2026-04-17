"""
WebSocket consumer for real-time scan progress updates.
"""
import json
import logging

from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)


class ScanProgressConsumer(AsyncWebsocketConsumer):
    """Pushes scan progress updates to connected WebSocket clients."""

    async def connect(self):
        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.group_name = f'scan_{self.scan_id}'

        # Verify user is authenticated
        user = self.scope.get('user')
        if not user or user.is_anonymous:
            await self.close()
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.debug(f"WS connected: {self.group_name} by user {user}")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        # Client can send a ping or request current status
        pass

    # ---- Handler methods (called by channel_layer.group_send) ----

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
