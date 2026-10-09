from importlib import import_module
from types import SimpleNamespace

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.conf import settings
from django.contrib.auth import get_user

from .models import Switch
from .permissions import can_access


class SwitchConsumer(AsyncJsonWebsocketConsumer):
    @database_sync_to_async
    def authorized(self):
        session_key = self.scope["session"].session_key
        if not session_key:
            return False
        session = import_module(settings.SESSION_ENGINE).SessionStore(session_key=session_key)
        user = get_user(SimpleNamespace(session=session))
        switch = Switch.objects.filter(pk=self.switch_id).first()
        return bool(switch and can_access(user, switch))

    async def connect(self):
        self.switch_id = self.scope["url_route"]["kwargs"]["switch_id"]
        self.group_name = f"switch.{self.switch_id}"
        if not await self.authorized():
            await self.close(code=4403)
            return
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        # Close the race between the initial access check and joining the group.
        if not await self.authorized():
            await self.close(code=4403)

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        if not await self.authorized():
            await self.close(code=4403)

    async def switch_updated(self, event):
        if not await self.authorized():
            await self.close(code=4403)
            return
        if event.get("switch_id") == self.switch_id:
            await self.send_json({"switch_id": self.switch_id, "event": "updated"})
