from importlib import import_module
from types import SimpleNamespace

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.conf import settings
from django.contrib.auth import get_user
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.middleware.csrf import CsrfViewMiddleware

from .models import Switch
from .permissions import can_access
from .live import snapshot


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


class LiveConsumer(AsyncJsonWebsocketConsumer):
    @database_sync_to_async
    def payload(self):
        session_key = self.scope["session"].session_key
        if not session_key:
            return None
        request = HttpRequest()
        request.session = import_module(settings.SESSION_ENGINE).SessionStore(session_key=session_key)
        request.user = get_user(SimpleNamespace(session=request.session))
        request.COOKIES = self.scope.get("cookies", {})
        CsrfViewMiddleware(lambda request: None).process_request(request)
        try:
            return snapshot(request, self.topic, self.pk)
        except PermissionDenied:
            return None

    async def send_snapshot(self):
        payload = await self.payload()
        if payload is None:
            await self.close(code=4403)
            return False
        await self.send_json(payload)
        return True

    async def connect(self):
        arguments = self.scope["url_route"]["kwargs"]
        self.topic = arguments["topic"]
        self.pk = arguments.get("pk")
        if await self.payload() is None:
            await self.close(code=4403)
            return
        await self.channel_layer.group_add("live.updates", self.channel_name)
        await self.accept()
        await self.send_snapshot()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("live.updates", self.channel_name)

    async def receive_json(self, content, **kwargs):
        await self.send_snapshot()

    async def live_updated(self, event):
        resources = {
            "fleet": {"switch", "job", "access"},
            "discovery": {"discovery", "credentials", "access"},
            "credentials": {"credentials", "access"},
            "credential-options": {"credentials", "access"},
            "switch": {"switch", "job", "access"},
            "job": {"job", "switch", "access"},
        }
        if event.get("resource") in resources.get(self.topic, set()):
            await self.send_snapshot()
