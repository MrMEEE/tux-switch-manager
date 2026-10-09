from django.urls import path
from .consumers import SwitchConsumer

websocket_urlpatterns = [
    path("ws/switches/<int:switch_id>/", SwitchConsumer.as_asgi()),
]
