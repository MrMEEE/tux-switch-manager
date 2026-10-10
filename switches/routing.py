from django.urls import path
from .consumers import LiveConsumer, SwitchConsumer

websocket_urlpatterns = [
    path("ws/switches/<int:switch_id>/", SwitchConsumer.as_asgi()),
    path("ws/live/<str:topic>/", LiveConsumer.as_asgi()),
    path("ws/live/<str:topic>/<int:pk>/", LiveConsumer.as_asgi()),
]
