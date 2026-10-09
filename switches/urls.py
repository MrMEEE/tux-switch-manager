from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("switches/add/", views.inventory, name="switch-add"),
    path("discovery/", views.discovery, name="discovery"),
    path("switches/<int:pk>/", views.detail, name="switch-detail"),
    path("switches/<int:pk>/edit/", views.inventory, name="switch-edit"),
    path("switches/<int:pk>/status/", views.status, name="switch-status"),
    path("switches/<int:pk>/action/", views.action, name="switch-action"),
    path("switches/<int:pk>/stage/", views.stage, name="switch-stage"),
    path("switches/<int:pk>/changes/<int:change_id>/", views.change_action, name="change-action"),
    path("switches/<int:pk>/revisions/<int:revision_id>/", views.revision, name="revision-detail"),
    path("switches/<int:pk>/revisions/<int:revision_id>/restore/", views.restore, name="revision-restore"),
    path("switches/<int:pk>/jobs/<int:job_id>/", views.job, name="job-detail"),
]
