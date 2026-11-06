from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("applications/", views.app_list, name="app_list"),
    path("applications/new/", views.app_create, name="app_create"),
    path("applications/notify/", views.notify_bulk, name="app_notify_bulk"),
    path("applications/<str:app_id>/", views.app_detail, name="app_detail"),
    path("applications/<str:app_id>/edit/", views.app_edit, name="app_edit"),
    path("applications/<str:app_id>/delete/", views.app_delete, name="app_delete"),
    path("applications/<str:app_id>/export.csv", views.app_export, name="app_export"),
    path("applications/<str:app_id>/notify/", views.app_notify, name="app_notify"),
    path("notifications/", views.notification_log, name="notification_log"),
    path("imports/", views.import_home, name="import_home"),
    path("imports/template.<str:fmt>", views.import_template, name="import_template"),
    path("imports/<int:pk>/", views.import_detail, name="import_detail"),
    path("imports/<int:pk>/add/", views.import_add_file, name="import_add_file"),
    path("imports/<int:pk>/finalize/", views.import_finalize, name="import_finalize"),
    path("imports/<int:pk>/discard/", views.import_discard, name="import_discard"),
]
