from django.urls import path

from . import views

urlpatterns = [
    path("dashboard/servers/", views.dashboard, name="dashboard_servers"),
    path("applications/<str:app_id>/servers/", views.app_servers, name="app_servers"),
    path("applications/<str:app_id>/servers/export.csv", views.app_servers_export, name="app_servers_export"),
    path("applications/<str:app_id>/servers/notify/", views.app_servers_notify, name="app_servers_notify"),
    path("servers/", views.server_list, name="server_list"),
    path("servers/app-search/", views.server_app_search, name="server_app_search"),
    path("servers/assign/", views.server_assign, name="server_assign"),
    path("servers/<int:pk>/", views.server_detail, name="server_detail"),
    path("servers/imports/", views.import_home, name="server_import_home"),
    path("servers/imports/<int:pk>/", views.import_detail, name="server_import_detail"),
    path("servers/imports/<int:pk>/add/", views.import_add_file, name="server_import_add_file"),
    path("servers/imports/<int:pk>/expected/", views.import_expected, name="server_import_expected"),
    path("servers/imports/<int:pk>/finalize/", views.import_finalize, name="server_import_finalize"),
    path("servers/imports/<int:pk>/discard/", views.import_discard, name="server_import_discard"),
    path(
        "servers/imports/<int:pk>/will-be-remediated.csv", views.import_planned_export, name="server_import_planned_export"
    ),
    path("servers/cmdb/", views.inventory_home, name="inventory_home"),
    path("servers/cmdb/<int:pk>/", views.inventory_detail, name="inventory_detail"),
    path("servers/cmdb/<int:pk>/apply/", views.inventory_apply, name="inventory_apply"),
    path("servers/cmdb/<int:pk>/discard/", views.inventory_discard, name="inventory_discard"),
    path("servers/cmdb/<int:pk>/rejected.csv", views.inventory_rejected, name="inventory_rejected"),
]
