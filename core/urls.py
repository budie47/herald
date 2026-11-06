from django.urls import path

from . import views

urlpatterns = [
    path("settings/", views.settings_home, name="settings"),
    path("settings/general/", views.general_settings, name="settings_general"),
    path("settings/email/", views.email_settings, name="settings_email"),
    path("settings/email/test/", views.send_test_email, name="settings_email_test"),
]
