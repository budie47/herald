from django.contrib import messages
from django.core.mail import EmailMultiAlternatives
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.permissions import admin_required

from .models import AppSettings, EmailSettings
from .settings_forms import AppSettingsForm, EmailSettingsForm, TestEmailForm


@admin_required
def settings_home(request):
    return redirect("settings_general")


@admin_required
def general_settings(request):
    form = AppSettingsForm(request.POST or None, instance=AppSettings.load())
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Settings saved.")
        return redirect("settings_general")
    return render(request, "settings/general.html", {"form": form, "section": "general"})


@admin_required
def email_settings(request):
    cfg = EmailSettings.load()
    form = EmailSettingsForm(request.POST or None, instance=cfg)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Email settings saved.")
        return redirect("settings_email")
    test_form = TestEmailForm(initial={"recipient": request.user.email})
    return render(request, "settings/email.html", {"form": form, "test_form": test_form, "cfg": cfg, "section": "email"})


@admin_required
@require_POST
def send_test_email(request):
    form = TestEmailForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Enter a valid email address.")
        return redirect("settings_email")
    recipient = form.cleaned_data["recipient"]
    sent_at = timezone.now().strftime("%Y-%m-%d %H:%M UTC")
    message = EmailMultiAlternatives(
        subject="Herald test email",
        body=f"This is a test email from Herald, sent by {request.user.email} at {sent_at}.\n\nYour SMTP settings work.",
        to=[recipient],
    )
    try:
        message.send()
        messages.success(request, f"Test email sent to {recipient}.")
    except Exception as exc:
        messages.error(request, f"Test email failed: {exc}")
    return redirect("settings_email")
