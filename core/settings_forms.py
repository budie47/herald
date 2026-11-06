from django import forms

from .forms import BootstrapMixin
from .models import AppSettings, EmailSettings


class AppSettingsForm(BootstrapMixin, forms.ModelForm):
    class Meta:
        model = AppSettings
        fields = ["not_seen_days", "slo_critical_days", "slo_high_days", "slo_medium_days", "slo_low_days"]


class EmailSettingsForm(BootstrapMixin, forms.ModelForm):
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}),
        help_text="Stored encrypted and never shown. Leave blank to keep the current password.",
    )
    clear_password = forms.BooleanField(required=False, label="Remove the stored password")

    class Meta:
        model = EmailSettings
        fields = ["host", "port", "security", "username", "sender"]

    def save(self, commit=True):
        cfg = super().save(commit=False)
        if self.cleaned_data.get("clear_password"):
            cfg.password_encrypted = ""
        elif self.cleaned_data.get("password"):
            cfg.set_password(self.cleaned_data["password"])
        if commit:
            cfg.save()
        return cfg


class TestEmailForm(BootstrapMixin, forms.Form):
    recipient = forms.EmailField(label="Send a test email to")
