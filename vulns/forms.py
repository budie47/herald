from django import forms
from django.core.validators import validate_email
from django.utils import timezone

from core.forms import BootstrapMixin

from .models import Application, split_emails


class ApplicationForm(BootstrapMixin, forms.ModelForm):
    class Meta:
        model = Application
        fields = [
            "app_id", "name", "support_team", "support_emails", "owner_name", "owner_email", "extra_emails",
            "business_service", "department", "notes",
        ]
        widgets = {
            "support_emails": forms.Textarea(attrs={"rows": 2}),
            "extra_emails": forms.Textarea(attrs={"rows": 2}),
            "notes": forms.Textarea(attrs={"rows": 3}),
        }

    def clean_app_id(self):
        return self.cleaned_data["app_id"].strip()

    def _clean_email_list(self, field):
        value = self.cleaned_data[field]
        bad = []
        for email in split_emails(value):
            try:
                validate_email(email)
            except forms.ValidationError:
                bad.append(email)
        if bad:
            raise forms.ValidationError(f"Not valid email address(es): {', '.join(bad)}")
        return value

    def clean_support_emails(self):
        return self._clean_email_list("support_emails")

    def clean_extra_emails(self):
        return self._clean_email_list("extra_emails")


class ResponseForm(BootstrapMixin, forms.Form):
    responder = forms.CharField(label="Who responded", max_length=200)
    responded_on = forms.DateField(label="Response date", widget=forms.DateInput(attrs={"type": "date"}))
    response = forms.CharField(label="What they said", widget=forms.Textarea(attrs={"rows": 3}))
    close = forms.BooleanField(required=False, label="Close this follow-up")

    def clean_responded_on(self):
        value = self.cleaned_data["responded_on"]
        if value > timezone.localdate():
            raise forms.ValidationError("The response date can't be in the future.")
        return value


class UploadForm(forms.Form):
    file = forms.FileField(widget=forms.ClearableFileInput(attrs={"class": "form-control", "accept": ".csv,.xlsx,.xlsm"}))
