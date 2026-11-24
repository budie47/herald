from django import forms
from django.core.validators import validate_email
from django.utils import timezone

from core.forms import BootstrapMixin

from .models import Application, ImportFile, split_emails, unique_emails


class ApplicationForm(BootstrapMixin, forms.ModelForm):
    class Meta:
        model = Application
        fields = [
            "app_id", "name", "support_team", "support_emails", "owner_name", "owner_email", "extra_emails",
            "business_service", "department", "notes",
        ]
        labels = {
            "support_team": "Team name", "support_emails": "Team email", "owner_name": "Owner name",
            "owner_email": "Owner email", "extra_emails": "Additional emails",
        }
        help_texts = {
            "support_emails": "Needed before Herald can send a notification.",
            "owner_email": "",
            "extra_emails": "",
        }
        widgets = {
            "support_emails": forms.Textarea(attrs={"rows": 2, "data-email-chips": "1", "placeholder": "team@company.com"}),
            "owner_email": forms.EmailInput(attrs={"placeholder": "owner@company.com"}),
            "extra_emails": forms.Textarea(attrs={"rows": 2, "data-email-chips": "1", "placeholder": "name@company.com"}),
            "notes": forms.Textarea(attrs={"rows": 3}),
        }

    def clean_app_id(self):
        if self.instance.pk:
            return self.instance.app_id  # locked: alerts and history refer to it
        app_id = self.cleaned_data["app_id"].strip().upper()  # scan data stores App IDs in uppercase
        if "/" in app_id:
            raise forms.ValidationError("App ID can't contain '/'.")
        existing = Application.objects.filter(app_id__iexact=app_id).first()
        if existing:
            raise forms.ValidationError(f"Already registered as {existing.app_id}.")
        return app_id

    def _clean_email_list(self, field):
        emails = unique_emails(split_emails(self.cleaned_data[field]))
        bad = []
        for email in emails:
            try:
                validate_email(email)
            except forms.ValidationError:
                bad.append(email)
        if bad:
            raise forms.ValidationError(f"Not valid email address(es): {', '.join(bad)}")
        return ", ".join(emails)

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
    date_order = forms.ChoiceField(
        label="Date order", required=False, choices=ImportFile.DATE_ORDER_CHOICES,
        widget=forms.Select(attrs={"class": "form-select"}),
    )


class ContactUploadForm(forms.Form):
    file = forms.FileField(widget=forms.ClearableFileInput(attrs={"class": "form-control", "accept": ".csv,.xlsx,.xlsm"}))
