from django import forms
from django.core.validators import validate_email

from core.forms import BootstrapMixin

from .models import Application


class ApplicationForm(BootstrapMixin, forms.ModelForm):
    class Meta:
        model = Application
        fields = ["app_id", "name", "owner_name", "owner_email", "extra_emails", "business_service", "department", "notes"]
        widgets = {"extra_emails": forms.Textarea(attrs={"rows": 2}), "notes": forms.Textarea(attrs={"rows": 3})}

    def clean_app_id(self):
        return self.cleaned_data["app_id"].strip()

    def clean_extra_emails(self):
        value = self.cleaned_data["extra_emails"]
        bad = []
        for email in Application(extra_emails=value).extra_email_list():
            try:
                validate_email(email)
            except forms.ValidationError:
                bad.append(email)
        if bad:
            raise forms.ValidationError(f"Not valid email address(es): {', '.join(bad)}")
        return value


class UploadForm(forms.Form):
    file = forms.FileField(widget=forms.ClearableFileInput(attrs={"class": "form-control", "accept": ".csv,.xlsx,.xlsm"}))
