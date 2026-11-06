from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, SetPasswordForm
from django.contrib.auth.password_validation import validate_password

from core.forms import BootstrapMixin

from .models import Role, User


class EmailAuthenticationForm(BootstrapMixin, AuthenticationForm):
    username = forms.EmailField(label="Email", widget=forms.EmailInput(attrs={"autofocus": True, "autocomplete": "email"}))
    error_messages = {
        "invalid_login": "Incorrect email or password.",
        "inactive": "This account is disabled.",
    }


class StyledPasswordChangeForm(BootstrapMixin, PasswordChangeForm):
    pass


class StyledSetPasswordForm(BootstrapMixin, SetPasswordForm):
    pass


class UserCreateForm(BootstrapMixin, forms.ModelForm):
    temporary_password = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        help_text="The user must change this password at first login.",
    )

    class Meta:
        model = User
        fields = ["email", "full_name", "role"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].queryset = Role.objects.all()
        self.fields["role"].required = True

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email

    def clean_temporary_password(self):
        password = self.cleaned_data["temporary_password"]
        validate_password(password)
        return password

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["temporary_password"])
        user.must_change_password = True
        if commit:
            user.save()
        return user


class UserEditForm(BootstrapMixin, forms.ModelForm):
    class Meta:
        model = User
        fields = ["full_name", "role", "is_active"]
        labels = {"is_active": "Active (can sign in)"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].queryset = Role.objects.all()


class TemporaryPasswordForm(BootstrapMixin, forms.Form):
    temporary_password = forms.CharField(widget=forms.PasswordInput(render_value=False))

    def clean_temporary_password(self):
        password = self.cleaned_data["temporary_password"]
        validate_password(password)
        return password
