import logging

from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import PasswordResetForm
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.decorators.http import require_POST

from accounts.permissions import admin_required, superadmin_required

from .forms import (
    EmailAuthenticationForm,
    StyledPasswordChangeForm,
    StyledSetPasswordForm,
    TemporaryPasswordForm,
    UserCreateForm,
    UserEditForm,
)
from .models import Role, User

log = logging.getLogger(__name__)

RESET_EMAIL = {
    "email_template_name": "accounts/emails/password_reset.txt",
    "html_email_template_name": "accounts/emails/password_reset.html",
    "subject_template_name": "accounts/emails/password_reset_subject.txt",
}


class LoginView(auth_views.LoginView):
    template_name = "accounts/login.html"
    authentication_form = EmailAuthenticationForm
    redirect_authenticated_user = True


class PasswordChangeView(auth_views.PasswordChangeView):
    template_name = "accounts/password_change.html"
    form_class = StyledPasswordChangeForm
    success_url = reverse_lazy("dashboard")

    def form_valid(self, form):
        response = super().form_valid(form)
        user = form.user
        user.must_change_password = False
        user.save(update_fields=["must_change_password"])
        update_session_auth_hash(self.request, user)
        messages.success(self.request, "Your password has been changed.")
        return response


class PasswordResetView(auth_views.PasswordResetView):
    """Django only emails active users that already exist; the response never reveals whether an account exists."""

    template_name = "accounts/password_reset.html"
    success_url = reverse_lazy("password_reset_done")
    email_template_name = RESET_EMAIL["email_template_name"]
    html_email_template_name = RESET_EMAIL["html_email_template_name"]
    subject_template_name = RESET_EMAIL["subject_template_name"]

    def form_valid(self, form):
        try:
            return super().form_valid(form)
        except Exception:
            # Same response either way so the page never leaks whether the account exists.
            log.exception("Password reset email could not be sent")
            return redirect(self.success_url)


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = "accounts/password_reset_confirm.html"
    form_class = StyledSetPasswordForm
    success_url = reverse_lazy("password_reset_complete")

    def form_valid(self, form):
        response = super().form_valid(form)
        form.user.must_change_password = False
        form.user.save(update_fields=["must_change_password"])
        return response


def send_reset_link(request, user):
    form = PasswordResetForm({"email": user.email})
    form.is_valid()
    form.save(
        request=request,
        use_https=request.is_secure(),
        email_template_name=RESET_EMAIL["email_template_name"],
        html_email_template_name=RESET_EMAIL["html_email_template_name"],
        subject_template_name=RESET_EMAIL["subject_template_name"],
    )


# --- Settings > Users and Roles ---------------------------------------------------------


@admin_required
def user_list(request):
    users = User.objects.select_related("role").all()
    return render(request, "settings/users.html", {"users": users, "section": "users"})


@superadmin_required
def user_create(request):
    form = UserCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save(commit=False)
        user.created_by = request.user
        user.save()
        messages.success(request, f"User {user.email} created. They must change the temporary password at first login.")
        return redirect("settings_users")
    return render(request, "settings/user_form.html", {"form": form, "section": "users", "title": "Add user"})


@superadmin_required
def user_edit(request, pk):
    target = get_object_or_404(User, pk=pk)
    form = UserEditForm(request.POST or None, instance=target)
    password_form = TemporaryPasswordForm()
    if request.method == "POST" and form.is_valid():
        if target == request.user and not form.cleaned_data["is_active"]:
            form.add_error("is_active", "You cannot deactivate your own account.")
        else:
            form.save()
            messages.success(request, f"User {target.email} updated.")
            return redirect("settings_users")
    return render(
        request,
        "settings/user_edit.html",
        {"form": form, "password_form": password_form, "target": target, "section": "users"},
    )


@superadmin_required
@require_POST
def user_set_password(request, pk):
    target = get_object_or_404(User, pk=pk)
    form = TemporaryPasswordForm(request.POST)
    if form.is_valid():
        target.set_password(form.cleaned_data["temporary_password"])
        target.must_change_password = True
        target.save()
        messages.success(request, f"Temporary password set for {target.email}. They must change it at next login.")
    else:
        messages.error(request, " ".join(form.errors.get("temporary_password", ["Invalid password."])))
    return redirect("settings_user_edit", pk=pk)


@superadmin_required
@require_POST
def user_send_reset(request, pk):
    target = get_object_or_404(User, pk=pk)
    try:
        send_reset_link(request, target)
        messages.success(request, f"Password reset link sent to {target.email}.")
    except Exception as exc:
        messages.error(request, f"Could not send the reset email: {exc}")
    return redirect("settings_user_edit", pk=pk)


@admin_required
def role_list(request):
    roles = Role.objects.all()
    return render(request, "settings/roles.html", {"roles": roles, "section": "roles"})
