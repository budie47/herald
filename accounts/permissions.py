from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db.models import Q


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_admin:
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapper


def superadmin_required(view):
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapper


def visible_app_ids(user):
    """None means every App ID; otherwise the set of App IDs whose owner or extra emails include the user."""
    if user.can_view_all:
        return None
    from vulns.models import Application

    email = user.email.lower()
    candidates = Application.objects.filter(Q(owner_email__iexact=email) | Q(extra_emails__icontains=email))
    return {app.app_id for app in candidates if email in {e.lower() for e in app.recipients()}}


def can_view_app(user, app_id):
    ids = visible_app_ids(user)
    return ids is None or app_id in ids
