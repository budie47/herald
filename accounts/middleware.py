from django.shortcuts import redirect

ALLOWED_URL_NAMES = {"password_change", "logout"}


class ForcePasswordChangeMiddleware:
    """Users created with a temporary password must set their own before doing anything else."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        user = getattr(request, "user", None)
        if not (user and user.is_authenticated and user.must_change_password):
            return None
        match = request.resolver_match
        if match and match.url_name in ALLOWED_URL_NAMES:
            return None
        return redirect("password_change")
