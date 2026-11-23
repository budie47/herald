def herald(request):
    user = getattr(request, "user", None)
    if not (user and user.is_authenticated and user.can_view_all):
        return {}
    from vulns.assignment import needs_assignment
    from vulns.models import ImportRun

    return {
        "draft_import": ImportRun.objects.filter(status=ImportRun.DRAFT).first(),
        "unassigned_accounts": needs_assignment().count(),
    }
