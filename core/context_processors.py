def herald(request):
    user = getattr(request, "user", None)
    if not (user and user.is_authenticated and user.can_view_all):
        return {}
    from servers.assignment import needs_assignment as servers_needing_assignment
    from servers.models import ServerImport
    from vulns.assignment import needs_assignment
    from vulns.models import ImportRun

    return {
        "draft_import": ImportRun.objects.filter(status=ImportRun.DRAFT).first(),
        "draft_server_import": ServerImport.objects.filter(status=ServerImport.DRAFT).first(),
        "unassigned_accounts": needs_assignment().count(),
        "unassigned_servers": servers_needing_assignment().count(),
    }
