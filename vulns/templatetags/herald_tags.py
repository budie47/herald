from django import template

register = template.Library()

SEVERITY_CLASSES = {"Critical": "sev-critical", "High": "sev-high", "Medium": "sev-medium", "Low": "sev-low"}
STATUS_CLASSES = {"Open": "text-bg-danger", "Reopened": "text-bg-warning", "Not seen": "text-bg-warning", "Remediated": "text-bg-success"}


@register.simple_tag(takes_context=True)
def qs(context, **kwargs):
    """Current query string with some parameters replaced (None/'' removes them)."""
    params = context["request"].GET.copy()
    for key, value in kwargs.items():
        if value is None or value == "":
            params.pop(key, None)
        else:
            params[key] = value
    encoded = params.urlencode()
    return f"?{encoded}" if encoded else "?"


@register.simple_tag(takes_context=True)
def active(context, *prefixes):
    match = getattr(context["request"], "resolver_match", None)
    name = (match.url_name if match else "") or ""
    return "active" if any(name.startswith(p) for p in prefixes) else ""


@register.filter
def sev_class(severity):
    return SEVERITY_CLASSES.get(severity, "sev-other")


@register.filter
def status_class(status):
    return STATUS_CLASSES.get(status, "text-bg-secondary")


@register.filter
def pct(value, total):
    return round(100 * value / total) if total else 0


@register.filter
def get(mapping, key):
    return mapping.get(key) if mapping else None


@register.simple_tag
def vuln_status(vuln, cutoff):
    return vuln.display_status(cutoff)
