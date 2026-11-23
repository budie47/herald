"""Notification follow-ups: support team first, then a manual escalation to the application owner.

A failed email is logged but never changes a follow-up's status.
"""
from django.db import transaction
from django.utils import timezone

from .models import Application, FollowUp, FollowUpEvent, Notification, unique_emails
from .notify import NotificationNotAllowed, send_app_notification


def _lock(follow_up):
    return FollowUp.objects.select_for_update().get(pk=follow_up.pk)


def _owner_recipients(app):
    to = unique_emails([app.owner_email])
    return to, unique_emails([*app.support_email_list(), *app.extra_email_list()], exclude=to)


def _event(follow_up, kind, user, remark="", include=False, notification=None, **extra):
    return FollowUpEvent.objects.create(
        follow_up=follow_up, kind=kind, actor=user, remark=remark, include_in_email=include,
        notification=notification, **extra,
    )


@transaction.atomic
def notify_support(app, user, remark="", include=False):
    """Opens a follow-up, or sends a reminder on the one already open."""
    if app is None:
        raise NotificationNotAllowed("This App ID is not registered.")
    app = Application.objects.select_for_update().get(pk=app.pk)
    support = app.support_email_list()
    if not support:
        raise NotificationNotAllowed(f"{app.app_id} has no support email. Add one to the application first.")

    follow_up = FollowUp.objects.select_for_update().filter(application=app).exclude(status=FollowUp.CLOSED).first()
    if follow_up and follow_up.status == FollowUp.ESCALATED:
        to, cc = _owner_recipients(app)
    else:
        to, cc = support, unique_emails(app.extra_email_list(), exclude=support)
    kind = Notification.REMINDER if follow_up else Notification.SUPPORT
    log = send_app_notification(
        app, user, kind, to, cc, follow_up=follow_up, remark=remark if include else "",
    )
    if log.status != Notification.SENT:
        return log

    now = timezone.now()
    if follow_up is None:
        follow_up = FollowUp.objects.create(
            application=app, app_id=app.app_id, opened_at=now, opened_by=user, waiting_since=now,
            first_vuln_count=log.vuln_count,
        )
        log.follow_up = follow_up
        log.save(update_fields=["follow_up"])
        _event(follow_up, FollowUpEvent.SENT, user, remark, include, log)
        return log
    follow_up.reminder_count += 1
    if follow_up.status == FollowUp.RESPONDED:  # a new request after the last answer starts a new wait
        follow_up.status = FollowUp.WAITING
        follow_up.waiting_since = now
    follow_up.save(update_fields=["reminder_count", "status", "waiting_since"])
    _event(follow_up, FollowUpEvent.REMINDER, user, remark, include, log)
    return log


@transaction.atomic
def escalate(follow_up, user, remark="", include=False):
    follow_up = _lock(follow_up)
    app = follow_up.application
    if not follow_up.is_open or app is None:
        raise NotificationNotAllowed("Only an open follow-up can be escalated.")
    if follow_up.status == FollowUp.ESCALATED:
        raise NotificationNotAllowed("This follow-up is already escalated. Send a reminder to the owner instead.")
    if follow_up.status == FollowUp.RESPONDED and not remark:
        raise NotificationNotAllowed("Support has responded, so a reason is required to escalate.")
    to, cc = _owner_recipients(app)
    if not to:
        raise NotificationNotAllowed(f"{app.app_id} has no application owner email. Add one to escalate.")
    log = send_app_notification(
        app, user, Notification.ESCALATION, to, cc, follow_up=follow_up, remark=remark if include else "",
        escalation={
            "first_notified": follow_up.opened_at,
            "reminders": follow_up.reminder_count,
            "first_count": follow_up.first_vuln_count,
            "support_team": app.support_team or "The support team",
            "responded": follow_up.status == FollowUp.RESPONDED,
            "earlier_response": follow_up.events.filter(kind=FollowUpEvent.RESPONSE).exists(),
        },
    )
    if log.status != Notification.SENT:
        return log
    now = timezone.now()
    follow_up.status = FollowUp.ESCALATED
    follow_up.escalated_at = now
    follow_up.escalated_by = user
    follow_up.waiting_since = now
    follow_up.save(update_fields=["status", "escalated_at", "escalated_by", "waiting_since"])
    _event(follow_up, FollowUpEvent.ESCALATED, user, remark, include, log)
    return log


@transaction.atomic
def record_response(follow_up, user, responder, responded_on, response, close=False):
    follow_up = _lock(follow_up)
    if not follow_up.is_open:
        raise NotificationNotAllowed("This follow-up is closed.")
    _event(follow_up, FollowUpEvent.RESPONSE, user, response, responder=responder, responded_on=responded_on)
    follow_up.status = FollowUp.RESPONDED
    follow_up.save(update_fields=["status"])
    if close:
        _close(follow_up, user)
    return follow_up


@transaction.atomic
def add_remark(follow_up, user, remark):
    return _event(_lock(follow_up), FollowUpEvent.REMARK, user, remark)


def _close(follow_up, user, remark=""):
    follow_up.status = FollowUp.CLOSED
    follow_up.closed_at = timezone.now()
    follow_up.closed_by = user
    follow_up.save(update_fields=["status", "closed_at", "closed_by"])
    _event(follow_up, FollowUpEvent.CLOSED, user, remark)


@transaction.atomic
def close(follow_up, user, remark=""):
    follow_up = _lock(follow_up)
    if not follow_up.is_open:
        raise NotificationNotAllowed("This follow-up is already closed.")
    _close(follow_up, user, remark)
    return follow_up


def close_for_deleted_app(app, user):
    for follow_up in FollowUp.objects.select_for_update().filter(application=app).exclude(status=FollowUp.CLOSED):
        _close(follow_up, user, "Application deleted.")


def notify_many(payload, user):
    """Bulk send from the Applications page, run by the worker. Every attempt is in the Notification log."""
    remark, include = payload.get("remark", ""), payload.get("include", False)
    apps = {a.app_id: a for a in Application.objects.filter(app_id__in=payload.get("app_ids", []))}
    sent, failed, skipped = 0, 0, 0
    for app_id in payload.get("app_ids", []):
        try:
            log = notify_support(apps.get(app_id), user, remark, include)
        except NotificationNotAllowed:
            skipped += 1
            continue
        if log.status == Notification.SENT:
            sent += 1
        else:
            failed += 1
    return f"Sent {sent}, failed {failed}, skipped {skipped}."
