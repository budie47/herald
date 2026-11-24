"""A small database-backed job queue, run by the `run_worker` service."""
import logging

from django.conf import settings
from django.db import close_old_connections, transaction
from django.utils import timezone

from .models import Job

log = logging.getLogger(__name__)

PARSE, PLAN, FINALIZE, ASSIGN, SUMMARIES, NOTIFY, ARCHIVE = (
    "parse", "plan", "finalize", "assign", "summaries", "notify", "archive"
)
MAX_ATTEMPTS = 2


def enqueue(kind, payload=None, user=None):
    job = Job.objects.create(kind=kind, payload=payload or {}, created_by=user)
    if settings.HERALD_JOBS_EAGER:
        run(job)
        job.refresh_from_db()
    return job


def claim():
    with transaction.atomic():
        job = Job.objects.select_for_update(skip_locked=True).filter(status=Job.QUEUED).order_by("id").first()
        if job is None:
            return None
        job.status = Job.RUNNING
        job.started_at = timezone.now()
        job.attempts += 1
        job.save(update_fields=["status", "started_at", "attempts"])
        return job


def recover():
    """After a crash or restart, retry what was running. A job that crashed twice is marked failed."""
    for job in Job.objects.filter(status=Job.RUNNING):
        if job.attempts >= MAX_ATTEMPTS:
            _failed(job, "The worker stopped twice while running this job.")
        else:
            job.status = Job.QUEUED
            job.save(update_fields=["status"])


def _failed(job, message):
    if job.kind == PARSE:  # first, so a database error here leaves the job to be recovered and retried
        from . import lifecycle

        lifecycle.fail_file(job.payload.get("file"), message)
    job.status = Job.FAILED
    job.message = message[:2000]
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "message", "finished_at"])
    if job.kind in (PLAN, FINALIZE):
        from .models import ImportRun

        ImportRun.objects.filter(pk=job.payload.get("run")).update(phase="")


def run(job):
    try:
        message = _handlers()[job.kind](job)
    except Exception as exc:
        log.exception("Job %s (%s) failed", job.pk, job.kind)
        _failed(job, str(exc) or exc.__class__.__name__)
        return
    job.status = Job.DONE
    job.message = (message or "")[:2000]
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "message", "finished_at"])


def _handlers():
    from . import archive, assignment, followups, lifecycle, summaries
    from .models import ImportRun

    def plan(job):
        lifecycle.build_plan(ImportRun.objects.get(pk=job.payload["run"]))

    def finalize(job):
        run_obj = ImportRun.objects.get(pk=job.payload["run"])
        p = job.payload
        run_obj = lifecycle.finalize(
            run_obj, job.created_by, p.get("override_reason", ""), p.get("confirm_text", ""), p.get("skip_remediation", False)
        )
        summaries.refresh()
        return (
            f"Import #{run_obj.pk} finalized: {run_obj.new_count} new, {run_obj.updated_count} updated, "
            f"{run_obj.reopened_count} reopened, {run_obj.remediated_count} remediated, {run_obj.skipped_count} skipped."
        )

    def assign(job):
        assignment.apply_owners(job.payload["accounts"])

    return {
        PARSE: lambda job: lifecycle.process_file(job.payload["file"]),
        PLAN: plan,
        FINALIZE: finalize,
        ASSIGN: assign,
        SUMMARIES: lambda job: summaries.refresh(),
        NOTIFY: lambda job: followups.notify_many(job.payload, job.created_by),
        ARCHIVE: lambda job: archive.run_archive(),
    }


def daily_maintenance():
    """Keeps Past SLO and Not seen correct as days pass, and runs the archive if it is switched on."""
    from core.models import AppSettings

    cfg = AppSettings.load()
    today = timezone.now().date()
    if cfg.summaries_refreshed_at and cfg.summaries_refreshed_at.date() == today:
        return
    if Job.objects.filter(status__in=[Job.QUEUED, Job.RUNNING]).exists():
        return
    if cfg.retention_enabled:
        enqueue(ARCHIVE)
    else:
        enqueue(SUMMARIES)


def close_connections():
    close_old_connections()
