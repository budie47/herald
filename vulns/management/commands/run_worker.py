import signal
import time

from django.core.management.base import BaseCommand
from django.db import InterfaceError, OperationalError, connections

from vulns import jobs

IDLE_SECONDS = 2
MAINTENANCE_SECONDS = 300
RECONNECT_SECONDS = 5


class Command(BaseCommand):
    help = "Runs background jobs: imports, summaries, large assignments, bulk emails and the nightly archive."

    def handle(self, *args, **options):
        self.running = True
        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT, self._stop)
        jobs.recover()
        self.stdout.write("Herald worker started.")
        last_maintenance = 0
        while self.running:
            try:
                jobs.close_connections()
                job = jobs.claim()
                if job:
                    self.stdout.write(f"Job {job.pk}: {job.kind}")
                    jobs.run(job)
                    continue
                if time.monotonic() - last_maintenance > MAINTENANCE_SECONDS:
                    last_maintenance = time.monotonic()
                    jobs.daily_maintenance()
            except (OperationalError, InterfaceError) as exc:  # database restarting: wait, then retry unfinished work
                self.stderr.write(f"Database unavailable: {exc}")
                connections.close_all()
                time.sleep(RECONNECT_SECONDS)
                self._recover()
                continue
            time.sleep(IDLE_SECONDS)

    def _recover(self):
        try:
            jobs.recover()
        except (OperationalError, InterfaceError):
            connections.close_all()

    def _stop(self, *args):
        self.running = False
