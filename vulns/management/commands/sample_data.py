import csv
import random
import tempfile
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from openpyxl import Workbook

from vulns import assignment, lifecycle, summaries
from vulns.columns import COLUMNS
from vulns.models import Application, CloudAccount, ImportRun, Vulnerability

PACKAGES = [
    ("openssl", "3.0.2", "3.0.13"), ("glibc", "2.35", "2.35-0ubuntu3.6"), ("log4j-core", "2.14.1", "2.17.1"),
    ("curl", "7.81.0", "8.5.0"), ("zlib", "1.2.11", "1.2.13"), ("jackson-databind", "2.9.10", "2.15.3"),
    ("libxml2", "2.9.13", "2.9.14"), ("busybox", "1.35.0", "1.36.1"), ("nghttp2", "1.43.0", "1.57.0"),
]
SEVERITIES = ["Critical", "High", "High", "Medium", "Medium", "Medium", "Low", "Low"]
SLO_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}
APPLICATIONS = {
    "APP-1001": ("Payments", "Sample Owner A", "payments-owner@example.com", "Digital Payments", "Finance Technology"),
    "APP-1002": ("Customer Portal", "Sample Owner B", "portal-owner@example.com", "Customer Experience", "Digital"),
    "APP-1003": ("Data Platform", "Sample Owner C", "data-owner@example.com", "Analytics", "Data Office"),
}
SUPPORT = {
    "APP-1001": ("Payments Support", "payments-support@example.com"),
    "APP-1002": ("Portal Support", "portal-support@example.com"),
    "APP-1003": ("Data Platform Support", "data-support@example.com"),
}
# account id, name, provider, environment, App ID on tagged alerts, share of alerts tagged, assign to
ACCOUNTS = [
    ("012345678901", "payments-prod", "AWS", "Production", "APP-1001", .75, "APP-1001"),
    ("012345678902", "payments-nonprod", "AWS", "Staging", "APP-1001", .60, "APP-1001"),
    ("7c1e9a52-3b44-4d10-9f6e-1a2b3c4d5e01", "sub-payments-dr", "Azure", "Production", "APP-1001", .80, None),
    ("210987654321", "portal-prod", "AWS", "Production", "APP-1002", .90, "APP-1002"),
    ("7c1e9a52-3b44-4d10-9f6e-1a2b3c4d5e02", "sub-portal-uat", "Azure", "Staging", "APP-1002", .70, None),
    ("345678901234", "data-platform-prod", "AWS", "Production", "APP-1003", 1.0, None),
    ("7c1e9a52-3b44-4d10-9f6e-1a2b3c4d5e03", "sub-analytics-prod", "Azure", "Production", "APP-1004", 1.0, None),
    ("456789012345", "shared-tools", "AWS", "Development", "MIXED", .55, None),
    ("567890123456", "legacy-batch", "AWS", "Production", None, 0, None),
    ("078901234567", "network-hub", "AWS", "Production", None, 0, None),
    ("7c1e9a52-3b44-4d10-9f6e-1a2b3c4d5e04", "sub-sandbox-eu", "Azure", "Development", None, 0, None),
]


class Command(BaseCommand):
    help = "Write three example scanner exports; with --load, also register sample apps and import them."

    def add_arguments(self, parser):
        parser.add_argument("--out", default=None)
        parser.add_argument("--seed", type=int, default=7)
        parser.add_argument("--load", action="store_true", help="Import into an empty database")

    def handle(self, *args, out, seed, load, **options):
        if load and (Vulnerability.objects.exists() or Application.objects.exists() or ImportRun.objects.exists()):
            raise CommandError("--load needs an empty database: scan data or applications already exist.")
        outdir = Path(out or (tempfile.mkdtemp(prefix="herald-sample-") if load else "sample_data"))
        outdir.mkdir(parents=True, exist_ok=True)
        paths = self._write_files(random.Random(seed), outdir, timezone.now().replace(microsecond=0, tzinfo=None))
        if load:
            self._load(paths)

    def _write_files(self, rng, outdir, now):
        scans = [now - timedelta(days=100), now - timedelta(days=40), now - timedelta(days=5)]
        output = [[], [], []]
        alert_no = 100000

        def new_row(account, asset_no, opened):
            nonlocal alert_no
            alert_no += 1
            account_id, name, provider, env, tag, tagged_share, _ = account
            package, current, fixed = rng.choice(PACKAGES)
            severity = rng.choice(SEVERITIES)
            app_id = ""
            if tag and rng.random() < tagged_share:
                app_id = rng.choice(["APP-1001", "APP-1002"]) if tag == "MIXED" else tag
            app = APPLICATIONS.get(app_id, ("", "", "", "", ""))
            cve = f"CVE-202{rng.randint(1, 5)}-{rng.randint(1000, 49999)}"
            slo = opened + timedelta(days=SLO_DAYS[severity])
            repository = f"{name}/service-{asset_no}"
            return {
                "CSB ID": f"CSB-{alert_no}", "Alert ID": f"ALR-{alert_no}", "Severity": severity,
                "Alert Opened": opened.strftime("%Y-%m-%d"), "SLO Date": "" if rng.random() < .15 else slo.strftime("%Y-%m-%d"),
                "Exception": "Yes" if rng.random() < .05 else "No",
                "Exception RITM": f"RITM{rng.randint(100000, 999999)}" if rng.random() < .05 else "",
                "Account ID": account_id, "Account Name": name, "Provider": provider, "Enviroment": env,
                "Asset ID": f"{name}-asset-{asset_no}", "Asset Type": "Container Image", "CVE ID": cve,
                "CVE Description": f"Sample finding: a flaw in {package} could allow a remote attacker to affect availability.",
                "CVE Link": f"https://nvd.nist.gov/vuln/detail/{cve}", "Cluster": f"{name}-cluster",
                "Namespace": f"ns-{asset_no}", "Instance": f"{name}-pod-{asset_no}", "Repository": repository,
                "Registry": "registry.example.com", "Image": f"registry.example.com/{repository}:1.{asset_no}",
                "Image Tag": f"1.{asset_no}", "Image Created": (opened - timedelta(days=30)).strftime("%Y-%m-%d"),
                "Package": package, "Current Version": current, "Recommended Version": fixed,
                "Package Path": f"/usr/lib/{package}", "Layer ID": f"sha256:{rng.getrandbits(64):016x}",
                "Layer Instruction": f"RUN install {package}", "OS": "Ubuntu", "OS Version": "22.04",
                "OS End of Life": "2027-04-01", "Participating Firm": "Example Firm", "Country": "MY", "CMS": "Sample CMS",
                "Function": "Technology", "App ID": app_id, "App Service": app[0], "Business Service": app[3],
                "Department": app[4], "Service Line": "Sample Service Line", "Data Classification": "Internal",
                "Data Qualification": "Sample",
            }

        for account in ACCOUNTS:
            for asset_no in range(1, rng.randint(3, 5)):
                rows = [
                    new_row(account, asset_no, scans[0] - timedelta(days=rng.randint(0, 150)))
                    for _ in range(rng.randint(5, 11))
                ]
                in_second = rng.random() > .1
                in_third = in_second and rng.random() > .05  # the rest age into Not seen
                output[0] += [{**r, "Last Scan": scans[0].strftime("%Y-%m-%d %H:%M:%S")} for r in rows]
                second = [r for r in rows if rng.random() < .8] if in_second else []
                if in_second:
                    second += [new_row(account, asset_no, scans[1]) for _ in range(rng.randint(0, 2))]
                    output[1] += [{**r, "Last Scan": scans[1].strftime("%d-%b-%Y %H:%M:%S")} for r in second]
                if in_third:
                    kept = [r for r in second if rng.random() < .85]
                    returned = [r for r in rows if r not in second and rng.random() < .35]  # reopened
                    fresh = [new_row(account, asset_no, scans[2]) for _ in range(rng.randint(0, 2))]
                    output[2] += [{**r, "Last Scan": scans[2]} for r in kept + returned + fresh]

        headers = [label for label, _, _ in COLUMNS]
        paths = []
        for index in (0, 1):
            path = outdir / f"container_scan_{scans[index]:%Y-%m-%d}.csv"
            with path.open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=headers)
                writer.writeheader()
                writer.writerows(output[index])
            paths.append(path)

        # Newest scan: title rows above the header, real Excel dates, and AWS IDs stored as numbers.
        workbook = Workbook()
        sheet = workbook.active
        sheet.append(["Container vulnerability export (sample data)"])
        sheet.append([])
        sheet.append(headers)
        for row in output[2]:
            values = {**row}
            if values["Provider"] == "AWS":
                values["Account ID"] = int(values["Account ID"])
            sheet.append([values.get(h, "") for h in headers])
        path = outdir / f"container_scan_{scans[2]:%Y-%m-%d}.xlsx"
        workbook.save(path)
        paths.append(path)
        for path, rows in zip(paths, output):
            self.stdout.write(f"Wrote {path} ({len(rows)} rows)")
        return paths

    def _load(self, paths):
        user = get_user_model().objects.filter(is_superuser=True).first()
        if user is None:
            raise CommandError("Create a superadmin first (manage.py bootstrap).")
        for app_id, (name, owner, email, service, department) in APPLICATIONS.items():
            Application.objects.create(
                app_id=app_id, name=name, support_team=SUPPORT[app_id][0], support_emails=SUPPORT[app_id][1],
                owner_name=owner, owner_email=email,
                business_service=service, department=department, notes="Sample data",
            )
        settings.HERALD_JOBS_EAGER = True  # this command does the work itself
        for path in paths:
            run = lifecycle.get_or_create_draft(user)
            lifecycle.add_file(run, SimpleUploadedFile(path.name, path.read_bytes()), user)
            run.refresh_from_db()
            ImportRun.objects.filter(pk=run.pk).update(expected_total=run.unique_rows)
            run = lifecycle.finalize(run, user, confirm_text=lifecycle.CONFIRM_WORD)
            summaries.refresh()
            self.stdout.write(
                f"Import #{run.pk}: {run.new_count} new, {run.updated_count} updated, {run.reopened_count} reopened, "
                f"{run.remediated_count} remediated"
            )
        for account_id, _, _, _, _, _, assign_to in ACCOUNTS:
            if assign_to:
                account = CloudAccount.objects.get(account_id=account_id)
                assignment.assign([account.pk], Application.objects.get(app_id=assign_to), user)
        self.stdout.write(self.style.SUCCESS(
            f"Loaded {Vulnerability.objects.count()} alerts in {CloudAccount.objects.count()} cloud accounts; "
            f"{assignment.needs_assignment().count()} accounts need assignment."
        ))
