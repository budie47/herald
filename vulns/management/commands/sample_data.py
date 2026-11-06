import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

from django.core.management.base import BaseCommand
from openpyxl import Workbook

from vulns.columns import COLUMNS

PACKAGES = [("openssl", "3.0.2", "3.0.13"), ("glibc", "2.35", "2.35-0ubuntu3.6"), ("log4j-core", "2.14.1", "2.17.1"),
            ("curl", "7.81.0", "8.5.0"), ("zlib", "1.2.11", "1.2.13"), ("jackson-databind", "2.9.10", "2.15.3"),
            ("libxml2", "2.9.13", "2.9.14"), ("busybox", "1.35.0", "1.36.1"), ("nghttp2", "1.43.0", "1.57.0")]
SEVERITIES = ["Critical", "High", "High", "Medium", "Medium", "Medium", "Low", "Low"]
ENVS = ["Production", "Staging", "Development"]


class Command(BaseCommand):
    help = "Write two example scanner exports (an older and a newer scan) to try the import flow."

    def add_arguments(self, parser):
        parser.add_argument("--out", default="sample_data")
        parser.add_argument("--apps", type=int, default=7)
        parser.add_argument("--seed", type=int, default=7)

    def handle(self, *args, out, apps, seed, **options):
        rng = random.Random(seed)
        outdir = Path(out)
        outdir.mkdir(parents=True, exist_ok=True)
        first_scan = datetime(2026, 7, 1, 8, 0)
        second_scan = first_scan + timedelta(days=60)

        rows_first, rows_second = [], []
        alert = 1000
        for a in range(1, apps + 1):
            app_id = f"APP-{1000 + a}"
            for asset_no in range(1, rng.randint(3, 6)):
                env = rng.choice(ENVS)
                asset_id = f"{app_id.lower()}-pod-{asset_no}"
                image = f"registry.example.com/{app_id.lower()}/svc{asset_no}:1.{rng.randint(0, 9)}"
                rescanned = rng.random() > 0.15  # some assets are missing from the newer scan
                for _ in range(rng.randint(4, 14)):
                    alert += 1
                    pkg, cur, fix = rng.choice(PACKAGES)
                    sev = rng.choice(SEVERITIES)
                    row = {
                        "Alert ID": f"ALR-{alert}", "App ID": app_id, "App Name": f"Service {a}", "Asset ID": asset_id,
                        "Asset Name": f"{app_id.lower()}-svc{asset_no}", "Asset Type": "Container", "Image": image,
                        "Cluster": f"eks-{env.lower()[:4]}-01", "Namespace": app_id.lower(), "Environment": env,
                        "CVE": f"CVE-202{rng.randint(1, 5)}-{rng.randint(1000, 49999)}",
                        "CVE Description": f"A flaw in {pkg} may allow a remote attacker to cause denial of service or execute code.",
                        "Severity": sev, "CVSS Score": {"Critical": 9.8, "High": 7.5, "Medium": 5.3, "Low": 3.1}[sev],
                        "Package": pkg, "Package Type": "os", "Current Version": cur, "Recommended Version": fix,
                        "First Detected": (first_scan - timedelta(days=rng.randint(0, 200))).strftime("%Y-%m-%d"),
                        "Last Scan": first_scan.strftime("%Y-%m-%d %H:%M:%S"),
                        "Exception": "Yes" if rng.random() < 0.05 else "No",
                        "RITM Number": f"RITM{rng.randint(100000, 999999)}" if rng.random() < 0.05 else "",
                    }
                    rows_first.append(row)
                    if rescanned and rng.random() > 0.3:  # ~30% fixed by the newer scan
                        rows_second.append({**row, "Last Scan": second_scan.strftime("%d/%m/%Y %H:%M")})
                if rescanned:
                    for _ in range(rng.randint(0, 3)):  # brand new findings
                        alert += 1
                        pkg, cur, fix = rng.choice(PACKAGES)
                        rows_second.append({**rows_first[-1], "Alert ID": f"ALR-{alert}", "Package": pkg,
                                            "Current Version": cur, "Recommended Version": fix,
                                            "Severity": rng.choice(SEVERITIES), "First Detected": "",
                                            "Last Scan": second_scan.strftime("%d/%m/%Y %H:%M")})

        headers = [label for label, _, _ in COLUMNS]
        first_path = outdir / "scan_2026-07-01.csv"
        with first_path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows_first)

        # The newer scan as Excel, with a title above the header and the "Enviroment" spelling.
        wb = Workbook()
        ws = wb.active
        ws.append(["Container vulnerability export"])
        ws.append([])
        ws.append([h if h != "Environment" else "Enviroment" for h in headers])
        for row in rows_second:
            ws.append([row.get(h, "") for h in headers])
        second_path = outdir / "scan_2026-08-30.xlsx"
        wb.save(second_path)
        self.stdout.write(f"Wrote {first_path} ({len(rows_first)} rows) and {second_path} ({len(rows_second)} rows)")
