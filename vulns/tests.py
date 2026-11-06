import io
from datetime import datetime, timezone

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from openpyxl import Workbook

from accounts.models import Role, User
from core.models import AppSettings

from . import lifecycle
from .columns import COLUMNS
from .models import Application, ImportRun, Vulnerability
from .parsing import FileFormatError, parse_file, to_datetime

HEADERS = ["Alert ID", "App ID", "Asset ID", "Severity", "CVE", "Last Scan"]


def csv_file(rows, headers=HEADERS, name="scan.csv", preamble=""):
    lines = [preamble] if preamble else []
    lines.append(",".join(headers))
    lines += [",".join(str(v) for v in row) for row in rows]
    return SimpleUploadedFile(name, ("\n".join(lines) + "\n").encode())


class ParsingTests(TestCase):
    def test_header_on_any_row_and_case_space_insensitive(self):
        f = csv_file([["A1", "APP-1", "asset-1", "high", "CVE-2024-1", "2026-10-01"]],
                     headers=["alert id", "APPID", " Asset  ID", "SEVERITY", "cve", "LastScan"],
                     preamble="Exported by scanner\n")
        result = parse_file(f, f.name)
        self.assertEqual(result.header_row, 3)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.rows[0]["severity"], "High")
        self.assertEqual(result.rows[0]["last_scan"], "2026-10-01T00:00:00+00:00")

    def test_enviroment_spelling_is_accepted(self):
        f = csv_file([["A1", "APP-1", "Production"]], headers=["Alert ID", "App ID", "Enviroment"])
        self.assertEqual(parse_file(f, f.name).rows[0]["environment"], "Production")

    def test_bad_rows_are_rejected_with_row_number_and_reason(self):
        f = csv_file([["A1", "APP-1", "a", "High", "CVE-1", "2026-10-01"],
                      ["", "APP-1", "a", "High", "CVE-2", "2026-10-01"],
                      ["A3", "APP-1", "a", "High", "CVE-3", "not a date"]])
        result = parse_file(f, f.name)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual([e["row"] for e in result.errors], [3, 4])
        self.assertIn("Alert ID is missing", result.errors[0]["reason"])
        self.assertIn("Last Scan", result.errors[1]["reason"])

    def test_missing_header_raises(self):
        f = csv_file([["x"]], headers=["Foo", "Bar"])
        with self.assertRaises(FileFormatError):
            parse_file(f, f.name)

    def test_dates_real_values_text_and_serials(self):
        expected = datetime(2026, 10, 28, tzinfo=timezone.utc)
        self.assertEqual(to_datetime(datetime(2026, 10, 28), "d"), expected)
        self.assertEqual(to_datetime("28/10/2026", "d"), expected)
        self.assertEqual(to_datetime("2026-10-28", "d"), expected)
        self.assertEqual(to_datetime(46323, "d"), expected)  # Excel serial number
        self.assertEqual(to_datetime("46323", "d"), expected)  # serial stored as text

    def test_excel_first_sheet_with_typed_values(self):
        wb = Workbook()
        ws = wb.active
        ws.append(["title row"])
        ws.append(["Alert ID", "App ID", "Last Scan", "CVSS Score", "Exception"])
        ws.append([12345, "APP-9", datetime(2026, 10, 28, 8, 30), 9.8, "Yes"])
        ws.append(["A2", "APP-9", "2026-10-28 08:30", "7.5", "No"])
        wb.create_sheet("ignored").append(["Alert ID", "App ID"])
        buffer = io.BytesIO()
        wb.save(buffer)
        result = parse_file(io.BytesIO(buffer.getvalue()), "scan.xlsx")
        self.assertEqual(result.header_row, 2)
        self.assertEqual(result.rows[0]["alert_id"], "12345")
        self.assertEqual(result.rows[0]["cvss_score"], 9.8)
        self.assertTrue(result.rows[0]["exception"])
        self.assertEqual(result.rows[1]["last_scan"], result.rows[0]["last_scan"])
        self.assertEqual(result.rows[1]["cvss_score"], 7.5)
        self.assertFalse(result.rows[1]["exception"])

    def test_has_44_columns(self):
        self.assertEqual(len(COLUMNS), 44)


class LifecycleTests(TestCase):
    def setUp(self):
        Role.ensure_defaults()
        AppSettings.load()
        self.user = User.objects.create_superuser("admin@example.com", "pw-Example-123")

    def run_import(self, *files):
        run = lifecycle.get_or_create_draft(self.user)
        for f in files:
            lifecycle.add_file(run, f, self.user)
        plan = lifecycle.build_plan(run)
        lifecycle.finalize(run, self.user)
        return plan

    def status(self, alert_id):
        return Vulnerability.objects.get(alert_id=alert_id).status

    def test_new_then_remediated_only_on_newer_scan_of_same_asset(self):
        self.run_import(csv_file([
            ["A1", "APP-1", "asset-1", "High", "CVE-1", "2026-09-01"],
            ["A2", "APP-1", "asset-1", "Low", "CVE-2", "2026-09-01"],
            ["B1", "APP-2", "asset-2", "High", "CVE-3", "2026-09-01"],
        ]))
        self.assertEqual(Vulnerability.objects.filter(status="open").count(), 3)

        plan = self.run_import(csv_file([["A1", "APP-1", "asset-1", "High", "CVE-1", "2026-10-01"]]))
        self.assertEqual(len(plan.updated), 1)
        self.assertEqual([v.alert_id for v, _ in plan.remediated], ["A2"])
        self.assertEqual(self.status("A2"), "remediated")
        self.assertEqual(self.status("B1"), "open")  # asset-2 was not in the upload: untouched
        a2 = Vulnerability.objects.get(alert_id="A2")
        self.assertEqual(a2.remediated_at, datetime(2026, 10, 1, tzinfo=timezone.utc))
        self.assertEqual(a2.remediated_import, ImportRun.objects.get(status="finalized", pk=a2.remediated_import_id))

    def test_older_file_changes_nothing(self):
        self.run_import(csv_file([["A1", "APP-1", "asset-1", "High", "CVE-1", "2026-10-01"]]))
        plan = self.run_import(csv_file([
            ["A1", "APP-1", "asset-1", "Critical", "CVE-1", "2026-09-01"],
            ["A0", "APP-1", "asset-1", "Low", "CVE-0", "2026-09-01"],
        ]))
        self.assertEqual(len(plan.skipped), 1)
        self.assertEqual(plan.remediated, [])
        self.assertEqual(Vulnerability.objects.get(alert_id="A1").severity, "High")

    def test_reopened_when_seen_in_newer_scan(self):
        self.run_import(csv_file([["A1", "APP-1", "asset-1", "High", "CVE-1", "2026-09-01"],
                                  ["A2", "APP-1", "asset-1", "High", "CVE-2", "2026-09-01"]]))
        self.run_import(csv_file([["A2", "APP-1", "asset-1", "High", "CVE-2", "2026-10-01"]]))
        self.assertEqual(self.status("A1"), "remediated")
        plan = self.run_import(csv_file([["A1", "APP-1", "asset-1", "High", "CVE-1", "2026-11-01"],
                                         ["A2", "APP-1", "asset-1", "High", "CVE-2", "2026-11-01"]]))
        self.assertEqual(len(plan.reopened), 1)
        a1 = Vulnerability.objects.get(alert_id="A1")
        self.assertEqual(a1.status, "open")
        self.assertIsNotNone(a1.reopened_at)
        self.assertIsNone(a1.remediated_at)

    def test_rejected_row_never_counts_as_fix(self):
        self.run_import(csv_file([["A1", "APP-1", "asset-1", "High", "CVE-1", "2026-09-01"],
                                  ["A2", "APP-1", "asset-1", "High", "CVE-2", "2026-09-01"]]))
        plan = self.run_import(csv_file([["A1", "APP-1", "asset-1", "High", "CVE-1", "2026-10-01"],
                                         ["A2", "APP-1", "asset-1", "High", "CVE-2", "garbage"]]))
        self.assertEqual(plan.remediated, [])
        self.assertEqual(self.status("A2"), "open")

    def test_later_batch_replaces_earlier_row(self):
        plan = self.run_import(
            csv_file([["A1", "APP-1", "asset-1", "Low", "CVE-1", "2026-09-01"]], name="b1.csv"),
            csv_file([["A1", "APP-1", "asset-1", "Critical", "CVE-1", "2026-09-01"]], name="b2.csv"),
        )
        self.assertEqual(len(plan.new), 1)
        self.assertEqual(Vulnerability.objects.get(alert_id="A1").severity, "Critical")

    def test_only_one_draft_and_discard_changes_nothing(self):
        run = lifecycle.get_or_create_draft(self.user)
        self.assertEqual(lifecycle.get_or_create_draft(self.user), run)
        lifecycle.add_file(run, csv_file([["A1", "APP-1", "asset-1", "Low", "CVE-1", "2026-09-01"]]), self.user)
        lifecycle.discard(run)
        self.assertFalse(Vulnerability.objects.exists())
        self.assertNotEqual(lifecycle.get_or_create_draft(self.user), run)


class AccessTests(TestCase):
    def setUp(self):
        Role.ensure_defaults()
        AppSettings.load()
        role = Role.objects.get(key=Role.USER)
        self.owner = User.objects.create_user("owner@example.com", "pw-Example-123", role=role)
        Application.objects.create(app_id="APP-1", owner_email="other@example.com", extra_emails="Owner@Example.com")
        Application.objects.create(app_id="APP-2", owner_email="other@example.com")

    def test_user_role_sees_only_own_apps(self):
        self.client.force_login(self.owner)
        self.assertEqual(self.client.get("/applications/APP-1/").status_code, 200)
        self.assertEqual(self.client.get("/applications/APP-2/").status_code, 404)
        self.assertEqual(self.client.get("/imports/").status_code, 403)

    def test_temporary_password_forces_change(self):
        self.owner.must_change_password = True
        self.owner.save()
        self.client.force_login(self.owner)
        response = self.client.get("/")
        self.assertRedirects(response, "/password/change/")

    def test_recipients_are_deduplicated(self):
        app = Application(owner_email="a@example.com", extra_emails="A@example.com; b@example.com\nb@example.com")
        self.assertEqual(app.recipients(), ["a@example.com", "b@example.com"])
