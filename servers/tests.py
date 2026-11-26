import csv
import io
from datetime import datetime, timezone as dt_timezone

from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from openpyxl import Workbook

from accounts.models import Role, User
from core.models import AppSettings
from vulns import followups
from vulns.models import CONTAINERS, SERVERS, AlertSummary, Application, FollowUp, Job, Notification
from vulns.notify import NotificationNotAllowed
from vulns.parsing import FileFormatError

from . import assignment, inventory, lifecycle, summaries
from .columns import CMDB_COLUMNS, MFS12, QUALYS
from .matching import AMBIGUOUS, EXACT, FQDN, SHORT, UNMATCHED, Resolver
from .models import InventoryImport, InventoryRow, Server, ServerFinding, ServerImport, ServerImportFile
from .parsing import MFS12Parser, QualysParser, detect_kind, split_cvss

# The headers of the real exports, as in the sample files.
MFS12_HEADERS = [
    "Asset Name", "QID", "OS", "Title", "CISA_KEV", "First Detected", "Last Detected", "CVSS3.1 Base",
    "Non-running Kernel", "Severity",
]
QUALYS_HEADERS = [
    "QID", "Title", "Severity", "KB Severity", "Type Detected", "Last Detected", "First Detected", "Protocol", "Port",
    "Status", "Asset Id", "Asset Name", "Asset IPV4", "Asset IPV6", "Solution", "Asset Tags", "Disabled", "Ignored",
    "QDS", "QDS Severity", "Detection AGE", "Published Date", "Patch Released", "Category", "RTI", "Operating System",
    "Last Fixed", "Last Reopened", "Times Detected", "Threat", "Vuln Patchable", "Asset Critical Score",
    "TruRisk Score", "Vulnerability Tags", "Results", "Deep Scan Result", "MITRE ATT&CK TACTIC ID",
    "MITRE ATT&CK TACTIC NAME", "MITRE ATT&CK TECHNIQUE ID", "MITRE ATT&CK TECHNIQUE NAME",
]
LAST = "11/20/2026 8:00:00 AM"
CONFIRM = lifecycle.CONFIRM_WORD


def upload(headers, rows, name="file.csv"):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(headers)
    writer.writerows(rows)
    return SimpleUploadedFile(name, buffer.getvalue().encode())


def mfs(asset, qid, severity="High", kev="No", first="1/15/2026 8:00:00 AM", last=LAST, title=None, os_name="Linux"):
    return [
        asset, qid, os_name, title or f"Vulnerability {qid}", kev, first, last,
        "9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)", "No", severity,
    ]


def mfs_file(*rows, name="mfs12.csv"):
    return upload(MFS12_HEADERS, rows, name)


def qualys(asset, qid, port="443", protocol="TCP", solution="Apply the update.", results="Version 1.0"):
    values = dict.fromkeys(QUALYS_HEADERS, "")
    values.update({
        "QID": qid, "Title": f"Vulnerability {qid}", "Severity": "5", "Asset Name": asset, "Port": port,
        "Protocol": protocol, "Solution": solution, "Results": results, "Last Detected": "Nov 11, 2026 09:07 AM",
        "First Detected": "Nov 7, 2026 09:07 AM", "Asset Tags": "Demo Scanner,Example Industries Ltd.",
    })
    return [values[h] for h in QUALYS_HEADERS]


def qualys_file(*rows):
    return upload(QUALYS_HEADERS, rows, "qualys.csv")


def cmdb(name, app="APP-1", env="Production", cls="Linux Server", fqdn="", **extra):
    values = dict.fromkeys(CMDB_COLUMNS, "")
    values.update({
        "name": name, "u_id": app, "u_environment": env, "sys_class_name": cls, "fqdn": fqdn,
        "operational_status": "Operational", "owned_by": "Alex Morgan", "managed_by": "Jordan Lee",
        "company": "Example Industries Ltd.", "asset": "Virtual Machine", "ip_address": "192.0.2.10",
        "os": "Example Linux Enterprise 9", "sys_updated_on": "2026-10-05 11:00:00",
    })
    values.update(extra)
    return [values[c] for c in CMDB_COLUMNS]


def cmdb_file(*rows, headers=CMDB_COLUMNS):
    return upload(headers, rows, "cmdb.csv")


def load_cmdb(user, *rows):
    item = inventory.start(cmdb_file(*rows), user)
    item.refresh_from_db()
    assert item.status == InventoryImport.PREVIEW, item.error
    inventory.queue_apply(item, user)
    item.refresh_from_db()
    assert item.status == InventoryImport.APPLIED, item.error
    return item


def draft_with(user, *files):
    run = lifecycle.get_or_create_draft(user)
    for f in files:
        lifecycle.add_file(run, f, user)
    run.refresh_from_db()
    return run


def finish(user, *files, reason="", skip=False):
    run = draft_with(user, *files)
    ServerImport.objects.filter(pk=run.pk).update(expected_total=run.unique_rows)
    run.refresh_from_db()
    plan = run.plan
    lifecycle.finalize(run, user, reason, CONFIRM, skip)
    summaries.refresh()
    return plan


def finding(server_name, qid):
    return ServerFinding.objects.get(server__name_key=server_name.lower(), qid=qid)


class Base(TestCase):
    def setUp(self):
        Role.ensure_defaults()
        AppSettings.load()
        self.admin = User.objects.create_superuser("admin@example.com", "pw-Example-123")


class ParsingTests(TestCase):
    def test_mfs12_sample_format(self):
        f = mfs_file(
            ["lab-lnx-0001", "800000", "Linux", "Sample Web Service Input Validation Issue", "Yes", "1/1/2026 8:00:00 AM",
             "1/8/2026 8:00:00 AM", "9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)", "Yes", "Critical"],
            ["lab-win-0003", "800002", "Windows", "Test Runtime", "No", "1/15/2026 2:22:00 PM", "1/25/2026 12:22:00 AM",
             "10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)", "No", "High"],
        )
        self.assertEqual(detect_kind(f, f.name), MFS12)
        parser = MFS12Parser(f, f.name)
        (records, errors), = list(parser.batches())
        self.assertEqual(errors, [])
        first, second = records
        self.assertEqual(first["asset_key"], "lab-lnx-0001")
        self.assertTrue(first["cisa_kev"])
        self.assertTrue(first["non_running_kernel"])
        self.assertEqual(first["severity"], "Critical")
        self.assertEqual(first["cvss_score"], 9.1)
        self.assertEqual(first["cvss_vector"], "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        # 1/15/2026 settles the file as month first, so 1/8/2026 is 8 January
        self.assertEqual(first["last_detected"], "2026-01-08T08:00:00+00:00")
        self.assertEqual(second["last_detected"], "2026-01-25T00:22:00+00:00")

    def test_cvss_split(self):
        self.assertEqual(split_cvss("7.5"), (7.5, ""))
        self.assertEqual(split_cvss(""), (None, ""))
        self.assertEqual(split_cvss("not scored"), (None, "not scored"))

    def test_qualys_sample_format(self):
        f = qualys_file(qualys("lab-srv-001", "900001", results="x" * 5000), qualys("LAB-SRV-001", "900001", port="8443"))
        self.assertEqual(detect_kind(f, f.name), QUALYS)
        parser = QualysParser(f, f.name)
        (records, errors), = list(parser.batches())
        self.assertEqual(errors, [])
        self.assertEqual(len(records[0]["results"]), 4000)
        self.assertEqual(records[1]["asset_key"], "lab-srv-001")
        self.assertIn("Asset Tags", parser.unknown_columns)

    def test_rows_without_server_or_qid_are_rejected(self):
        f = mfs_file(mfs("", "1"), mfs("srv", ""))
        (records, errors), = list(MFS12Parser(f, f.name).batches())
        self.assertEqual(records, [])
        self.assertIn("Asset Name is missing", errors[0]["reason"])
        self.assertIn("QID is missing", errors[1]["reason"])
        self.assertEqual(errors[1]["asset_key"], "srv")

    def test_other_files_are_refused(self):
        f = upload(["Alert ID", "Account ID", "Account Name"], [["1", "2", "3"]])
        with self.assertRaises(FileFormatError):
            detect_kind(f, f.name)

    def test_excel_mfs12(self):
        workbook = Workbook()
        sheet = workbook.active
        sheet.append(["Exported from Power BI"])
        sheet.append(MFS12_HEADERS)
        sheet.append(["SRV-01", 800000, "Linux", "Title", "Yes", datetime(2026, 1, 1), datetime(2026, 11, 1), "8.8", "No", "High"])
        buffer = io.BytesIO()
        workbook.save(buffer)
        f = SimpleUploadedFile("mfs12.xlsx", buffer.getvalue())
        self.assertEqual(detect_kind(f, f.name), MFS12)
        parser = MFS12Parser(f, f.name)
        (records, _), = list(parser.batches())
        self.assertEqual(parser.header_row, 2)
        self.assertEqual(records[0]["qid"], "800000")
        self.assertEqual(records[0]["cvss_score"], 8.8)


class InventoryTests(Base):
    def test_preview_then_apply(self):
        f = cmdb_file(cmdb("lab-win-001", "app-1001"), cmdb("lab-lnx-002", "APP-1002", fqdn="lab-lnx-002.example.internal"))
        item = inventory.start(f, self.admin)
        item.refresh_from_db()
        self.assertEqual((item.status, item.new_count, item.new_app_ids_count), (InventoryImport.PREVIEW, 2, 2))
        self.assertFalse(Server.objects.exists())
        inventory.queue_apply(item, self.admin)
        server = Server.objects.get(name_key="lab-win-001")
        self.assertEqual((server.app_id, server.environment, server.server_class), ("APP-1001", "Production", "Linux Server"))
        self.assertEqual(server.cmdb["owned_by"], "Alex Morgan")
        self.assertEqual(Server.objects.get(name="lab-lnx-002").fqdn_key, "lab-lnx-002.example.internal")
        self.assertEqual(Application.objects.get(app_id="APP-1001").source, "cmdb")

    def test_second_upload_shows_changes_and_leaves_missing_servers(self):
        load_cmdb(self.admin, cmdb("a", "APP-1"), cmdb("b", "APP-1"))
        item = inventory.start(cmdb_file(cmdb("A", "APP-2", env="Test")), self.admin)
        item.refresh_from_db()
        self.assertEqual((item.updated_count, item.not_in_file_count, item.app_changed_count), (1, 1, 1))
        row = item.rows.get(action=InventoryRow.UPDATED)
        self.assertEqual(row.changes["u_id"], ["APP-1", "APP-2"])
        self.assertEqual(row.changes["u_environment"], ["Production", "Test"])
        inventory.queue_apply(item, self.admin)
        self.assertEqual(Server.objects.get(name_key="a").app_id, "APP-2")
        self.assertEqual(Server.objects.get(name_key="b").app_id, "APP-1")
        again = inventory.start(cmdb_file(cmdb("A", "APP-2", env="Test")), self.admin)
        again.refresh_from_db()
        self.assertEqual((again.unchanged_count, again.change_count), (1, 0))

    def test_duplicate_names(self):
        f = cmdb_file(cmdb("same"), cmdb("SAME"), cmdb("clash", "APP-1"), cmdb("clash", "APP-2"), cmdb("bad", "A/B"))
        item = inventory.start(f, self.admin)
        item.refresh_from_db()
        self.assertEqual((item.new_count, item.duplicate_count, item.rejected_count), (1, 1, 3))
        reasons = list(item.rows.filter(action=InventoryRow.REJECTED).values_list("reason", flat=True))
        self.assertTrue(any("rows 4, 5" in r for r in reasons))
        self.assertTrue(any("can't contain '/'" in r for r in reasons))
        response = self.client_for(self.admin).get(f"/servers/cmdb/{item.pk}/rejected.csv")
        self.assertIn("A/B", b"".join(response.streaming_content).decode())

    def test_header_aliases_and_multiple_app_ids(self):
        f = cmdb_file(["srv", "APP-1; APP-2", "Linux Server"], headers=["Asset Name", "AppID", "sys_class_name"])
        item = inventory.start(f, self.admin)
        item.refresh_from_db()
        self.assertEqual(item.rejected_count, 1)
        self.assertIn("more than one App ID", item.rows.get().reason)

    def test_stale_preview_is_refused(self):
        first = inventory.start(cmdb_file(cmdb("a")), self.admin)
        load_cmdb(self.admin, cmdb("b"))
        first.refresh_from_db()
        with self.assertRaises(inventory.InventoryStale):
            inventory.queue_apply(first, self.admin)

    def test_cmdb_wins_over_manual_app_id(self):
        app = Application.objects.create(app_id="MANUAL")
        load_cmdb(self.admin, cmdb("untagged", ""))
        server = Server.objects.get()
        self.assertEqual(assignment.assign([server.pk], app, self.admin), (1, 0))
        load_cmdb(self.admin, cmdb("untagged", "", env="Test"))
        self.assertEqual(Server.objects.get().app_id, "MANUAL")  # CMDB still has no App ID
        load_cmdb(self.admin, cmdb("untagged", "APP-9"))
        server = Server.objects.get()
        self.assertEqual(server.app_id, "APP-9")
        self.assertEqual(assignment.assign([server.pk], app, self.admin), (0, 1))

    def client_for(self, user):
        self.client.force_login(user)
        return self.client


class MatchingTests(Base):
    def setUp(self):
        super().setUp()
        load_cmdb(
            self.admin, cmdb("web01", fqdn="web01.corp.local"), cmdb("db01.corp.local"), cmdb("app01.a.local"),
            cmdb("APP01.b.local"),
        )

    def test_order(self):
        resolver = Resolver()
        self.assertEqual(resolver.resolve("web01")[1], EXACT)
        self.assertEqual(resolver.resolve("web01.corp.local")[1], FQDN)
        self.assertEqual(resolver.resolve("db01")[1], SHORT)
        self.assertEqual(resolver.resolve("db01.other.local")[1], SHORT)
        self.assertEqual(resolver.resolve("nothing")[1], UNMATCHED)
        pk, how, note = resolver.resolve("app01")
        self.assertEqual((pk, how), (None, AMBIGUOUS))
        self.assertIn("Matches 2 CMDB servers", note)

    def test_import_uses_the_rules(self):
        plan = finish(self.admin, mfs_file(mfs("WEB01", "1"), mfs("db01", "2"), mfs("app01", "3"), mfs("new-srv", "4")))
        self.assertEqual(plan["unmatched"], 2)
        self.assertEqual(finding("web01", "1").server.app_id, "APP-1")
        self.assertEqual(finding("db01.corp.local", "2").server.in_cmdb, True)
        orphan = Server.objects.get(name_key="app01")
        self.assertFalse(orphan.in_cmdb)
        self.assertEqual(orphan.app_id, "")
        self.assertIn("Matches 2 CMDB servers", orphan.match_note)
        self.assertEqual(assignment.needs_assignment().count(), 2)

    def test_scanned_server_is_merged_when_cmdb_adds_it(self):
        finish(self.admin, mfs_file(mfs("late-srv.corp.local", "1"), mfs("late-srv.corp.local", "2")))
        orphan = Server.objects.get(name_key="late-srv.corp.local")
        app = Application.objects.create(app_id="HAND")
        assignment.assign([orphan.pk], app, self.admin)
        item = load_cmdb(self.admin, cmdb("LATE-SRV", "APP-7"))
        self.assertEqual(item.merged_count, 1)
        self.assertFalse(Server.objects.filter(pk=orphan.pk).exists())
        target = Server.objects.get(name_key="late-srv")
        self.assertEqual(set(target.findings.values_list("qid", flat=True)), {"1", "2"})
        self.assertEqual(target.app_id, "APP-7")
        self.assertEqual(target.assignments.count(), 1)
        # The next weekly upload finds the CMDB server, so nothing is new or remediated.
        plan = finish(self.admin, mfs_file(mfs("late-srv.corp.local", "1"), mfs("late-srv.corp.local", "2")))
        self.assertEqual((plan["new"], plan["remediated"], plan["updated"]), (0, 0, 2))


class ImportTests(Base):
    def setUp(self):
        super().setUp()
        load_cmdb(self.admin, cmdb("srv-a", "APP-1"), cmdb("srv-b", "APP-1"), cmdb("srv-c", "APP-2"))

    def test_first_import(self):
        plan = finish(self.admin, mfs_file(mfs("srv-a", "100", "Critical", kev="Yes"), mfs("srv-b", "200")))
        self.assertEqual((plan["new"], plan["remediated"], plan["servers"]), (2, 0, 2))
        f = finding("srv-a", "100")
        self.assertTrue(f.cisa_kev)
        self.assertEqual(f.first_detected, datetime(2026, 1, 15, 8, tzinfo=dt_timezone.utc))
        self.assertEqual(f.slo_date, datetime(2026, 1, 30, 8, tzinfo=dt_timezone.utc))  # 15 days for Critical
        server = Server.objects.get(name_key="srv-a")
        self.assertEqual((server.open_count, server.kev_open, server.critical_open, server.scan_os), (1, 1, 1, "Linux"))
        self.assertEqual(ServerImport.objects.get().status, ServerImport.FINALIZED)

    def test_missing_findings_and_servers_are_remediated_and_come_back(self):
        finish(self.admin, mfs_file(mfs("srv-a", "1"), mfs("srv-a", "2"), mfs("srv-b", "3"), mfs("srv-c", "4")))
        plan = finish(self.admin, mfs_file(mfs("srv-a", "1"), mfs("srv-c", "4")))
        self.assertEqual((plan["remediated"], plan["missing_servers"], plan["updated"]), (2, 1, 2))
        self.assertEqual(finding("srv-a", "2").status, ServerFinding.REMEDIATED)
        self.assertEqual(finding("srv-b", "3").status, ServerFinding.REMEDIATED)
        self.assertEqual(finding("srv-a", "1").status, ServerFinding.OPEN)
        plan = finish(self.admin, mfs_file(mfs("srv-a", "1"), mfs("srv-a", "2"), mfs("srv-c", "4")))
        self.assertEqual((plan["reopened"], plan["remediated"]), (1, 0))
        reopened = finding("srv-a", "2")
        self.assertEqual(reopened.display_status, "Reopened")
        self.assertIsNone(reopened.remediated_at)

    def test_newest_last_detected_wins_within_a_draft(self):
        finish(self.admin, mfs_file(
            mfs("srv-a", "1", "High", last="11/01/2026 8:00:00 AM"), mfs("SRV-A", "1", "Critical", last="11/21/2026 8:00:00 AM"),
            mfs("srv-a", "1", "High", last="11/02/2026 8:00:00 AM"),
        ))
        run = ServerImport.objects.get()
        self.assertEqual((run.unique_rows, run.duplicates_count), (1, 2))
        self.assertEqual(finding("srv-a", "1").severity, "Critical")

    def test_completeness_and_large_share_are_required_to_remediate(self):
        finish(self.admin, mfs_file(mfs("srv-a", "1"), mfs("srv-a", "2")))
        run = draft_with(self.admin, mfs_file(mfs("srv-a", "1")))
        problems = lifecycle.finalize_blockers(run, run.plan)
        self.assertTrue(any("Power BI total" in p for p in problems))
        self.assertTrue(any(CONFIRM in p for p in problems))
        self.assertEqual(lifecycle.finalize_blockers(run, run.plan, "Partial week", CONFIRM), [])
        self.assertEqual(lifecycle.finalize_blockers(run, run.plan, skip_remediation=True), [])
        with self.assertRaises(ValueError):
            lifecycle.finalize(run, self.admin)
        self.assertEqual(finding("srv-a", "2").status, ServerFinding.OPEN)
        lifecycle.finalize(run, self.admin, skip_remediation=True)
        self.assertEqual(finding("srv-a", "2").status, ServerFinding.OPEN)

    def test_older_upload_needs_a_reason(self):
        finish(self.admin, mfs_file(mfs("srv-a", "1"), mfs("srv-a", "2")))
        run = draft_with(self.admin, mfs_file(mfs("srv-a", "1", last="10/01/2026 8:00:00 AM")))
        ServerImport.objects.filter(pk=run.pk).update(expected_total=1)
        run.refresh_from_db()
        self.assertTrue(run.plan["older"])
        problems = lifecycle.finalize_blockers(run, run.plan, confirm_text=CONFIRM)
        self.assertTrue(any("older than in Herald" in p for p in problems))

    def test_rejected_rows_protect_their_server(self):
        finish(self.admin, mfs_file(mfs("srv-a", "1"), mfs("srv-b", "2")))
        plan = finish(self.admin, mfs_file(mfs("srv-a", ""), mfs("srv-c", "9")), reason="test")
        self.assertEqual((plan["protected"], plan["remediated"]), (1, 1))
        self.assertEqual(finding("srv-a", "1").status, ServerFinding.OPEN)
        self.assertEqual(finding("srv-b", "2").status, ServerFinding.REMEDIATED)

    def test_row_without_a_server_or_a_failed_file_stops_all_remediation(self):
        finish(self.admin, mfs_file(mfs("srv-a", "1"), mfs("srv-b", "2")))
        plan = finish(self.admin, mfs_file(mfs("", "1"), mfs("srv-c", "9")), reason="test")
        self.assertTrue(plan["protect_all"])
        self.assertEqual(ServerFinding.objects.filter(status=ServerFinding.REMEDIATED).count(), 0)
        broken = SimpleUploadedFile("broken.xlsx", b"not a workbook")
        plan = finish(self.admin, mfs_file(mfs("srv-c", "9")), broken, reason="test")
        self.assertTrue(plan["protect_all"])
        self.assertEqual(ServerImportFile.objects.get(filename="broken.xlsx").status, ServerImportFile.FAILED)
        self.assertEqual(ServerFinding.objects.filter(status=ServerFinding.REMEDIATED).count(), 0)

    def test_qualys_adds_details(self):
        plan = finish(self.admin, mfs_file(mfs("srv-a", "900001"), mfs("srv-b", "2")), qualys_file(
            qualys("SRV-A", "900001", "443", results="Path: C:\\Demo\\a.dll"), qualys("srv-a", "900001", "8443"),
            qualys("srv-z", "5"),
        ))
        self.assertEqual((plan["qualys_rows"], plan["qualys_matched"], plan["qualys_unmatched"]), (3, 1, 1))
        f = finding("srv-a", "900001")
        self.assertEqual(f.ports, "443/TCP, 8443/TCP")
        self.assertEqual(f.solution, "Apply the update.")
        self.assertEqual(f.results, "Path: C:\\Demo\\a.dll")
        self.assertEqual(finding("srv-b", "2").solution, "")
        self.assertFalse(Server.objects.filter(name_key="srv-z").exists())
        finish(self.admin, mfs_file(mfs("srv-a", "900001"), mfs("srv-b", "2")))
        self.assertEqual(finding("srv-a", "900001").solution, "Apply the update.")  # kept without a new Qualys file

    def test_qualys_alone_cant_be_finalized(self):
        run = draft_with(self.admin, qualys_file(qualys("srv-a", "1")))
        self.assertFalse(run.plan["has_findings"])
        self.assertIn("Upload at least one MFS12 file", lifecycle.finalize_blockers(run, run.plan)[0])

    def test_two_names_for_one_server_count_once(self):
        load_cmdb(self.admin, cmdb("web01", fqdn="web01.corp.local"))
        plan = finish(self.admin, mfs_file(mfs("web01", "1", last="11/19/2026 8:00:00 AM"), mfs("web01.corp.local", "1")))
        self.assertEqual((plan["new"], plan["servers"]), (1, 1))
        self.assertEqual(finding("web01", "1").last_detected.day, 20)

    def test_discard(self):
        run = draft_with(self.admin, mfs_file(mfs("srv-a", "1")))
        lifecycle.discard(run)
        run.refresh_from_db()
        self.assertEqual(run.status, ServerImport.DISCARDED)
        self.assertFalse(ServerFinding.objects.exists())


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class NotificationTests(Base):
    def setUp(self):
        super().setUp()
        load_cmdb(self.admin, cmdb("srv-a", "APP-1", env="Production"), cmdb("srv-b", "APP-1"))
        self.app = Application.objects.get(app_id="APP-1")
        self.app.support_team, self.app.support_emails = "Platform", "team@example.com"
        self.app.owner_email, self.app.extra_emails = "owner@example.com", "cc@example.com"
        self.app.save()
        finish(self.admin, mfs_file(mfs("srv-a", "1", "High"), mfs("srv-b", "2", "Critical", kev="Yes")))

    def test_server_email_and_its_own_follow_up(self):
        log = followups.notify_support(self.app, self.admin, module=SERVERS)
        self.assertEqual((log.status, log.module, log.vuln_count), (Notification.SENT, SERVERS, 2))
        message = mail.outbox[0]
        self.assertIn("2 open server vulnerabilities", message.subject)
        self.assertIn("1 actively exploited", message.subject)
        self.assertEqual((message.to, message.cc), (["team@example.com"], ["cc@example.com"]))
        body = message.body
        self.assertLess(body.index("QID 2"), body.index("QID 1"))  # KEV first
        name, content, _ = message.attachments[0]
        self.assertTrue(name.endswith(".csv"))
        self.assertIn("srv-b", content)
        follow_up = FollowUp.objects.get()
        self.assertEqual(follow_up.module, SERVERS)
        # A container follow-up for the same application is separate.
        container = FollowUp.objects.create(application=self.app, app_id="APP-1", module=CONTAINERS)
        followups.notify_support(self.app, self.admin, module=SERVERS)
        follow_up.refresh_from_db()
        self.assertEqual(follow_up.reminder_count, 1)
        self.assertEqual(FollowUp.objects.filter(module=CONTAINERS).get(), container)

    def test_escalation_goes_to_the_owner(self):
        followups.notify_support(self.app, self.admin, module=SERVERS)
        log = followups.escalate(FollowUp.objects.get(), self.admin)
        self.assertEqual(log.module, SERVERS)
        self.assertEqual(mail.outbox[-1].to, ["owner@example.com"])
        self.assertIn("ESCALATION", mail.outbox[-1].subject)

    def test_no_open_server_vulnerabilities(self):
        other = Application.objects.create(app_id="APP-X", support_emails="x@example.com")
        with self.assertRaises(NotificationNotAllowed):
            followups.notify_support(other, self.admin, module=SERVERS)

    def test_bulk_send_for_servers(self):
        self.client.force_login(self.admin)
        self.client.post("/applications/notify/", {"app_ids": ["APP-1"], "module": SERVERS})
        self.assertEqual(Notification.objects.get().module, SERVERS)

    def test_views(self):
        self.client.force_login(self.admin)
        response = self.client.post("/applications/APP-1/servers/notify/", {"remark": "Please patch", "include_in_email": "on"})
        self.assertRedirects(response, "/applications/APP-1/servers/", fetch_redirect_response=False)
        self.assertIn("Please patch", mail.outbox[0].body)
        follow_up = FollowUp.objects.get()
        response = self.client.post(f"/follow-ups/{follow_up.pk}/remark/", {"remark": "Called them"})
        self.assertRedirects(response, "/applications/APP-1/servers/#follow-up", fetch_redirect_response=False)
        page = self.client.get("/applications/APP-1/servers/")
        self.assertContains(page, "Called them")
        self.assertNotContains(self.client.get("/applications/APP-1/"), "Called them")
        self.assertContains(self.client.get("/notifications/?module=servers"), "Servers")


class ApplicationTabTests(Base):
    def setUp(self):
        super().setUp()
        load_cmdb(self.admin, cmdb("srv-a", "APP-S", env="Production"), cmdb("srv-b", "APP-S"), cmdb("srv-c", "APP-BOTH", env="Test"))
        finish(self.admin, mfs_file(mfs("srv-a", "1", "Critical", kev="Yes"), mfs("srv-c", "2")))
        AlertSummary.objects.create(owner_app_id="APP-C", cloud_account_id=1, status="open", severity="High", total=4)
        AlertSummary.objects.create(owner_app_id="APP-BOTH", cloud_account_id=1, status="open", severity="Low", total=1)
        Application.objects.create(app_id="APP-NEW", support_emails="new@example.com")
        Application.objects.filter(app_id="APP-S").update(support_emails="s@example.com")
        self.client.force_login(self.admin)

    def ids(self, path):
        return [row["app_id"] for row in self.client.get(path).context["page"]]

    def test_each_tab_lists_its_own_applications(self):
        self.assertEqual(sorted(self.ids("/applications/")), ["APP-BOTH", "APP-C", "APP-NEW"])
        self.assertEqual(sorted(self.ids("/applications/?tab=servers")), ["APP-BOTH", "APP-NEW", "APP-S"])
        page = self.client.get("/applications/?tab=servers")
        row = next(r for r in page.context["page"] if r["app_id"] == "APP-S")
        self.assertEqual(
            (row["servers"], row["servers_open"], row["open"], row["critical"], row["kev"]), (2, 1, 1, 1, 1)
        )
        self.assertEqual([n for _, _, n in page.context["tabs"]], [5, 2])
        self.assertContains(page, '<input type="hidden" name="module" value="servers">')
        self.assertContains(page, "Send server vulnerabilities to support")
        self.assertContains(page, 'href="/applications/APP-S/servers/"')
        self.assertContains(self.client.get("/applications/"), '<input type="hidden" name="module" value="containers">')

    def test_server_tab_filters(self):
        self.assertEqual(self.ids("/applications/?tab=servers&kev=yes"), ["APP-S"])
        self.assertEqual(self.ids("/applications/?tab=servers&severity=Critical"), ["APP-S"])
        self.assertEqual(self.ids("/applications/?tab=servers&env=Production&status=with_vulns"), ["APP-S"])
        self.assertEqual(self.ids("/applications/?tab=servers&q=app-both"), ["APP-BOTH"])
        self.assertEqual(self.ids("/applications/?tab=servers&notified=never&status=no_email"), ["APP-BOTH"])

    def test_navigation(self):
        page = self.client.get("/applications/")
        self.assertContains(page, 'href="/cloud-accounts/?state=all">Cloud accounts</a>')
        self.assertContains(page, 'href="/cloud-accounts/?state=needs">Needs assignment')
        self.assertContains(page, 'href="/imports/">Upload Data')
        user = User.objects.create_user("u@example.com", "pw-Example-123", role=Role.objects.get(key=Role.USER))
        self.client.force_login(user)
        self.assertNotContains(self.client.get("/applications/"), "Cloud Accounts")


class AccessAndPageTests(Base):
    def setUp(self):
        super().setUp()
        load_cmdb(self.admin, cmdb("mine", "APP-1"), cmdb("theirs", "APP-2"))
        Application.objects.filter(app_id="APP-1").update(support_emails="user@example.com")
        finish(self.admin, mfs_file(mfs("mine", "1"), mfs("theirs", "2"), mfs("stray", "3")), qualys_file(qualys("mine", "1")))
        self.user = User.objects.create_user("user@example.com", "pw-Example-123", role=Role.objects.get(key=Role.USER))
        self.operation = User.objects.create_user(
            "op@example.com", "pw-Example-123", role=Role.objects.get(key=Role.OPERATION)
        )

    def test_user_sees_only_own_servers(self):
        self.client.force_login(self.user)
        mine, theirs = Server.objects.get(name="mine"), Server.objects.get(name="theirs")
        self.assertEqual(self.client.get(f"/servers/{mine.pk}/").status_code, 200)
        self.assertEqual(self.client.get(f"/servers/{theirs.pk}/").status_code, 404)
        self.assertEqual(self.client.get("/applications/APP-2/servers/").status_code, 404)
        listing = self.client.get("/servers/?state=all")
        self.assertContains(listing, "mine")
        self.assertNotContains(listing, "theirs")
        self.assertNotContains(listing, "stray")
        self.assertContains(self.client.get("/dashboard/servers/"), "Showing only")
        for path in ("/servers/imports/", "/servers/cmdb/", "/servers/app-search/"):
            self.assertEqual(self.client.get(path).status_code, 403)

    def test_operation_assigns_unassigned_servers(self):
        self.client.force_login(self.operation)
        stray = Server.objects.get(name="stray")
        self.assertContains(self.client.get("/servers/?state=unassigned"), "stray")
        self.assertEqual(self.client.get("/servers/app-search/?q=APP").json()["matches"][0]["app_id"], "APP-1")
        app = Application.objects.get(app_id="APP-1")
        self.client.post("/servers/assign/", {"server_ids": [stray.pk], "application": app.pk})
        stray.refresh_from_db()
        self.assertEqual((stray.app_id, stray.manual_app_id), ("APP-1", "APP-1"))
        self.assertEqual(stray.assignments.get().new_app_id, "APP-1")
        self.assertEqual(self.client.get("/servers/imports/").status_code, 403)

    def test_pages(self):
        self.client.force_login(self.admin)
        server = Server.objects.get(name="mine")
        run = ServerImport.objects.get()
        cmdb_item = InventoryImport.objects.first()
        pages = [
            "/dashboard/servers/", "/", "/servers/", "/servers/?state=unassigned", "/servers/?state=not_in_cmdb",
            "/servers/?state=all&q=mine&kev=yes", f"/servers/{server.pk}/", f"/servers/{server.pk}/?status=all&q=1",
            "/applications/APP-1/servers/", "/applications/APP-1/servers/?status=remediated&severity=High",
            "/applications/APP-1/", "/servers/imports/", f"/servers/imports/{run.pk}/", "/servers/cmdb/",
            f"/servers/cmdb/{cmdb_item.pk}/", f"/servers/cmdb/{cmdb_item.pk}/?show=unchanged", "/notifications/",
        ]
        for path in pages:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)
        page = self.client.get("/applications/APP-1/servers/")
        self.assertContains(page, "Apply the update.")
        self.assertContains(page, 'href="/applications/APP-1/servers/"')
        export = self.client.get("/applications/APP-1/servers/export.csv")
        rows = list(csv.reader(io.StringIO(b"".join(export.streaming_content).decode())))
        self.assertEqual((rows[0][0], rows[1][0], len(rows)), ("Server", "mine", 2))
        listing = self.client.get("/servers/?state=all")
        self.assertEqual(listing.context["environments"], ["Production"])  # each value once
        self.assertEqual(listing.context["classes"], ["Linux Server"])
        dashboard = self.client.get("/dashboard/servers/")
        self.assertEqual(dashboard.context["open_count"], 3)
        self.assertEqual(dashboard.context["unassigned_findings"], 1)

    def test_upload_flow_through_views(self):
        self.client.force_login(self.admin)
        response = self.client.post("/servers/imports/", {"file": mfs_file(mfs("mine", "1"), mfs("mine", "5"))})
        run = ServerImport.objects.get(status=ServerImport.DRAFT)
        self.assertRedirects(response, f"/servers/imports/{run.pk}/")
        self.client.post(f"/servers/imports/{run.pk}/add/", {"file": qualys_file(qualys("mine", "5"))})
        self.assertEqual(run.files.count(), 2)
        page = self.client.get(f"/servers/imports/{run.pk}/")
        self.assertContains(page, "Will be marked remediated")
        planned = self.client.get(f"/servers/imports/{run.pk}/will-be-remediated.csv")
        self.assertIn("theirs", b"".join(planned.streaming_content).decode())
        response = self.client.post(f"/servers/imports/{run.pk}/finalize/", {})
        self.assertEqual(ServerImport.objects.get(pk=run.pk).status, ServerImport.DRAFT)  # needs the total or a reason
        self.client.post(f"/servers/imports/{run.pk}/expected/", {"expected_total": "2"})
        self.client.post(f"/servers/imports/{run.pk}/finalize/", {"confirm_text": CONFIRM})
        run.refresh_from_db()
        self.assertEqual((run.status, run.new_count, run.remediated_count), (ServerImport.FINALIZED, 1, 2))
        self.assertEqual(finding("mine", "5").solution, "Apply the update.")
        self.assertFalse(Job.objects.filter(status=Job.FAILED).exists())

    def test_cmdb_views(self):
        self.client.force_login(self.admin)
        response = self.client.post("/servers/cmdb/", {"file": cmdb_file(cmdb("mine", "APP-3"), cmdb("brand-new", "APP-3"))})
        item = InventoryImport.objects.first()
        self.assertRedirects(response, f"/servers/cmdb/{item.pk}/")
        self.assertContains(self.client.get(f"/servers/cmdb/{item.pk}/"), "brand-new")
        self.client.post(f"/servers/cmdb/{item.pk}/apply/")
        item.refresh_from_db()
        self.assertEqual(item.status, InventoryImport.APPLIED)
        self.assertEqual(Server.objects.get(name="mine").app_id, "APP-3")
        self.assertEqual(AlertSummary.objects.count(), 0)  # containers are untouched
        discard = inventory.start(cmdb_file(cmdb("x")), self.admin)
        self.client.post(f"/servers/cmdb/{discard.pk}/discard/")
        self.assertFalse(InventoryImport.objects.filter(pk=discard.pk).exists())
