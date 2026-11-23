import io
from datetime import datetime, timedelta, timezone as dt_timezone

from django.core import mail
from django.core.mail.backends.base import BaseEmailBackend
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone
from openpyxl import Workbook

from accounts.models import Role, User
from core.models import AppSettings

from . import assignment, followups, lifecycle
from .columns import COLUMNS, REQUIRED
from .models import AccountAssignment, Application, CloudAccount, FollowUp, FollowUpEvent, Notification, Vulnerability
from .notify import NotificationNotAllowed
from .parsing import FileFormatError, normalize_account_id, normalize_provider, parse_file, to_datetime
from .queries import followup_cutoff, vulns_for_app

HEADERS = ["Alert ID", "Account ID", "Account Name", "App ID", "Asset ID", "Severity", "CVE ID", "Last Scan"]
AWS_A, AWS_B = "111111111111", "222222222222"


def row(alert, asset="asset-1", scan="2026-09-01", app="", account=AWS_A, severity="High", name=None):
    return [alert, account, name or f"acct-{account}", app, asset, severity, f"CVE-{alert}", scan]


def csv_file(rows, headers=HEADERS, name="scan.csv", preamble=""):
    lines = [preamble] if preamble else []
    lines.append(",".join(headers))
    lines += [",".join(str(v) for v in r) for r in rows]
    return SimpleUploadedFile(name, ("\n".join(lines) + "\n").encode())


class BrokenBackend(BaseEmailBackend):
    def send_messages(self, email_messages):
        raise OSError("SMTP down")


class ParsingTests(TestCase):
    def test_real_export_headers(self):
        self.assertEqual(len(COLUMNS), 46)
        self.assertEqual(COLUMNS[0][0], "CSB ID")
        self.assertEqual(COLUMNS[-1][0], "Data Qualification")
        self.assertEqual(REQUIRED, ("alert_id", "account_id", "account_name"))

    def test_header_on_any_row_and_app_id_optional(self):
        f = csv_file([["A1", AWS_A, "prod", "high", "2026-10-01"]],
                     headers=["alert id", "ACCOUNTID", " Account  Name", "SEVERITY", "LastScan"],
                     preamble="Exported by scanner\n")
        result = parse_file(f, f.name)
        self.assertEqual(result.header_row, 3)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.rows[0]["severity"], "High")

    def test_both_environment_spellings(self):
        for header in ("Enviroment", "Environment"):
            f = csv_file([["A1", AWS_A, "prod", "Production"]], headers=["Alert ID", "Account ID", "Account Name", header])
            self.assertEqual(parse_file(f, f.name).rows[0]["environment"], "Production")

    def test_required_columns_are_enforced_per_row(self):
        f = csv_file([row("A1"), ["", AWS_A, "n", "", "a", "High", "C", "2026-10-01"],
                      ["A3", "", "n", "", "a", "High", "C", "2026-10-01"],
                      ["A4", AWS_A, "", "", "a", "High", "C", "2026-10-01"],
                      row("A5", scan="not a date")])
        result = parse_file(f, f.name)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual([e["row"] for e in result.errors], [3, 4, 5, 6])
        self.assertIn("Alert ID is missing", result.errors[0]["reason"])
        self.assertIn("Account ID is missing", result.errors[1]["reason"])
        self.assertIn("Account Name is missing", result.errors[2]["reason"])
        self.assertIn("Last Scan", result.errors[3]["reason"])

    def test_missing_required_header_raises(self):
        f = csv_file([["x", "y"]], headers=["Alert ID", "App ID"])
        with self.assertRaises(FileFormatError):
            parse_file(f, f.name)

    def test_account_id_normalization(self):
        self.assertEqual(normalize_account_id("12345678901", "AWS"), "012345678901")
        guid = "7C1E9A52-3B44-4D10-9F6E-1A2B3C4D5E01"
        self.assertEqual(normalize_account_id(guid, "Azure"), guid.lower())
        self.assertEqual(normalize_provider("", guid), "Azure")
        self.assertEqual(normalize_provider("", "12345678901"), "AWS")
        self.assertEqual(normalize_provider("Microsoft Azure", ""), "Azure")
        with self.assertRaises(ValueError):
            normalize_account_id("1.23457E+11", "AWS")

    def test_dates_real_values_text_and_serials(self):
        expected = datetime(2026, 10, 28, tzinfo=dt_timezone.utc)
        self.assertEqual(to_datetime(datetime(2026, 10, 28), "d"), expected)
        self.assertEqual(to_datetime("28/10/2026", "d"), expected)
        self.assertEqual(to_datetime("2026-10-28", "d"), expected)
        self.assertEqual(to_datetime(46323, "d"), expected)
        self.assertEqual(to_datetime("46323", "d"), expected)

    def test_excel_numeric_aws_id_keeps_leading_zero(self):
        wb = Workbook()
        ws = wb.active
        ws.append(["title row"])
        ws.append(["Alert ID", "Account ID", "Account Name", "Provider", "Last Scan", "Exception"])
        ws.append([12345, 12345678901, "prod", "AWS", datetime(2026, 10, 28, 8, 30), "Yes"])
        wb.create_sheet("ignored").append(["Alert ID", "Account ID", "Account Name"])
        buffer = io.BytesIO()
        wb.save(buffer)
        result = parse_file(io.BytesIO(buffer.getvalue()), "scan.xlsx")
        self.assertEqual(result.header_row, 2)
        self.assertEqual(result.rows[0]["alert_id"], "12345")
        self.assertEqual(result.rows[0]["account_id"], "012345678901")
        self.assertTrue(result.rows[0]["exception"])


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

    def test_remediated_only_on_newer_scan_of_same_account_and_asset(self):
        self.run_import(csv_file([row("A1"), row("A2"), row("B1", account=AWS_B)]))
        plan = self.run_import(csv_file([row("A1", scan="2026-10-01")]))
        self.assertEqual([v.alert_id for v, _ in plan.remediated], ["A2"])
        self.assertEqual(self.status("A2"), "remediated")
        self.assertEqual(self.status("B1"), "open")  # same Asset ID, different account
        self.assertEqual(Vulnerability.objects.get(alert_id="A2").remediated_at, datetime(2026, 10, 1, tzinfo=dt_timezone.utc))

    def test_older_file_changes_nothing(self):
        self.run_import(csv_file([row("A1", scan="2026-10-01")]))
        plan = self.run_import(csv_file([row("A1", severity="Critical"), row("A0")]))
        self.assertEqual(len(plan.skipped), 1)
        self.assertEqual(plan.remediated, [])
        self.assertEqual(Vulnerability.objects.get(alert_id="A1").severity, "High")

    def test_reopened_when_seen_in_newer_scan(self):
        self.run_import(csv_file([row("A1"), row("A2")]))
        self.run_import(csv_file([row("A2", scan="2026-10-01")]))
        self.assertEqual(self.status("A1"), "remediated")
        plan = self.run_import(csv_file([row("A1", scan="2026-11-01"), row("A2", scan="2026-11-01")]))
        self.assertEqual(len(plan.reopened), 1)
        a1 = Vulnerability.objects.get(alert_id="A1")
        self.assertEqual(a1.status, "open")
        self.assertIsNotNone(a1.reopened_at)
        self.assertIsNone(a1.remediated_at)

    def test_rejected_row_never_counts_as_fix(self):
        self.run_import(csv_file([row("A1"), row("A2")]))
        plan = self.run_import(csv_file([row("A1", scan="2026-10-01"), row("A2", scan="garbage")]))
        self.assertEqual(plan.remediated, [])
        self.assertEqual(self.status("A2"), "open")

    def test_rejected_row_with_no_account_or_asset_blocks_remediation(self):
        self.run_import(csv_file([row("A1"), row("A2")]))
        plan = self.run_import(csv_file([row("A1", scan="2026-10-01"), ["A9", "", "", "", "", "High", "C", "2026-10-01"]]))
        self.assertTrue(plan.protect_all)
        self.assertEqual(plan.remediated, [])

    def test_later_batch_replaces_earlier_row(self):
        plan = self.run_import(
            csv_file([row("A1", severity="Low")], name="b1.csv"),
            csv_file([row("A1", severity="Critical")], name="b2.csv"),
        )
        self.assertEqual(len(plan.new), 1)
        self.assertEqual(Vulnerability.objects.get(alert_id="A1").severity, "Critical")

    def test_account_name_change_does_not_create_new_account(self):
        self.run_import(csv_file([row("A1", name="old-name")]))
        self.run_import(csv_file([row("A1", scan="2026-10-01", name="new-name")]))
        self.assertEqual(CloudAccount.objects.count(), 1)
        self.assertEqual(CloudAccount.objects.get().account_name, "new-name")

    def test_only_one_draft_and_discard_changes_nothing(self):
        run = lifecycle.get_or_create_draft(self.user)
        self.assertEqual(lifecycle.get_or_create_draft(self.user), run)
        lifecycle.add_file(run, csv_file([row("A1")]), self.user)
        lifecycle.discard(run)
        self.assertFalse(Vulnerability.objects.exists())
        self.assertNotEqual(lifecycle.get_or_create_draft(self.user), run)


class AssignmentTests(TestCase):
    def setUp(self):
        Role.ensure_defaults()
        AppSettings.load()
        self.admin = User.objects.create_superuser("admin@example.com", "pw-Example-123")
        self.app = Application.objects.create(app_id="APP-1", owner_email="owner@example.com")
        self.other = Application.objects.create(app_id="APP-2", owner_email="other@example.com")
        run = lifecycle.get_or_create_draft(self.admin)
        lifecycle.add_file(run, csv_file([
            row("U1"), row("T1", app="APP-2"), row("X1", account=AWS_B),
        ]), self.admin)
        lifecycle.finalize(run, self.admin)
        self.account = CloudAccount.objects.get(account_id=AWS_A)

    def owner(self, alert_id):
        return Vulnerability.objects.with_owner().get(alert_id=alert_id).owner_app_id

    def test_untagged_inherit_and_own_tag_wins(self):
        self.assertIsNone(self.owner("U1"))
        assignment.assign([self.account.pk], self.app, self.admin)
        self.assertEqual(self.owner("U1"), "APP-1")
        self.assertEqual(self.owner("T1"), "APP-2")
        self.assertIsNone(self.owner("X1"))
        log = AccountAssignment.objects.get()
        self.assertEqual((log.old_app_id, log.new_app_id, log.untagged_open, log.changed_by), ("", "APP-1", 1, self.admin))

    def test_future_untagged_alerts_follow_assignment(self):
        assignment.assign([self.account.pk], self.app, self.admin)
        run = lifecycle.get_or_create_draft(self.admin)
        lifecycle.add_file(run, csv_file([row("U1", scan="2026-10-01"), row("U2", scan="2026-10-01")]), self.admin)
        lifecycle.finalize(run, self.admin)
        self.assertEqual(self.owner("U2"), "APP-1")

    def test_multiple_accounts_can_share_one_app(self):
        other = CloudAccount.objects.get(account_id=AWS_B)
        assignment.assign([self.account.pk, other.pk], self.app, self.admin)
        ids = set(vulns_for_app("APP-1").values_list("alert_id", flat=True))
        self.assertEqual(ids, {"U1", "X1"})

    def test_mixed_account_warning(self):
        result = assignment.preview(CloudAccount.objects.filter(pk=self.account.pk), self.app)
        self.assertEqual([a.pk for a in result["mixed"]], [self.account.pk])

    def test_deleting_app_returns_accounts_to_unassigned_and_keeps_alerts(self):
        assignment.assign([self.account.pk], self.app, self.admin)
        self.client.force_login(self.admin)
        self.client.post("/applications/APP-1/delete/")
        self.assertIsNone(self.owner("U1"))
        self.assertTrue(Vulnerability.objects.filter(alert_id="U1").exists())
        self.assertEqual(self.account.assignments.first().new_app_id, "")

    def test_roles_that_may_assign(self):
        url = "/cloud-accounts/assign/"
        data = {"account_ids": [self.account.pk], "application": self.app.pk, "confirm": "1"}
        for key, allowed in ((Role.OPERATION, True), (Role.ADMINISTRATOR, True), (Role.USER, False)):
            CloudAccount.objects.update(application=None)
            user = User.objects.create_user(f"{key}@example.com", "pw-Example-123", role=Role.objects.get(key=key))
            self.client.force_login(user)
            response = self.client.post(url, data)
            self.assertEqual(response.status_code, 302 if allowed else 403)
            self.account.refresh_from_db()
            self.assertEqual(self.account.application_id, self.app.pk if allowed else None)

    def test_operation_cannot_edit_owner_upload_or_notify(self):
        user = User.objects.create_user("op@example.com", "pw-Example-123", role=Role.objects.get(key=Role.OPERATION))
        self.client.force_login(user)
        self.assertEqual(self.client.get("/applications/new/").status_code, 403)
        self.assertEqual(self.client.get("/imports/").status_code, 403)
        self.assertEqual(self.client.post("/applications/APP-1/notify/").status_code, 403)

    def test_assign_requires_confirmation(self):
        self.client.force_login(self.admin)
        response = self.client.post("/cloud-accounts/assign/", {"account_ids": [self.account.pk], "application": self.app.pk})
        self.assertContains(response, "Shared account")
        self.account.refresh_from_db()
        self.assertIsNone(self.account.application)

    def test_user_role_sees_inherited_alerts(self):
        assignment.assign([self.account.pk], self.app, self.admin)
        owner = User.objects.create_user("owner@example.com", "pw-Example-123", role=Role.objects.get(key=Role.USER))
        self.client.force_login(owner)
        self.assertContains(self.client.get("/applications/APP-1/"), "U1")
        self.assertEqual(self.client.get("/applications/APP-2/").status_code, 404)
        self.assertEqual(self.client.get("/cloud-accounts/").status_code, 403)

    def test_notification_covers_inherited_alerts(self):
        assignment.assign([self.account.pk], self.app, self.admin)
        self.app.support_emails = "support@example.com"
        self.app.save()
        with self.settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend"):
            log = followups.notify_support(self.app, self.admin)
        self.assertEqual((log.status, log.vuln_count), ("sent", 1))
        self.assertIn("U1", mail.outbox[0].attachments[0][1])

    def test_all_pages_render_with_unassigned_data(self):
        self.client.force_login(self.admin)
        for url in ("/", "/applications/", "/applications/APP-2/", "/cloud-accounts/", "/cloud-accounts/?state=all",
                    f"/cloud-accounts/{AWS_A}/", "/imports/", "/imports/1/"):
            self.assertEqual(self.client.get(url).status_code, 200, url)


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
        self.assertEqual(app.contact_emails(), ["a@example.com", "b@example.com"])


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class FollowUpTests(TestCase):
    def setUp(self):
        Role.ensure_defaults()
        AppSettings.load()
        self.admin = User.objects.create_superuser("admin@example.com", "pw-Example-123")
        self.operation = User.objects.create_user(
            "op@example.com", "pw-Example-123", role=Role.objects.get(key=Role.OPERATION)
        )
        self.app = Application.objects.create(
            app_id="APP-1", support_team="Payments Support", support_emails="support@example.com",
            owner_name="Owner", owner_email="owner@example.com", extra_emails="extra@example.com",
        )
        run = lifecycle.get_or_create_draft(self.admin)
        lifecycle.add_file(run, csv_file([row("A1", app="APP-1"), row("A2", app="APP-1")]), self.admin)
        lifecycle.finalize(run, self.admin)

    def case(self):
        return FollowUp.objects.get(application=self.app)

    def test_first_send_goes_to_support_and_copies_extra_only(self):
        log = followups.notify_support(self.app, self.admin, "note")
        self.assertEqual(mail.outbox[0].to, ["support@example.com"])
        self.assertEqual(mail.outbox[0].cc, ["extra@example.com"])
        self.assertNotIn("owner@example.com", mail.outbox[0].recipients())
        self.assertEqual((log.kind, self.case().status, self.case().first_vuln_count), ("support", "waiting", 2))

    def test_no_support_email_blocks_send(self):
        self.app.support_emails = ""
        self.app.save()
        with self.assertRaises(NotificationNotAllowed):
            followups.notify_support(self.app, self.admin)
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(FollowUp.objects.exists())

    def test_second_send_is_a_reminder_on_the_same_follow_up(self):
        followups.notify_support(self.app, self.admin)
        waiting_since = self.case().waiting_since
        log = followups.notify_support(self.app, self.admin)
        self.assertEqual(log.kind, Notification.REMINDER)
        self.assertEqual(FollowUp.objects.count(), 1)
        self.assertEqual((self.case().reminder_count, self.case().waiting_since), (1, waiting_since))
        self.assertIn("Reminder", mail.outbox[1].subject)

    def test_remark_is_internal_unless_included(self):
        followups.notify_support(self.app, self.admin, "private note")
        self.assertNotIn("private note", mail.outbox[0].body)
        self.assertNotIn("private note", mail.outbox[0].alternatives[0][0])
        followups.notify_support(self.app, self.admin, "shared note", True)
        self.assertIn("shared note", mail.outbox[1].body)
        self.assertIn("shared note", mail.outbox[1].alternatives[0][0])

    def test_escalation_emails_owner_and_copies_support(self):
        followups.notify_support(self.app, self.admin)
        log = followups.escalate(self.case(), self.admin)
        message = mail.outbox[1]
        self.assertEqual(message.to, ["owner@example.com"])
        self.assertEqual(message.cc, ["support@example.com", "extra@example.com"])
        self.assertIn("ESCALATION", message.subject)
        self.assertIn("2 at first notice, 2 now", message.body)
        self.assertEqual((log.kind, self.case().status), ("escalation", "escalated"))
        followups.notify_support(self.app, self.admin)
        self.assertEqual(mail.outbox[2].to, ["owner@example.com"])

    def test_escalating_after_response_requires_reason(self):
        followups.notify_support(self.app, self.admin)
        followups.record_response(self.case(), self.operation, "Sam", timezone.localdate(), "Looking at it")
        self.assertEqual(self.case().status, "responded")
        with self.assertRaises(NotificationNotAllowed):
            followups.escalate(self.case(), self.admin)
        followups.escalate(self.case(), self.admin, "Not resolved")
        self.assertEqual(self.case().status, "escalated")

    def test_failed_email_is_logged_and_changes_nothing(self):
        followups.notify_support(self.app, self.admin)
        with override_settings(EMAIL_BACKEND="vulns.tests.BrokenBackend"):
            log = followups.escalate(self.case(), self.admin, "reason")
        self.assertEqual(log.status, Notification.FAILED)
        self.assertEqual(self.case().status, "waiting")
        self.assertFalse(self.case().events.filter(kind=FollowUpEvent.ESCALATED).exists())

    def test_failed_first_send_opens_no_follow_up(self):
        with override_settings(EMAIL_BACKEND="vulns.tests.BrokenBackend"):
            log = followups.notify_support(self.app, self.admin)
        self.assertEqual(log.status, Notification.FAILED)
        self.assertFalse(FollowUp.objects.exists())

    def test_overdue_after_configured_days(self):
        followups.notify_support(self.app, self.admin)
        FollowUp.objects.update(waiting_since=timezone.now() - timedelta(days=6))
        self.assertTrue(self.case().is_overdue(followup_cutoff()))
        settings = AppSettings.load()
        settings.followup_overdue_days = 10
        settings.save()
        self.assertFalse(self.case().is_overdue(followup_cutoff()))

    def test_closed_follow_up_lets_next_send_start_a_new_one(self):
        followups.notify_support(self.app, self.admin)
        followups.close(self.case(), self.admin)
        log = followups.notify_support(self.app, self.admin)
        self.assertEqual(log.kind, Notification.SUPPORT)
        self.assertEqual(FollowUp.objects.count(), 2)

    def test_operation_records_but_cannot_send_escalate_or_close(self):
        followups.notify_support(self.app, self.admin)
        case = self.case()
        self.client.force_login(self.operation)
        response = self.client.post(f"/follow-ups/{case.pk}/respond/", {
            "responder": "Sam", "responded_on": timezone.localdate().isoformat(), "response": "On it", "close": "on",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.case().status, "responded")  # the close tick is ignored for Operation
        self.assertEqual(self.client.post(f"/follow-ups/{case.pk}/remark/", {"remark": "note"}).status_code, 302)
        self.assertTrue(case.events.filter(kind=FollowUpEvent.REMARK).exists())
        for url in (f"/follow-ups/{case.pk}/escalate/", f"/follow-ups/{case.pk}/close/", "/applications/APP-1/notify/"):
            self.assertEqual(self.client.post(url, {"remark": "x"}).status_code, 403, url)

    def test_user_role_cannot_see_internal_notes_or_record(self):
        followups.notify_support(self.app, self.admin, "secret internal note")
        followups.notify_support(self.app, self.admin, "visible shared note", True)
        support = User.objects.create_user("support@example.com", "pw-Example-123", role=Role.objects.get(key=Role.USER))
        self.client.force_login(support)
        page = self.client.get("/applications/APP-1/")
        self.assertContains(page, "visible shared note")
        self.assertNotContains(page, "secret internal note")
        self.assertEqual(
            self.client.post(f"/follow-ups/{self.case().pk}/remark/", {"remark": "x"}).status_code, 403
        )

    def test_deleting_app_closes_follow_up_and_keeps_history(self):
        followups.notify_support(self.app, self.admin)
        case = self.case()
        self.client.force_login(self.admin)
        self.client.post("/applications/APP-1/delete/")
        case.refresh_from_db()
        self.assertEqual((case.status, case.application), ("closed", None))

    def test_pages_render_in_every_state(self):
        self.client.force_login(self.admin)
        urls = ("/", "/applications/", "/applications/?followup=overdue", "/applications/APP-1/", "/notifications/",
                "/notifications/?followup=overdue", "/settings/general/")
        for step in (lambda: None, lambda: followups.notify_support(self.app, self.admin),
                     lambda: followups.escalate(self.case(), self.admin),
                     lambda: followups.record_response(self.case(), self.admin, "Sam", timezone.localdate(), "Done"),
                     lambda: followups.close(self.case(), self.admin)):
            step()
            for url in urls:
                self.assertEqual(self.client.get(url).status_code, 200, url)
