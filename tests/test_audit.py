import copy
import json
import tempfile
import unittest
from pathlib import Path

from entra_audit.audit import evaluate
from entra_audit.report import csv_safe, export_report, html_report
from main import ROOT


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads((ROOT / "samples/demo_snapshot.json").read_text(encoding="utf-8"))
        self.policy = json.loads((ROOT / "config/policy.json").read_text(encoding="utf-8"))

    def test_demo_baseline_and_rules(self):
        report = evaluate(self.snapshot, self.policy)
        self.assertEqual(report["metrics"]["total_users"], 8)
        self.assertEqual(report["metrics"]["total_groups"], 6)
        self.assertEqual(report["metrics"]["scoped_groups"], 5)
        self.assertEqual(report["metrics"]["scoped_direct_membership_edges"], 8)
        rules = [f["rule"] for f in report["findings"]]
        self.assertIn("DISABLED_ACCOUNT_IN_GROUP", rules)
        self.assertIn("SENSITIVE_GROUP_MEMBER_REVIEW", rules)
        self.assertIn("CROSS_GROUP_REVIEW", rules)
        self.assertIn("MISSING_USER_ATTRIBUTE", rules)
        self.assertNotIn("BASELINE_COUNT_VARIANCE", rules)
        self.assertNotIn("BASELINE_MEMBER_VARIANCE", rules)

    def test_baseline_drift_is_review_not_failure(self):
        different = copy.deepcopy(self.snapshot)
        different["users"].pop()
        report = evaluate(different, self.policy)
        self.assertTrue(any(f["rule"] == "BASELINE_COUNT_VARIANCE" for f in report["findings"]))

    def test_unresolved_user_does_not_silently_disappear(self):
        different = copy.deepcopy(self.snapshot)
        different["memberships"]["g-hr"].append({"id": "deleted-u", "@odata.type": "#microsoft.graph.user"})
        report = evaluate(different, self.policy)
        self.assertTrue(any(f["rule"] == "UNRESOLVED_USER" for f in report["findings"]))

    def test_missing_group_collection_fails_closed(self):
        different = copy.deepcopy(self.snapshot)
        del different["memberships"]["g-it"]
        with self.assertRaises(ValueError):
            evaluate(different, self.policy)

    def test_nongroup_type_covered(self):
        different = copy.deepcopy(self.snapshot)
        different["memberships"]["g-fin"].append({"id": "object-01", "@odata.type": "#microsoft.graph.device"})
        report = evaluate(different, self.policy)
        self.assertEqual(report["metrics"]["non_user_members"], 1)
        self.assertTrue(any(f["rule"] == "NON_USER_MEMBER" for f in report["findings"]))

    def test_report_files_and_escaping(self):
        report = evaluate(self.snapshot, self.policy)
        with tempfile.TemporaryDirectory() as tmp:
            output = export_report(report, tmp)
            for name in ("audit.html", "audit.json", "users.csv", "groups.csv", "memberships.csv", "findings.csv", "evidence_manifest.json"):
                self.assertTrue((output / name).is_file(), name)
            self.assertIn("SYNTHETIC", (output / "audit.html").read_text(encoding="utf-8"))
            manifest = json.loads((output / "evidence_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["sha256"]), 6)

    def test_html_escapes_directory_fields(self):
        hostile = copy.deepcopy(self.snapshot)
        hostile["users"][6]["userPrincipalName"] = '<script>alert("x")</script>'
        rendered = html_report(evaluate(hostile, self.policy))
        self.assertNotIn('<script>alert("x")</script>', rendered)
        self.assertIn('&lt;script&gt;', rendered)

    def test_excel_formula_injection_hardened(self):
        self.assertEqual(csv_safe("=HYPERLINK(\"https://test\")"), "'=HYPERLINK(\"https://test\")")
        self.assertEqual(csv_safe("+1+2"), "'+1+2")
        self.assertEqual(csv_safe("Normal Name"), "Normal Name")


if __name__ == "__main__":
    unittest.main()
