import json
import os
import sys
import unittest
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit

FIX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")


def run_result():
    result = audit.AuditResult()
    rows = audit.load_cost_report(os.path.join(FIX, "cost_report.csv"))
    snap = audit.load_snapshot(os.path.join(FIX, "tenancy_snapshot.json"))
    audit.analyze_cost(rows, snap["budgets"], result)
    audit.audit_security(snap, result, today=date(2026, 9, 1))
    return result


class TestCostParsing(unittest.TestCase):
    def test_rows_load(self):
        rows = audit.load_cost_report(os.path.join(FIX, "cost_report.csv"))
        self.assertGreater(len(rows), 100)
        self.assertEqual(set(r["compartment"] for r in rows), {"prod", "dev"})

    def test_empty_report_rejected(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
            fh.write("date,service,compartment,usage_amount,cost\n")
            path = fh.name
        with self.assertRaises(ValueError):
            audit.load_cost_report(path)
        os.unlink(path)

    def test_totals_and_top_spender(self):
        r = run_result()
        top = next(iter(r.cost_by_service))
        self.assertEqual(top, "Compute")
        self.assertTrue(any(f.rule == "top_spender" and f.severity == "INFO" for f in r.findings))


class TestCostFindings(unittest.TestCase):
    def test_spike_detected(self):
        r = run_result()
        spikes = [f for f in r.findings if f.rule == "cost_spike"]
        self.assertEqual(len(spikes), 1)
        self.assertIn("Object Storage", spikes[0].resource)
        self.assertEqual(spikes[0].severity, "HIGH")

    def test_mom_math(self):
        r = run_result()
        mom = r.month_over_month["Object Storage"]
        self.assertGreater(mom["change_pct"], 100.0)

    def test_budget_compares_latest_month(self):
        r = run_result()
        exceeded = {f.resource for f in r.findings if f.rule == "budget_exceeded"}
        self.assertEqual(exceeded, {"budget:dev-monthly"})


class TestSecurityRules(unittest.TestCase):
    def setUp(self):
        self.r = run_result()
        self.rules = {}
        for f in self.r.findings:
            self.rules.setdefault(f.rule, []).append(f)

    def test_public_bucket(self):
        self.assertEqual([f.resource for f in self.rules["public_bucket"]], ["bucket:team-assets-public"])

    def test_open_admin_port(self):
        f = self.rules["open_admin_port"][0]
        self.assertEqual(f.resource, "security-list:legacy-sl")
        self.assertEqual(f.severity, "HIGH")

    def test_broad_policy_skips_admin_group(self):
        self.assertEqual([f.resource for f in self.rules["broad_policy"]], ["policy:devs-too-broad"])

    def test_mfa_and_old_key(self):
        self.assertEqual([f.resource for f in self.rules["user_without_mfa"]], ["user:arjun.mehta"])
        self.assertEqual(self.rules["old_api_key"][0].severity, "LOW")

    def test_no_budget_rule_absent_when_budgets_exist(self):
        self.assertNotIn("no_budget", self.rules)

    def test_no_budget_rule_fires(self):
        r = audit.AuditResult()
        snap = {"buckets": [], "security_lists": [], "iam_policies": [], "users": [], "budgets": []}
        audit.audit_security(snap, r, today=date(2026, 9, 1))
        self.assertIn("no_budget", {f.rule for f in r.findings})


class TestGate(unittest.TestCase):
    def test_fail_on_triggers(self):
        code = audit.main(["--cost-report", os.path.join(FIX, "cost_report.csv"),
                           "--snapshot", os.path.join(FIX, "tenancy_snapshot.json"),
                           "--fail-on", "HIGH"])
        self.assertEqual(code, 1)

    def test_fail_on_passes_above_worst(self):
        code = audit.main(["--cost-report", os.path.join(FIX, "cost_report.csv"),
                           "--snapshot", os.path.join(FIX, "tenancy_snapshot.json"),
                           "--output", os.devnull])
        self.assertEqual(code, 0)

    def test_json_output_shape(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            path = fh.name
        audit.main(["--cost-report", os.path.join(FIX, "cost_report.csv"),
                    "--snapshot", os.path.join(FIX, "tenancy_snapshot.json"),
                    "--output", path])
        report = json.load(open(path))
        os.unlink(path)
        self.assertIn("findings", report)
        self.assertIn("cost_by_service", report)
        self.assertTrue(all({"rule", "severity", "resource", "detail"} <= set(f) for f in report["findings"]))


if __name__ == "__main__":
    unittest.main()
