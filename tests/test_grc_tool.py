"""
Test suite for the GRC Tool.
Uses only the standard library (unittest + sqlite3 in-memory DB).
"""

import json
import os
import sys
import unittest
import tempfile

# Ensure the repo root is on the path so tests work without installing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from grc_tool.database import Database
from grc_tool.models import Risk, Control, Policy, Assessment
from grc_tool.risk_manager import RiskManager
from grc_tool.control_manager import ControlManager
from grc_tool.policy_manager import PolicyManager
from grc_tool.assessment_manager import AssessmentManager
from grc_tool.report_generator import ReportGenerator
from grc_tool.ai_advisor import AIAdvisor
from grc_tool.frameworks import available_frameworks, get_framework_controls


# ──────────────────────────────────────────────────────────────────────────────
# Helper – in-memory database
# ──────────────────────────────────────────────────────────────────────────────

def make_db() -> Database:
    db = Database(":memory:")
    db.initialize()
    return db


# ──────────────────────────────────────────────────────────────────────────────
# Database tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.db = make_db()

    def tearDown(self):
        self.db.close()

    def test_initialize_creates_tables(self):
        tables = {
            row[0]
            for row in self.db.fetchall(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertIn("risks", tables)
        self.assertIn("controls", tables)
        self.assertIn("policies", tables)
        self.assertIn("assessments", tables)
        self.assertIn("audit_log", tables)
        self.assertIn("risk_controls", tables)

    def test_audit_log(self):
        self.db.log_action("TEST", "risk", 42, {"foo": "bar"}, actor="unit-test")
        row = self.db.fetchone("SELECT * FROM audit_log WHERE actor='unit-test'")
        self.assertIsNotNone(row)
        self.assertEqual(row["action"], "TEST")
        self.assertEqual(row["entity_type"], "risk")
        details = json.loads(row["details"])
        self.assertEqual(details["foo"], "bar")

    def test_idempotent_initialize(self):
        # Should not raise even if called twice
        self.db.initialize()
        self.db.initialize()


# ──────────────────────────────────────────────────────────────────────────────
# Model tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskModel(unittest.TestCase):

    def test_risk_score(self):
        r = Risk(title="Test", likelihood=4, impact=5)
        self.assertEqual(r.risk_score, 20)

    def test_risk_level_critical(self):
        r = Risk(title="T", likelihood=4, impact=5)
        self.assertEqual(r.risk_level, "Critical")

    def test_risk_level_high(self):
        r = Risk(title="T", likelihood=3, impact=4)
        self.assertEqual(r.risk_level, "High")

    def test_risk_level_medium(self):
        r = Risk(title="T", likelihood=2, impact=3)
        self.assertEqual(r.risk_level, "Medium")

    def test_risk_level_low(self):
        r = Risk(title="T", likelihood=1, impact=1)
        self.assertEqual(r.risk_level, "Low")

    def test_to_dict_serialises_tags(self):
        r = Risk(title="T", tags=["cloud", "iam"])
        d = r.to_dict()
        self.assertIsInstance(d["tags"], str)
        self.assertEqual(json.loads(d["tags"]), ["cloud", "iam"])

    def test_risk_score_boundary_25(self):
        r = Risk(title="T", likelihood=5, impact=5)
        self.assertEqual(r.risk_score, 25)
        self.assertEqual(r.risk_level, "Critical")


# ──────────────────────────────────────────────────────────────────────────────
# RiskManager tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskManager(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        self.mgr = RiskManager(self.db)

    def tearDown(self):
        self.db.close()

    def _add(self, **kwargs) -> int:
        risk = Risk(title=kwargs.pop("title", "Test Risk"), **kwargs)
        return self.mgr.add_risk(risk)

    def test_add_and_get(self):
        rid = self._add(title="SQL Injection Risk", likelihood=4, impact=5)
        r = self.mgr.get_risk(rid)
        self.assertIsNotNone(r)
        self.assertEqual(r.title, "SQL Injection Risk")
        self.assertEqual(r.risk_score, 20)

    def test_list_all(self):
        self._add(title="R1")
        self._add(title="R2")
        risks = self.mgr.list_risks()
        self.assertEqual(len(risks), 2)

    def test_list_filter_status(self):
        self._add(title="Open Risk")
        rid2 = self._add(title="Closed Risk")
        self.mgr.update_risk(rid2, {"status": "Closed"})
        open_risks = self.mgr.list_risks(status="Open")
        self.assertEqual(len(open_risks), 1)
        self.assertEqual(open_risks[0].title, "Open Risk")

    def test_update_risk(self):
        rid = self._add(title="R", likelihood=2, impact=2)
        self.mgr.update_risk(rid, {"status": "Mitigated", "likelihood": 1})
        r = self.mgr.get_risk(rid)
        self.assertEqual(r.status, "Mitigated")
        self.assertEqual(r.likelihood, 1)

    def test_update_recalculates_level(self):
        rid = self._add(likelihood=1, impact=1)  # Low
        self.mgr.update_risk(rid, {"likelihood": 5, "impact": 5})
        r = self.mgr.get_risk(rid)
        self.assertEqual(r.risk_level, "Critical")

    def test_delete_risk(self):
        rid = self._add(title="To Delete")
        self.mgr.delete_risk(rid)
        self.assertIsNone(self.mgr.get_risk(rid))

    def test_risk_summary(self):
        self._add(likelihood=4, impact=5)   # Critical
        self._add(likelihood=3, impact=4)   # High
        self._add(likelihood=2, impact=3)   # Medium
        summary = self.mgr.risk_summary()
        self.assertEqual(summary["total"], 3)
        self.assertGreater(summary["by_level"]["Critical"], 0)

    def test_top_risks_ordered_by_score(self):
        self._add(title="Low",  likelihood=1, impact=1)
        self._add(title="High", likelihood=5, impact=5)
        top = self.mgr.top_risks(2)
        self.assertEqual(top[0].title, "High")

    def test_get_nonexistent_returns_none(self):
        self.assertIsNone(self.mgr.get_risk(9999))


# ──────────────────────────────────────────────────────────────────────────────
# ControlManager tests
# ──────────────────────────────────────────────────────────────────────────────

class TestControlManager(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        self.mgr = ControlManager(self.db)

    def tearDown(self):
        self.db.close()

    def test_import_nist_csf(self):
        count = self.mgr.import_framework("NIST CSF")
        self.assertGreater(count, 0)

    def test_import_idempotent(self):
        count1 = self.mgr.import_framework("NIST CSF")
        count2 = self.mgr.import_framework("NIST CSF")
        self.assertGreater(count1, 0)
        self.assertEqual(count2, 0)  # no duplicates

    def test_import_all_frameworks(self):
        results = self.mgr.import_all_frameworks()
        self.assertEqual(set(results.keys()), set(available_frameworks()))
        for fw, cnt in results.items():
            self.assertGreater(cnt, 0, f"Expected controls for {fw}")

    def test_list_by_framework(self):
        self.mgr.import_framework("ISO 27001")
        controls = self.mgr.list_controls(framework="ISO 27001")
        self.assertTrue(all(c.framework == "ISO 27001" for c in controls))

    def test_update_control_status(self):
        self.mgr.import_framework("NIST CSF")
        ok = self.mgr.update_control_status(
            "ID.AM-01", "Implemented",
            implementation="Asset DB deployed",
            evidence="CMDB export",
            owner="IT Ops",
        )
        self.assertTrue(ok)
        ctrl = self.mgr.get_control("ID.AM-01")
        self.assertEqual(ctrl.status, "Implemented")
        self.assertEqual(ctrl.owner, "IT Ops")

    def test_update_invalid_status_raises(self):
        self.mgr.import_framework("NIST CSF")
        with self.assertRaises(ValueError):
            self.mgr.update_control_status("ID.AM-01", "Invalid Status")

    def test_compliance_score_zero_before_implementation(self):
        self.mgr.import_framework("NIST CSF")
        scores = self.mgr.compliance_score("NIST CSF")
        self.assertIn("NIST CSF", scores)
        self.assertEqual(scores["NIST CSF"]["implemented"], 0)

    def test_compliance_score_increases_after_implementation(self):
        self.mgr.import_framework("NIST CSF")
        self.mgr.update_control_status("ID.AM-01", "Implemented")
        scores = self.mgr.compliance_score("NIST CSF")
        self.assertGreater(scores["NIST CSF"]["score"], 0)

    def test_get_control_by_string_id(self):
        self.mgr.import_framework("SOC 2")
        ctrl = self.mgr.get_control("CC6.1")
        self.assertIsNotNone(ctrl)
        self.assertEqual(ctrl.framework, "SOC 2")


# ──────────────────────────────────────────────────────────────────────────────
# PolicyManager tests
# ──────────────────────────────────────────────────────────────────────────────

class TestPolicyManager(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        self.mgr = PolicyManager(self.db)

    def tearDown(self):
        self.db.close()

    def test_create_from_template(self):
        pid = self.mgr.create_from_template("Cloud Security Policy", "POL-001", owner="CISO")
        p = self.mgr.get_policy("POL-001")
        self.assertIsNotNone(p)
        self.assertEqual(p.title, "Cloud Security Policy")
        self.assertEqual(p.status, "Draft")
        self.assertIn("MFA", p.content)

    def test_invalid_template_raises(self):
        with self.assertRaises(ValueError):
            self.mgr.create_from_template("Nonexistent Template", "POL-X")

    def test_approve_policy(self):
        self.mgr.create_from_template("AI Governance Policy", "POL-002")
        ok = self.mgr.approve_policy("POL-002", approver="Board")
        self.assertTrue(ok)
        p = self.mgr.get_policy("POL-002")
        self.assertEqual(p.status, "Approved")
        self.assertEqual(p.approver, "Board")

    def test_list_by_status(self):
        self.mgr.create_from_template("Cloud Security Policy",  "POL-003")
        self.mgr.create_from_template("AI Governance Policy",    "POL-004")
        self.mgr.approve_policy("POL-004", approver="CISO")
        drafts = self.mgr.list_policies(status="Draft")
        approved = self.mgr.list_policies(status="Approved")
        self.assertEqual(len(drafts), 1)
        self.assertEqual(len(approved), 1)

    def test_available_templates(self):
        templates = self.mgr.available_templates()
        self.assertIn("Cloud Security Policy", templates)
        self.assertIn("AI Governance Policy", templates)
        self.assertIn("Incident Response Policy", templates)

    def test_policy_summary(self):
        self.mgr.create_from_template("Cloud Security Policy", "P-S1")
        summary = self.mgr.policy_summary()
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["Draft"], 1)


# ──────────────────────────────────────────────────────────────────────────────
# AssessmentManager tests
# ──────────────────────────────────────────────────────────────────────────────

class TestAssessmentManager(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        self.ctrl_mgr = ControlManager(self.db)
        self.mgr = AssessmentManager(self.db)

    def tearDown(self):
        self.db.close()

    def test_create_and_retrieve(self):
        a = Assessment(name="Q1 NIST CSF", framework="NIST CSF")
        aid = self.mgr.create_assessment(a)
        fetched = self.mgr.get_assessment(aid)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.framework, "NIST CSF")

    def test_score_from_controls(self):
        self.ctrl_mgr.import_framework("NIST CSF")
        # Implement half the controls
        controls = self.ctrl_mgr.list_controls(framework="NIST CSF")
        half = controls[:len(controls) // 2]
        for c in half:
            self.ctrl_mgr.update_control_status(c.control_id, "Implemented")

        a = Assessment(name="Test Assessment", framework="NIST CSF")
        aid = self.mgr.create_assessment(a)
        score = self.mgr.score_from_controls(aid)
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 100)

        # Re-fetch and check status
        fetched = self.mgr.get_assessment(aid)
        self.assertEqual(fetched.status, "Completed")
        self.assertIsNotNone(fetched.score)

    def test_list_assessments(self):
        self.mgr.create_assessment(Assessment(name="A1", framework="SOC 2"))
        self.mgr.create_assessment(Assessment(name="A2", framework="ISO 27001"))
        assessments = self.mgr.list_assessments()
        self.assertEqual(len(assessments), 2)


# ──────────────────────────────────────────────────────────────────────────────
# ReportGenerator tests
# ──────────────────────────────────────────────────────────────────────────────

class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        self.risk_mgr = RiskManager(self.db)
        self.ctrl_mgr = ControlManager(self.db)
        self.policy_mgr = PolicyManager(self.db)
        self.gen = ReportGenerator(self.db, org_name="Test Org")

        # Seed some data
        self.risk_mgr.add_risk(Risk(title="Test Risk", likelihood=3, impact=4))
        self.ctrl_mgr.import_framework("NIST CSF")
        self.ctrl_mgr.update_control_status("ID.AM-01", "Implemented")
        self.policy_mgr.create_from_template("Cloud Security Policy", "POL-TEST")

    def tearDown(self):
        self.db.close()

    def test_generate_json(self):
        json_str = self.gen.generate_json()
        data = json.loads(json_str)
        self.assertIn("risk_summary", data)
        self.assertIn("compliance_scores", data)
        self.assertIn("policies", data)
        self.assertEqual(data["org_name"], "Test Org")

    def test_generate_html(self):
        html = self.gen.generate_html()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("GRC Status Report", html)
        self.assertIn("Test Org", html)
        self.assertIn("NIST CSF", html)

    def test_generate_risk_csv(self):
        csv_str = self.gen.generate_risk_csv()
        self.assertIn("Title", csv_str)
        self.assertIn("Test Risk", csv_str)

    def test_generate_controls_csv(self):
        csv_str = self.gen.generate_controls_csv()
        self.assertIn("Control ID", csv_str)
        self.assertIn("NIST CSF", csv_str)

    def test_generate_json_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.gen.generate_json(path)
            with open(path) as f:
                data = json.load(f)
            self.assertIn("risk_summary", data)
        finally:
            os.unlink(path)

    def test_generate_html_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            self.gen.generate_html(path)
            with open(path) as f:
                content = f.read()
            self.assertIn("<!DOCTYPE html>", content)
        finally:
            os.unlink(path)


# ──────────────────────────────────────────────────────────────────────────────
# Framework catalogue tests
# ──────────────────────────────────────────────────────────────────────────────

class TestFrameworks(unittest.TestCase):

    def test_available_frameworks(self):
        fws = available_frameworks()
        self.assertIn("NIST CSF", fws)
        self.assertIn("NIST AI RMF", fws)
        self.assertIn("ISO 27001", fws)
        self.assertIn("SOC 2", fws)
        self.assertIn("CSA CCM", fws)

    def _validate_controls(self, framework: str):
        controls = get_framework_controls(framework)
        self.assertIsInstance(controls, list)
        self.assertGreater(len(controls), 0, f"{framework} has no controls")
        required_keys = {"control_id", "framework", "domain", "title"}
        for c in controls:
            self.assertTrue(
                required_keys.issubset(c.keys()),
                f"Control {c.get('control_id','?')} missing keys in {framework}",
            )
            self.assertEqual(c["framework"], framework)

    def test_nist_csf_controls(self):
        self._validate_controls("NIST CSF")

    def test_nist_ai_rmf_controls(self):
        self._validate_controls("NIST AI RMF")

    def test_iso27001_controls(self):
        self._validate_controls("ISO 27001")

    def test_soc2_controls(self):
        self._validate_controls("SOC 2")

    def test_csa_ccm_controls(self):
        self._validate_controls("CSA CCM")

    def test_invalid_framework_raises(self):
        with self.assertRaises(ValueError):
            get_framework_controls("NONEXISTENT")

    def test_control_ids_unique_per_framework(self):
        for fw in available_frameworks():
            controls = get_framework_controls(fw)
            ids = [c["control_id"] for c in controls]
            self.assertEqual(len(ids), len(set(ids)), f"Duplicate control IDs in {fw}")


# ──────────────────────────────────────────────────────────────────────────────
# AIAdvisor tests (no network required)
# ──────────────────────────────────────────────────────────────────────────────

class TestAIAdvisor(unittest.TestCase):

    def test_is_available_false_when_offline(self):
        advisor = AIAdvisor(base_url="http://localhost:19999")  # unlikely port
        self.assertFalse(advisor.is_available())

    def test_list_models_returns_empty_when_offline(self):
        advisor = AIAdvisor(base_url="http://localhost:19999")
        self.assertEqual(advisor.list_models(), [])

    def test_safe_chat_returns_fallback_when_offline(self):
        advisor = AIAdvisor(base_url="http://localhost:19999")
        result = advisor._safe_chat("test", fallback="FALLBACK")
        self.assertEqual(result, "FALLBACK")

    def test_safe_chat_returns_warning_when_offline_no_fallback(self):
        advisor = AIAdvisor(base_url="http://localhost:19999")
        result = advisor._safe_chat("test")
        self.assertIn("Ollama", result)

    def test_analyse_risk_returns_string(self):
        advisor = AIAdvisor(base_url="http://localhost:19999")
        result = advisor.analyse_risk("Test", "Description", "Cloud", 3, 4)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 10)


# ──────────────────────────────────────────────────────────────────────────────
# CLI integration tests
# ──────────────────────────────────────────────────────────────────────────────

class TestCLI(unittest.TestCase):
    """Smoke tests for the CLI layer using an in-memory database."""

    def setUp(self):
        from grc_tool.cli import GRCApp
        self.app = GRCApp(db_path=":memory:")
        # Pre-load some data
        from grc_tool.models import Risk
        self.app.risk_mgr.add_risk(Risk(title="CLI Test Risk", likelihood=3, impact=3))
        self.app.ctrl_mgr.import_framework("NIST CSF")

    def test_dashboard_runs(self):
        # Should not raise
        import argparse
        self.app.cmd_dashboard(argparse.Namespace())

    def test_risk_list_runs(self):
        import argparse
        args = argparse.Namespace(status=None, category=None, level=None)
        self.app.cmd_risk_list(args)

    def test_control_list_runs(self):
        import argparse
        args = argparse.Namespace(framework=None, status=None)
        self.app.cmd_control_list(args)

    def test_control_score_runs(self):
        import argparse
        args = argparse.Namespace(framework=None)
        self.app.cmd_control_score(args)

    def test_report_json_runs(self):
        import argparse
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            args = argparse.Namespace(format="json", output=path[:-5])
            self.app.cmd_report(args)
            self.assertTrue(os.path.exists(path))
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_policy_list_empty(self):
        import argparse
        args = argparse.Namespace(status=None)
        self.app.cmd_policy_list(args)  # Should not raise even with no policies

    def test_ai_status_runs(self):
        import argparse
        # Should not raise; Ollama will just be flagged as unavailable
        self.app.cmd_ai_status(argparse.Namespace())


if __name__ == "__main__":
    unittest.main(verbosity=2)
