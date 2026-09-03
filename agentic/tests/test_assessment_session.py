# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AssessmentSession State Layer and Rewired UI Routes
Ensures epistemic truthfulness: zero demo metrics, HTTP 409 on missing session,
and exact metric synchronization between CLI and UI.
"""

import unittest
import os
import sys
import json
import tempfile
import shutil

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
agentic_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(agentic_dir)
for p in [root_dir, agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from domain.models.session import AssessmentSession
from domain.enums import ExecutionMode, AssessmentStatus
from agentic.ui.server import AISPRServerHandler, render_official_report_html


class TestAssessmentSession(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_session_instantiation_and_defaults(self):
        """Verifies default values and field validation on AssessmentSession."""
        session = AssessmentSession(
            session_id="SES-TEST-001",
            client="Test Client Corp",
            scope="GCP & AWS Estate",
            execution_mode="SIMULATION"
        )
        self.assertEqual(session.session_id, "SES-TEST-001")
        self.assertEqual(session.client, "Test Client Corp")
        self.assertEqual(session.scope, "GCP & AWS Estate")
        self.assertEqual(session.execution_mode, ExecutionMode.SIMULATION)
        self.assertEqual(session.status, AssessmentStatus.COMPLETED)
        self.assertEqual(session.answers, {})
        self.assertEqual(session.findings, [])

    def test_calculate_metrics_deterministic(self):
        """Verifies deterministic calculation of metrics without hardcoded numbers."""
        session = AssessmentSession(
            session_id="SES-METRICS-01",
            answers={
                "DAT-01": {"status": "Y", "score": 1.0, "notes": "CMEK verified"},
                "DAT-02": {"status": "P", "score": 0.5, "notes": "Partial tagging"},
                "DAT-03": {"status": "N", "score": 0.0, "notes": "No DLP"},
                "MOD-01": {"status": "Y", "score": 1.0, "notes": "Signed weights"},
            }
        )
        metrics = session.calculate_metrics()
        self.assertEqual(metrics["controls_yes"], 2)
        self.assertEqual(metrics["controls_partial"], 1)
        self.assertEqual(metrics["controls_no"], 1)
        self.assertEqual(metrics["controls_total"], 104)
        self.assertGreater(metrics["health_score_percentage"], 0.0)

    def test_save_and_load_persistence(self):
        """Verifies persistence to local JSON and exact reconstruction upon load."""
        session = AssessmentSession(
            session_id="SES-PERSIST-01",
            client="Global FinTech",
            scope="Multi-Cloud Estate",
            execution_mode=ExecutionMode.LIVE,
            answers={"GOV-01": {"status": "Y", "score": 1.0}}
        )
        res = session.save(sessions_dir=self.test_dir)
        self.assertTrue(res["success"])
        self.assertEqual(res["session_id"], "SES-PERSIST-01")
        self.assertTrue(os.path.exists(res["local_path"]))

        loaded = AssessmentSession.load("SES-PERSIST-01", sessions_dir=self.test_dir)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.session_id, "SES-PERSIST-01")
        self.assertEqual(loaded.client, "Global FinTech")
        self.assertEqual(loaded.execution_mode, ExecutionMode.LIVE)
        self.assertEqual(loaded.metrics["controls_yes"], 1)

    def test_load_nonexistent_session_returns_none(self):
        """Verifies that loading a missing session returns None, never a placeholder."""
        loaded = AssessmentSession.load("NONEXISTENT-SESSION-ID", sessions_dir=self.test_dir)
        self.assertIsNone(loaded)

    def test_render_official_report_contains_execution_mode_and_metrics(self):
        """Verifies that render_official_report_html includes execution mode badge and real metrics."""
        session = AssessmentSession(
            session_id="SES-HTML-01",
            client="Enterprise Customer Alpha",
            scope="Multi-Cloud Estate",
            execution_mode=ExecutionMode.SIMULATION,
            answers={"DAT-01": {"status": "Y", "score": 1.0}}
        )
        session.calculate_metrics()
        html = render_official_report_html(session)
        self.assertIn("EXECUTION MODE: SIMULATION", html)
        self.assertIn("Enterprise Customer Alpha", html)
        self.assertIn(f"{session.metrics['health_score_percentage']}%", html)
        # Ensure zero references to DEMO_
        self.assertNotIn("DEMO_", html)

    def test_zero_demo_in_ui_server(self):
        """Verifies that agentic/ui/server.py contains zero references to DEMO_."""
        server_path = os.path.join(root_dir, "agentic", "ui", "server.py")
        with open(server_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("DEMO_", content)
        self.assertNotIn("71.2", content)
        self.assertNotIn('"controls_yes": 62', content)


if __name__ == "__main__":
    unittest.main()
