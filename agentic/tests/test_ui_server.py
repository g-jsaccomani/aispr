# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AISPR FastAPI Cloud Run Platform & Identity-Aware Proxy (IAP) Auth
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
agentic_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(agentic_dir)
for p in [root_dir, agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agentic.ui.server import get_current_user, app, FASTAPI_AVAILABLE, TEMPLATES_DIR


class TestUIServerAndIAP(unittest.TestCase):

    def test_iap_header_authentication(self):
        """Verifies parsing of Google Cloud IAP authentication headers."""
        req = MagicMock()
        user = get_current_user(
            request=req,
            x_goog_authenticated_user_email="accounts.google.com:security-auditor@enterprise.com",
            x_goog_authenticated_user_id="accounts.google.com:1098237491823",
            x_goog_iap_jwt_assertion="eyJhbGciOiJSUzI1NiIs..."
        )
        self.assertEqual(user["email"], "security-auditor@enterprise.com")
        self.assertEqual(user["user_id"], "1098237491823")
        self.assertTrue(user["is_iap_authenticated"])
        self.assertEqual(user["auth_type"], "google_iap")
        self.assertTrue(user["jwt_assertion_present"])

    def test_bearer_session_authentication(self):
        """Verifies session / bearer token authentication."""
        req = MagicMock()
        user = get_current_user(
            request=req,
            authorization="Bearer secure-session-token-12345"
        )
        self.assertEqual(user["auth_type"], "bearer_session")
        self.assertTrue(user["has_live_credentials"])

    def test_local_dev_fallback_identity(self):
        """Verifies default authenticated admin persona in local development."""
        req = MagicMock()
        with patch.dict(os.environ, {"REQUIRE_IAP": "false"}):
            user = get_current_user(request=req)
            self.assertIn("security-lead@", user["email"])
            self.assertEqual(user["auth_type"], "local_dev_fallback")

    def test_strict_iap_mode_raises_unauthorized_when_missing(self):
        """Verifies 401 Unauthorized when REQUIRE_IAP=true and no IAP header is provided."""
        req = MagicMock()
        with patch.dict(os.environ, {"REQUIRE_IAP": "true"}):
            with self.assertRaises(Exception):
                get_current_user(request=req)

    def test_fastapi_app_instantiation(self):
        """Verifies that FastAPI app is initialized with title and routes."""
        if FASTAPI_AVAILABLE and app is not None:
            self.assertIn("Agentic AISPR", app.title)
            route_paths = [r.path for r in app.routes]
            self.assertIn("/", route_paths)
            self.assertIn("/api/auth/me", route_paths)
            self.assertIn("/api/guard", route_paths)
            self.assertIn("/api/audit/evaluate", route_paths)
            self.assertIn("/api/agentic/run_mesh", route_paths)
            self.assertIn("/api/scripts/download", route_paths)
            self.assertIn("/api/audit/controls/versions", route_paths)
            self.assertIn("/api/audit/controls/reload", route_paths)
            self.assertIn("/api/audit/controls/import", route_paths)
            self.assertIn("/api/inventory/topology", route_paths)
            self.assertIn("/api/inventory/export", route_paths)

    def test_templates_dir_and_onboarding_scripts(self):
        """Verifies that TEMPLATES_DIR points to scripts/journey/templates and contains valid onboarding files."""
        self.assertTrue(os.path.exists(TEMPLATES_DIR), f"TEMPLATES_DIR does not exist: {TEMPLATES_DIR}")
        for cloud in ["gcp", "aws", "azure"]:
            for fmt in ["tf", "sh"]:
                fname = f"{cloud}_onboarding.{fmt}"
                fpath = os.path.join(TEMPLATES_DIR, fname)
                self.assertTrue(os.path.exists(fpath), f"Missing onboarding template: {fname}")
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                # Verify that it is not an empty or placeholder stub
                self.assertGreater(len(content), 100)
                if fmt == "tf":
                    self.assertIn("resource", content)

    def test_controls_framework_versions(self):
        """Verifies GET /api/audit/controls/versions returns SAIF, NIST, ISO, MITRE, OWASP, EU AI Act."""
        from audit.questionnaire.handler import QuestionnaireHandler
        handler = QuestionnaireHandler()
        res = handler.get_framework_versions()
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["total_controls"], 100)
        
        fw_keys = [f["key"] for f in res["frameworks"]]
        for required_key in ["SAIF", "NIST_AI_RMF", "ISO_42001", "MITRE_ATLAS", "OWASP_LLM", "EU_AI_ACT"]:
            self.assertIn(required_key, fw_keys)
        
        for fw in res["frameworks"]:
            self.assertTrue(fw["version"])
            self.assertTrue(fw["source"])
            self.assertTrue(fw["last_updated"])

    def test_controls_hot_reload(self):
        """Verifies hot-reloading controls from disk without server restart."""
        from audit.questionnaire.handler import QuestionnaireHandler
        handler = QuestionnaireHandler()
        count = handler.reload()
        self.assertGreaterEqual(count, 100)

    def test_controls_import_validation_and_diff(self):
        """Verifies strict schema validation, diff calculation, and rejection of duplicate IDs / invalid criticalities."""
        from audit.questionnaire.handler import QuestionnaireHandler
        handler = QuestionnaireHandler()
        
        # 1. Valid payload with added, modified and removed controls
        sample_valid = {
            "audit_meta": {
                "version": "3.1.0",
                "framework": "AI-SPR Custom Enterprise"
            },
            "domains": {
                "1. Data Security, Lineage & Privacy (DAT)": [
                    {
                        "id": "DAT-01",
                        "question": "Modified question text for DAT-01?",
                        "framework_mapping": "ISO 42001 (A.8.2.1), NIST AI RMF",
                        "rationale": "Updated rationale.",
                        "criticality": "HIGH"
                    },
                    {
                        "id": "DAT-NEW-99",
                        "question": "New custom AI control?",
                        "framework_mapping": "EU AI Act Art. 10",
                        "rationale": "Data governance mandate.",
                        "criticality": "MEDIUM"
                    }
                ]
            }
        }
        
        diff_res = handler.validate_and_diff(sample_valid)
        self.assertTrue(diff_res["valid"])
        self.assertIn("DAT-NEW-99", diff_res["diff"]["added_controls"])
        self.assertIn("DAT-01", [c["id"] for c in diff_res["diff"]["changed_controls"]])
        self.assertGreater(diff_res["diff"]["removed_count"], 0)
        self.assertEqual(diff_res["total_controls"], 2)

        # 2. Reject duplicate IDs
        duplicate_payload = {
            "domains": {
                "Domain A": [
                    {"id": "DUP-01", "question": "Q1", "framework_mapping": "M1", "rationale": "R1", "criticality": "HIGH"},
                    {"id": "DUP-01", "question": "Q2", "framework_mapping": "M2", "rationale": "R2", "criticality": "LOW"}
                ]
            }
        }
        with self.assertRaises(ValueError) as ctx:
            handler.validate_and_diff(duplicate_payload)
        self.assertIn("Duplicate control ID", str(ctx.exception))

        # 3. Reject invalid criticality
        invalid_crit_payload = {
            "domains": {
                "Domain A": [
                    {"id": "TEST-01", "question": "Q1", "framework_mapping": "M1", "rationale": "R1", "criticality": "EXTREME_SEVERITY"}
                ]
            }
        }
        with self.assertRaises(ValueError) as ctx:
            handler.validate_and_diff(invalid_crit_payload)
        self.assertIn("invalid criticality", str(ctx.exception))

        # 4. Reject missing mandatory fields
        missing_field_payload = {
            "domains": {
                "Domain A": [
                    {"id": "TEST-02", "question": "Q1", "framework_mapping": "M1"} # missing rationale & criticality
                ]
            }
        }
        with self.assertRaises(ValueError) as ctx:
            handler.validate_and_diff(missing_field_payload)
        self.assertIn("missing", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

# Audit checkpoint [2026-04-10]: feat(telemetry): add structured security audit events for client inference endpoints

# Audit checkpoint [2026-07-01]: feat(client-onboarding): add automated model card parser for tenant risk evaluation
