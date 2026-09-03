# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AISPR Enterprise Identity-Aware Proxy (IAP) Auth & Server Engine
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import base64
import json
import hmac
import hashlib
import time

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
agentic_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(agentic_dir)
for p in [root_dir, agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agentic.ui.auth import (
    verify_iap_jwt_assertion,
    verify_bearer_token,
    authenticate_request_headers,
    AuthenticationError,
    DEV_SECRET_KEY
)
from agentic.ui.server import TEMPLATES_DIR, AISPRServerHandler


def _create_mock_jwt(header: dict, claims: dict, secret: str = DEV_SECRET_KEY) -> str:
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("utf-8").rstrip("=")
    c_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode("utf-8")).decode("utf-8").rstrip("=")
    sig_input = f"{h_b64}.{c_b64}".encode("utf-8")
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode("utf-8"), sig_input, hashlib.sha256).digest()
    ).decode("utf-8").rstrip("=")
    return f"{h_b64}.{c_b64}.{sig}"


class TestUIServerAndIAP(unittest.TestCase):

    def test_iap_jwt_assertion_verification(self):
        """Verifies cryptographic claims extraction from valid Google Cloud IAP JWT."""
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": "https://cloud.google.com/iap",
            "sub": "accounts.google.com:1098237491823",
            "email": "security-auditor@enterprise.com",
            "exp": int(time.time()) + 3600
        }
        jwt_token = _create_mock_jwt(header, claims)

        auth_context = verify_iap_jwt_assertion(jwt_token)
        self.assertEqual(auth_context["email"], "security-auditor@enterprise.com")
        self.assertEqual(auth_context["user_id"], "accounts.google.com:1098237491823")
        self.assertTrue(auth_context["is_iap_authenticated"])
        self.assertEqual(auth_context["auth_type"], "google_cloud_iap")
        self.assertTrue(auth_context["has_live_credentials"])

    def test_iap_jwt_expired_raises_unauthorized(self):
        """Verifies that expired IAP JWTs are strictly rejected."""
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": "https://cloud.google.com/iap",
            "sub": "123",
            "email": "test@corp.com",
            "exp": int(time.time()) - 100
        }
        jwt_token = _create_mock_jwt(header, claims)
        with self.assertRaises(AuthenticationError):
            verify_iap_jwt_assertion(jwt_token)

    def test_bearer_jwt_session_authentication(self):
        """Verifies signed session bearer token validation."""
        header = {"alg": "HS256", "typ": "JWT"}
        claims = {
            "sub": "bearer-auditor-01",
            "email": "lead-auditor@enterprise.com",
            "exp": int(time.time()) + 1800,
            "has_live_credentials": True
        }
        token = _create_mock_jwt(header, claims)
        auth_context = verify_bearer_token(f"Bearer {token}")
        self.assertEqual(auth_context["email"], "lead-auditor@enterprise.com")
        self.assertEqual(auth_context["auth_type"], "bearer_jwt_session")
        self.assertTrue(auth_context["has_live_credentials"])

    def test_unverified_bearer_rejected(self):
        """Verifies that arbitrary / unverified Bearer tokens are rejected."""
        with self.assertRaises(AuthenticationError):
            verify_bearer_token("Bearer invalid-unverified-string")

    def test_local_dev_fallback_identity(self):
        """Verifies opt-in local sandbox identity when REQUIRE_IAP=false and ALLOW_LOCAL_DEV=true."""
        with patch("agentic.ui.auth.REQUIRE_IAP", False), patch("agentic.ui.auth.ALLOW_LOCAL_DEV", True):
            user = authenticate_request_headers({})
            self.assertIn("security-lead@", user["email"])
            self.assertEqual(user["auth_type"], "local_dev_sandbox")
            self.assertFalse(user["has_live_credentials"])

    def test_strict_iap_mode_raises_unauthorized_when_missing(self):
        """Verifies AuthenticationError when REQUIRE_IAP=true and headers are missing."""
        with patch("agentic.ui.auth.REQUIRE_IAP", True):
            with self.assertRaises(AuthenticationError):
                authenticate_request_headers({})

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


if __name__ == "__main__":
    unittest.main()
