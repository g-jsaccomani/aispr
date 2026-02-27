# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests verifying GCP ADC Authentication and Tools usage from the audit/ module.
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import logging

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
audit_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(audit_dir)
for p in [root_dir, audit_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from config.gcp_auth import GCPAuth, get_gcp_credentials, get_default_project_id
from audit.agent.tools import fetch_scc_ai_findings, fetch_scc_ai_findings_live, get_gcp_ai_inventory, get_gcp_ai_inventory_live


class TestAuditGCPAuthAndTools(unittest.TestCase):

    def test_audit_can_import_and_use_gcp_auth(self):
        auth = GCPAuth(project_id="audit-test-project")
        self.assertEqual(auth.project_id, "audit-test-project")

    def test_fetch_scc_ai_findings_fallback_with_warning_on_permission_error(self):
        """Verifies clear warning logging and fallback to mock findings when permission is missing."""
        with self.assertLogs("AISPR-Audit-Tools", level="WARNING") as log_cm:
            findings = fetch_scc_ai_findings("audit-proj")
            self.assertEqual(len(findings), 3)
            self.assertTrue(any("AI-SEC-001" in f for f in findings))
            self.assertTrue(any("securitycenter.findings.list" in m or "lacks" in m for m in log_cm.output))

    def test_fetch_scc_ai_findings_with_mocked_scc_client(self):
        """Verifies real SCC finding query when google-cloud-securitycenter client is available."""
        mock_google = MagicMock()
        mock_cloud = MagicMock()
        mock_scc_v1 = MagicMock()
        mock_google.cloud = mock_cloud
        mock_cloud.securitycenter_v1 = mock_scc_v1

        mock_client = MagicMock()
        mock_scc_v1.SecurityCenterClient.return_value = mock_client

        mock_finding_res = MagicMock()
        mock_finding = MagicMock()
        mock_finding.name = "projects/test-p/sources/1/findings/AI-PROT-001"
        mock_finding.category = "AI_PROTECTION_UNVALIDATED_PROMPT"
        mock_finding.description = "Vertex AI endpoint accepts unfiltered prompts."
        mock_finding.severity = "CRITICAL"
        mock_finding_res.finding = mock_finding

        mock_client.list_findings.return_value = [mock_finding_res]

        with patch.dict(sys.modules, {
            "google": mock_google,
            "google.cloud": mock_cloud,
            "google.cloud.securitycenter_v1": mock_scc_v1,
        }):
            findings = fetch_scc_ai_findings("test-p")
            self.assertIsInstance(findings, list)
            self.assertEqual(len(findings), 1)
            self.assertIn("AI-PROT-001", findings[0])
            self.assertIn("AI_PROTECTION_UNVALIDATED_PROMPT", findings[0])

    def test_get_gcp_ai_inventory(self):
        inventory = get_gcp_ai_inventory("audit-proj")
        self.assertEqual(len(inventory), 3)
        self.assertTrue(any(item["resource_type"] == "vertex_endpoint" for item in inventory))


if __name__ == "__main__":
    unittest.main()
