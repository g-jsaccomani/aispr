# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for Multi-Cloud Findings Correlator & Questionnaire Enrichment
Engineered by: @jsaccomani
"""

import unittest
import os
import sys

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
audit_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(audit_dir)
for p in [root_dir, audit_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from audit.engine.findings_correlator import CloudFindingsCorrelator, build_unified_cloud_findings
from audit.questionnaire.handler import QuestionnaireHandler
from audit.cli import AISPRAssessmentCLI


class TestCloudFindingsCorrelator(unittest.TestCase):

    def setUp(self):
        self.project_id = "test-fintech-ai-prod"
        self.sample_scc = [
            "AI-SEC-001: Excessive Agency - Unrestricted IAM role assigned to Vertex AI Endpoint service account in 'test-fintech-ai-prod'.",
            "AI-SEC-002: Model Exposure - Public ingress enabled without Private Service Connect (PSC) isolation.",
            "AI-SEC-003: Cryptographic Sovereignty - Vertex AI Notebook persistent disk encrypted with Google-managed key (CMEK missing)."
        ]
        self.sample_shadow = {
            "project_id": "test-fintech-ai-prod",
            "findings": {
                "shadow_ai": [
                    {
                        "finding_id": "SHADOW-01",
                        "severity": "CRITICAL",
                        "engine": "Ollama (Llama-3)",
                        "cluster": "gke-prod-cluster",
                        "risk": "Rogue LLM daemon listening on unauthenticated internal port 11434."
                    }
                ],
                "workbench_vulnerabilities": [
                    {
                        "finding_id": "WB-CVE-01",
                        "cve": "CVE-2026-2244",
                        "severity": "CRITICAL",
                        "resource_name": "workbench-analyst-gpu-01",
                        "vulnerability_type": "OAuth Token Exposure in logs",
                        "risk": "Startup script writes access token to world-readable log file."
                    }
                ]
            }
        }
        self.sample_sast = [
            {
                "file": "chatbot.py",
                "line": 42,
                "severity": "HIGH",
                "message": "Direct f-string prompt formatting detected without sanitization (OWASP LLM01: Prompt Injection)."
            }
        ]

    def test_correlator_scc_mapping(self):
        correlator = CloudFindingsCorrelator(
            project_id=self.project_id,
            scc_findings=self.sample_scc
        )
        correlated = correlator.correlate()

        # Check IAM finding mapped to INF-03
        self.assertIn("INF-03", correlated)
        self.assertTrue(correlated["INF-03"]["has_finding"])
        self.assertEqual(correlated["INF-03"]["suggested_status"], "N")
        self.assertIn("Excessive Agency", correlated["INF-03"]["summary"])

        # Check PSC/Ingress finding mapped to INF-02
        self.assertIn("INF-02", correlated)
        self.assertIn("PSC", correlated["INF-02"]["summary"])

        # Check CMEK finding mapped to INF-04
        self.assertIn("INF-04", correlated)
        self.assertIn("CMEK", correlated["INF-04"]["summary"])

    def test_correlator_shadow_and_sast_mapping(self):
        correlator = CloudFindingsCorrelator(
            project_id=self.project_id,
            shadow_findings=self.sample_shadow,
            sast_findings=self.sample_sast
        )
        correlated = correlator.correlate()

        # Check Shadow AI mapped to GOV-02
        self.assertIn("GOV-02", correlated)
        self.assertEqual(correlated["GOV-02"]["severity"], "CRITICAL")
        self.assertIn("Ollama", correlated["GOV-02"]["summary"])

        # Check Workbench CVE mapped to INF-01
        self.assertIn("INF-01", correlated)
        self.assertIn("CVE-2026-2244", correlated["INF-01"]["summary"])

        # Check SAST prompt injection mapped to APP-01
        self.assertIn("APP-01", correlated)
        self.assertIn("chatbot.py:42", correlated["APP-01"]["summary"])

    def test_questionnaire_handler_enriches_questions_with_findings(self):
        correlator = CloudFindingsCorrelator(
            project_id=self.project_id,
            scc_findings=self.sample_scc,
            shadow_findings=self.sample_shadow
        )
        findings_map = correlator.get_findings_map_dict()
        handler = QuestionnaireHandler(findings_map=findings_map)

        session_state = {"current_question_index": 0, "findings_map": findings_map}
        
        # Step through questions until reaching an INF control with findings
        found_enriched = False
        while session_state["current_question_index"] < len(handler.flat_questions):
            step_output = handler.get_next_step("start questionnaire", session_state)
            if "Cloud Finding Detected" in step_output:
                found_enriched = True
                self.assertIn("Recommended Answer", step_output)
                break

        self.assertTrue(found_enriched, "Expected at least one question to be enriched with real-time cloud findings.")

    def test_record_answer_auto_populates_cloud_evidence(self):
        findings_map = {
            "INF-03": "Scan Finding: Excessive Agency on Vertex SA"
        }
        handler = QuestionnaireHandler(findings_map=findings_map)
        answers = {}
        # User replies with status only, no notes
        handler.record_answer("INF-03", "N", "", answers)

        self.assertIn("INF-03", answers)
        self.assertEqual(answers["INF-03"]["status"], "N")
        self.assertIn("Cloud Scan Evidence", answers["INF-03"]["notes"])

    def test_cli_findings_initialization(self):
        cli = AISPRAssessmentCLI(
            client_name="Test Enterprise",
            project_name="test-fintech-ai-prod",
            findings_map={"APP-01": "Scan Finding: Direct prompt injection on /api/v1/chat"}
        )
        self.assertEqual(len(cli.findings_map), 1)
        self.assertIn("APP-01", cli.findings_map)


if __name__ == "__main__":
    unittest.main()
