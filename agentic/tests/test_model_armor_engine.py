# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AISPR Model Armor Implementation Engine:
- Pillar 1: Consultiva (ModelArmorConsultingAdvisor)
- Pillar 2: Construtiva (ModelArmorConstructiveBuilder)
- Pillar 3: Protetiva (ModelArmorProtectiveEvaluator)
- Master Orchestrator (ModelArmorOrchestrator)
"""

import unittest
import os
import sys
import json
from unittest.mock import patch, MagicMock

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
agentic_dir = os.path.dirname(current_dir)
project_root = os.path.dirname(agentic_dir)
for p in [project_root, agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agentic.model_armor.advisor import ModelArmorConsultingAdvisor
from agentic.model_armor.builder import ModelArmorConstructiveBuilder
from agentic.model_armor.evaluator import ModelArmorProtectiveEvaluator
from agentic.model_armor.orchestrator import ModelArmorOrchestrator


class TestModelArmorEngine(unittest.TestCase):

    def setUp(self):
        self.project_root = project_root
        self.advisor = ModelArmorConsultingAdvisor(self.project_root)
        self.builder = ModelArmorConstructiveBuilder(self.project_root)
        self.evaluator = ModelArmorProtectiveEvaluator(self.project_root)
        self.orchestrator = ModelArmorOrchestrator(self.project_root)

    def test_advisor_transformation_matrix_generation(self):
        """Verifies that the Advisor ingests AISPR findings and generates the 5-domain Transformation Matrix."""
        findings = self.advisor.collect_aispr_findings()
        matrix = self.advisor.generate_transformation_matrix(findings, project_id="test-sec-prod")
        
        self.assertGreaterEqual(len(matrix), 5)
        domains = [item["aispr_domain"] for item in matrix]
        self.assertTrue(any("Application Security" in d for d in domains))
        self.assertTrue(any("Data Security" in d for d in domains))
        self.assertTrue(any("Governance" in d for d in domains))
        self.assertTrue(any("RAG Perimeter" in d for d in domains))
        self.assertTrue(any("Security Assurance" in d for d in domains))

        # Check critical fields
        for item in matrix:
            self.assertIn("gap_summary", item)
            self.assertIn("model_armor_component", item)
            self.assertIn("protection_impact", item)
            self.assertIn("owasp_mapping", item)
            self.assertIn("saif_pillar", item)

    def test_advisor_consulting_blueprint_export(self):
        """Verifies that the Advisor writes out the Markdown blueprint and JSON plan."""
        adv_res = self.advisor.execute_advisory_flow(
            project_id="test-fintech-ai",
            location="us-central1",
            template_id="test-guardrail-v1"
        )
        self.assertTrue(os.path.exists(adv_res["blueprint_path"]))
        self.assertTrue(os.path.exists(adv_res["plan_path"]))
        
        with open(adv_res["blueprint_path"], "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Google Cloud Model Armor - Security Architecture Blueprint", content)
        self.assertIn("Current State vs. Model Armor Protected State", content)
        self.assertIn("AISPR Gap-to-Protection Transformation Matrix", content)
        self.assertIn("Phased Implementation Roadmap", content)

    def test_builder_terraform_and_middleware_generation(self):
        """Verifies that the Builder generates complete Terraform modules and app middleware interceptors."""
        plan = {
            "metadata": {
                "project_id": "test-fintech-ai",
                "location": "us-central1",
                "template_id": "test-guardrail-v1"
            },
            "parameters": {
                "enable_floor_setting": True,
                "enable_dlp": True
            }
        }
        build_res = self.builder.execute_constructive_flow(plan, deploy_live=False)
        
        # Verify Terraform files
        tf_dir = build_res["terraform_package_dir"]
        for tf_file in ["main.tf", "variables.tf", "outputs.tf", "terraform.tfvars"]:
            path = os.path.join(tf_dir, tf_file)
            self.assertTrue(os.path.exists(path), f"Missing Terraform file: {tf_file}")
            with open(path, "r", encoding="utf-8") as f:
                c = f.read()
            self.assertGreater(len(c), 50)
            if tf_file == "main.tf":
                self.assertIn("modelarmor.googleapis.com", c)
                self.assertIn("model_armor_floor_setting", c)
                self.assertIn("model_armor_template", c)

        # Verify Cloud Shell Script
        sh_path = build_res["cloud_shell_script"]
        self.assertTrue(os.path.exists(sh_path))
        with open(sh_path, "r", encoding="utf-8") as f:
            sh_content = f.read()
        self.assertIn("gcloud services enable modelarmor.googleapis.com", sh_content)
        self.assertIn("floorSetting", sh_content)

        # Verify App Middleware
        app_dir = build_res["app_middleware_dir"]
        for mw_file in ["fastapi_model_armor_middleware.py", "vertex_ai_model_armor_wrapper.py", "langchain_model_armor_guard.py"]:
            mw_path = os.path.join(app_dir, mw_file)
            self.assertTrue(os.path.exists(mw_path), f"Missing app middleware: {mw_file}")

    def test_evaluator_protection_evals_and_certificate(self):
        """Verifies that the Evaluator executes attack tests and generates the Protection Certificate."""
        eval_res = self.evaluator.execute_protective_flow(
            project_id="test-fintech-ai",
            location="us-central1",
            template_id="test-guardrail-v1",
            client_name="Test Enterprise Bank"
        )
        self.assertTrue(os.path.exists(eval_res["certificate_path"]))
        self.assertTrue(os.path.exists(eval_res["results_path"]))

        metrics = eval_res["metrics"]
        self.assertGreater(metrics["total_evaluations"], 10)
        self.assertGreaterEqual(metrics["defense_efficacy_percentage"], 95.0)
        self.assertEqual(metrics["security_bypasses"], 0)
        self.assertEqual(metrics["false_positive_rate_percentage"], 0.0)

        with open(eval_res["certificate_path"], "r", encoding="utf-8") as f:
            cert_content = f.read()
        self.assertIn("PROTECTION ASSURANCE CERTIFICATE", cert_content)
        self.assertIn("MA-CERT-", cert_content)
        self.assertIn("VERIFIED PROTECTED & COMPLIANT", cert_content)
        self.assertIn("CERTIFICATE SIGNATURE DIGEST: SHA256:", cert_content)

    def test_master_orchestrator_full_journey(self):
        """Verifies the complete 3-pillar orchestrated execution flow."""
        res = self.orchestrator.run_full_implementation_flow(
            project_id="test-enterprise-ai",
            location="us-central1",
            template_id="secops-guardrail-prod",
            profile_name="balanced",
            client_name="Test Enterprise Inc.",
            deploy_live=False
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn("advisory", res)
        self.assertIn("constructive", res)
        self.assertIn("protective", res)


if __name__ == "__main__":
    unittest.main()

# Audit checkpoint [2026-03-02]: fix(prompt-defense): adjust prompt injection heuristic thresholds for client customer-service bot

# Audit checkpoint [2026-03-11]: feat(rag-security): implement vector database access control validation for client

# Audit checkpoint [2026-06-08]: feat(client-onboarding): add automated model card parser for tenant risk evaluation
