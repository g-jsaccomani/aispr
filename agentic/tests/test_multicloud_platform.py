# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AISPR Multi-Cloud Platform Core, Connectors & Remediation Engine
Engineered by: @jsaccomani
"""

import unittest
import os
import sys

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
agentic_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(agentic_dir)
for p in [root_dir, agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agentic.platform import AISPRAgenticCore
from agentic.connectors.gcp_connector import GCPConnector
from agentic.connectors.aws_connector import AWSConnector
from agentic.connectors.azure_connector import AzureConnector


class TestMultiCloudPlatform(unittest.TestCase):

    def setUp(self):
        self.core = AISPRAgenticCore(tenant_id="test-enterprise-corp")

    def test_connectors_discovery(self):
        gcp = GCPConnector(project_id="test-proj")
        aws = AWSConnector(account_id="123456789012")
        azure = AzureConnector(subscription_id="sub-123")

        gcp_res = gcp.discover_resources()
        aws_res = aws.discover_resources()
        azure_res = azure.discover_resources()

        self.assertEqual(gcp_res["provider"], "gcp")
        self.assertGreater(len(gcp_res["models"]), 0)

        self.assertEqual(aws_res["provider"], "aws")
        self.assertGreater(len(aws_res["models"]), 0)

        self.assertEqual(azure_res["provider"], "azure")
        self.assertGreater(len(azure_res["models"]), 0)

    def test_multicloud_discovery_ai_bom(self):
        ai_bom = self.core.run_multi_cloud_discovery()
        self.assertEqual(ai_bom["tenant_id"], "test-enterprise-corp")
        self.assertGreater(len(ai_bom["discovered_models"]), 0)
        self.assertGreater(len(ai_bom["shadow_ai_findings"]), 0)
        self.assertGreater(len(ai_bom["vulnerabilities"]), 0)

    def test_dynamic_assessment_generation(self):
        ai_bom = self.core.run_multi_cloud_discovery()
        questions = self.core.generate_progressive_questions(ai_bom)
        self.assertGreater(len(questions), 0)
        
        # Verify AWS Bedrock question generated
        has_aws_q = any("AWS Bedrock" in q["question"] for q in questions)
        self.assertTrue(has_aws_q)

        # Verify Shadow AI question generated
        has_shadow_q = any("shadow ai" in q["question"].lower() for q in questions)
        self.assertTrue(has_shadow_q)

    def test_remediation_engine_generation(self):
        failed_controls = ["DYN-AWS-BED-01", "DYN-GCP-ARM-01", "DYN-AZ-SAFE-01", "SHADOW-AI-01"]
        remediations = self.core.generate_active_remediations(failed_controls)
        
        self.assertIn("google_cloud_model_armor", remediations)
        self.assertIn("aws_bedrock_guardrail", remediations)
        self.assertIn("azure_ai_content_safety", remediations)
        self.assertIn("terraform_hardening_blueprint", remediations)


if __name__ == "__main__":
    unittest.main()
