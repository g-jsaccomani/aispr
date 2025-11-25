# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for Static AI-BOM, Semantic Prompt SAST, and Multi-Cloud CLI Scanners
"""

import unittest
import os
import sys
import tempfile

current_dir = os.path.dirname(os.path.abspath(__file__))
agentic_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(agentic_dir)
for p in [root_dir, agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agentic.threat_operations.ai_bom_generator import AIBOMGenerator
from agentic.threat_operations.static_prompt_sast import PromptSASTScanner, scan_repository_for_prompt_sast
from agentic.threat_operations.multi_cloud_posture_scanner import MultiCloudPostureScanner
from audit.engine.reporter import ExecutiveReporter


class TestStaticOperations(unittest.TestCase):

    def test_ai_bom_generation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a mock model file
            model_file = os.path.join(tmp_dir, "test_model.safetensors")
            with open(model_file, "wb") as f:
                f.write(b"mock model weights buffer")

            generator = AIBOMGenerator(tmp_dir)
            bom = generator.generate_bom()

            self.assertEqual(bom["bom_format"], "CycloneDX-AI")
            self.assertEqual(bom["metadata"]["author"], "@jsaccomani")
            self.assertEqual(len(bom["components"]["discovered_models"]), 1)
            self.assertEqual(bom["components"]["discovered_models"][0]["model_name"], "test_model.safetensors")
            self.assertEqual(bom["components"]["discovered_models"][0]["format"], "SAFETENSORS")
            self.assertNotEqual(bom["components"]["discovered_models"][0]["sha256_hash"], "")

    def test_prompt_sast_scanner(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_code_file = os.path.join(tmp_dir, "vulnerable_app.py")
            with open(bad_code_file, "w", encoding="utf-8") as f:
                f.write("""
user_input = "test"
model.generate_content(f"Translate {user_input}")
model.predict("Hello " + user_input)
""")

            findings = scan_repository_for_prompt_sast(tmp_dir)
            self.assertGreaterEqual(len(findings), 2)
            vulnerability_types = [f["vulnerability"] for f in findings]
            self.assertIn("INSECURE_PROMPT_CONCATENATION", vulnerability_types)
            self.assertIn("RAW_STRING_CONCATENATION_IN_PROMPT", vulnerability_types)

    def test_multicloud_static_posture_scanner(self):
        scanner = MultiCloudPostureScanner()
        results = scanner.scan_all_clouds()
        self.assertIn("gcp", results)
        self.assertIn("aws", results)
        self.assertIn("azure", results)

    def test_reporter_regulatory_gap_table(self):
        failed = [
            {"id": "DAT-04", "question_text": "Do you strictly isolate untrusted RAG data?", "status": "N", "criticality": "HIGH"},
            {"id": "APP-04", "question_text": "Are Human-in-the-Loop gates enforced?", "status": "N", "criticality": "HIGH"}
        ]
        table = ExecutiveReporter.build_regulatory_gap_table(failed)
        self.assertIn("Cross-Framework Regulatory Compliance", table)
        self.assertIn("EU AI Act", table)
        self.assertIn("LGPD", table)
        self.assertIn("DAT-04", table)
        self.assertIn("APP-04", table)


if __name__ == "__main__":
    unittest.main()
