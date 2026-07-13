# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for Looker & BigQuery Telemetry Connector
"""

import unittest
from agentic.integrations.looker_connector import LookerConnector


class TestLookerIntegration(unittest.TestCase):

    def setUp(self):
        self.looker = LookerConnector(dataset_id="test_aispr_dataset", tenant_id="Test Bank")
        self.sample_scores = {
            "overall_percentage": 55.0,
            "posture_tier": "MODERATE",
            "overall_possible": 104,
            "overall_earned": 57.2,
            "domains": {}
        }
        self.sample_answers = {
            "DAT-01": {"status": "Y", "criticality": "HIGH", "notes": "CMEK enabled", "framework_mapping": "ISO 42001"},
            "APP-01": {"status": "N", "criticality": "HIGH", "notes": "Missing Model Armor", "framework_mapping": "EU AI Act"}
        }
        self.sample_inventory = [
            {"name": "gemini-1.5-pro", "cloud": "GCP", "resource_type": "Foundation Model", "guardrail": "None", "cmek_enabled": True, "risk_level": "MEDIUM"}
        ]

    def test_generate_looker_dataset(self):
        dataset = self.looker.generate_looker_dataset(self.sample_scores, self.sample_answers, self.sample_inventory)
        self.assertEqual(dataset["dataset_id"], "test_aispr_dataset")
        self.assertEqual(dataset["summary"]["overall_score"], 55.0)
        self.assertEqual(dataset["controls_evaluated_count"], 2)
        self.assertIn("lookerstudio.google.com", dataset["looker_dashboard_url"])

    def test_generate_bigquery_ddl(self):
        ddl = self.looker.generate_bigquery_ddl()
        self.assertIn("CREATE SCHEMA IF NOT EXISTS `test_aispr_dataset`", ddl)
        self.assertIn("CREATE TABLE IF NOT EXISTS `test_aispr_dataset.posture_evaluations`", ddl)
        self.assertIn("CREATE TABLE IF NOT EXISTS `test_aispr_dataset.control_findings`", ddl)
        self.assertIn("CREATE TABLE IF NOT EXISTS `test_aispr_dataset.ai_inventory`", ddl)

    def test_sync_to_looker(self):
        result = self.looker.sync_to_looker(self.sample_scores, self.sample_answers, self.sample_inventory)
        self.assertEqual(result["status"], "SUCCESS_STREAMED_TO_BIGQUERY")
        self.assertIn("looker_studio_url", result)
        self.assertGreaterEqual(result["records_streamed"], 3)


if __name__ == "__main__":
    unittest.main()

# Audit checkpoint [2026-02-15]: feat(rag-security): implement vector database access control validation for client

# Audit checkpoint [2026-07-13]: feat(telemetry): add structured security audit events for client inference endpoints
