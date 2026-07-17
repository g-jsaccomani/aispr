# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit test suite for SessionStateStore Cloud Storage persistence & local fallback.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from audit.agent.state import SessionStateStore


class TestSessionStateStore(unittest.TestCase):
    """Verifies SessionStateStore Cloud Storage upload and fallback capabilities."""

    def setUp(self):
        self.session_id = "test-session-12345"
        self.sample_answers = {"DAT-01": "YES", "MOD-02": "PARTIAL"}
        self.sample_findings = [{"finding_id": "FIND-001", "severity": "HIGH"}]

    def test_save_state_with_mocked_gcs(self):
        """Verifies real GCS upload flow when google.cloud.storage client is present."""
        mock_google = MagicMock()
        mock_cloud = MagicMock()
        mock_storage = MagicMock()
        mock_client = MagicMock()
        mock_bucket = MagicMock()
        mock_blob = MagicMock()

        mock_google.cloud = mock_cloud
        mock_cloud.storage = mock_storage
        mock_storage.Client.return_value = mock_client
        mock_client.bucket.return_value = mock_bucket
        mock_bucket.blob.return_value = mock_blob

        modules_dict = {
            "google": mock_google,
            "google.cloud": mock_cloud,
            "google.cloud.storage": mock_storage
        }

        with patch.dict("sys.modules", modules_dict):
            store = SessionStateStore(
                session_id=self.session_id,
                storage_bucket="gs://my-audit-vault-prod",
                project_id="test-gcp-project"
            )
            self.assertEqual(store.storage_bucket, "my-audit-vault-prod")

            result = store.save_state(self.sample_answers, self.sample_findings)

            self.assertTrue(result["success"])
            self.assertEqual(result["status"], "SAVED_TO_GCS")
            self.assertEqual(result["uri"], f"gs://my-audit-vault-prod/sessions/{self.session_id}/state.json")
            self.assertTrue(result["persistent"])

            mock_storage.Client.assert_called_with(project="test-gcp-project")
            mock_client.bucket.assert_called_with("my-audit-vault-prod")
            mock_bucket.blob.assert_called_with(f"sessions/{self.session_id}/state.json")
            self.assertTrue(mock_blob.upload_from_string.called)

            uploaded_payload = json.loads(mock_blob.upload_from_string.call_args[0][0])
            self.assertEqual(uploaded_payload["session_id"], self.session_id)
            self.assertEqual(uploaded_payload["answers"], self.sample_answers)
            self.assertEqual(uploaded_payload["scc_findings"], self.sample_findings)

    def test_save_state_local_fallback(self):
        """Verifies local cache fallback when GCS client raises exception or is unavailable."""
        store = SessionStateStore(
            session_id="local-fallback-session",
            storage_bucket="aispr-vault"
        )

        result = store.save_state(self.sample_answers, self.sample_findings)

        self.assertTrue(result["success"])
        self.assertIn(result["status"], ["SAVED_LOCAL_FALLBACK", "SAVED_IN_MEMORY_ONLY"])
        self.assertFalse(result["persistent"])

        # Verify load_state retrieves cached state
        loaded = store.load_state()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["session_id"], "local-fallback-session")
        self.assertEqual(loaded["answers"]["DAT-01"], "YES")


if __name__ == "__main__":
    unittest.main()

# Audit checkpoint [2026-03-15]: feat(telemetry): add structured security audit events for client inference endpoints

# Audit checkpoint [2026-04-10]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment

# Audit checkpoint [2026-06-08]: feat(telemetry): add structured security audit events for client inference endpoints

# Audit checkpoint [2026-07-17]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout
