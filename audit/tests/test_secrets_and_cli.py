# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit test suite for Secret Manager persistence and CLI finding redaction.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config.secret_manager import SecretManagerStore, store_multicloud_credentials, get_multicloud_credentials
from scripts.cli.aispr_cli import redact_sensitive_info


class TestSecretManagerAndRedaction(unittest.TestCase):
    """Verifies Secret Manager credential storage and CLI finding redaction."""

    def test_store_and_retrieve_ephemeral_fallback(self):
        """Tests in-memory vault when Google Cloud Secret Manager client is not installed."""
        store = SecretManagerStore(project_id="test-sec-project")
        
        aws_creds = {
            "role_arn": "arn:aws:iam::123456789012:role/AISPR-ReadOnly-Role",
            "external_id": "ext-secret-123"
        }
        res = store.store_multicloud_credentials(
            provider="AWS",
            credentials_data=aws_creds,
            tenant_id="bank-client-01"
        )
        self.assertTrue(res["success"])
        self.assertFalse(res["persistent"])
        self.assertIn("VOLATILE_MEMORY_VAULT", res["storage_backend"])

        # Retrieve credentials
        retrieved = store.get_multicloud_credentials(provider="AWS", tenant_id="bank-client-01")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["role_arn"], aws_creds["role_arn"])
        self.assertEqual(retrieved["external_id"], "ext-secret-123")

    def test_store_with_mocked_secret_manager(self):
        """Verifies Secret Manager API calls when google.cloud.secretmanager is present."""
        mock_google = MagicMock()
        mock_cloud = MagicMock()
        mock_sm = MagicMock()
        mock_client = MagicMock()
        mock_version_resp = MagicMock()
        mock_version_resp.name = "projects/test-proj/secrets/aispr-azure-creds/versions/1"

        mock_google.cloud = mock_cloud
        mock_cloud.secretmanager = mock_sm
        mock_sm.SecretManagerServiceClient.return_value = mock_client
        mock_client.add_secret_version.return_value = mock_version_resp

        modules_dict = {
            "google": mock_google,
            "google.cloud": mock_cloud,
            "google.cloud.secretmanager": mock_sm
        }

        with patch.dict("sys.modules", modules_dict):
            store = SecretManagerStore(project_id="test-proj")
            azure_creds = {
                "tenant_id": "11111111-2222-3333-4444-555555555555",
                "client_id": "app-auditor",
                "client_secret": "sensitive-token-xyz"
            }
            res = store.store_multicloud_credentials(
                provider="AZURE",
                credentials_data=azure_creds,
                tenant_id="client-enterprise"
            )
            self.assertTrue(res["success"])
            self.assertTrue(res["persistent"])
            self.assertEqual(res["storage_backend"], "GOOGLE_CLOUD_SECRET_MANAGER")

    def test_redact_sensitive_info_aws_arn(self):
        """Verifies AWS ARN masking when verbose is False vs unmasked when True."""
        raw_arn = "arn:aws:iam::123456789012:role/AISPR-ReadOnly-Role"
        
        # Masked (default)
        redacted = redact_sensitive_info(raw_arn, verbose=False)
        self.assertNotIn("123456789012", redacted)
        self.assertIn("arn:aws:iam::***:[MASKED_ARN]", redacted)

        # Unmasked with verbose=True
        unmasked = redact_sensitive_info(raw_arn, verbose=True)
        self.assertEqual(unmasked, raw_arn)

    def test_redact_sensitive_info_gcp_and_azure(self):
        """Verifies GCP resource hierarchy and Azure UUID masking."""
        gcp_res = "projects/my-prod-proj/locations/us-central1/endpoints/498230194810"
        redacted_gcp = redact_sensitive_info(gcp_res, verbose=False)
        self.assertNotIn("my-prod-proj", redacted_gcp)
        self.assertIn("projects/***/locations/us-central1/[MASKED_RESOURCE]", redacted_gcp)

        azure_sub = "Subscription: 12345678-abcd-1234-abcd-1234567890ab"
        redacted_az = redact_sensitive_info(azure_sub, verbose=False)
        self.assertNotIn("12345678-abcd", redacted_az)
        self.assertIn("********-****-****-****-************", redacted_az)

        email = "auditor@secret-bank.internal.corp"
        redacted_email = redact_sensitive_info(email, verbose=False)
        self.assertIn("***@secret-bank.internal.corp", redacted_email)


if __name__ == "__main__":
    unittest.main()
