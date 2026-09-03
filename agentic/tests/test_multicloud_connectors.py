# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 6 Comprehensive Multi-Cloud Connectors Test Suite.
Covers:
  1. Unit tests & Base Connector Contracts
  2. Mocked Provider Tests (GCP, AWS, Azure)
  3. Authentication Failure Tests
  4. Permission Failure Tests
  5. Malformed API Response Tests
  6. Canonical Normalization Tests (AIAsset, SecurityFinding, Evidence)
  7. Live vs Simulation Epistemological Gate Tests
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, Any

# Ensure project root is in sys.path
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_proj_root = os.path.abspath(os.path.join(_cur_dir, "../.."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from domain.enums import (
    CloudProvider,
    ExecutionMode,
    AssetType,
    FindingSeverity,
    FindingStatus,
    ConfidenceLevel,
    EvidenceType,
    EvidenceStatus,
    FindingSource,
    ControlRelationType,
)
from domain.models.asset import AIAsset
from domain.models.finding import SecurityFinding
from domain.models.evidence import Evidence
from agentic.connectors import (
    BaseCloudConnector,
    NormalizedDiscoveryResult,
    GCPConnector,
    AWSConnector,
    AzureConnector,
    CloudConnectorError,
    CloudAuthenticationError,
    CloudPermissionDeniedError,
    CloudAPIResponseError,
    ReadOnlyEnforcementError,
    CloudSDKMissingError,
)
from agentic.core_platform import AISPRAgenticCore

try:
    import boto3
    import botocore
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    import azure.core
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False


# ==============================================================================
# 1. UNIT TESTS & BASE CONNECTOR CONTRACTS
# ==============================================================================

class TestConnectorUnitAndContracts(unittest.TestCase):
    """Verifies baseline connector behavior, mode declaration, and read-only enforcement."""

    def test_explicit_execution_mode_declaration(self):
        """1. Every connector MUST explicitly declare its execution mode."""
        gcp = GCPConnector(project_id="test-proj")
        aws = AWSConnector(account_id="123456789012")
        azure = AzureConnector(subscription_id="sub-12345")

        # Default simulation mode
        self.assertEqual(gcp.execution_mode, ExecutionMode.SIMULATION)
        self.assertEqual(aws.execution_mode, ExecutionMode.SIMULATION)
        self.assertEqual(azure.execution_mode, ExecutionMode.SIMULATION)

        # Explicit mock mode
        gcp_mock = GCPConnector(project_id="test-proj", execution_mode=ExecutionMode.MOCK)
        self.assertEqual(gcp_mock.execution_mode, ExecutionMode.MOCK)

        # Explicit fixture mode
        aws_fix = AWSConnector(account_id="123456789012", execution_mode=ExecutionMode.FIXTURE)
        self.assertEqual(aws_fix.execution_mode, ExecutionMode.FIXTURE)

    def test_read_only_enforcement_prevents_mutations(self):
        """2. Connectors MUST be strictly read-only and block write actions."""
        aws = AWSConnector(account_id="123456789012")
        azure = AzureConnector(subscription_id="sub-12345")

        self.assertTrue(aws.is_read_only)
        self.assertTrue(azure.is_read_only)

        # Prohibited write keywords MUST raise ReadOnlyEnforcementError
        prohibited_actions = [
            "create_model", "update_endpoint", "delete_bucket",
            "put_object", "patch_deployment", "modify_security_group",
            "terminate_instance", "drop_table"
        ]
        for act in prohibited_actions:
            with self.assertRaises(ReadOnlyEnforcementError):
                aws.assert_read_only(act)
            with self.assertRaises(ReadOnlyEnforcementError):
                azure.assert_read_only(act)

        # Permitted read actions do not raise
        permitted_actions = ["list_models", "describe_endpoint", "get_bucket_encryption", "accounts_list"]
        for act in permitted_actions:
            aws.assert_read_only(act)
            azure.assert_read_only(act)

    def test_credential_sanitization_security(self):
        """3. Credentials MUST NOT be persisted, logged, or included in telemetry."""
        gcp = GCPConnector(project_id="test-proj")

        payload = {
            "model_name": "gemini-1.5-pro",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "bearer_token": "ya29.a0AfH6SMBabc12345fakeToken999",
            "nested": {
                "db_password": "SuperSecretPassword123!",
                "safe_field": "public-config"
            }
        }

        sanitized = gcp.sanitize_credentials(payload)
        self.assertEqual(sanitized["model_name"], "gemini-1.5-pro")
        self.assertEqual(sanitized["aws_secret_access_key"], "[REDACTED_CREDENTIAL]")
        self.assertEqual(sanitized["bearer_token"], "[REDACTED_CREDENTIAL]")
        self.assertEqual(sanitized["nested"]["db_password"], "[REDACTED_CREDENTIAL]")
        self.assertEqual(sanitized["nested"]["safe_field"], "public-config")


# ==============================================================================
# 2. MOCKED PROVIDER TESTS (AWS & AZURE & GCP)
# ==============================================================================

class TestMockedProviderDiscovery(unittest.TestCase):
    """Tests live discovery pipelines with mocked provider SDK clients."""

    def test_mocked_aws_live_discovery(self):
        """4. AWS live discovery queries Bedrock, SageMaker, and S3 in read-only mode."""
        mock_bedrock = MagicMock()
        mock_bedrock.list_foundation_models.return_value = {
            "modelSummaries": [
                {
                    "modelId": "anthropic.claude-3-5-sonnet-20241022-v2:0",
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "providerName": "Anthropic"
                }
            ]
        }
        mock_bedrock.list_custom_models.return_value = {
            "modelSummaries": [
                {
                    "modelName": "custom-fraud-model",
                    "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/custom-fraud-model",
                    "customModelKmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/123"
                }
            ]
        }
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"textDataDeliveryEnabled": False}
        }

        mock_sagemaker = MagicMock()
        mock_sagemaker.list_endpoints.return_value = {
            "Endpoints": [{"EndpointName": "fraud-ep", "EndpointArn": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/fraud-ep"}]
        }
        mock_sagemaker.describe_endpoint.return_value = {
            "EndpointName": "fraud-ep",
            "KmsKeyId": None,  # Gap: missing CMEK
        }
        mock_sagemaker.list_notebook_instances.return_value = {
            "NotebookInstances": [{"NotebookInstanceName": "nb-dev", "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/nb-dev"}]
        }
        mock_sagemaker.describe_notebook_instance.return_value = {
            "NotebookInstanceName": "nb-dev",
            "RootAccess": "Enabled",  # Gap: root access enabled
            "DirectInternetAccess": "Enabled",
        }

        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "banco-ai-rag-knowledge-base"}]
        }
        mock_s3.get_bucket_encryption.side_effect = Exception("ServerSideEncryptionConfigurationNotFoundError")

        # Mock session to dispatch clients
        mock_session = MagicMock()
        def client_dispatcher(service_name, region_name=None):
            if service_name == "bedrock":
                return mock_bedrock
            elif service_name == "sagemaker":
                return mock_sagemaker
            elif service_name == "s3":
                return mock_s3
            return MagicMock()
        mock_session.client.side_effect = client_dispatcher

        connector = AWSConnector(account_id="123456789012", boto3_session=mock_session)
        res = connector.discover_resources_live(regions=["us-east-1"])

        # Verifies live discovery outcome
        self.assertEqual(res["provider"], "aws")
        self.assertEqual(connector.execution_mode, ExecutionMode.LIVE)
        self.assertGreater(len(res["models"]), 0)
        self.assertGreater(len(res["endpoints"]), 0)
        self.assertGreater(len(res["vulnerabilities"]), 0)
        self.assertGreater(len(res["shadow_ai"]), 0)

        # Verifies specific gaps detected
        gap_ids = [v["id"] for v in res["vulnerabilities"]]
        self.assertTrue(any("GUARDRAIL" in g for g in gap_ids))
        self.assertTrue(any("LOGGING" in g for g in gap_ids))
        self.assertTrue(any("CMEK" in g for g in gap_ids))
        self.assertTrue(any("ROOT" in g for g in gap_ids))

    def test_mocked_azure_live_discovery(self):
        """5. Azure live discovery queries Cognitive Services and Resource Management in read-only mode."""
        mock_cog = MagicMock()
        mock_account = MagicMock()
        mock_account.name = "aoai-customer-prod"
        mock_account.id = "/subscriptions/sub-12345/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/aoai-customer-prod"
        mock_account.kind = "OpenAI"
        mock_account.location = "eastus2"
        mock_account.properties.public_network_access = "Enabled"  # Gap: public ingress
        mock_account.properties.encryption = None  # Gap: missing CMEK
        mock_account.properties.endpoint = "https://aoai-customer-prod.openai.azure.com"
        mock_cog.accounts.list.return_value = [mock_account]

        mock_deployment = MagicMock()
        mock_deployment.name = "gpt-4o"
        mock_deployment.id = f"{mock_account.id}/deployments/gpt-4o"
        mock_deployment.properties.model.name = "gpt-4o"
        mock_deployment.properties.rai_policy_name = None  # Gap: no RAI policy
        mock_cog.deployments.list.return_value = [mock_deployment]

        mock_res = MagicMock()
        mock_ml = MagicMock()
        mock_ml.name = "ml-workspace-prod"
        mock_ml.id = "/subscriptions/sub-12345/resourceGroups/rg-ai/providers/Microsoft.MachineLearningServices/workspaces/ml-workspace-prod"
        mock_ml.type = "Microsoft.MachineLearningServices/workspaces"
        mock_ml.location = "eastus2"

        mock_search = MagicMock()
        mock_search.name = "credit-search-rag"
        mock_search.id = "/subscriptions/sub-12345/resourceGroups/rg-ai/providers/Microsoft.Search/searchServices/credit-search-rag"
        mock_search.type = "Microsoft.Search/searchServices"
        mock_search.location = "eastus2"

        mock_res.resources.list.return_value = [mock_ml, mock_search]

        connector = AzureConnector(
            subscription_id="sub-12345",
            cognitive_client=mock_cog,
            resource_client=mock_res
        )
        res = connector.discover_resources_live()

        self.assertEqual(res["provider"], "azure")
        self.assertEqual(connector.execution_mode, ExecutionMode.LIVE)
        self.assertGreater(len(res["models"]), 0)
        self.assertGreater(len(res["endpoints"]), 0)
        self.assertGreater(len(res["vulnerabilities"]), 0)
        self.assertGreater(len(res["shadow_ai"]), 0)

        # Verifies specific gaps detected
        gap_ids = [v["id"] for v in res["vulnerabilities"]]
        self.assertTrue(any("PUB-NET" in g for g in gap_ids))
        self.assertTrue(any("CMEK-GAP" in g for g in gap_ids))
        self.assertTrue(any("RAI-GAP" in g for g in gap_ids))


# ==============================================================================
# 3. AUTHENTICATION FAILURE TESTS
# ==============================================================================

class TestAuthenticationFailures(unittest.TestCase):
    """Verifies that invalid credentials or expired tokens raise CloudAuthenticationError."""

    @unittest.skipUnless(HAS_BOTO3, "boto3 not installed")
    def test_aws_authentication_failure(self):
        """6. AWS credentials error raises CloudAuthenticationError."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        
        # Simulate InvalidClientTokenId error
        error_response = {"Error": {"Code": "InvalidClientTokenId", "Message": "The security token included in the request is invalid"}}
        from botocore.exceptions import ClientError
        mock_client.list_foundation_models.side_effect = ClientError(error_response, "ListFoundationModels")
        mock_session.client.return_value = mock_client

        connector = AWSConnector(account_id="123456789012", boto3_session=mock_session)
        with self.assertRaises(CloudAuthenticationError):
            connector.discover_resources_live(regions=["us-east-1"])

    @unittest.skipUnless(HAS_AZURE, "azure not installed")
    def test_azure_authentication_failure(self):
        """7. Azure 401 Unauthorized raises CloudAuthenticationError."""
        mock_cog = MagicMock()
        from azure.core.exceptions import ClientAuthenticationError
        mock_cog.accounts.list.side_effect = ClientAuthenticationError("Invalid client secret provided.")

        connector = AzureConnector(
            subscription_id="sub-12345",
            cognitive_client=mock_cog,
            resource_client=MagicMock()
        )
        with self.assertRaises(CloudAuthenticationError):
            connector.discover_resources_live()


# ==============================================================================
# 4. PERMISSION FAILURE TESTS
# ==============================================================================

class TestPermissionFailures(unittest.TestCase):
    """Verifies that IAM 403 / AccessDenied errors raise CloudPermissionDeniedError."""

    @unittest.skipUnless(HAS_BOTO3, "boto3 not installed")
    def test_aws_permission_denied_failure(self):
        """8. AWS AccessDenied raises CloudPermissionDeniedError."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        
        error_response = {"Error": {"Code": "AccessDeniedException", "Message": "User is not authorized to perform bedrock:ListFoundationModels"}}
        from botocore.exceptions import ClientError
        mock_client.list_foundation_models.side_effect = ClientError(error_response, "ListFoundationModels")
        mock_session.client.return_value = mock_client

        connector = AWSConnector(account_id="123456789012", boto3_session=mock_session)
        with self.assertRaises(CloudPermissionDeniedError):
            connector.discover_resources_live(regions=["us-east-1"])

    @unittest.skipUnless(HAS_AZURE, "azure not installed")
    def test_azure_permission_denied_failure(self):
        """9. Azure 403 Forbidden raises CloudPermissionDeniedError."""
        mock_cog = MagicMock()
        from azure.core.exceptions import HttpResponseError
        err = HttpResponseError("The client does not have authorization to perform action.")
        err.status_code = 403
        mock_cog.accounts.list.side_effect = err

        connector = AzureConnector(
            subscription_id="sub-12345",
            cognitive_client=mock_cog,
            resource_client=MagicMock()
        )
        with self.assertRaises(CloudPermissionDeniedError):
            connector.discover_resources_live()


# ==============================================================================
# 5. MALFORMED API RESPONSE TESTS
# ==============================================================================

class TestMalformedAPIResponses(unittest.TestCase):
    """Verifies that malformed or incomplete API responses are handled safely without crashing."""

    def test_aws_empty_or_corrupted_response(self):
        """10. AWS connector gracefully handles empty or non-standard API responses."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        # Return empty dictionaries without expected keys
        mock_client.list_foundation_models.return_value = {}
        mock_client.list_custom_models.return_value = {}
        mock_client.list_guardrails.return_value = {}
        mock_client.get_model_invocation_logging_configuration.return_value = {}
        mock_client.list_endpoints.return_value = {}
        mock_client.list_notebook_instances.return_value = {}
        mock_client.list_buckets.return_value = {}
        mock_session.client.return_value = mock_client

        connector = AWSConnector(account_id="123456789012", boto3_session=mock_session)
        res = connector.discover_resources_live(regions=["us-east-1"])
        self.assertIsInstance(res["models"], list)
        self.assertIsInstance(res["vulnerabilities"], list)

    def test_azure_empty_or_corrupted_response(self):
        """11. Azure connector gracefully handles empty resource lists."""
        mock_cog = MagicMock()
        mock_cog.accounts.list.return_value = []
        mock_res = MagicMock()
        mock_res.resources.list.return_value = []

        connector = AzureConnector(
            subscription_id="sub-12345",
            cognitive_client=mock_cog,
            resource_client=mock_res
        )
        res = connector.discover_resources_live()
        self.assertEqual(res["models"], [])
        self.assertEqual(res["endpoints"], [])


# ==============================================================================
# 6. CANONICAL NORMALIZATION TESTS
# ==============================================================================

class TestCanonicalNormalization(unittest.TestCase):
    """Verifies that all connectors normalize into canonical AIAsset, SecurityFinding, Evidence."""

    def test_gcp_normalization(self):
        """12. GCP output normalizes into strongly-typed canonical entities."""
        gcp = GCPConnector(project_id="test-fintech-ai-core")
        res = gcp.discover_canonical(live=False)

        self.assertIsInstance(res, NormalizedDiscoveryResult)
        self.assertEqual(res.provider, CloudProvider.GCP)
        self.assertEqual(res.execution_mode, ExecutionMode.SIMULATION)
        self.assertFalse(res.is_live)

        # Check Assets
        self.assertGreater(len(res.assets), 0)
        for a in res.assets:
            self.assertIsInstance(a, AIAsset)
            self.assertEqual(a.provider, CloudProvider.GCP)

        # Check Findings
        self.assertGreater(len(res.findings), 0)
        for f in res.findings:
            self.assertIsInstance(f, SecurityFinding)
            self.assertEqual(f.provider, CloudProvider.GCP)
            self.assertGreater(len(f.evidence), 0)
            self.assertIsNotNone(f.primary_control_id)

        # Check Evidence (Epistemology: simulation evidence cannot be VERIFIED)
        for e in res.evidence:
            self.assertIsInstance(e, Evidence)
            self.assertNotEqual(e.status, EvidenceStatus.VERIFIED)
            self.assertEqual(e.execution_mode, ExecutionMode.SIMULATION)
            self.assertTrue(len(e.content_hash) == 64)  # SHA-256 length

    def test_aws_normalization(self):
        """13. AWS output normalizes into strongly-typed canonical entities."""
        aws = AWSConnector(account_id="123456789012")
        res = aws.discover_canonical(live=False)

        self.assertIsInstance(res, NormalizedDiscoveryResult)
        self.assertEqual(res.provider, CloudProvider.AWS)
        self.assertEqual(res.execution_mode, ExecutionMode.SIMULATION)

        # Check Assets
        self.assertGreater(len(res.assets), 0)
        for a in res.assets:
            self.assertIsInstance(a, AIAsset)
            self.assertEqual(a.provider, CloudProvider.AWS)

        # Check Findings
        self.assertGreater(len(res.findings), 0)
        for f in res.findings:
            self.assertIsInstance(f, SecurityFinding)
            self.assertEqual(f.provider, CloudProvider.AWS)
            self.assertIsNotNone(f.primary_control_id)

        # Check Evidence
        for e in res.evidence:
            self.assertIsInstance(e, Evidence)
            self.assertNotEqual(e.status, EvidenceStatus.VERIFIED)
            self.assertTrue(len(e.content_hash) == 64)

    def test_azure_normalization(self):
        """14. Azure output normalizes into strongly-typed canonical entities."""
        azure = AzureConnector(subscription_id="sub-12345")
        res = azure.discover_canonical(live=False)

        self.assertIsInstance(res, NormalizedDiscoveryResult)
        self.assertEqual(res.provider, CloudProvider.AZURE)
        self.assertEqual(res.execution_mode, ExecutionMode.SIMULATION)

        # Check Assets
        self.assertGreater(len(res.assets), 0)
        for a in res.assets:
            self.assertIsInstance(a, AIAsset)
            self.assertEqual(a.provider, CloudProvider.AZURE)

        # Check Findings
        self.assertGreater(len(res.findings), 0)
        for f in res.findings:
            self.assertIsInstance(f, SecurityFinding)
            self.assertEqual(f.provider, CloudProvider.AZURE)
            self.assertIsNotNone(f.primary_control_id)

        # Check Evidence
        for e in res.evidence:
            self.assertIsInstance(e, Evidence)
            self.assertNotEqual(e.status, EvidenceStatus.VERIFIED)
            self.assertTrue(len(e.content_hash) == 64)

    def test_live_normalization_epistemology(self):
        """15. LIVE normalized findings MUST contain VERIFIED LIVE evidence."""
        aws = AWSConnector(account_id="123456789012")
        raw_live_data = {
            "provider": "aws",
            "account_id": "123456789012",
            "models": [{"name": "bedrock-claude", "resource_type": "bedrock_foundation_model", "location": "us-east-1"}],
            "endpoints": [],
            "shadow_ai": [],
            "vulnerabilities": [
                {
                    "id": "AWS-BEDROCK-GAP-LIVE",
                    "cve": "MISCONFIG-NO-GUARDRAIL",
                    "severity": "HIGH",
                    "resource": "arn:aws:bedrock:us-east-1:123456789012:model/bedrock-claude",
                    "description": "Live Bedrock inspection confirms absence of guardrails."
                }
            ]
        }
        res = aws.normalize(raw_live_data, execution_mode=ExecutionMode.LIVE)
        self.assertTrue(res.is_live)
        self.assertEqual(len(res.findings), 1)
        finding = res.findings[0]
        self.assertEqual(finding.execution_mode, ExecutionMode.LIVE)
        self.assertTrue(finding.is_live_verified)
        self.assertEqual(finding.evidence[0].status, EvidenceStatus.VERIFIED)
        self.assertEqual(finding.evidence[0].execution_mode, ExecutionMode.LIVE)

    def test_platform_core_canonical_discovery(self):
        """16. AISPRAgenticCore returns multi-cloud canonical discovery results."""
        core = AISPRAgenticCore(tenant_id="test-enterprise")
        results = core.run_canonical_discovery(live=False)

        self.assertIn("gcp", results)
        self.assertIn("aws", results)
        self.assertIn("azure", results)

        for provider, res in results.items():
            self.assertIsInstance(res, NormalizedDiscoveryResult)
            self.assertGreater(len(res.assets), 0)
            self.assertGreater(len(res.findings), 0)


# ==============================================================================
# 7. LIVE INTEGRATION GATE TESTS (MOCKS != LIVE SUPPORT)
# ==============================================================================

class TestLiveIntegrationGate(unittest.TestCase):
    """
    CRITICAL RULE: A connector can only be classified as LIVE if real provider
    API calls are executed successfully. Do not claim live support based on mocks.
    """

    def test_simulation_cannot_claim_live(self):
        """17. Calling discover_resources() CANNOT result in LIVE execution mode."""
        gcp = GCPConnector(project_id="test-proj")
        aws = AWSConnector(account_id="123456789012")
        azure = AzureConnector(subscription_id="sub-12345")

        gcp_res = gcp.discover_resources()
        aws_res = aws.discover_resources()
        azure_res = azure.discover_resources()

        self.assertNotEqual(gcp.execution_mode, ExecutionMode.LIVE)
        self.assertNotEqual(aws.execution_mode, ExecutionMode.LIVE)
        self.assertNotEqual(azure.execution_mode, ExecutionMode.LIVE)

        self.assertEqual(gcp.execution_mode, ExecutionMode.SIMULATION)
        self.assertEqual(aws.execution_mode, ExecutionMode.SIMULATION)
        self.assertEqual(azure.execution_mode, ExecutionMode.SIMULATION)

    def test_live_failure_does_not_silently_fallback_to_live_label(self):
        """18. If live discovery encounters credentials error, it does NOT claim LIVE."""
        # Unset credentials to ensure failure
        with patch.dict(os.environ, {}, clear=True):
            aws = AWSConnector(account_id="123456789012", role_arn=None)
            # Live discovery must either raise CloudAuthenticationError or remain non-LIVE
            try:
                res = aws.discover_resources_live()
            except (CloudAuthenticationError, CloudSDKMissingError, CloudConnectorError):
                pass
            self.assertNotEqual(aws.execution_mode, ExecutionMode.LIVE)


if __name__ == "__main__":
    unittest.main()
