# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for GCP Authentication & Live Discovery Connector.
All Google Cloud SDK clients (google-cloud-aiplatform, google-cloud-asset,
google-cloud-securitycenter, google-cloud-modelarmor) are fully mocked via unittest.mock.
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys
from typing import Dict, Any

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
agentic_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(agentic_dir)
for p in [root_dir, agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from config.gcp_auth import (
    GCPAuth,
    get_gcp_credentials,
    get_authenticated_session,
    get_default_project_id,
    get_auth_headers,
    check_adc_status
)
from agentic.connectors.gcp_connector import GCPConnector
from agentic.dynamic_assessment import DynamicAssessmentEngine
from agentic.remediation_engine import RemediationEngine
from audit.agent.tools import fetch_scc_ai_findings_live, get_gcp_ai_inventory_live
from agentic.agent.tools import fetch_scc_ai_findings_live as agentic_fetch_scc_live


class TestGCPAuthAndLiveConnector(unittest.TestCase):

    def test_default_project_id_resolution(self):
        # 1. Explicit parameter takes priority
        self.assertEqual(get_default_project_id("explicit-proj-123"), "explicit-proj-123")

        # 2. Environment variable fallback
        with patch.dict(os.environ, {"GOOGLE_CLOUD_PROJECT": "env-proj-456"}):
            self.assertEqual(get_default_project_id(), "env-proj-456")

        with patch.dict(os.environ, {"GCP_PROJECT": "env-gcp-789"}, clear=True):
            self.assertEqual(get_default_project_id(), "env-gcp-789")

    def test_gcp_auth_class_initialization(self):
        auth = GCPAuth(project_id="test-client-project")
        self.assertIsNotNone(auth)
        self.assertEqual(auth.project_id, "test-client-project")

    def test_check_adc_status(self):
        status = check_adc_status()
        self.assertIsInstance(status, dict)
        self.assertIn("adc_available", status)

    def test_mock_discover_resources_preserved(self):
        """Ensures the original mock discover_resources() is intact and unmodified."""
        connector = GCPConnector(project_id="test-fintech-ai-core")
        res = connector.discover_resources()

        # Check top-level keys
        expected_keys = {"provider", "project_id", "models", "endpoints", "shadow_ai", "vulnerabilities"}
        self.assertEqual(set(res.keys()), expected_keys)

        self.assertEqual(res["provider"], "gcp")
        self.assertEqual(res["project_id"], "test-fintech-ai-core")
        self.assertEqual(len(res["models"]), 3)
        self.assertEqual(len(res["endpoints"]), 1)
        self.assertEqual(len(res["shadow_ai"]), 2)
        self.assertEqual(len(res["vulnerabilities"]), 2)

    def test_discover_resources_live_schema_shape_matches_mock(self):
        """Validates that discover_resources_live() returns the exact same schema shape as discover_resources()."""
        connector = GCPConnector(project_id="live-fintech-project")
        res = connector.discover_resources_live(locations=["us-central1"])

        expected_keys = {"provider", "project_id", "models", "endpoints", "shadow_ai", "vulnerabilities"}
        self.assertEqual(set(res.keys()), expected_keys)
        self.assertEqual(res["provider"], "gcp")
        self.assertEqual(res["project_id"], "live-fintech-project")
        self.assertIsInstance(res["models"], list)
        self.assertIsInstance(res["endpoints"], list)
        self.assertIsInstance(res["shadow_ai"], list)
        self.assertIsInstance(res["vulnerabilities"], list)

    def test_discover_resources_live_with_mocked_gcp_clients(self):
        """
        Tests live discovery using mocked google-cloud-aiplatform, google-cloud-asset,
        google-cloud-modelarmor, and google-cloud-securitycenter SDK clients.
        """
        project_id = "fintech-cloud-prod"

        mock_google = MagicMock()
        mock_cloud = MagicMock()
        mock_aiplatform = MagicMock()
        mock_asset_v1 = MagicMock()
        mock_ma_v1 = MagicMock()
        mock_scc_v1 = MagicMock()

        # Link parent/child packages for "from google.cloud import ..." syntax
        mock_google.cloud = mock_cloud
        mock_cloud.aiplatform = mock_aiplatform
        mock_cloud.asset_v1 = mock_asset_v1
        mock_cloud.modelarmor_v1 = mock_ma_v1
        mock_cloud.securitycenter_v1 = mock_scc_v1

        # 1. Mock google.cloud.aiplatform
        mock_model = MagicMock()
        mock_model.display_name = "gemini-1.5-pro-financial-rag"
        mock_model.resource_name = f"projects/{project_id}/locations/us-central1/models/gemini-1.5-pro"
        mock_model.encryption_spec = MagicMock(kms_key_name="projects/k/locations/us-central1/keyRings/r/cryptoKeys/k")
        mock_model.to_dict.return_value = {"encryption_spec": {"kms_key_name": "projects/k/..."}}

        mock_endpoint = MagicMock()
        mock_endpoint.display_name = "credit-scoring-endpoint"
        mock_endpoint.resource_name = f"projects/{project_id}/locations/us-central1/endpoints/credit-scoring-prod"
        mock_endpoint.network = "projects/fintech/global/networks/ai-vpc"
        mock_endpoint.encryption_spec = MagicMock()
        mock_endpoint.to_dict.return_value = {
            "network": "projects/fintech/global/networks/ai-vpc",
            "encryption_spec": {"kms_key_name": "projects/k/..."}
        }

        mock_aiplatform.Model.list.return_value = [mock_model]
        mock_aiplatform.Endpoint.list.return_value = [mock_endpoint]

        # 2. Mock google.cloud.asset_v1 (Cloud Asset Inventory)
        mock_asset_client = MagicMock()
        mock_asset_v1.AssetServiceClient.return_value = mock_asset_client

        # Discovered Assets: Workbench Instance, Storage Bucket, GKE cluster with shadow AI
        asset_wb = MagicMock()
        asset_wb.name = f"//notebooks.googleapis.com/projects/{project_id}/locations/southamerica-east1-a/instances/wb-01"
        asset_wb.display_name = "workbench-analyst-gpu-01"
        asset_wb.asset_type = "notebooks.googleapis.com/Instance"
        asset_wb.location = "southamerica-east1-a"
        asset_wb.kms_keys = []  # No CMEK -> should flag vulnerability
        asset_wb.additional_attributes = {"noPublicIp": False}

        asset_bucket = MagicMock()
        asset_bucket.name = f"//storage.googleapis.com/projects/{project_id}/buckets/banco-credit-rag-knowledge-base"
        asset_bucket.display_name = "banco-credit-rag-knowledge-base"
        asset_bucket.asset_type = "storage.googleapis.com/Bucket"
        asset_bucket.kms_keys = []  # No CMEK

        asset_gke = MagicMock()
        asset_gke.name = f"//container.googleapis.com/projects/{project_id}/locations/us-central1/clusters/gke-ollama-cluster"
        asset_gke.display_name = "gke-ollama-cluster"
        asset_gke.asset_type = "container.googleapis.com/Cluster"
        asset_gke.additional_attributes = {"workload": "ollama-inference-engine"}

        mock_asset_client.search_all_resources.return_value = [asset_wb, asset_bucket, asset_gke]

        # IAM Policy Search: Public IAM exposure and Over-privileged AI SA
        iam_policy_pub = MagicMock()
        iam_policy_pub.resource = f"//aiplatform.googleapis.com/projects/{project_id}/locations/us-central1/endpoints/credit-scoring-prod"
        binding_pub = MagicMock()
        binding_pub.role = "roles/aiplatform.user"
        binding_pub.members = ["allUsers"]
        iam_policy_pub.policy.bindings = [binding_pub]

        iam_policy_sa = MagicMock()
        iam_policy_sa.resource = f"//cloudresourcemanager.googleapis.com/projects/{project_id}"
        binding_sa = MagicMock()
        binding_sa.role = "roles/owner"
        binding_sa.members = ["serviceAccount:ai-agent-executor@fintech.iam.gserviceaccount.com"]
        iam_policy_sa.policy.bindings = [binding_sa]

        mock_asset_client.search_all_iam_policies.return_value = [iam_policy_pub, iam_policy_sa]

        # 3. Mock Model Armor templates
        mock_ma_client = MagicMock()
        mock_ma_v1.ModelArmorClient.return_value = mock_ma_client
        mock_template = MagicMock()
        mock_template.name = f"projects/{project_id}/locations/us-central1/templates/fintech-guard"
        mock_ma_client.list_templates.return_value = [mock_template]

        # Execute Live Discovery with injected mocks
        with patch.dict(sys.modules, {
            "google": mock_google,
            "google.cloud": mock_cloud,
            "google.cloud.aiplatform": mock_aiplatform,
            "google.cloud.asset_v1": mock_asset_v1,
            "google.cloud.modelarmor_v1": mock_ma_v1,
            "google.cloud.securitycenter_v1": mock_scc_v1,
        }):
            connector = GCPConnector(project_id=project_id)
            res = connector.discover_resources_live(locations=["us-central1"])

            # 1. Verify exact schema shape
            expected_keys = {"provider", "project_id", "models", "endpoints", "shadow_ai", "vulnerabilities"}
            self.assertEqual(set(res.keys()), expected_keys)
            self.assertEqual(res["provider"], "gcp")
            self.assertEqual(res["project_id"], project_id)

            # 2. Verify Models list contains Vertex Models, Endpoints, and Workbench instances
            self.assertGreaterEqual(len(res["models"]), 3)
            model_types = [m["resource_type"] for m in res["models"]]
            self.assertIn("vertex_ai_model", model_types)
            self.assertIn("vertex_ai_endpoint", model_types)
            self.assertIn("vertex_workbench_instance", model_types)

            # Verify each model item has standard fields
            for m in res["models"]:
                self.assertIn("name", m)
                self.assertIn("provider", m)
                self.assertIn("resource_type", m)
                self.assertIn("location", m)
                self.assertIn("cmek_enabled", m)
                self.assertIn("model_armor_enabled", m)
                self.assertIn("private_endpoint", m)
                self.assertIn("status", m)

            # 3. Verify Endpoints list
            self.assertGreaterEqual(len(res["endpoints"]), 1)
            for ep in res["endpoints"]:
                self.assertIn("name", ep)
                self.assertIn("provider", ep)
                self.assertIn("url", ep)
                self.assertIn("protected", ep)

            # 4. Verify Shadow AI detected from GKE cluster
            self.assertGreaterEqual(len(res["shadow_ai"]), 1)
            shadow_types = [s["type"] for s in res["shadow_ai"]]
            self.assertTrue(any("Ollama" in t for t in shadow_types))

            # 5. Verify Vulnerabilities detected (Workbench public/no CMEK, Storage no CMEK, IAM public exposure, IAM excessive agency)
            self.assertGreaterEqual(len(res["vulnerabilities"]), 3)
            vuln_cves = [v["cve"] for v in res["vulnerabilities"]]
            self.assertIn("MISCONFIG-CMEK", vuln_cves)
            self.assertTrue(any("PUBLIC" in c for c in vuln_cves))
            self.assertTrue(any("EXCESSIVE_AGENCY" in c for c in vuln_cves))

            # 6. Verify Downstream Compatibility (Dynamic Assessment & Remediations)
            ai_bom = {
                "tenant_id": "test-tenant",
                "discovered_models": res["models"],
                "discovered_endpoints": res["endpoints"],
                "shadow_ai_findings": res["shadow_ai"],
                "vulnerabilities": res["vulnerabilities"]
            }
            questions = DynamicAssessmentEngine.generate_questions(ai_bom)
            self.assertIsInstance(questions, list)
            self.assertGreater(len(questions), 0)

            failed_controls = ["DYN-GCP-ARM-01", "SHADOW-AI-01"]
            remediations = RemediationEngine.generate_remediations(failed_controls)
            self.assertIn("google_cloud_model_armor", remediations)
            self.assertIn("terraform_hardening_blueprint", remediations)

    def test_discover_resources_live_with_mocked_rest_fallback(self):
        """Tests live discovery via REST fallback when SDK modules are mocked to use session.get."""
        mock_session = MagicMock()

        # Mock Model Armor REST
        mock_ma_resp = MagicMock()
        mock_ma_resp.status_code = 200
        mock_ma_resp.json.return_value = {
            "templates": [{"name": "projects/test-p/locations/us-central1/templates/fintech-shield"}]
        }

        # Mock Vertex AI models REST
        mock_models_resp = MagicMock()
        mock_models_resp.status_code = 200
        mock_models_resp.json.return_value = {
            "models": [
                {
                    "name": "projects/test-p/locations/us-central1/models/credit-model-live",
                    "displayName": "credit-model-live",
                    "encryptionSpec": {"kmsKeyName": "projects/test-p/locations/us-central1/keyRings/r/cryptoKeys/k"}
                }
            ]
        }

        # Mock Vertex AI endpoints REST
        mock_endpoints_resp = MagicMock()
        mock_endpoints_resp.status_code = 200
        mock_endpoints_resp.json.return_value = {
            "endpoints": [
                {
                    "name": "projects/test-p/locations/us-central1/endpoints/ep-1",
                    "displayName": "ep-1",
                    "network": "projects/test-p/global/networks/ai-vpc"
                }
            ]
        }

        # Mock Asset search REST
        mock_asset_resp = MagicMock()
        mock_asset_resp.status_code = 200
        mock_asset_resp.json.return_value = {
            "results": [
                {
                    "name": "//notebooks.googleapis.com/test-nb",
                    "displayName": "workbench-analyst-gpu-01",
                    "assetType": "notebooks.googleapis.com/Instance",
                    "location": "us-central1",
                    "kmsKeys": []
                },
                {
                    "name": "//storage.googleapis.com/test-bucket",
                    "displayName": "test-ai-bucket",
                    "assetType": "storage.googleapis.com/Bucket",
                    "kmsKeys": []
                }
            ]
        }

        # Mock SCC findings REST
        mock_scc_resp = MagicMock()
        mock_scc_resp.status_code = 200
        mock_scc_resp.json.return_value = {
            "listFindingsResults": [
                {
                    "finding": {
                        "name": "projects/test-p/sources/1/findings/AI-FINDING-01",
                        "category": "UNSANCTIONED_SHADOW_AI_OLLAMA",
                        "severity": "CRITICAL",
                        "resourceName": "//container.googleapis.com/cluster-1",
                        "description": "Rogue Ollama container detected."
                    }
                }
            ]
        }

        def session_get_side_effect(url, **kwargs):
            if "modelarmor" in url:
                return mock_ma_resp
            elif "/models" in url:
                return mock_models_resp
            elif "/endpoints" in url:
                return mock_endpoints_resp
            elif "cloudasset" in url:
                return mock_asset_resp
            elif "securitycenter" in url:
                return mock_scc_resp
            return MagicMock(status_code=404)

        mock_session.get.side_effect = session_get_side_effect

        with patch("agentic.connectors.gcp_connector.get_authenticated_session", return_value=mock_session):
            connector = GCPConnector(project_id="test-p")
            res = connector.discover_resources_live(locations=["us-central1"], use_rest_fallback=True)

            expected_keys = {"provider", "project_id", "models", "endpoints", "shadow_ai", "vulnerabilities"}
            self.assertEqual(set(res.keys()), expected_keys)
            self.assertEqual(res["project_id"], "test-p")
            self.assertGreaterEqual(len(res["models"]), 2)
            self.assertGreaterEqual(len(res["endpoints"]), 1)
            self.assertGreaterEqual(len(res["shadow_ai"]), 1)
            self.assertGreaterEqual(len(res["vulnerabilities"]), 2)

    def test_audit_tools_live_functions(self):
        findings = fetch_scc_ai_findings_live("test-proj")
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)

        inventory = get_gcp_ai_inventory_live("test-proj")
        self.assertIsInstance(inventory, list)
        self.assertGreater(len(inventory), 0)

    def test_agentic_tools_live_functions(self):
        findings = agentic_fetch_scc_live("test-proj")
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()

# Audit checkpoint [2026-02-19]: refactor(scoring): calibrate model vulnerability scoring formula for client audit
