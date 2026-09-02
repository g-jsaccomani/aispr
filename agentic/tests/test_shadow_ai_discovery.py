# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 9: Enterprise Shadow AI Discovery - Comprehensive Test Suite.
Verifies:
  1. Known AI service detection
  2. Unknown AI endpoint detection
  3. False positive filtering
  4. Inferred service classification (Do not classify inference as fact)
  5. Public endpoint risk classification
  6. Private endpoint classification
  7. Duplicate discovery & corroboration
  8. Mandatory provenance and confidence invariant
  9. Platform integration via AISPRAgenticCore
"""

import os
import sys
import unittest
from datetime import datetime, timezone
from typing import Dict, Any

# Ensure project root is in sys.path
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_proj_root = os.path.abspath(os.path.join(_cur_dir, "../.."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from domain.enums import CloudProvider, ExecutionMode, FindingSeverity, EvidenceStatus
from agentic.shadow_ai import (
    EnterpriseShadowAIDiscoveryEngine,
    ShadowAIDiscoveryReport,
    ShadowAIDiscovery,
    ShadowConfidence,
    DetectionSource,
    ShadowAIRiskFactor,
    ShadowAIDetectors,
    ShadowAIDeduplicator,
    ShadowAIRiskEngine,
)
from agentic.core_platform import AISPRAgenticCore


class TestShadowAIDiscovery(unittest.TestCase):
    """Verifies all Phase 9 Shadow AI requirements."""

    def setUp(self):
        self.engine = EnterpriseShadowAIDiscoveryEngine(default_mode=ExecutionMode.SIMULATION)

    # ==========================================================================
    # 1. KNOWN AI SERVICE TEST
    # ==========================================================================
    def test_known_ai_service_detection(self):
        """1. Detects known external AI service (e.g. OpenAI / Anthropic) with canonical fields."""
        api_logs = [
            {
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "caller_ip": "10.0.4.15",
                "api_key": "sk-proj-test12345678",
                "payload_pii": True,
            }
        ]

        report = self.engine.discover(api_logs=api_logs)
        self.assertEqual(report.unique_assets_count, 1)
        disc = report.discoveries[0]

        # Verify all mandatory fields
        self.assertIsNotNone(disc.asset)
        self.assertIsNotNone(disc.provider)
        self.assertEqual(disc.source, DetectionSource.API_USAGE)
        self.assertEqual(disc.confidence, ShadowConfidence.OBSERVED)
        self.assertIsNotNone(disc.evidence)
        self.assertIsNotNone(disc.discovery_timestamp)
        self.assertEqual(disc.execution_mode, ExecutionMode.SIMULATION)
        self.assertTrue(len(disc.provenance) > 10)
        self.assertIn("api.openai.com", disc.asset.name)

    # ==========================================================================
    # 2. UNKNOWN AI ENDPOINT TEST
    # ==========================================================================
    def test_unknown_ai_endpoint_detection(self):
        """2. Detects unknown self-hosted AI model endpoint (e.g. Ollama/vLLM) on internal or public IP."""
        model_endpoints = [
            {
                "url": "http://10.200.5.12:11434/v1/models",
                "is_public": False,
                "models": ["llama-3-70b-instruct", "mistral-7b"],
                "headers": {"server": "ollama"},
            }
        ]

        report = self.engine.discover(model_endpoints=model_endpoints)
        self.assertEqual(report.unique_assets_count, 1)
        disc = report.discoveries[0]

        self.assertEqual(disc.source, DetectionSource.MODEL_ENDPOINT)
        self.assertEqual(disc.confidence, ShadowConfidence.OBSERVED)
        self.assertFalse(disc.is_public)
        self.assertIn("llama-3", str(disc.details["models"]))

    # ==========================================================================
    # 3. FALSE POSITIVE FILTERING TEST
    # ==========================================================================
    def test_false_positive_filtering(self):
        """3. Standard non-AI web services on ports 8000/8080 are rejected and not flagged as AI."""
        benign_endpoints = [
            {
                "url": "http://10.0.1.50:8000/health",
                "is_public": False,
                "models": [],  # No AI models
                "headers": {"server": "nginx/1.24"},  # Non-AI server
            },
            {
                "url": "http://10.0.1.51:8080/metrics",
                "is_public": False,
                "models": [],
                "headers": {"server": "prometheus-node-exporter"},
            }
        ]

        report = self.engine.discover(model_endpoints=benign_endpoints)
        # MUST filter out false positives
        self.assertEqual(report.unique_assets_count, 0)
        self.assertEqual(report.total_discovered, 0)

    # ==========================================================================
    # 4. INFERRED SERVICE CLASSIFICATION TEST
    # ==========================================================================
    def test_inferred_service_classification(self):
        """4. Network flows and metadata are classified as INFERRED, never as OBSERVED fact."""
        network_flows = [
            {
                "destination_host": "huggingface.co",
                "destination_port": 443,
                "source_ip": "10.0.2.22",
                "contains_pii": False,
            }
        ]
        metadata_records = [
            {
                "resource_name": "gce-analytics-vm",
                "env_vars": {"OPENAI_API_KEY": "sk-unmanaged-key"},
                "startup_script": "echo starting",
            }
        ]

        report = self.engine.discover(
            network_flows=network_flows,
            infrastructure_metadata=metadata_records
        )
        self.assertEqual(report.unique_assets_count, 2)

        for disc in report.discoveries:
            # Mandate: "Do not classify inference as fact."
            self.assertNotEqual(disc.confidence, ShadowConfidence.OBSERVED)
            self.assertIn(disc.confidence, [ShadowConfidence.INFERRED, ShadowConfidence.SUSPECTED])
            self.assertIn(disc.source, [DetectionSource.NETWORK_INDICATOR, DetectionSource.INFRASTRUCTURE_METADATA])

    # ==========================================================================
    # 5. PUBLIC ENDPOINT TEST
    # ==========================================================================
    def test_public_endpoint_risk_elevation(self):
        """5. Public unmanaged AI endpoints receive PUBLIC_ENDPOINT factor, high risk, and public flag."""
        public_cloud_resources = [
            {
                "name": "rogue-vllm-vm",
                "provider": "aws",
                "image": "vllm/vllm-openai:v0.4.0",
                "is_public": True,  # Exposed to 0.0.0.0
                "privileged": True,
                "sensitive_data": True,
            }
        ]

        report = self.engine.discover(cloud_resources=public_cloud_resources)
        self.assertEqual(report.unique_assets_count, 1)
        disc = report.discoveries[0]

        self.assertTrue(disc.is_public)
        self.assertIn(ShadowAIRiskFactor.PUBLIC_ENDPOINT, disc.risk_factors)
        self.assertIn(ShadowAIRiskFactor.EXTERNAL_EXPOSURE, disc.risk_factors)
        self.assertIn(ShadowAIRiskFactor.IDENTITY_PRIVILEGE, disc.risk_factors)
        self.assertIn(ShadowAIRiskFactor.DATA_SENSITIVITY, disc.risk_factors)
        self.assertGreaterEqual(disc.risk_score, 75.0)
        self.assertEqual(disc.severity, FindingSeverity.CRITICAL)

    # ==========================================================================
    # 6. PRIVATE ENDPOINT TEST
    # ==========================================================================
    def test_private_endpoint_classification(self):
        """6. Private internal AI workload has is_public=False and is_private_endpoint=True."""
        private_cloud_resources = [
            {
                "name": "private-internal-ollama",
                "provider": "gcp",
                "image": "ollama/ollama:latest",
                "is_public": False,
                "privileged": False,
                "sensitive_data": False,
            }
        ]

        report = self.engine.discover(cloud_resources=private_cloud_resources)
        self.assertEqual(report.unique_assets_count, 1)
        disc = report.discoveries[0]

        self.assertFalse(disc.is_public)
        self.assertTrue(disc.asset.is_private_endpoint)
        self.assertNotIn(ShadowAIRiskFactor.PUBLIC_ENDPOINT, disc.risk_factors)
        self.assertNotIn(ShadowAIRiskFactor.EXTERNAL_EXPOSURE, disc.risk_factors)

    # ==========================================================================
    # 7. DUPLICATE DISCOVERY & CORROBORATION TEST
    # ==========================================================================
    def test_duplicate_discovery_deduplication_and_corroboration(self):
        """7. Ingesting duplicate discoveries across multiple sensors merges and elevates confidence."""
        deduplicator = ShadowAIDeduplicator()

        # Step A: Inferred network traffic from workstation
        inferred_disc = ShadowAIDetectors.detect_network_indicators(
            [{"destination_host": "api.openai.com", "destination_port": 443, "source_ip": "10.0.1.99"}]
        )[0]
        self.assertEqual(inferred_disc.confidence, ShadowConfidence.INFERRED)

        # Ingest inferred
        merged1, is_new1 = deduplicator.ingest(inferred_disc)
        self.assertTrue(is_new1)
        self.assertEqual(deduplicator.total_unique, 1)

        # Step B: Direct API usage log with confirmed token from same endpoint
        observed_disc = ShadowAIDetectors.detect_api_usage(
            [{"endpoint": "api.openai.com", "caller_ip": "10.0.1.99", "api_key": "sk-active"}]
        )[0]
        # Force matching fingerprint to simulate same logical asset
        observed_disc.fingerprint = inferred_disc.fingerprint

        merged2, is_new2 = deduplicator.ingest(observed_disc)
        # Must NOT create a duplicate record
        self.assertFalse(is_new2)
        self.assertEqual(deduplicator.total_unique, 1)
        # Must elevate confidence to OBSERVED
        self.assertEqual(merged2.confidence, ShadowConfidence.OBSERVED)
        self.assertIn("Corroborated with direct OBSERVED telemetry", merged2.provenance)

    # ==========================================================================
    # 8. MANDATORY PROVENANCE & CONFIDENCE INVARIANT (FINAL RULE)
    # ==========================================================================
    def test_mandatory_provenance_and_confidence_invariant(self):
        """8. Every discovery MUST contain non-empty provenance, confidence, and SHA-256 evidence."""
        # Test constructing discovery with all 7 sources
        cloud_res = [{"name": "cld-ollama", "image": "ollama"}]
        host_proc = [{"command": "vllm serve", "hostname": "dev-box", "pid": 1234}]
        saas_rec = [{"application_name": "ChatGPT Enterprise Plugin", "user_email": "alice@corp.com"}]

        report = self.engine.discover(
            cloud_resources=cloud_res,
            host_processes=host_proc,
            saas_records=saas_rec
        )

        self.assertEqual(report.unique_assets_count, 3)
        for disc in report.discoveries:
            self.assertTrue(len(disc.provenance) > 0)
            self.assertIn(disc.confidence, [ShadowConfidence.OBSERVED, ShadowConfidence.INFERRED, ShadowConfidence.SUSPECTED])
            self.assertIsNotNone(disc.evidence)
            self.assertEqual(len(disc.evidence.content_hash), 64)

        # Invariant: Cannot declare OBSERVED if provenance states it was inferred
        with self.assertRaises(ValueError):
            ShadowAIDiscovery(
                discovery_id="DSC-INVALID-01",
                asset=disc.asset,
                provider=CloudProvider.GCP,
                source=DetectionSource.CLOUD_RESOURCE,
                confidence=ShadowConfidence.OBSERVED,
                provenance="Inferred from heuristic guessing",  # Forbidden by epistemological invariant
            )

    # ==========================================================================
    # 9. PLATFORM CORE INTEGRATION TEST
    # ==========================================================================
    def test_platform_core_discover_shadow_ai(self):
        """9. AISPRAgenticCore integrates discover_shadow_ai seamlessly across multi-cloud."""
        core = AISPRAgenticCore(tenant_id="enterprise-fintech")
        report = core.discover_shadow_ai(
            cloud_resources=[{"name": "k8s-shadow-ollama", "provider": "gcp", "image": "ollama/ollama"}],
            network_flows=[{"destination_host": "api.anthropic.com", "destination_port": 443, "source_ip": "10.0.5.1"}],
        )

        self.assertIsInstance(report, ShadowAIDiscoveryReport)
        self.assertEqual(report.unique_assets_count, 2)
        self.assertIn(ShadowConfidence.OBSERVED.value, report.confidence_breakdown)
        self.assertIn(ShadowConfidence.INFERRED.value, report.confidence_breakdown)


if __name__ == "__main__":
    unittest.main()
