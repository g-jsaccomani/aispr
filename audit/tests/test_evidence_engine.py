# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AISPR Phase 2: Evidence-First Assessment Engine
Validates live vs simulation findings, SHA-256 evidence hashing, secret redaction,
tampering detection, confidence propagation, and evidence-first report rendering.
"""

import os
import sys
import hashlib
import unittest
from datetime import datetime, timezone
from pydantic import ValidationError

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
audit_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(audit_dir)
for p in [root_dir, audit_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from domain.enums import (
    CloudProvider,
    FindingSeverity,
    FindingStatus,
    FindingSource,
    EvidenceType,
    EvidenceStatus,
    ExecutionMode,
    ConfidenceLevel,
    AssetType,
)
from domain.models import (
    Evidence,
    EvidenceReference,
    EvidenceCollectionResult,
    AIAsset,
    SecurityFinding,
    AssessmentRun,
)
from domain.sanitization import (
    redact_string,
    sanitize_value,
    sanitize_evidence_content,
)
from audit.engine.reporter import ExecutiveReporter


class TestEvidenceFirstAssessmentEngine(unittest.TestCase):

    def setUp(self):
        self.sample_asset = AIAsset(
            asset_id="AST-VERTEX-ENDPOINT-01",
            name="projects/fintech-prod/locations/us-central1/endpoints/credit-scoring-v2",
            asset_type=AssetType.INFERENCE_ENDPOINT,
            provider=CloudProvider.GCP,
            location="us-central1",
            display_name="Credit Scoring v2",
            cmek_enabled=False,
            is_private_endpoint=False,
        )

    def test_live_finding_validation_rules(self):
        """Tests that a LIVE finding requires at least one verified live evidence item."""
        live_evidence = Evidence(
            source=FindingSource.CLOUD_ASSET_INVENTORY,
            provider=CloudProvider.GCP,
            resource=self.sample_asset.name,
            evidence_type=EvidenceType.API_RESPONSE,
            status=EvidenceStatus.VERIFIED,
            execution_mode=ExecutionMode.LIVE,
            confidence=0.98,
            sanitized_content="Live Cloud Asset Inventory response confirms endpoint is public."
        )

        # Successfully creates LIVE finding with real verified live evidence
        live_finding = SecurityFinding(
            asset=self.sample_asset,
            title="Public AI Endpoint without PSC Isolation",
            severity=FindingSeverity.HIGH,
            execution_mode=ExecutionMode.LIVE,
            evidence=[live_evidence]
        )
        self.assertTrue(live_finding.is_live_verified)
        self.assertFalse(live_finding.is_simulated)

        # Attempting to create a LIVE finding with ONLY fixture/simulated evidence must fail
        sim_evidence = Evidence(
            source=FindingSource.MANUAL_AUDIT,
            status=EvidenceStatus.SIMULATED,
            execution_mode=ExecutionMode.FIXTURE,
            sanitized_content="Hardcoded demo fixture finding"
        )
        with self.assertRaises(ValueError) as ctx:
            SecurityFinding(
                asset=self.sample_asset,
                title="Fake Live Finding",
                execution_mode=ExecutionMode.LIVE,
                evidence=[sim_evidence]
            )
        self.assertIn("Um finding LIVE não pode ser criado apenas a partir de fixture", str(ctx.exception))

    def test_simulation_finding_cannot_be_verified(self):
        """Tests that a SIMULATION finding cannot contain or appear as VERIFIED."""
        # Creating an evidence item in SIMULATION mode with VERIFIED status auto-normalizes or raises error
        sim_evidence = Evidence(
            source=FindingSource.SHADOW_AI_HUNTER,
            status=EvidenceStatus.VERIFIED,
            execution_mode=ExecutionMode.SIMULATION,
            sanitized_content="Simulation of Ollama container"
        )
        # Evidence model validator normalizes SIMULATION + VERIFIED to SIMULATED
        self.assertEqual(sim_evidence.status, EvidenceStatus.SIMULATED)

        # Force verified on simulation finding raises ValueError
        with self.assertRaises(ValueError) as ctx:
            finding = SecurityFinding(
                asset=self.sample_asset,
                title="Simulated Finding",
                execution_mode=ExecutionMode.SIMULATION
            )
            # Directly appending an illegally forced verified evidence
            fake_verified = Evidence(
                status=EvidenceStatus.UNVERIFIED,
                execution_mode=ExecutionMode.LIVE
            )
            object.__setattr__(fake_verified, "status", EvidenceStatus.VERIFIED)
            finding.evidence.append(fake_verified)
            finding.validate_epistemology()
        self.assertIn("Um finding SIMULATION não pode aparecer como VERIFIED", str(ctx.exception))

    def test_fixture_finding_behavior(self):
        """Tests that fixture findings are strictly identified as simulated and not verified."""
        fixture_ev = Evidence(
            source=FindingSource.MANUAL_AUDIT,
            status=EvidenceStatus.SIMULATED,
            execution_mode=ExecutionMode.FIXTURE,
            resource="fixtures/demo_data.py",
            sanitized_content="Topology reference fixture node"
        )
        finding = SecurityFinding(
            asset=self.sample_asset,
            title="Topology Reference Node",
            execution_mode=ExecutionMode.FIXTURE,
            evidence=[fixture_ev]
        )
        self.assertFalse(finding.is_live_verified)
        self.assertTrue(finding.is_simulated)

    def test_evidence_hashing_sha256(self):
        """Tests that evidence content is automatically and deterministically hashed with SHA-256."""
        content = "GCP Cloud KMS key ring projects/demo/locations/global/keyRings/ai-ring missing"
        evidence = Evidence(
            source=FindingSource.CLOUD_ASSET_INVENTORY,
            sanitized_content=content
        )
        expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        self.assertEqual(evidence.content_hash, expected_hash)
        self.assertTrue(evidence.verify_integrity())

    def test_secret_redaction_and_sanitization(self):
        """Tests that access tokens, private keys, API keys, and passwords are never persisted."""
        raw_text_with_secrets = (
            "User credentials: password='SuperSecretPassword123' "
            "token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak' "
            "Google API Key AIzaSyD3ExampleKey35CharactersLongSafe "
            "OpenAI Key sk-abcdef12345678901234567890123456 "
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m...\n-----END RSA PRIVATE KEY-----"
        )
        sanitized = sanitize_evidence_content(raw_text_with_secrets)

        # Verify none of the raw secrets exist in the sanitized text
        self.assertNotIn("SuperSecretPassword123", sanitized)
        self.assertNotIn("AIzaSyD3ExampleKey35CharactersLongSafe", sanitized)
        self.assertNotIn("sk-abcdef12345678901234567890123456", sanitized)
        self.assertNotIn("MIIEowIBAAKCAQEA0m", sanitized)

        # Verify replacement tokens are present
        self.assertIn("[REDACTED_SECRET]", sanitized)
        self.assertIn("[REDACTED_GOOGLE_API_KEY]", sanitized)
        self.assertIn("[REDACTED_AI_API_KEY]", sanitized)
        self.assertIn("[REDACTED_PRIVATE_KEY]", sanitized)

        # Test setting content on Evidence model directly
        ev = Evidence()
        ev.set_content({"api_key": "AIzaSyD3ExampleKey35CharactersLongSafe", "status": "active"})
        self.assertNotIn("AIzaSyD3ExampleKey35CharactersLongSafe", ev.sanitized_content)
        self.assertTrue(ev.verify_integrity())

    def test_evidence_tampering_detection(self):
        """Tests that any modification to evidence content breaks cryptographic hash verification."""
        original_text = "Vertex AI endpoint credit-scoring is exposed on public 0.0.0.0/0"
        ev = Evidence(sanitized_content=original_text)
        self.assertTrue(ev.verify_integrity())

        # Simulate tampering by an unauthorized process modifying the text in memory
        object.__setattr__(ev, "sanitized_content", "Vertex AI endpoint credit-scoring is completely private and secure")
        self.assertFalse(ev.verify_integrity(), "Tampered evidence should fail cryptographic verification!")

    def test_confidence_propagation(self):
        """Tests that finding confidence is mathematically aggregated from attached evidence."""
        ev1 = Evidence(confidence=0.96)
        ev2 = Evidence(confidence=0.98)

        finding = SecurityFinding(
            asset=self.sample_asset,
            title="Multi-Sensor Verified Vulnerability",
            evidence=[ev1, ev2]
        )
        self.assertEqual(finding.propagated_confidence, 0.97)

    def test_invalid_evidence_validation(self):
        """Tests validation bounds on evidence fields."""
        # Confidence must be between 0.0 and 1.0
        with self.assertRaises(ValidationError):
            Evidence(confidence=1.5)

        with self.assertRaises(ValidationError):
            Evidence(confidence=-0.1)

        # Inferred finding without explicit origin gets origin auto-populated
        inferred_ev = Evidence(
            status=EvidenceStatus.INFERRED,
            sanitized_content="Heuristic finding without explicit origin in source"
        )
        finding = SecurityFinding(
            asset=self.sample_asset,
            title="Inferred Anomaly",
            evidence=[inferred_ev]
        )
        self.assertIn("inferred_origin", finding.metadata)

    def test_report_rendering_with_evidence_cards(self):
        """Tests that ExecutiveReporter renders the exact evidence-first audit format."""
        live_ev = Evidence(
            source=FindingSource.CLOUD_ASSET_INVENTORY,
            provider=CloudProvider.GCP,
            resource="projects/fintech-prod/endpoints/public-ai",
            evidence_type=EvidenceType.API_RESPONSE,
            status=EvidenceStatus.VERIFIED,
            execution_mode=ExecutionMode.LIVE,
            confidence=0.97,
            sanitized_content="GCP Compute API confirmed public IP without Cloud IAP"
        )
        live_finding = SecurityFinding(
            asset=self.sample_asset,
            title="Public AI Endpoint",
            severity=FindingSeverity.HIGH,
            execution_mode=ExecutionMode.LIVE,
            evidence=[live_ev]
        )

        card_text = ExecutiveReporter.render_finding_evidence_card(live_finding)
        self.assertIn("**Finding:** Public AI Endpoint", card_text)
        self.assertIn("**Severity:** HIGH", card_text)
        self.assertIn("**Evidence:** Google Cloud Asset Inventory", card_text)
        self.assertIn("**Execution:** LIVE", card_text)
        self.assertIn("**Verification:** VERIFIED", card_text)
        self.assertIn("**Confidence:** 0.97", card_text)
        self.assertIn("**Content Hash (SHA-256):**", card_text)

        # Test full report segregation: Live vs Simulated
        sim_ev = Evidence(
            source=FindingSource.SHADOW_AI_HUNTER,
            status=EvidenceStatus.SIMULATED,
            execution_mode=ExecutionMode.SIMULATION,
            sanitized_content="Simulated rogue Ollama container"
        )
        sim_finding = SecurityFinding(
            asset=self.sample_asset,
            title="Simulated Rogue Container",
            severity=FindingSeverity.MEDIUM,
            execution_mode=ExecutionMode.SIMULATION,
            evidence=[sim_ev]
        )

        run = AssessmentRun(
            assessment_id="ASM-FINTECH-01",
            execution_mode=ExecutionMode.LIVE_PARTIAL
        )
        run.add_finding(live_finding)
        run.add_finding(sim_finding)

        reporter = ExecutiveReporter(client_name="Fintech Bank", project_name="fintech-prod")
        report_md = reporter.build_consolidated_report(
            answers={},
            question_db={},
            findings=[live_finding, sim_finding],
            assessment_run=run
        )

        # Assert Section 4 exists and segregates live from simulated
        self.assertIn("## 4. Evidence-First Verification & Technical Audit Trail", report_md)
        self.assertIn("### 4.1 Live Verified Findings (Observed in Production Cloud)", report_md)
        self.assertIn("AUDIT NOTICE:", report_md)
        self.assertIn("The following items originate from test fixtures", report_md)


if __name__ == "__main__":
    unittest.main()
