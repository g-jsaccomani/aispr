# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AISPR Canonical Security Data Model
Validates serialization, deserialization, validation, enum enforcement,
multi-control relationships, framework mappings, and epistemological evidence status.
"""

import os
import sys
import json
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
    ControlEvaluation,
    ControlRelationType,
    RiskLevel,
    AssessmentStatus,
)
from domain.models import (
    Evidence,
    AIAsset,
    AttackTechnique,
    FrameworkMapping,
    Control,
    ControlLink,
    ControlResult,
    Remediation,
    Risk,
    SecurityFinding,
    Finding,
    SecurityEvent,
    Assessment,
    AssessmentRun,
)


class TestCanonicalSecurityDataModel(unittest.TestCase):

    def setUp(self):
        self.sample_asset = AIAsset(
            asset_id="AST-VERTEX-01",
            name="projects/test-fintech/locations/us-central1/endpoints/credit-scoring-v2",
            asset_type=AssetType.INFERENCE_ENDPOINT,
            provider=CloudProvider.GCP,
            location="us-central1",
            display_name="Credit Scoring v2",
            cmek_enabled=False,
            is_private_endpoint=False,
            model_armor_enabled=False,
        )

    def test_serialization_and_deserialization(self):
        """Tests that models serialize to dict and JSON and deserialize losslessly."""
        evidence = Evidence(
            evidence_type=EvidenceType.API_RESPONSE,
            status=EvidenceStatus.VERIFIED,
            execution_mode=ExecutionMode.LIVE,
            description="Cloud Asset Inventory confirms CMEK is missing.",
            raw_data={"encryption_spec": None, "network": None}
        )

        finding = SecurityFinding(
            finding_id="FND-LIVE-001",
            assessment_id="ASM-2026-01",
            source=FindingSource.CLOUD_ASSET_INVENTORY,
            provider=CloudProvider.GCP,
            asset=self.sample_asset,
            title="Vertex AI Endpoint lacks CMEK encryption and VPC-SC perimeter isolation",
            description="Sensitive credit scoring endpoint is encrypted with Google default key.",
            severity=FindingSeverity.HIGH,
            confidence=ConfidenceLevel.CONFIRMED,
            status=FindingStatus.OPEN,
            evidence=[evidence]
        )
        finding.set_primary_control("INF-04", "Cryptographic sovereignty requirement")
        finding.add_secondary_control("INF-02", "Private Service Connect isolation")

        # Serialize to dict & JSON
        finding_dict = finding.to_dict()
        finding_json = finding.to_json()

        self.assertIsInstance(finding_dict, dict)
        self.assertIsInstance(finding_json, str)
        self.assertEqual(finding_dict["finding_id"], "FND-LIVE-001")
        self.assertEqual(finding_dict["severity"], "HIGH")

        # Deserialize back
        reconstituted = SecurityFinding.model_validate_json(finding_json)
        self.assertEqual(reconstituted.finding_id, finding.finding_id)
        self.assertEqual(reconstituted.severity, FindingSeverity.HIGH)
        self.assertEqual(len(reconstituted.evidence), 1)
        self.assertEqual(reconstituted.primary_control_id, "INF-04")
        self.assertIn("INF-02", reconstituted.control_ids)

    def test_enum_enforcement_and_case_insensitivity(self):
        """Tests that enums are strictly enforced and normalize case variations."""
        asset = AIAsset(
            name="Bedrock Claude",
            asset_type="foundation_model",
            provider="AWS"
        )
        self.assertEqual(asset.provider, CloudProvider.AWS)
        self.assertEqual(asset.asset_type, AssetType.FOUNDATION_MODEL)

        evidence = Evidence(
            status="verified",
            execution_mode="live"
        )
        self.assertEqual(evidence.status, EvidenceStatus.VERIFIED)
        self.assertEqual(evidence.execution_mode, ExecutionMode.LIVE)

    def test_missing_required_fields_raises_validation_error(self):
        """Tests that omitting required fields raises Pydantic ValidationError."""
        # SecurityFinding requires at least title and asset
        with self.assertRaises(ValidationError):
            SecurityFinding(title="Incomplete Finding")  # missing asset

        with self.assertRaises(ValidationError):
            AIAsset()  # missing name

    def test_invalid_severity_handling(self):
        """Tests that invalid severity strings raise ValidationError with zero silent fallback."""
        with self.assertRaises(ValidationError):
            SecurityFinding(
                asset=self.sample_asset,
                title="Test Finding",
                severity="NON_EXISTENT_SEVERITY"
            )

    def test_multi_control_findings_differentiation(self):
        """Tests explicit distinction between PRIMARY, SECONDARY, and RELATED controls."""
        finding = SecurityFinding(
            asset=self.sample_asset,
            title="Excessive Agency & Token Exposure in Startup Script"
        )
        finding.set_primary_control("INF-01", "Direct CVE-2026-2244 token leakage in startup log")
        finding.add_secondary_control("INF-03", "Service account has roles/editor assigned")
        finding.add_related_control("GOV-02", "Unregistered AI workbench instance")

        self.assertEqual(finding.primary_control_id, "INF-01")
        self.assertListEqual(finding.control_ids, ["INF-01", "INF-03", "GOV-02"])

        primary_controls = finding.get_controls_by_relation(ControlRelationType.PRIMARY_CONTROL)
        secondary_controls = finding.get_controls_by_relation(ControlRelationType.SECONDARY_CONTROL)
        related_controls = finding.get_controls_by_relation(ControlRelationType.RELATED_CONTROL)

        self.assertEqual(primary_controls, ["INF-01"])
        self.assertEqual(secondary_controls, ["INF-03"])
        self.assertEqual(related_controls, ["GOV-02"])

        # Setting a new primary automatically downgrades the old one to secondary
        finding.set_primary_control("INF-03", "Elevating IAM excessive agency to primary root cause")
        self.assertEqual(finding.primary_control_id, "INF-03")
        self.assertIn("INF-01", finding.get_controls_by_relation(ControlRelationType.SECONDARY_CONTROL))

    def test_framework_mappings_and_attack_techniques(self):
        """Tests attaching and querying multi-standard framework and MITRE ATLAS mappings."""
        finding = SecurityFinding(
            asset=self.sample_asset,
            title="Prompt Injection Vulnerability in Chat Endpoint"
        )
        finding.add_framework_mapping("Google SAIF", "Pillar 1", "2.0", "Strong security foundations")
        finding.add_framework_mapping("NIST AI RMF", "MANAGE 2.4", "1.0", "Residual risk management")
        finding.add_framework_mapping("ISO/IEC 42001", "A.8.5", "2023", "AI system security controls")
        finding.add_framework_mapping("EU AI Act", "Article 15", "2024/1689", "Accuracy, robustness and cybersecurity")
        finding.add_framework_mapping("OWASP LLM", "LLM01", "2025", "Prompt Injection")

        finding.add_attack_technique("AML.T0054", "LLM Jailbreak", "MITRE ATLAS", "Defense Evasion")
        finding.add_attack_technique("AML.T0051.000", "Direct Prompt Injection", "MITRE ATLAS", "Execution")

        self.assertEqual(len(finding.framework_mappings), 5)
        self.assertEqual(len(finding.attack_techniques), 2)
        
        framework_names = [fm.framework for fm in finding.framework_mappings]
        self.assertIn("Google SAIF", framework_names)
        self.assertIn("EU AI Act", framework_names)
        self.assertIn("OWASP LLM", framework_names)

        atlas_ids = [at.technique_id for at in finding.attack_techniques]
        self.assertIn("AML.T0054", atlas_ids)
        self.assertIn("AML.T0051.000", atlas_ids)

    def test_live_vs_simulation_differentiation(self):
        """Tests that evidence epistemological status strictly separates live from simulation."""
        live_evidence = Evidence(
            status=EvidenceStatus.VERIFIED,
            execution_mode=ExecutionMode.LIVE,
            description="Live API call to Vertex AI confirmed endpoint is public."
        )
        self.assertTrue(live_evidence.is_verified_live)
        self.assertFalse(live_evidence.is_simulated)

        sim_evidence = Evidence(
            status=EvidenceStatus.SIMULATED,
            execution_mode=ExecutionMode.SIMULATION,
            description="Simulated mock fixture finding."
        )
        self.assertFalse(sim_evidence.is_verified_live)
        self.assertTrue(sim_evidence.is_simulated)

        # Finding with live evidence is marked live
        finding_live = SecurityFinding(asset=self.sample_asset, title="Live Finding", evidence=[live_evidence])
        self.assertTrue(finding_live.is_live_verified)
        self.assertFalse(finding_live.is_simulated)

        # Finding with simulated evidence is marked simulated
        finding_sim = SecurityFinding(asset=self.sample_asset, title="Simulated Finding", evidence=[sim_evidence])
        self.assertFalse(finding_sim.is_live_verified)
        self.assertTrue(finding_sim.is_simulated)

        # Finding with no evidence defaults to is_simulated=True
        finding_empty = SecurityFinding(asset=self.sample_asset, title="Empty Evidence Finding")
        self.assertFalse(finding_empty.is_live_verified)
        self.assertTrue(finding_empty.is_simulated)

    def test_assessment_and_assessment_run_lifecycle(self):
        """Tests Assessment and AssessmentRun initialization, evaluation, and completion."""
        assessment = Assessment(
            tenant_id="tenant-fintech-corp",
            client_name="Fintech Bank S/A",
            scope_description="Google Cloud Vertex AI & Azure OpenAI Services",
            status=AssessmentStatus.IN_PROGRESS
        )
        self.assertEqual(assessment.status, AssessmentStatus.IN_PROGRESS)

        run = AssessmentRun(
            assessment_id=assessment.assessment_id,
            execution_mode=ExecutionMode.LIVE_PARTIAL,
            assets=[self.sample_asset]
        )
        
        finding = SecurityFinding(
            assessment_id=assessment.assessment_id,
            asset=self.sample_asset,
            title="Public Ingress without VPC-SC",
            severity=FindingSeverity.HIGH
        )
        finding.set_primary_control("INF-02")
        run.findings.append(finding)

        ctrl_result = ControlResult(
            control_id="INF-02",
            evaluation=ControlEvaluation.NOT_MET,
            score=0.0,
            auditor_notes="Endpoint allows public ingress."
        )
        run.control_results.append(ctrl_result)

        run.complete(overall_score=75.0, posture_tier="MODERATE")
        self.assertEqual(run.status, AssessmentStatus.COMPLETED)
        self.assertIsNotNone(run.completed_at)
        self.assertEqual(run.summary_counts["total_findings"], 1)
        self.assertEqual(run.summary_counts["high_findings"], 1)
        self.assertEqual(run.summary_counts["evaluated_controls"], 1)

    def test_security_event_and_remediation_entities(self):
        """Tests SecurityEvent and Remediation entity creation and validation."""
        event = SecurityEvent(
            event_type="MODEL_ARMOR_BLOCK",
            source=FindingSource.MODEL_ARMOR,
            provider=CloudProvider.GCP,
            severity=FindingSeverity.CRITICAL,
            message="Prompt injection payload blocked by Model Armor filter",
            raw_payload={"matched_rules": ["PROMPT_INJECTION_OR_JAILBREAK_ATTEMPT"], "risk_score": 0.95}
        )
        self.assertEqual(event.severity, FindingSeverity.CRITICAL)
        self.assertIn("matched_rules", event.raw_payload)

        remediation = Remediation(
            title="Enforce VPC Service Controls Perimeter",
            description="Create Service Perimeter isolating Vertex AI services.",
            remediation_type="TERRAFORM",
            target_cloud=CloudProvider.GCP,
            target_resource="projects/test-fintech",
            priority=FindingSeverity.HIGH,
            automated_remediation_available=True,
            code_snippet='resource "google_access_context_manager_service_perimeter" "ai_perimeter" { ... }'
        )
        self.assertEqual(remediation.remediation_type, "TERRAFORM")
        self.assertTrue(remediation.automated_remediation_available)


if __name__ == "__main__":
    unittest.main()
