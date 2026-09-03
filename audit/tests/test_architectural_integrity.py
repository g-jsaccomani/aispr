# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

PHASE 4.5 — ARCHITECTURAL INTEGRITY GATE TEST SUITE
Exhaustively tests all requirements of Phase 4.5:
1. Invalid enums rejection (no silent fallback)
2. Invalid providers rejection
3. Invalid evidence types rejection
4. LIVE finding without evidence rejection
5. LIVE finding with simulation evidence rejection
6. Simulation with VERIFIED evidence rejection
7. Duplicate controls detection before dictionary indexing
8. Missing controls detection
9. Invalid control ID format rejection
10. Invalid domain/prefix consistency rejection
11. Duplicate test definitions rejection
12. Duplicate evidence requirements rejection
13. Strict 5-stage mapping precedence
14. Exact 6-stage pipeline execution order
15. Questionnaire mismatch failure
16. Deterministic evidence hashing & tamper detection
17. Implementation status distinction (IMPLEMENTED, PARTIAL, DECLARED_ONLY, NOT_IMPLEMENTED)
"""

import os
import sys
import unittest
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
    AssessmentType,
    AutomationLevel,
    MappingConfidence,
    ImplementationStatus,
)
from domain.models import (
    SecurityFinding,
    Evidence,
    AIAsset,
    Control,
    ControlResult,
    SecurityControlContract,
    TestDefinition,
    EvidenceRequirement,
    RegulatoryMapping,
)
from audit.contracts.registry import ControlContractRegistry
from audit.contracts.validator import ControlContractValidator
from audit.engine.correlator.control_mapper import ControlMapper, MappingPrecedence
from audit.engine.correlator.correlator import DeterministicCorrelator
from audit.questionnaire.handler import QuestionnaireHandler


class TestArchitecturalIntegrityGate(unittest.TestCase):

    def test_invalid_enums_raise_validation_error(self):
        """1. Invalid enum values MUST raise ValidationError, with zero silent fallback to defaults."""
        # Invalid severity
        with self.assertRaises(ValidationError):
            SecurityFinding(
                finding_id="FIND-INV-01",
                source=FindingSource.PROMPT_SAST,
                description="Test invalid severity",
                severity="CATASTROPHIC_EXPLOSION"
            )

        # Invalid status
        with self.assertRaises(ValidationError):
            SecurityFinding(
                finding_id="FIND-INV-02",
                source=FindingSource.PROMPT_SAST,
                description="Test invalid status",
                status="NOT_A_REAL_STATUS"
            )

        # Invalid confidence
        with self.assertRaises(ValidationError):
            SecurityFinding(
                finding_id="FIND-INV-03",
                source=FindingSource.PROMPT_SAST,
                description="Test invalid confidence",
                confidence="ABSOLUTELY_SURE"
            )

        # Invalid assessment_type in Contract
        with self.assertRaises(ValidationError):
            SecurityControlContract(
                control_id="APP-01",
                domain="3. Application Security (APP)",
                title="Test",
                objective="Test",
                description="Test",
                remediation="Test",
                assessment_type="MAGIC_AUTOMATION"
            )

        # Invalid automation_level in Contract
        with self.assertRaises(ValidationError):
            SecurityControlContract(
                control_id="APP-01",
                domain="3. Application Security (APP)",
                title="Test",
                objective="Test",
                description="Test",
                remediation="Test",
                automation_level="SEMI_FULL_NONE"
            )

    def test_invalid_providers_raise_validation_error(self):
        """2. Invalid provider strings MUST raise ValidationError with no fallback to GCP."""
        with self.assertRaises(ValidationError):
            Evidence(
                source=FindingSource.GCP_SCC,
                resource="projects/123",
                provider="ALIBABA_CLOUD_UNSUPPORTED"
            )

        with self.assertRaises(ValidationError):
            SecurityFinding(
                finding_id="FIND-INV-PROV",
                source=FindingSource.GCP_SCC,
                description="Test",
                provider="ORACLE_CLOUD_UNSUPPORTED"
            )

        with self.assertRaises(ValidationError):
            SecurityControlContract(
                control_id="APP-01",
                domain="3. Application Security (APP)",
                title="Test",
                objective="Test",
                description="Test",
                remediation="Test",
                applicable_providers=["GCP", "UNKNOWN_PROVIDER_XYZ"]
            )

    def test_invalid_evidence_types_raise_validation_error(self):
        """3. Invalid evidence types MUST raise ValidationError with no fallback to CONFIGURATION."""
        with self.assertRaises(ValidationError):
            Evidence(
                source=FindingSource.GCP_SCC,
                resource="projects/123",
                evidence_type="UNSUPPORTED_SCREENSHOT_TYPE"
            )

        with self.assertRaises(ValidationError):
            EvidenceRequirement(
                requirement_id="EVD-REQ-01",
                evidence_type="TELEMETRY_DUMP_INVALID",
                description="Test"
            )

    def test_live_finding_without_evidence_fails(self):
        """4. A finding with execution_mode=LIVE and zero evidence MUST fail with ValidationError."""
        with self.assertRaises(ValidationError):
            SecurityFinding(
                finding_id="FIND-LIVE-01",
                source=FindingSource.GCP_SCC,
                description="Production finding with missing evidence",
                execution_mode=ExecutionMode.LIVE,
                evidence=[]
            )

    def test_live_finding_with_simulation_evidence_fails(self):
        """5. A finding with execution_mode=LIVE containing solely simulation evidence MUST fail."""
        sim_ev = Evidence(
            source=FindingSource.AI_RED_TEAM,
            resource="test-model",
            execution_mode=ExecutionMode.SIMULATION,
            status=EvidenceStatus.SIMULATED,
            sanitized_content="Simulated jailbreak attack"
        )
        with self.assertRaises(ValidationError):
            SecurityFinding(
                finding_id="FIND-LIVE-02",
                source=FindingSource.AI_RED_TEAM,
                description="Production finding falsely claiming simulation evidence",
                execution_mode=ExecutionMode.LIVE,
                evidence=[sim_ev]
            )

    def test_simulation_with_verified_evidence_fails(self):
        """6. SIMULATION, FIXTURE, and MOCK evidence MUST NOT be VERIFIED (reject invalid combination)."""
        with self.assertRaises(ValidationError):
            Evidence(
                source=FindingSource.AI_RED_TEAM,
                resource="test-model",
                execution_mode=ExecutionMode.SIMULATION,
                status=EvidenceStatus.VERIFIED,
                sanitized_content="Mock response"
            )

        with self.assertRaises(ValidationError):
            Evidence(
                source=FindingSource.MANUAL_AUDIT,
                resource="test-model",
                execution_mode=ExecutionMode.FIXTURE,
                status=EvidenceStatus.VERIFIED,
                sanitized_content="Fixture response"
            )

    def test_duplicate_controls_in_raw_catalog_detected_before_indexing(self):
        """7. Duplicate control IDs in raw catalog JSON MUST be detected and rejected before indexing."""
        import tempfile
        import json

        raw_sample = [
            {
                "control_id": "DAT-01",
                "domain": "1. Data Security, Lineage & Privacy (DAT)",
                "title": "T1", "objective": "O1", "description": "D1", "remediation": "R1",
                "test_definitions": [{"test_id": "data.1", "name": "N"}],
                "evidence_requirements": [{"requirement_id": "EVD-1"}],
                "framework_mappings": []
            },
            {
                "control_id": "DAT-01",  # DUPLICATE!
                "domain": "1. Data Security, Lineage & Privacy (DAT)",
                "title": "T2", "objective": "O2", "description": "D2", "remediation": "R2",
                "test_definitions": [{"test_id": "data.2", "name": "N"}],
                "evidence_requirements": [{"requirement_id": "EVD-2"}],
                "framework_mappings": []
            }
        ]

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(raw_sample, f)
            temp_path = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                ControlContractRegistry(catalog_path=temp_path)
            self.assertIn("Duplicate control ID detected", str(ctx.exception))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_missing_controls_detected(self):
        """8. Missing required control IDs in catalog MUST raise ValueError."""
        import tempfile
        import json

        # Only 1 control in catalog
        raw_sample = [
            {
                "control_id": "DAT-01",
                "domain": "1. Data Security, Lineage & Privacy (DAT)",
                "title": "T1", "objective": "O1", "description": "D1", "remediation": "R1",
                "test_definitions": [{"test_id": "data.1", "name": "N"}],
                "evidence_requirements": [{"requirement_id": "EVD-1"}],
                "framework_mappings": []
            }
        ]

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(raw_sample, f)
            temp_path = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                ControlContractRegistry(catalog_path=temp_path)
            self.assertIn("Invalid total control count", str(ctx.exception))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_invalid_control_id_format(self):
        """9. Invalid control ID format outside ^(DAT|MOD|APP|INF|ASR|GOV)-\\d{2}$ MUST fail."""
        contract = SecurityControlContract(
            control_id="INVALID-01",
            domain="1. Data Security, Lineage & Privacy (DAT)",
            title="T", objective="O", description="D", remediation="R",
            test_definitions=[TestDefinition(test_id="test.1", name="N")],
            evidence_requirements=[EvidenceRequirement(requirement_id="EVD-1", description="D")]
        )
        fake_registry = ControlContractRegistry()
        fake_registry._contracts["INVALID-01"] = contract
        validator = ControlContractValidator(registry=fake_registry)
        is_valid, errors = validator.validate()
        self.assertFalse(is_valid)
        self.assertTrue(any("Invalid ID format" in e for e in errors))

    def test_invalid_domain_prefix_consistency(self):
        """10. Inconsistency between ID prefix and domain name MUST fail validation."""
        contract = SecurityControlContract(
            control_id="DAT-01",
            domain="4. Infrastructure, VPC Isolation & Cryptography (INF)",  # MISMATCH!
            title="T", objective="O", description="D", remediation="R",
            test_definitions=[TestDefinition(test_id="test.1", name="N")],
            evidence_requirements=[EvidenceRequirement(requirement_id="EVD-1", description="D")]
        )
        fake_registry = ControlContractRegistry()
        fake_registry._contracts["DAT-01"] = contract
        validator = ControlContractValidator(registry=fake_registry)
        is_valid, errors = validator.validate()
        self.assertFalse(is_valid)
        self.assertTrue(any("Domain/prefix inconsistency" in e for e in errors))

    def test_duplicate_tests_within_control(self):
        """11. Duplicate test IDs within the same control contract MUST fail validation."""
        contract = SecurityControlContract(
            control_id="APP-01",
            domain="3. Application Security & Runtime Prompt Defense (APP)",
            title="T", objective="O", description="D", remediation="R",
            test_definitions=[
                TestDefinition(test_id="runtime.prompt_injection", name="T1"),
                TestDefinition(test_id="runtime.prompt_injection", name="T2"),  # DUPLICATE!
            ],
            evidence_requirements=[EvidenceRequirement(requirement_id="EVD-1", description="D")]
        )
        fake_registry = ControlContractRegistry()
        fake_registry._contracts["APP-01"] = contract
        validator = ControlContractValidator(registry=fake_registry)
        is_valid, errors = validator.validate()
        self.assertFalse(is_valid)
        self.assertTrue(any("Duplicate test ID" in e for e in errors))

    def test_duplicate_evidence_requirements_within_control(self):
        """12. Duplicate evidence requirement IDs within the same control MUST fail validation."""
        contract = SecurityControlContract(
            control_id="APP-01",
            domain="3. Application Security & Runtime Prompt Defense (APP)",
            title="T", objective="O", description="D", remediation="R",
            test_definitions=[TestDefinition(test_id="runtime.prompt_injection", name="T1")],
            evidence_requirements=[
                EvidenceRequirement(requirement_id="EVD-REQ-APP-01-01", description="D1"),
                EvidenceRequirement(requirement_id="EVD-REQ-APP-01-01", description="D2"),  # DUPLICATE!
            ]
        )
        fake_registry = ControlContractRegistry()
        fake_registry._contracts["APP-01"] = contract
        validator = ControlContractValidator(registry=fake_registry)
        is_valid, errors = validator.validate()
        self.assertFalse(is_valid)
        self.assertTrue(any("Duplicate evidence requirement ID" in e for e in errors))

    def test_strict_mapping_precedence(self):
        """13. ControlMapper MUST enforce exact 5-level precedence."""
        mapper = ControlMapper()
        asset = AIAsset(name="test-asset", resource_uri="projects/test/models/test-asset")

        # Level 1: EXPLICIT_MAPPING takes precedence over metadata, type, attack technique, keyword
        f1 = SecurityFinding(
            title="Title 1",
            asset=asset,
            source=FindingSource.GCP_SCC,
            description="cve-2026-2244 token leakage in startup log roles/owner",
            metadata={"explicit_control_id": "INF-02", "control_id": "INF-03"}
        )
        mapper.map_controls(f1)
        self.assertEqual(f1.primary_control_id, "INF-02")
        self.assertEqual(f1.metadata.get("mapping_level"), MappingPrecedence.EXPLICIT_MAPPING)

        # Level 2: CONTROL_METADATA takes precedence over deterministic type and keywords
        f2 = SecurityFinding(
            title="Title 2",
            asset=asset,
            source=FindingSource.GCP_SCC,
            description="cve-2026-2244 token leakage",
            metadata={"control_id": "INF-04"}
        )
        mapper.map_controls(f2)
        self.assertEqual(f2.primary_control_id, "INF-04")
        self.assertEqual(f2.metadata.get("mapping_level"), MappingPrecedence.CONTROL_METADATA)

        # Level 3: DETERMINISTIC_FINDING_TYPE takes precedence over attack technique and keywords
        f3 = SecurityFinding(
            title="Title 3",
            asset=asset,
            source=FindingSource.SHADOW_AI_HUNTER,
            description="cve-2026-2244 token leakage in startup log"
        )
        mapper.map_controls(f3)
        self.assertEqual(f3.primary_control_id, "INF-01")
        self.assertEqual(f3.metadata.get("mapping_level"), MappingPrecedence.DETERMINISTIC_FINDING_TYPE)

        # Level 4: ATTACK_TECHNIQUE takes precedence over keyword heuristics
        f4 = SecurityFinding(
            title="Title 4",
            asset=asset,
            source=FindingSource.AI_RED_TEAM,
            description="Unidentified anomalous output",
        )
        f4.add_attack_technique("AML.T0054", "LLM Jailbreak")
        mapper.map_controls(f4)
        self.assertEqual(f4.primary_control_id, "APP-01")
        self.assertEqual(f4.metadata.get("mapping_level"), MappingPrecedence.ATTACK_TECHNIQUE)

        # Level 5: KEYWORD_FALLBACK when no higher rules match
        f5 = SecurityFinding(
            title="Title 5",
            asset=asset,
            source=FindingSource.MULTI_CLOUD_SCANNER,
            description="general service account permissions roles/editor detected"
        )
        mapper.map_controls(f5)
        self.assertEqual(f5.primary_control_id, "INF-03")
        self.assertEqual(f5.metadata.get("mapping_level"), MappingPrecedence.KEYWORD_FALLBACK)

    def test_canonical_pipeline_execution_order(self):
        """14. Pipeline MUST execute in exact order: Normalize -> Evidence Validation -> Deduplication -> Control Mapping -> Severity -> Canonical Finding."""
        correlator = DeterministicCorrelator(project_id="test-pipeline")
        correlator.add_raw_finding(
            source="GCP Security Command Center (SCC)",
            category="SCC Finding",
            severity="HIGH",
            resource="projects/test",
            description="cve-2026-2244 token leakage"
        )
        findings = correlator.execute_pipeline()
        self.assertEqual(
            correlator.execution_order,
            [
                "NORMALIZE",
                "EVIDENCE_VALIDATION",
                "DEDUPLICATION",
                "CONTROL_MAPPING",
                "SEVERITY",
                "CANONICAL_FINDING"
            ]
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata.get("pipeline_stages"), correlator.execution_order)

    def test_questionnaire_mismatch_fails(self):
        """15. Questionnaire mismatch with canonical contracts catalog MUST raise ValueError."""
        import tempfile
        import json

        # Fake questionnaire with mismatched controls
        fake_q = {
            "domains": {
                "1. Data Security": [
                    {"id": "DAT-99", "question": "Fake question"}  # Mismatched ID!
                ]
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(fake_q, f)
            temp_path = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                QuestionnaireHandler.verify_canonical_consistency(questions_path=temp_path)
            self.assertIn("Questionnaire integrity violation", str(ctx.exception))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_deterministic_evidence_hashing(self):
        """16. Identical evidence content MUST yield identical SHA-256 hashes, and mutations break verification."""
        ev1 = Evidence(
            source=FindingSource.GCP_SCC,
            resource="projects/p1/instances/i1",
            sanitized_content="Configuration setting: vpc_sc_enabled=true"
        )
        ev2 = Evidence(
            source=FindingSource.GCP_SCC,
            resource="projects/p1/instances/i1",
            sanitized_content="Configuration setting: vpc_sc_enabled=true"
        )
        self.assertEqual(ev1.content_hash, ev2.content_hash)
        self.assertTrue(ev1.verify_integrity())

        # Tampering with content breaks integrity
        ev1.sanitized_content = "Configuration setting: vpc_sc_enabled=false"
        self.assertFalse(ev1.verify_integrity())

    def test_implementation_status_distinction(self):
        """17. Test definitions MUST distinguish IMPLEMENTED, PARTIAL, DECLARED_ONLY, NOT_IMPLEMENTED."""
        registry = ControlContractRegistry()
        app_01 = registry.get_contract("APP-01")
        self.assertIsNotNone(app_01)
        # ModelArmorGuard & PromptSAST are active automated engines
        self.assertEqual(app_01.test_definitions[0].implementation_status, ImplementationStatus.IMPLEMENTED)

        gov_01 = registry.get_contract("GOV-01")
        self.assertIsNotNone(gov_01)
        # Manual governance review is declared only
        self.assertEqual(gov_01.test_definitions[0].implementation_status, ImplementationStatus.DECLARED_ONLY)

        gov_03 = registry.get_contract("GOV-03")
        self.assertIsNotNone(gov_03)
        # Semi-automated risk assessment is partial
        self.assertEqual(gov_03.test_definitions[0].implementation_status, ImplementationStatus.PARTIAL)


if __name__ == "__main__":
    unittest.main()
