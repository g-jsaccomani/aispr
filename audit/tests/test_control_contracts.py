# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AISPR Phase 4: Control Contract Engine
Exhaustively validates:
1. All 104 controls presence
2. Unique IDs
3. Mandatory fields
4. Valid cloud providers
5. Valid test definitions
6. Valid evidence requirements
7. No orphan controls
8. No invalid framework mappings
9. Validator failure on inconsistencies
10. Coverage matrix generation
"""

import os
import sys
import unittest
import subprocess

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
audit_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(audit_dir)
for p in [root_dir, audit_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from domain.enums import (
    CloudProvider,
    AssessmentType,
    AutomationLevel,
    FindingSeverity,
    EvidenceType,
    MappingConfidence,
    FrameworkName,
)
from domain.models import SecurityControlContract, RegulatoryMapping
from audit.contracts.registry import ControlContractRegistry
from audit.contracts.validator import ControlContractValidator


class TestControlContractEngine(unittest.TestCase):

    def setUp(self):
        self.registry = ControlContractRegistry()
        self.validator = ControlContractValidator(registry=self.registry)
        self.contracts = self.registry.list_contracts()

    def test_total_count_is_exact_104(self):
        """1. Must contain exactly 104 versioned Security Control Contracts."""
        self.assertEqual(len(self.contracts), 104, f"Expected 104 controls, found {len(self.contracts)}")

    def test_unique_control_ids(self):
        """2. All control IDs must be completely unique."""
        ids = [c.control_id for c in self.contracts]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate control IDs detected in catalog!")

    def test_no_orphan_controls(self):
        """3. No orphan controls: every ID must belong to the exact canonical set of 104 IDs."""
        expected_ids = (
            {f"DAT-{i:02d}" for i in range(1, 20)} |
            {f"MOD-{i:02d}" for i in range(1, 20)} |
            {f"APP-{i:02d}" for i in range(1, 20)} |
            {f"INF-{i:02d}" for i in range(1, 20)} |
            {f"ASR-{i:02d}" for i in range(1, 16)} |
            {f"GOV-{i:02d}" for i in range(1, 14)}
        )
        actual_ids = {c.control_id for c in self.contracts}
        self.assertEqual(actual_ids, expected_ids, "Catalog control IDs do not match the canonical 104 taxonomy!")

    def test_mandatory_fields_present_and_non_empty(self):
        """4. Every control contract must contain non-empty mandatory fields."""
        for c in self.contracts:
            cid = c.control_id
            self.assertTrue(bool(c.title and c.title.strip()), f"[{cid}] title is empty")
            self.assertTrue(bool(c.objective and c.objective.strip()), f"[{cid}] objective is empty")
            self.assertTrue(bool(c.description and c.description.strip()), f"[{cid}] description is empty")
            self.assertTrue(bool(c.remediation and c.remediation.strip()), f"[{cid}] remediation is empty")
            self.assertIn(c.severity, [s.value for s in FindingSeverity])
            self.assertIn(c.assessment_type, [a.value for a in AssessmentType])
            self.assertIn(c.automation_level, [a.value for a in AutomationLevel])
            self.assertTrue(len(c.references) > 0, f"[{cid}] references list is empty")

    def test_valid_cloud_providers(self):
        """5. Applicable cloud providers must be valid CloudProvider enums and non-empty."""
        for c in self.contracts:
            self.assertGreater(len(c.applicable_providers), 0, f"[{c.control_id}] applicable_providers is empty")
            for p in c.applicable_providers:
                self.assertIn(p, [cp.value for cp in CloudProvider])

    def test_valid_test_definitions(self):
        """6. Every control must define at least one valid dot-notated TestDefinition."""
        for c in self.contracts:
            self.assertGreater(len(c.test_definitions), 0, f"[{c.control_id}] has no test definitions")
            for t in c.test_definitions:
                self.assertIn(".", t.test_id, f"[{c.control_id}] test_id '{t.test_id}' must follow dot notation")
                self.assertTrue(bool(t.name and t.name.strip()))
                self.assertIn(t.execution_type, [a.value for a in AssessmentType])

    def test_valid_evidence_requirements(self):
        """7. Every control must define at least one valid EvidenceRequirement."""
        for c in self.contracts:
            self.assertGreater(len(c.evidence_requirements), 0, f"[{c.control_id}] has no evidence requirements")
            for req in c.evidence_requirements:
                self.assertTrue(req.requirement_id.startswith("EVD-REQ-"))
                self.assertIn(req.evidence_type, [e.value for e in EvidenceType])
                self.assertTrue(bool(req.description and req.description.strip()))

    def test_rigorous_framework_mappings_and_no_invented_claims(self):
        """8. Framework mappings must model all 7 frameworks; unverified mappings must be NOT_MAPPED."""
        supported_frameworks = {
            "Google SAIF",
            "NIST AI RMF 1.0",
            "ISO/IEC 42001",
            "MITRE ATLAS",
            "EU AI Act",
            "OWASP LLM",
            "OWASP Agentic Security"
        }
        for c in self.contracts:
            mapped_fws = {m.framework for m in c.framework_mappings}
            self.assertEqual(mapped_fws, supported_frameworks, f"[{c.control_id}] Framework model is incomplete")

            for m in c.framework_mappings:
                if m.reference == "NOT_MAPPED":
                    self.assertEqual(
                        m.mapping_confidence,
                        MappingConfidence.NOT_MAPPED,
                        f"[{c.control_id}] Framework '{m.framework}' reference is NOT_MAPPED but confidence is '{m.mapping_confidence}'"
                    )
                else:
                    self.assertTrue(bool(m.reference and m.reference.strip()))
                    self.assertNotEqual(
                        m.mapping_confidence,
                        MappingConfidence.NOT_MAPPED,
                        f"[{c.control_id}] Framework '{m.framework}' has reference '{m.reference}' but confidence is NOT_MAPPED"
                    )

    def test_validator_succeeds_on_canonical_catalog(self):
        """9. ControlContractValidator must succeed with zero errors on the canonical catalog."""
        is_valid, errors = self.validator.validate()
        self.assertTrue(is_valid, f"Validation failed with errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_validator_fails_on_injected_inconsistency(self):
        """10. ControlContractValidator must detect and fail on inconsistent contracts."""
        # Mutate contract to have an invalid framework mapping
        bad_contract = self.contracts[0].model_copy(deep=True)
        bad_contract.framework_mappings.append(
            RegulatoryMapping(
                framework="Invented Framework XYZ",
                reference="Clause 99",
                mapping_confidence=MappingConfidence.HIGH
            )
        )

        fake_registry = ControlContractRegistry()
        fake_registry._contracts[bad_contract.control_id] = bad_contract
        test_validator = ControlContractValidator(registry=fake_registry)

        is_valid, errors = test_validator.validate()
        self.assertFalse(is_valid)
        self.assertTrue(any("Invalid or unsupported framework" in e for e in errors))

        with self.assertRaises(ValueError):
            test_validator.validate_or_raise()

    def test_cli_controls_validate_execution(self):
        """11. CLI command './aispr controls validate' must execute and exit with 0."""
        cli_script = os.path.join(root_dir, "scripts", "cli", "aispr_cli.py")
        result = subprocess.run(
            [sys.executable, cli_script, "controls", "validate"],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("VALIDATION PASSED", result.stdout)
        self.assertIn("104 / 104", result.stdout)

    def test_coverage_matrix_generation(self):
        """12. Registry must generate a non-empty coverage matrix with 104 rows."""
        matrix = self.registry.get_coverage_matrix()
        self.assertEqual(len(matrix), 104)
        md_text = self.registry.generate_matrix_markdown()
        self.assertIn("| Control | Automation | Evidence | Frameworks | Providers | Tests | Coverage |", md_text)
        self.assertIn("`APP-01`", md_text)
        self.assertIn("`INF-01`", md_text)
        self.assertIn("`GOV-01`", md_text)


if __name__ == "__main__":
    unittest.main()
