# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Control Contract Engine - Validator
Strict validation engine that enforces integrity across all 104 Security Control Contracts.
Fails with non-zero exit code if any orphan, malformed, or unverified regulatory mapping is found.
"""

from typing import List, Tuple, Dict, Set, Optional
from domain.enums import CloudProvider, AssessmentType, AutomationLevel, FindingSeverity, EvidenceType, MappingConfidence, FrameworkName
from domain.models import SecurityControlContract
from audit.contracts.registry import ControlContractRegistry


class ControlContractValidator:
    """
    Validates all 104 Security Control Contracts against rigorous integrity specifications.
    """

    SUPPORTED_FRAMEWORKS: Set[str] = {
        "Google SAIF",
        "NIST AI RMF 1.0",
        "ISO/IEC 42001",
        "MITRE ATLAS",
        "EU AI Act",
        "OWASP LLM",
        "OWASP Agentic Security"
    }

    # Expected 104 control IDs across the 6 domains
    EXPECTED_IDS: Set[str] = (
        {f"DAT-{i:02d}" for i in range(1, 20)} |
        {f"MOD-{i:02d}" for i in range(1, 20)} |
        {f"APP-{i:02d}" for i in range(1, 20)} |
        {f"INF-{i:02d}" for i in range(1, 20)} |
        {f"ASR-{i:02d}" for i in range(1, 16)} |
        {f"GOV-{i:02d}" for i in range(1, 14)}
    )

    def __init__(self, registry: Optional[ControlContractRegistry] = None):
        self.registry = registry or ControlContractRegistry()

    def validate(self) -> Tuple[bool, List[str]]:
        """
        Executes exhaustive validation across all 104 controls.
        Returns:
            (is_valid: bool, errors: List[str])
        """
        errors: List[str] = []
        contracts = self.registry.list_contracts()

        # 1. Total Control Count
        if len(contracts) != 104:
            errors.append(f"Invalid total control count: expected exactly 104, found {len(contracts)}.")

        # 2. Unique Control IDs
        seen_ids: Set[str] = set()
        for c in contracts:
            if c.control_id in seen_ids:
                errors.append(f"Duplicate control ID detected: '{c.control_id}'.")
            seen_ids.add(c.control_id)

        # 3. No Orphan Controls
        orphan_ids = seen_ids - self.EXPECTED_IDS
        if orphan_ids:
            errors.append(f"Orphan control IDs detected outside taxonomy: {sorted(list(orphan_ids))}.")

        missing_ids = self.EXPECTED_IDS - seen_ids
        if missing_ids:
            errors.append(f"Missing expected control IDs: {sorted(list(missing_ids))}.")

        # 4. Field and Schema Integrity per Control
        for c in contracts:
            cid = c.control_id

            # ID format validation
            import re
            if not re.match(r"^(DAT|MOD|APP|INF|ASR|GOV)-\d{2}$", cid):
                errors.append(f"[{cid}] Invalid ID format. Must match ^(DAT|MOD|APP|INF|ASR|GOV)-\\d{{2}}$")

            # Domain/prefix consistency
            prefix = cid.split("-")[0] if "-" in cid else ""
            if f"({prefix})" not in c.domain and prefix not in c.domain:
                errors.append(f"[{cid}] Domain/prefix inconsistency: prefix '{prefix}' does not match domain '{c.domain}'.")

            # Required string fields
            if not c.title or not c.title.strip():
                errors.append(f"[{cid}] Missing mandatory field 'title'.")
            if not c.objective or not c.objective.strip():
                errors.append(f"[{cid}] Missing mandatory field 'objective'.")
            if not c.description or not c.description.strip():
                errors.append(f"[{cid}] Missing mandatory field 'description'.")
            if not c.remediation or not c.remediation.strip():
                errors.append(f"[{cid}] Missing mandatory field 'remediation'.")

            # Valid severity
            try:
                FindingSeverity(c.severity)
            except (ValueError, TypeError):
                errors.append(f"[{cid}] Invalid severity: '{c.severity}'.")

            # Valid assessment type
            try:
                AssessmentType(c.assessment_type)
            except (ValueError, TypeError):
                errors.append(f"[{cid}] Invalid assessment_type: '{c.assessment_type}'.")

            # Valid automation level
            try:
                AutomationLevel(c.automation_level)
            except (ValueError, TypeError):
                errors.append(f"[{cid}] Invalid automation_level: '{c.automation_level}'.")

            # Valid providers
            if not c.applicable_providers:
                errors.append(f"[{cid}] applicable_providers cannot be empty.")
            for p in c.applicable_providers:
                try:
                    CloudProvider(p)
                except (ValueError, TypeError):
                    errors.append(f"[{cid}] Invalid cloud provider: '{p}'.")

            # Valid test definitions & duplicate test check
            if not c.test_definitions:
                errors.append(f"[{cid}] Must define at least one TestDefinition.")
            seen_test_ids: Set[str] = set()
            for t in c.test_definitions:
                if not t.test_id or "." not in t.test_id:
                    errors.append(f"[{cid}] Test definition '{t.test_id}' must follow dot-notation '<category>.<test>'.")
                if not t.name:
                    errors.append(f"[{cid}] Test definition '{t.test_id}' is missing a name.")
                if t.test_id in seen_test_ids:
                    errors.append(f"[{cid}] Duplicate test ID '{t.test_id}' within control contract.")
                seen_test_ids.add(t.test_id)

            # Valid evidence requirements & duplicate requirement check
            if not c.evidence_requirements:
                errors.append(f"[{cid}] Must define at least one EvidenceRequirement.")
            seen_req_ids: Set[str] = set()
            for req in c.evidence_requirements:
                if not req.requirement_id:
                    errors.append(f"[{cid}] EvidenceRequirement missing requirement_id.")
                try:
                    EvidenceType(req.evidence_type)
                except (ValueError, TypeError):
                    errors.append(f"[{cid}] Invalid EvidenceType in requirement: '{req.evidence_type}'.")
                if req.requirement_id in seen_req_ids:
                    errors.append(f"[{cid}] Duplicate evidence requirement ID '{req.requirement_id}' within control contract.")
                seen_req_ids.add(req.requirement_id)

            # Framework mappings validation
            fw_names_in_contract: Set[str] = set()
            for m in c.framework_mappings:
                if m.framework not in self.SUPPORTED_FRAMEWORKS:
                    errors.append(f"[{cid}] Invalid or unsupported framework: '{m.framework}'.")
                fw_names_in_contract.add(m.framework)

                # Strict NOT_MAPPED rules: No invented regulatory claims
                if m.reference == "NOT_MAPPED":
                    if m.mapping_confidence != MappingConfidence.NOT_MAPPED:
                        errors.append(f"[{cid}] Framework '{m.framework}' reference is NOT_MAPPED but confidence is '{m.mapping_confidence}'.")
                else:
                    if not m.reference.strip():
                        errors.append(f"[{cid}] Framework '{m.framework}' has empty reference.")
                    if m.mapping_confidence == MappingConfidence.NOT_MAPPED:
                        errors.append(f"[{cid}] Framework '{m.framework}' has reference '{m.reference}' but confidence is NOT_MAPPED.")

            # Ensure all 7 frameworks are explicitly modeled (either mapped or NOT_MAPPED)
            missing_fws = self.SUPPORTED_FRAMEWORKS - fw_names_in_contract
            if missing_fws:
                errors.append(f"[{cid}] Incomplete framework model; missing: {sorted(list(missing_fws))}.")

        # 5. Questionnaire Consistency Check (Task 9)
        try:
            from audit.questionnaire.handler import QuestionnaireHandler
            QuestionnaireHandler.verify_canonical_consistency(contracts_catalog_path=self.registry.catalog_path)
        except Exception as q_err:
            errors.append(f"Questionnaire canonical consistency failure: {q_err}")

        return (len(errors) == 0, errors)

    def validate_or_raise(self):
        """Executes validation and raises ValueError with all diagnostic messages on failure."""
        is_valid, errors = self.validate()
        if not is_valid:
            error_report = "\n  • " + "\n  • ".join(errors[:20])
            if len(errors) > 20:
                error_report += f"\n  ... and {len(errors) - 20} more error(s)."
            raise ValueError(f"ControlContractValidator failed with {len(errors)} error(s):{error_report}")
