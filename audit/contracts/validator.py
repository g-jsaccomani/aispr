# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Control Contract Engine - Validator
Strict validation engine that enforces integrity across all 104 Security Control Contracts.
Fails with non-zero exit code if any orphan, malformed, or unverified regulatory mapping is found.
"""

from typing import List, Tuple, Dict, Set
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

        # 4. Field Integrity per Control
        for c in contracts:
            cid = c.control_id

            # Required string fields
            if not c.title or not c.title.strip():
                errors.append(f"[{cid}] Missing mandatory field 'title'.")
            if not c.objective or not c.objective.strip():
                errors.append(f"[{cid}] Missing mandatory field 'objective'.")
            if not c.description or not c.description.strip():
                errors.append(f"[{cid}] Missing mandatory field 'description'.")
            if not c.remediation or not c.remediation.strip():
                errors.append(f"[{cid}] Missing mandatory field 'remediation'.")

            # Valid providers
            if not c.applicable_providers:
                errors.append(f"[{cid}] applicable_providers cannot be empty.")
            for p in c.applicable_providers:
                if not isinstance(p, CloudProvider):
                    try:
                        CloudProvider(p)
                    except ValueError:
                        errors.append(f"[{cid}] Invalid cloud provider: '{p}'.")

            # Valid test definitions
            if not c.test_definitions:
                errors.append(f"[{cid}] Must define at least one TestDefinition.")
            for t in c.test_definitions:
                if not t.test_id or "." not in t.test_id:
                    errors.append(f"[{cid}] Test definition '{t.test_id}' must follow dot-notation '<category>.<test>'.")
                if not t.name:
                    errors.append(f"[{cid}] Test definition '{t.test_id}' is missing a name.")

            # Valid evidence requirements
            if not c.evidence_requirements:
                errors.append(f"[{cid}] Must define at least one EvidenceRequirement.")
            for req in c.evidence_requirements:
                if not req.requirement_id:
                    errors.append(f"[{cid}] EvidenceRequirement missing requirement_id.")
                if not isinstance(req.evidence_type, EvidenceType):
                    try:
                        EvidenceType(req.evidence_type)
                    except ValueError:
                        errors.append(f"[{cid}] Invalid EvidenceType in requirement: '{req.evidence_type}'.")

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

        return (len(errors) == 0, errors)

    def validate_or_raise(self):
        """Executes validation and raises ValueError with all diagnostic messages on failure."""
        is_valid, errors = self.validate()
        if not is_valid:
            error_report = "\n  • " + "\n  • ".join(errors[:20])
            if len(errors) > 20:
                error_report += f"\n  ... and {len(errors) - 20} more error(s)."
            raise ValueError(f"ControlContractValidator failed with {len(errors)} error(s):{error_report}")
