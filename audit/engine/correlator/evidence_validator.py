# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Findings Correlator - Step 5: Evidence Validator
Validates evidence quality, detects tampering via SHA-256, degrades confidence
when evidence is missing, and ensures absence of evidence is never converted into PASS.
"""

from typing import List
from domain.models import SecurityFinding, Evidence
from domain.enums import (
    EvidenceStatus,
    ExecutionMode,
    ConfidenceLevel,
    FindingStatus,
    EvidenceType,
    FindingSource,
)


class EvidenceValidator:
    """
    Ensures every finding possesses verifiable, tamper-free evidence.
    Degrades confidence on unverified assertions and preserves audit integrity.
    """

    def validate_finding_evidence(self, finding: SecurityFinding) -> SecurityFinding:
        """
        Validates empirical evidence quality for a single finding:
        1. Checks for missing or empty evidence and degrades confidence accordingly.
        2. Validates cryptographic SHA-256 hash integrity.
        3. Enforces epistemological rules (Live vs Simulation vs Inferred).
        4. Never converts absence of evidence into a PASS verdict.
        """
        # Case 1: Finding has zero evidence attached
        if not finding.evidence:
            synthetic_ev = Evidence(
                source=FindingSource.MANUAL_AUDIT,
                provider=finding.provider,
                resource=finding.asset.resource_uri,
                evidence_type=EvidenceType.MANUAL_ASSERTION,
                status=EvidenceStatus.UNVERIFIED,
                execution_mode=ExecutionMode.SIMULATION,
                confidence=0.25,
                sanitized_content="Finding registered without attached empirical evidence."
            )
            finding.evidence.append(synthetic_ev)
            finding.confidence = ConfidenceLevel.LOW
            finding.status = FindingStatus.OPEN
            finding.metadata["evidence_health"] = "MISSING_EVIDENCE"
            finding.metadata["evidence_note"] = "Confidence reduced due to complete absence of empirical telemetry."
            return finding

        # Case 2: Validate existing evidence items
        valid_items = []
        has_tampering = False

        for ev in finding.evidence:
            # Check content presence
            if not ev.sanitized_content or ev.sanitized_content.strip() == "":
                ev.status = EvidenceStatus.UNVERIFIED
                ev.confidence = min(ev.confidence, 0.40)
                finding.metadata["evidence_health"] = "INCOMPLETE_EVIDENCE"

            # Check cryptographic SHA-256 integrity
            if not ev.verify_integrity():
                has_tampering = True
                ev.confidence = 0.0
                finding.metadata["tampering_detected"] = True
                finding.metadata["tampering_evidence_id"] = ev.evidence_id

            valid_items.append(ev)

        finding.evidence = valid_items

        if has_tampering:
            finding.confidence = ConfidenceLevel.SUSPECTED
            finding.metadata["audit_warning"] = "Cryptographic integrity failure: Evidence hash does not match content."

        # Case 3: Enforce epistemological invariants
        finding.validate_epistemology()

        return finding

    def validate_all(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Validates all findings in a collection."""
        return [self.validate_finding_evidence(f) for f in findings]
