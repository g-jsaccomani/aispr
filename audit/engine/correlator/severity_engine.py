# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Findings Correlator - Step 4: Severity Engine
Calculates finding severities and resolves conflicting reports across multi-cloud sources.
Explicitly decoupled from GRC compliance scoring.
"""

from typing import List, Union
from domain.enums import FindingSeverity
from domain.models import SecurityFinding


class SeverityEngine:
    """
    Independent engine for evaluating finding severities, blast radiuses, and resolving
    conflicting severity ratings from multiple heterogeneous scanners.
    """

    SEVERITY_RANKS = {
        FindingSeverity.CRITICAL: 4,
        FindingSeverity.HIGH: 3,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 1,
        FindingSeverity.INFO: 0
    }

    RANK_TO_SEVERITY = {
        4: FindingSeverity.CRITICAL,
        3: FindingSeverity.HIGH,
        2: FindingSeverity.MEDIUM,
        1: FindingSeverity.LOW,
        0: FindingSeverity.INFO
    }

    def resolve_conflicting_severities(self, severities: List[Union[str, FindingSeverity]]) -> FindingSeverity:
        """
        Deterministically resolves conflicting severities from multiple sources,
        selecting the most conservative (highest risk) severity tier.
        """
        if not severities:
            return FindingSeverity.MEDIUM

        max_rank = -1
        for s in severities:
            norm_s = FindingSeverity(str(s).upper()) if isinstance(s, str) else s
            rank = self.SEVERITY_RANKS.get(norm_s, 1)
            if rank > max_rank:
                max_rank = rank

        return self.RANK_TO_SEVERITY.get(max_rank, FindingSeverity.MEDIUM)

    def evaluate_finding_severity(self, finding: SecurityFinding) -> SecurityFinding:
        """
        Re-evaluates finding severity considering blast radius, public exposure, and active CVEs.
        """
        combined = f"{finding.title} {finding.description}".lower()

        # 1. Critical Escalation: Active RCE, OAuth token leakage, or Critical CVEs
        if any(term in combined for term in ("cve-2026-2244", "token exposure", "remote code execution", "rce", "dump database")):
            finding.severity = FindingSeverity.CRITICAL
            return finding

        # 2. High Escalation: Public exposure without auth, unmasked financial PII, raw prompt injection
        if any(term in combined for term in ("public ip", "publicly accessible", "0.0.0.0/0", "unprotected llm", "credit card", "ssn")):
            if self.SEVERITY_RANKS.get(finding.severity, 0) < self.SEVERITY_RANKS[FindingSeverity.HIGH]:
                finding.severity = FindingSeverity.HIGH
                finding.metadata["severity_escalated"] = True
                finding.metadata["escalation_reason"] = "Public exposure or sensitive data blast radius"
            return finding

        return finding

    @staticmethod
    def suggest_control_status(severity: FindingSeverity) -> str:
        """
        Determines suggested questionnaire evaluation status from finding severity.
        Does not mutate the finding; used solely for auditor pre-population.
        """
        if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
            return "N"  # Failed control
        elif severity == FindingSeverity.MEDIUM:
            return "P"  # Partial deviation
        return "Y"      # Low or informational
