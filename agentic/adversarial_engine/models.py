# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 8: Controlled Adversarial Validation Engine - Canonical Models.
Enforces:
  - Strict MITRE ATLAS attack taxonomy mapping
  - 4-way outcome separation: ATTACK_ATTEMPTED, ATTACK_BLOCKED, ATTACK_SUCCEEDED, INCONCLUSIVE
  - Mandatory canonical Evidence with SHA-256 integrity
  - Default execution mode: SIMULATION
"""

from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pydantic import Field, field_validator

from domain.enums import (
    StrEnum,
    ExecutionMode,
    FindingSeverity,
    FindingSource,
    CloudProvider,
    EvidenceType,
    EvidenceStatus,
)
from domain.models.base import AISPRBaseModel, utc_now
from domain.models.evidence import Evidence, compute_sha256
from domain.sanitization import sanitize_evidence_content


class AttackOutcome(StrEnum):
    """
    Standardized 4-way outcome separation for adversarial test execution:
      - ATTACK_ATTEMPTED: Test payload dispatched against target.
      - ATTACK_BLOCKED: Defense successfully intercepted, sanitized, or denied payload.
      - ATTACK_SUCCEEDED: Attack bypassed defenses AND evidence proves successful impact.
      - INCONCLUSIVE: Target response was unverified, ambiguous, or no impact was proven.
    """
    ATTACK_ATTEMPTED = "ATTACK_ATTEMPTED"
    ATTACK_BLOCKED = "ATTACK_BLOCKED"
    ATTACK_SUCCEEDED = "ATTACK_SUCCEEDED"
    INCONCLUSIVE = "INCONCLUSIVE"


class AdversarialCategory(StrEnum):
    """
    The 9 mandated attack scope categories for AI systems.
    """
    PROMPT_INJECTION = "prompt injection"
    INDIRECT_PROMPT_INJECTION = "indirect prompt injection"
    EXCESSIVE_AGENCY = "excessive agency"
    INSECURE_TOOL_USE = "insecure tool use"
    DATA_LEAKAGE = "data leakage"
    RAG_POISONING = "RAG poisoning"
    MODEL_MANIPULATION = "model manipulation"
    UNSAFE_OUTPUT = "unsafe output"
    PRIVILEGE_ESCALATION = "privilege escalation"


class MitreAtlasTechnique(StrEnum):
    """
    Curated MITRE ATLAS (Adversarial Threat Landscape for AI Systems) techniques.
    Technique coverage is ONLY claimed when an implemented test exists.
    """
    DIRECT_PROMPT_INJECTION = "AML.T0051.000: LLM Prompt Injection: Direct"
    INDIRECT_PROMPT_INJECTION = "AML.T0051.001: LLM Prompt Injection: Indirect"
    EXCESSIVE_AGENCY = "AML.T0053: LLM Autonomous Actions (Excessive Agency)"
    INSECURE_TOOL_USE = "AML.T0054: LLM Tool Invocation Exploitation"
    DATA_LEAKAGE = "AML.T0040: ML Intellectual Property Theft & Data Exfiltration"
    RAG_POISONING = "AML.T0055: RAG Knowledge Base & Context Poisoning"
    MODEL_MANIPULATION = "AML.T0043: Adversarial Robustness & Behavior Drift"
    UNSAFE_OUTPUT = "AML.T0056: Unsafe or Toxic Content Generation"
    PRIVILEGE_ESCALATION = "AML.T0057: LLM System Privilege Escalation"


# Explicit mapping from AdversarialCategory to MitreAtlasTechnique
CATEGORY_TO_MITRE_MAP: Dict[AdversarialCategory, MitreAtlasTechnique] = {
    AdversarialCategory.PROMPT_INJECTION: MitreAtlasTechnique.DIRECT_PROMPT_INJECTION,
    AdversarialCategory.INDIRECT_PROMPT_INJECTION: MitreAtlasTechnique.INDIRECT_PROMPT_INJECTION,
    AdversarialCategory.EXCESSIVE_AGENCY: MitreAtlasTechnique.EXCESSIVE_AGENCY,
    AdversarialCategory.INSECURE_TOOL_USE: MitreAtlasTechnique.INSECURE_TOOL_USE,
    AdversarialCategory.DATA_LEAKAGE: MitreAtlasTechnique.DATA_LEAKAGE,
    AdversarialCategory.RAG_POISONING: MitreAtlasTechnique.RAG_POISONING,
    AdversarialCategory.MODEL_MANIPULATION: MitreAtlasTechnique.MODEL_MANIPULATION,
    AdversarialCategory.UNSAFE_OUTPUT: MitreAtlasTechnique.UNSAFE_OUTPUT,
    AdversarialCategory.PRIVILEGE_ESCALATION: MitreAtlasTechnique.PRIVILEGE_ESCALATION,
}


class AdversarialTest(AISPRBaseModel):
    """
    Canonical Adversarial Test specification and execution record.
    Every test MUST contain:
      - attack_id
      - technique
      - target
      - payload
      - expected_defense
      - observed_result
      - evidence
      - execution_mode
      - severity
    """
    attack_id: str
    technique: str
    target: str
    payload: str
    expected_defense: str
    observed_result: AttackOutcome = Field(default=AttackOutcome.ATTACK_ATTEMPTED)
    evidence: Optional[Evidence] = None
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)
    severity: FindingSeverity = Field(default=FindingSeverity.HIGH)

    # Extended audit metadata
    category: AdversarialCategory = Field(default=AdversarialCategory.PROMPT_INJECTION)
    mitre_technique_id: str = ""
    timestamp: datetime = Field(default_factory=utc_now)
    impact_proof: Optional[str] = None
    defense_reason: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("execution_mode", mode="before")
    @classmethod
    def validate_execution_mode(cls, v: Any) -> ExecutionMode:
        if isinstance(v, str):
            try:
                return ExecutionMode(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid ExecutionMode: '{v}'")
        return v

    @field_validator("observed_result", mode="before")
    @classmethod
    def validate_observed_result(cls, v: Any) -> AttackOutcome:
        if isinstance(v, str):
            try:
                return AttackOutcome(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid AttackOutcome: '{v}'")
        return v

    def attach_evidence(
        self,
        raw_content: str,
        collection_method: str = "ADVERSARIAL_VALIDATION_ENGINE",
        status: EvidenceStatus = EvidenceStatus.SIMULATED,
    ) -> Evidence:
        """Constructs and attaches canonical Evidence with SHA-256 integrity hash."""
        sanitized = sanitize_evidence_content(raw_content)
        ev_status = EvidenceStatus.VERIFIED if self.execution_mode == ExecutionMode.LIVE else status
        ev = Evidence(
            evidence_id=f"EVD-ADV-{compute_sha256(self.attack_id)[:8].upper()}",
            source=FindingSource.AI_RED_TEAM,
            provider=CloudProvider.MULTI_CLOUD,
            resource=self.target,
            collection_method=collection_method,
            evidence_type=EvidenceType.RED_TEAM_RESULT,
            status=ev_status,
            confidence=1.0 if self.observed_result != AttackOutcome.INCONCLUSIVE else 0.5,
            execution_mode=self.execution_mode,
            sanitized_content=sanitized,
            content_hash=compute_sha256(sanitized),
            metadata={
                "attack_id": self.attack_id,
                "technique": self.technique,
                "outcome": str(self.observed_result),
                "severity": str(self.severity),
            }
        )
        self.evidence = ev
        return ev


class AdversarialCampaignReport(AISPRBaseModel):
    """
    Summary report of an adversarial validation campaign.
    Guarantees strict separation of attempted, blocked, succeeded, and inconclusive outcomes.
    """
    campaign_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)
    total_tests: int = 0
    attempted_count: int = 0
    blocked_count: int = 0
    succeeded_count: int = 0
    inconclusive_count: int = 0
    mitre_atlas_coverage: Dict[str, str] = Field(default_factory=dict)
    tests: List[AdversarialTest] = Field(default_factory=list)
    defense_efficacy_pct: float = 0.0
