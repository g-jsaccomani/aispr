# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 9: Enterprise Shadow AI Discovery - Canonical Models.
Guarantees:
  - Epistemological confidence differentiation: OBSERVED vs INFERRED vs SUSPECTED
  - Strict mandate: "Do not classify inference as fact."
  - Mandatory fields: asset, provider, source, confidence, evidence, discovery timestamp, execution mode, provenance.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union
from pydantic import Field, field_validator

from domain.enums import StrEnum, CloudProvider, ExecutionMode, FindingSeverity, EvidenceStatus, EvidenceType, FindingSource
from domain.models.base import AISPRBaseModel, utc_now
from domain.models.asset import AIAsset
from domain.models.evidence import Evidence, compute_sha256
from domain.sanitization import sanitize_evidence_content


class ShadowConfidence(StrEnum):
    """
    Epistemological confidence tiers for Shadow AI detections.
    Strict rule: "Do not classify inference as fact."
    """
    OBSERVED = "OBSERVED"     # Verified physical evidence: running process, confirmed direct API telemetry, live listening port.
    INFERRED = "INFERRED"     # Behavioral inference: egress pattern, DNS lookup, environment variable, or startup script.
    SUSPECTED = "SUSPECTED"   # Heuristic or contextual suspicion: unmanaged GPU VM without active telemetry or package string.


class DetectionSource(StrEnum):
    """
    The 7 mandated detection sources for enterprise Shadow AI discovery.
    """
    CLOUD_RESOURCE = "cloud resources"
    NETWORK_INDICATOR = "network indicators"
    ENDPOINT = "endpoints"
    SAAS_INTEGRATION = "SaaS integrations"
    API_USAGE = "API usage"
    MODEL_ENDPOINT = "model endpoints"
    INFRASTRUCTURE_METADATA = "infrastructure metadata"


class ShadowAIRiskFactor(StrEnum):
    """
    Multi-dimensional risk vectors evaluated for unmanaged AI services.
    """
    EXTERNAL_EXPOSURE = "external exposure"
    DATA_SENSITIVITY = "data sensitivity"
    IDENTITY_PRIVILEGE = "identity privilege"
    MISSING_GOVERNANCE = "missing governance"
    MODEL_PROVENANCE = "model provenance"
    PUBLIC_ENDPOINT = "public endpoint"
    UNAUTHORIZED_DEPLOYMENT = "unauthorized deployment"


class ShadowAIDiscovery(AISPRBaseModel):
    """
    Canonical record of an unmanaged Shadow AI detection.
    Every discovery MUST include:
      - asset
      - provider
      - source
      - confidence
      - evidence
      - discovery timestamp
      - execution mode
      - provenance (mandatory)
    """
    discovery_id: str
    asset: AIAsset
    provider: CloudProvider = Field(default=CloudProvider.MULTI_CLOUD)
    source: DetectionSource
    confidence: ShadowConfidence = Field(default=ShadowConfidence.SUSPECTED)
    evidence: Optional[Evidence] = None
    discovery_timestamp: datetime = Field(default_factory=utc_now)
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)

    # Mandatory Provenance & Governance Tracking
    provenance: str = Field(description="Audit trail describing origin, method, and chain of custody.")
    risk_factors: List[ShadowAIRiskFactor] = Field(default_factory=list)
    risk_score: float = Field(default=50.0, ge=0.0, le=100.0)
    severity: FindingSeverity = Field(default=FindingSeverity.HIGH)
    is_public: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""

    @field_validator("confidence", mode="before")
    @classmethod
    def validate_confidence(cls, v: Any) -> ShadowConfidence:
        if isinstance(v, str):
            try:
                return ShadowConfidence(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid ShadowConfidence: '{v}'")
        return v

    def model_post_init(self, __context: Any) -> None:
        """Enforces invariant: Do not classify inference as fact."""
        super().model_post_init(__context)
        # If confidence is OBSERVED, ensure source or provenance doesn't indicate mere inference
        if self.confidence == ShadowConfidence.OBSERVED:
            prov_lower = self.provenance.lower()
            if "inferred from" in prov_lower or "heuristic" in prov_lower or "suspected" in prov_lower:
                raise ValueError(
                    "Epistemological safety violation: Cannot classify inferred or suspected telemetry as OBSERVED fact."
                )

        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Computes deterministic hash for deduplicating identical discoveries."""
        raw = f"{self.provider}:{self.source}:{self.asset.resource_uri or self.asset.name}"
        return compute_sha256(raw)[:16].upper()

    def attach_evidence(
        self,
        raw_telemetry: str,
        collection_method: str = "SHADOW_AI_DISCOVERY_SENSOR",
    ) -> Evidence:
        """Attaches canonical Evidence model with SHA-256 integrity hash."""
        sanitized = sanitize_evidence_content(raw_telemetry)
        ev_status = EvidenceStatus.VERIFIED if self.execution_mode == ExecutionMode.LIVE else EvidenceStatus.SIMULATED
        if self.confidence == ShadowConfidence.INFERRED:
            ev_status = EvidenceStatus.INFERRED
        elif self.confidence == ShadowConfidence.SUSPECTED:
            ev_status = EvidenceStatus.HEURISTIC

        ev = Evidence(
            evidence_id=f"EVD-SHADOW-{compute_sha256(self.discovery_id)[:8].upper()}",
            source=FindingSource.SHADOW_AI_HUNTER,
            provider=self.provider,
            resource=self.asset.resource_uri or self.asset.name,
            collection_method=collection_method,
            evidence_type=EvidenceType.RED_TEAM_RESULT,
            status=ev_status,
            confidence=1.0 if self.confidence == ShadowConfidence.OBSERVED else 0.7 if self.confidence == ShadowConfidence.INFERRED else 0.4,
            execution_mode=self.execution_mode,
            sanitized_content=sanitized,
            content_hash=compute_sha256(sanitized),
            metadata={
                "discovery_id": self.discovery_id,
                "confidence": str(self.confidence),
                "source": str(self.source),
                "provenance": self.provenance,
                "risk_factors": [str(rf) for rf in self.risk_factors],
            }
        )
        self.evidence = ev
        return ev
