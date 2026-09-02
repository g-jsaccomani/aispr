# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Evidence, EvidenceReference & CollectionResult
Implements evidence-first auditing, SHA-256 cryptographic verification, secret redaction,
and strict epistemological differentiation (LIVE vs SIMULATION).
"""

import uuid
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List, Union
from pydantic import Field, field_validator, model_validator

from domain.enums import (
    EvidenceType,
    EvidenceStatus,
    ExecutionMode,
    FindingSource,
    CloudProvider
)
from domain.models.base import AISPRBaseModel, utc_now
from domain.sanitization import sanitize_evidence_content, redact_string


def compute_sha256(content: str) -> str:
    """Computes SHA-256 hex digest for a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class Evidence(AISPRBaseModel):
    """
    Evidence-First technical artifact proving a compliance state or vulnerability.
    Guarantees tamper detection via SHA-256 and ensures zero raw secrets are persisted.
    """
    evidence_id: str = Field(default_factory=lambda: f"EVD-{uuid.uuid4().hex[:8].upper()}")
    finding_id: Optional[str] = None
    source: FindingSource = Field(default=FindingSource.MANUAL_AUDIT)
    provider: CloudProvider = Field(default=CloudProvider.GCP)
    resource: str = Field(default="")
    timestamp: datetime = Field(default_factory=utc_now)
    collection_method: str = Field(default="API_QUERY", description="API_CALL, LOCAL_INSPECTION, AST_STATIC_ANALYSIS, FIXTURE")
    evidence_type: EvidenceType = Field(default=EvidenceType.CONFIGURATION)
    status: EvidenceStatus = Field(default=EvidenceStatus.UNVERIFIED)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)
    content_hash: str = Field(default="")
    raw_reference: Optional[str] = None
    sanitized_content: str = Field(default="")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Legacy compatibility fields
    description: Optional[str] = None
    resource_uri: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    collector: Optional[str] = None

    @field_validator("source", mode="before")
    @classmethod
    def parse_source(cls, v: Any) -> FindingSource:
        if isinstance(v, str):
            try:
                return FindingSource(v)
            except ValueError:
                v_lower = v.lower()
                if "sast" in v_lower or "prompt" in v_lower:
                    return FindingSource.PROMPT_SAST
                if "scc" in v_lower:
                    return FindingSource.GCP_SCC
                if "shadow" in v_lower:
                    return FindingSource.SHADOW_AI_HUNTER
                if "asset" in v_lower or "inventory" in v_lower:
                    return FindingSource.CLOUD_ASSET_INVENTORY
                if "red team" in v_lower:
                    return FindingSource.AI_RED_TEAM
                if "armor" in v_lower:
                    return FindingSource.MODEL_ARMOR
                if "bom" in v_lower:
                    return FindingSource.AI_BOM
                if "multicloud" in v_lower or "posture" in v_lower or "aws" in v_lower or "azure" in v_lower:
                    return FindingSource.MULTI_CLOUD_SCANNER
                if "manual" in v_lower:
                    return FindingSource.MANUAL_AUDIT
                raise ValueError(f"Invalid FindingSource: '{v}'")
        return v

    @field_validator("status", mode="before")
    @classmethod
    def parse_status(cls, v: Any) -> EvidenceStatus:
        if isinstance(v, str):
            try:
                return EvidenceStatus(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid EvidenceStatus: '{v}'")
        return v

    @field_validator("execution_mode", mode="before")
    @classmethod
    def parse_execution_mode(cls, v: Any) -> ExecutionMode:
        if isinstance(v, str):
            try:
                return ExecutionMode(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid ExecutionMode: '{v}'")
        return v

    @field_validator("provider", mode="before")
    @classmethod
    def parse_provider(cls, v: Any) -> CloudProvider:
        if isinstance(v, str):
            val = v.lower().strip()
            if val in ("gcp", "google"):
                return CloudProvider.GCP
            if val in ("aws", "amazon"):
                return CloudProvider.AWS
            if val in ("azure", "microsoft"):
                return CloudProvider.AZURE
            try:
                return CloudProvider(val)
            except ValueError:
                raise ValueError(f"Invalid CloudProvider: '{v}'")
        return v

    @field_validator("evidence_type", mode="before")
    @classmethod
    def parse_evidence_type(cls, v: Any) -> EvidenceType:
        if isinstance(v, str):
            val = v.upper().strip()
            # Normalize legacy variants
            if val in ("LOG", "LOG_ENTRY"):
                return EvidenceType.LOG
            if val in ("IAM", "IAM_POLICY"):
                return EvidenceType.IAM
            if val in ("NETWORK", "NETWORK_TELEMETRY"):
                return EvidenceType.NETWORK
            if val in ("CODE", "CODE_SNIPPET"):
                return EvidenceType.CODE
            try:
                return EvidenceType(val)
            except ValueError:
                raise ValueError(f"Invalid EvidenceType: '{v}'")
        return v

    @model_validator(mode="before")
    @classmethod
    def sanitize_and_hash_initial_content(cls, data: Any) -> Any:
        """Sanitizes raw content and computes cryptographic SHA-256 hash automatically on creation."""
        if not isinstance(data, dict):
            return data

        # Map legacy resource_uri to resource if resource is empty
        if not data.get("resource") and data.get("resource_uri"):
            data["resource"] = data["resource_uri"]

        # If sanitized_content is provided, sanitize it against leakages
        content_source = data.get("sanitized_content") or data.get("description") or data.get("raw_data") or ""
        sanitized = sanitize_evidence_content(content_source)
        data["sanitized_content"] = sanitized

        # If description is empty, populate from sanitized_content
        if not data.get("description"):
            data["description"] = sanitized[:256]

        # Compute SHA-256 if not explicitly provided or re-verify
        if not data.get("content_hash") or data.get("content_hash") == "":
            data["content_hash"] = compute_sha256(sanitized)

        # Invariant checks: SIMULATION execution cannot be VERIFIED status
        exec_mode = str(data.get("execution_mode", "SIMULATION")).upper().strip()
        stat = str(data.get("status", "UNVERIFIED")).upper().strip()
        if exec_mode in ("SIMULATION", "FIXTURE", "MOCK", "FALLBACK") and stat == "VERIFIED":
            raise ValueError(f"Simulation integrity violation: Evidence with execution mode '{exec_mode}' cannot have VERIFIED status.")

        return data

    @model_validator(mode="after")
    def validate_simulation_evidence_not_verified(self) -> "Evidence":
        if self.execution_mode in (ExecutionMode.SIMULATION, ExecutionMode.FIXTURE, ExecutionMode.MOCK, ExecutionMode.FALLBACK):
            if self.status == EvidenceStatus.VERIFIED:
                raise ValueError(
                    f"Simulation integrity violation: Evidence with execution mode '{self.execution_mode}' cannot have VERIFIED status."
                )
        return self

    def set_content(self, content: Any):
        """Safely sets content by sanitizing secrets and updating the cryptographic SHA-256 hash."""
        self.sanitized_content = sanitize_evidence_content(content)
        self.content_hash = compute_sha256(self.sanitized_content)

    def verify_integrity(self) -> bool:
        """
        Validates cryptographic integrity of the evidence.
        Returns True if the content matches the SHA-256 hash, False if tampered.
        """
        recalculated = compute_sha256(self.sanitized_content)
        return recalculated == self.content_hash

    @property
    def is_verified_live(self) -> bool:
        """Returns True only if the evidence was verified in live production without simulation."""
        return self.status == EvidenceStatus.VERIFIED and self.execution_mode == ExecutionMode.LIVE

    @property
    def is_simulated(self) -> bool:
        """Returns True if the evidence originates from simulated, mock, or fixture sources."""
        return self.execution_mode in (
            ExecutionMode.SIMULATION,
            ExecutionMode.FIXTURE,
            ExecutionMode.MOCK
        ) or self.status in (
            EvidenceStatus.SIMULATED,
            EvidenceStatus.DERIVED,
            EvidenceStatus.INFERRED
        )


class EvidenceReference(AISPRBaseModel):
    """
    Lightweight pointer to an evidence artifact, useful for audits and cross-system correlation.
    """
    evidence_id: str
    finding_id: Optional[str] = None
    content_hash: str
    status: EvidenceStatus = Field(default=EvidenceStatus.UNVERIFIED)
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)
    uri: Optional[str] = None


class EvidenceCollectionResult(AISPRBaseModel):
    """
    Aggregated outcome of an automated or manual evidence collection sweep.
    """
    run_id: str
    source: FindingSource
    provider: CloudProvider = Field(default=CloudProvider.GCP)
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)
    evidence_items: List[Evidence] = Field(default_factory=list)
    collection_timestamp: datetime = Field(default_factory=utc_now)
    errors: List[str] = Field(default_factory=list)

    @property
    def total_collected(self) -> int:
        return len(self.evidence_items)

    @property
    def verified_count(self) -> int:
        return sum(1 for e in self.evidence_items if e.is_verified_live)

    @property
    def simulated_count(self) -> int:
        return sum(1 for e in self.evidence_items if e.is_simulated)
