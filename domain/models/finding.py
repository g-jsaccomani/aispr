# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - SecurityFinding Entity
"""

import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from pydantic import Field, field_validator, model_validator

from domain.enums import (
    CloudProvider,
    FindingSeverity,
    FindingStatus,
    FindingSource,
    EvidenceStatus,
    ExecutionMode,
    ConfidenceLevel,
    ControlRelationType,
    AssetType
)
from domain.models.base import AISPRBaseModel, utc_now
from domain.models.asset import AIAsset
from domain.models.evidence import Evidence
from domain.models.control import ControlLink
from domain.models.framework import FrameworkMapping
from domain.models.attack import AttackTechnique
from domain.models.remediation import Remediation


class SecurityFinding(AISPRBaseModel):
    """
    Canonical, strongly-typed security finding representing a detected risk,
    vulnerability, or compliance deviation in the enterprise AI ecosystem.
    Supports multi-control relationships (PRIMARY, SECONDARY, RELATED) without keyword coupling.
    """
    finding_id: str = Field(default_factory=lambda: f"FND-{uuid.uuid4().hex[:8].upper()}")
    assessment_id: str = Field(default="ASSESSMENT-DEFAULT")
    source: FindingSource = Field(default=FindingSource.MANUAL_AUDIT)
    provider: CloudProvider = Field(default=CloudProvider.GCP)
    asset: AIAsset
    title: str
    description: str = ""
    severity: FindingSeverity = Field(default=FindingSeverity.HIGH)
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH)
    status: FindingStatus = Field(default=FindingStatus.OPEN)
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)
    
    evidence: List[Evidence] = Field(default_factory=list)
    control_links: List[ControlLink] = Field(default_factory=list)
    framework_mappings: List[FrameworkMapping] = Field(default_factory=list)
    attack_techniques: List[AttackTechnique] = Field(default_factory=list)
    remediations: List[Remediation] = Field(default_factory=list)
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("source", mode="before")
    @classmethod
    def parse_source(cls, v: Any) -> FindingSource:
        if isinstance(v, str):
            val = v.strip()
            val_lower = val.lower()
            if "scc" in val_lower or "security command center" in val_lower:
                return FindingSource.GCP_SCC
            if "shadow" in val_lower:
                return FindingSource.SHADOW_AI_HUNTER
            if "sast" in val_lower or "prompt" in val_lower:
                return FindingSource.PROMPT_SAST
            if "red team" in val_lower:
                return FindingSource.AI_RED_TEAM
            if "model armor" in val_lower or "armor" in val_lower:
                return FindingSource.MODEL_ARMOR
            if "multicloud" in val_lower or "posture" in val_lower or "aws" in val_lower or "azure" in val_lower:
                return FindingSource.MULTI_CLOUD_SCANNER
            if "ai-bom" in val_lower or "bom" in val_lower:
                return FindingSource.AI_BOM
            if "manual" in val_lower:
                return FindingSource.MANUAL_AUDIT
            try:
                return FindingSource(val)
            except ValueError:
                raise ValueError(f"Invalid FindingSource: '{v}'")
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

    @field_validator("severity", mode="before")
    @classmethod
    def parse_severity(cls, v: Any) -> FindingSeverity:
        if isinstance(v, str):
            try:
                return FindingSeverity(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid FindingSeverity: '{v}'")
        return v

    @field_validator("status", mode="before")
    @classmethod
    def parse_status(cls, v: Any) -> FindingStatus:
        if isinstance(v, str):
            try:
                return FindingStatus(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid FindingStatus: '{v}'")
        return v

    @field_validator("confidence", mode="before")
    @classmethod
    def parse_confidence(cls, v: Any) -> ConfidenceLevel:
        if isinstance(v, str):
            try:
                return ConfidenceLevel(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid ConfidenceLevel: '{v}'")
        return v

    @model_validator(mode="before")
    @classmethod
    def infer_execution_mode_from_evidence(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("execution_mode"):
                ev_list = data.get("evidence", [])
                has_live_verified = False
                for e in ev_list:
                    if getattr(e, "is_verified_live", False):
                        has_live_verified = True
                        break
                    elif isinstance(e, dict):
                        st = str(e.get("status", "")).upper()
                        xm = str(e.get("execution_mode", "")).upper()
                        if st == "VERIFIED" and xm == "LIVE":
                            has_live_verified = True
                            break
                if has_live_verified:
                    data["execution_mode"] = ExecutionMode.LIVE
        return data

    @field_validator("asset", mode="before")
    @classmethod
    def parse_asset(cls, v: Any) -> Union[AIAsset, Dict[str, Any]]:
        if isinstance(v, str):
            return AIAsset(
                name=v,
                resource_uri=v,
                asset_type=AssetType.INFERENCE_ENDPOINT
            )
        return v

    @property
    def control_ids(self) -> List[str]:
        """Returns ordered list of all linked GRC control IDs."""
        return [link.control_id for link in self.control_links]

    @property
    def primary_control_id(self) -> Optional[str]:
        """Returns the single primary root-cause control ID, or None if unlinked."""
        for link in self.control_links:
            if link.relation_type == ControlRelationType.PRIMARY_CONTROL:
                return link.control_id
        # Fallback to first control link if no primary explicitly assigned
        return self.control_links[0].control_id if self.control_links else None

    @property
    def secondary_control_ids(self) -> List[str]:
        """Returns list of all secondary control IDs."""
        return [link.control_id for link in self.control_links if link.relation_type == ControlRelationType.SECONDARY_CONTROL]

    @property
    def related_control_ids(self) -> List[str]:
        """Returns list of all related control IDs."""
        return [link.control_id for link in self.control_links if link.relation_type == ControlRelationType.RELATED_CONTROL]

    def add_control(
        self,
        control_id: str,
        relation_type: ControlRelationType = ControlRelationType.PRIMARY_CONTROL,
        rationale: Optional[str] = None
    ) -> "SecurityFinding":
        """
        Attaches a GRC control relationship to this finding.
        If setting a PRIMARY_CONTROL, downgrades any existing primary to SECONDARY_CONTROL.
        """
        clean_id = control_id.strip()
        if relation_type == ControlRelationType.PRIMARY_CONTROL:
            for link in self.control_links:
                if link.relation_type == ControlRelationType.PRIMARY_CONTROL:
                    link.relation_type = ControlRelationType.SECONDARY_CONTROL

        # Avoid duplicates
        for link in self.control_links:
            if link.control_id == clean_id:
                link.relation_type = relation_type
                if rationale:
                    link.rationale = rationale
                return self

        self.control_links.append(
            ControlLink(control_id=clean_id, relation_type=relation_type, rationale=rationale)
        )
        return self

    def set_primary_control(self, control_id: str, rationale: Optional[str] = None) -> "SecurityFinding":
        """Convenience method to set the primary control."""
        return self.add_control(control_id, ControlRelationType.PRIMARY_CONTROL, rationale)

    def add_secondary_control(self, control_id: str, rationale: Optional[str] = None) -> "SecurityFinding":
        """Convenience method to set a secondary control."""
        return self.add_control(control_id, ControlRelationType.SECONDARY_CONTROL, rationale)

    def add_related_control(self, control_id: str, rationale: Optional[str] = None) -> "SecurityFinding":
        """Convenience method to set a related control."""
        return self.add_control(control_id, ControlRelationType.RELATED_CONTROL, rationale)

    def get_controls_by_relation(self, relation: ControlRelationType) -> List[str]:
        """Filters and returns control IDs linked with a specific relation type."""
        return [link.control_id for link in self.control_links if link.relation_type == relation]

    def add_evidence(self, evidence: Evidence) -> "SecurityFinding":
        """Appends technical evidence to the finding."""
        self.evidence.append(evidence)
        return self

    def add_framework_mapping(
        self,
        framework: str,
        section_or_control: str,
        version: Optional[str] = None,
        description: Optional[str] = None
    ) -> "SecurityFinding":
        """Attaches a formal framework mapping to this finding."""
        self.framework_mappings.append(
            FrameworkMapping(
                framework=framework,
                section_or_control=section_or_control,
                version=version,
                description=description
            )
        )
        return self

    def add_attack_technique(
        self,
        technique_id: str,
        name: str,
        framework: str = "MITRE ATLAS",
        tactic: Optional[str] = None,
        description: Optional[str] = None
    ) -> "SecurityFinding":
        """Attaches a MITRE ATLAS or OWASP attack technique to this finding."""
        self.attack_techniques.append(
            AttackTechnique(
                technique_id=technique_id,
                name=name,
                framework=framework,
                tactic=tactic,
                description=description
            )
        )
        return self

    def add_remediation(self, remediation: Remediation) -> "SecurityFinding":
        """Attaches an actionable remediation to this finding."""
        self.remediations.append(remediation)
        return self

    @model_validator(mode="after")
    def validate_epistemology(self) -> "SecurityFinding":
        """
        Enforces strict epistemological integrity rules:
        1. A LIVE finding cannot be established solely from fixture or simulation evidence.
        2. A SIMULATION finding cannot contain or appear as VERIFIED.
        3. An INFERRED finding must explicitly indicate its origin.
        """
        # Rule 1: LIVE finding integrity
        if self.execution_mode == ExecutionMode.LIVE:
            if not self.evidence or len(self.evidence) == 0:
                raise ValueError("LIVE finding integrity violation: Finding with execution_mode=LIVE must have attached evidence.")
            has_live_ev = any(ev.execution_mode == ExecutionMode.LIVE for ev in self.evidence)
            if not has_live_ev:
                raise ValueError("LIVE finding integrity violation: Finding with execution_mode=LIVE must contain at least one LIVE evidence.")
            has_valid_provenance = any(ev.status == EvidenceStatus.VERIFIED or (ev.status != EvidenceStatus.SIMULATED and ev.execution_mode == ExecutionMode.LIVE) for ev in self.evidence)
            if not has_valid_provenance:
                raise ValueError("LIVE finding integrity violation: Finding with execution_mode=LIVE must have valid evidence provenance.")

        # Rule 2: Simulation finding cannot be verified
        if self.execution_mode in (ExecutionMode.SIMULATION, ExecutionMode.FIXTURE, ExecutionMode.MOCK):
            for ev in self.evidence:
                if ev.status == EvidenceStatus.VERIFIED:
                    raise ValueError("Simulation finding integrity violation: Finding with SIMULATION mode cannot contain VERIFIED evidence.")

        # Rule 3: Inferred finding must specify origin
        has_inferred = any(ev.status == EvidenceStatus.INFERRED for ev in self.evidence)
        if has_inferred and not self.metadata.get("inferred_origin"):
            self.metadata["inferred_origin"] = "Inferred via secondary cloud telemetry correlation"

        return self

    @property
    def propagated_confidence(self) -> float:
        """Computes propagated confidence score based on attached empirical evidence."""
        if not self.evidence:
            return 0.5 if self.is_simulated else 0.85
        return round(sum(ev.confidence for ev in self.evidence) / len(self.evidence), 2)

    @property
    def is_live_verified(self) -> bool:
        """Returns True if at least one attached evidence artifact is verified live."""
        return any(ev.is_verified_live for ev in self.evidence)

    @property
    def is_simulated(self) -> bool:
        """Returns True if all attached evidence is simulated, or if no evidence is attached."""
        if not self.evidence:
            return True
        return all(ev.is_simulated for ev in self.evidence)


# Canonical Alias
Finding = SecurityFinding
