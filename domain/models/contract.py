# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Security Control Contract Entities
Elevates GRC checklist items into executable, versioned security control contracts
with explicit evidence requirements, multi-cloud automated tests, and rigorous framework mappings.
"""

from typing import List, Optional, Any, Union
from pydantic import Field, field_validator

from domain.enums import (
    AssessmentType,
    AutomationLevel,
    CloudProvider,
    FindingSeverity,
    EvidenceType,
    MappingConfidence,
    FrameworkName,
)
from domain.models.base import AISPRBaseModel


class RegulatoryMapping(AISPRBaseModel):
    """
    Formal regulatory and standard mapping.
    Enforces strict citation integrity: where no proven mapping exists, must be NOT_MAPPED.
    """
    framework: str = Field(description="Google SAIF, NIST AI RMF 1.0, ISO/IEC 42001, MITRE ATLAS, EU AI Act, OWASP LLM, OWASP Agentic Security, or NOT_MAPPED")
    reference: str = Field(description="Specific clause, article, pillar, or control ID, or NOT_MAPPED")
    applicability: str = Field(default="MANDATORY", description="MANDATORY, RECOMMENDED, OPTIONAL, or NOT_APPLICABLE")
    mapping_confidence: MappingConfidence = Field(default=MappingConfidence.HIGH)
    source: str = Field(default="", description="Citation source or official specification url/identifier")

    @field_validator("mapping_confidence", mode="before")
    @classmethod
    def parse_confidence(cls, v: Any) -> MappingConfidence:
        if isinstance(v, str):
            try:
                return MappingConfidence(v.upper().strip())
            except ValueError:
                return MappingConfidence.HIGH
        return v


class TestDefinition(AISPRBaseModel):
    """
    Executable or auditable test specification that evaluates this control.
    """
    test_id: str = Field(description="Dot-notated test ID, e.g. runtime.prompt_injection, config.cmek_key")
    name: str = Field(description="Descriptive name of the test procedure")
    description: str = Field(default="", description="Technical verification procedure")
    execution_type: AssessmentType = Field(default=AssessmentType.AUTOMATED)
    collector_or_engine: str = Field(default="", description="Collector engine, e.g. ModelArmorAdvisor, CloudAssetInventory, PromptSAST")

    @field_validator("execution_type", mode="before")
    @classmethod
    def parse_exec_type(cls, v: Any) -> AssessmentType:
        if isinstance(v, str):
            try:
                return AssessmentType(v.upper().strip())
            except ValueError:
                return AssessmentType.AUTOMATED
        return v


class EvidenceRequirement(AISPRBaseModel):
    """
    Formal technical artifact required to prove compliance with this control.
    """
    requirement_id: str = Field(description="Identifier for the evidence requirement")
    evidence_type: EvidenceType = Field(default=EvidenceType.CONFIGURATION)
    description: str = Field(description="Description of what the evidence artifact must demonstrate")
    mandatory: bool = Field(default=True)

    @field_validator("evidence_type", mode="before")
    @classmethod
    def parse_ev_type(cls, v: Any) -> EvidenceType:
        if isinstance(v, str):
            try:
                return EvidenceType(v.upper().strip())
            except ValueError:
                return EvidenceType.CONFIGURATION
        return v


class SecurityControlContract(AISPRBaseModel):
    """
    Versioned Security Control Contract defining the 104 AI-SPR GRC Controls.
    """
    control_id: str = Field(description="Unique Control ID (e.g., DAT-01, APP-01, INF-04)")
    domain: str = Field(description="Domain name and code (DAT, MOD, APP, INF, ASR, GOV)")
    title: str = Field(description="Concise, imperative security control title")
    objective: str = Field(description="Exact security and posture objective")
    description: str = Field(description="Detailed control description, scope, and technical requirement")
    severity: FindingSeverity = Field(default=FindingSeverity.HIGH)
    assessment_type: AssessmentType = Field(default=AssessmentType.AUTOMATED)
    automation_level: AutomationLevel = Field(default=AutomationLevel.FULL)
    applicable_providers: List[CloudProvider] = Field(default_factory=lambda: [CloudProvider.GCP, CloudProvider.AWS, CloudProvider.AZURE])
    test_definitions: List[TestDefinition] = Field(default_factory=list)
    evidence_requirements: List[EvidenceRequirement] = Field(default_factory=list)
    framework_mappings: List[RegulatoryMapping] = Field(default_factory=list)
    attack_technique_mappings: List[str] = Field(default_factory=list, description="MITRE ATLAS technique IDs, e.g. AML.T0054")
    remediation: str = Field(description="Technical and architectural remediation steps")
    references: List[str] = Field(default_factory=list, description="Official standards, documentation, and RFC links")
    version: str = Field(default="2.0.0", description="Contract specification version")

    @field_validator("applicable_providers", mode="before")
    @classmethod
    def parse_providers(cls, v: Any) -> List[CloudProvider]:
        if isinstance(v, list):
            parsed = []
            for item in v:
                if isinstance(item, str):
                    try:
                        parsed.append(CloudProvider(item.lower().strip()))
                    except ValueError:
                        parsed.append(CloudProvider.GCP)
                elif isinstance(item, CloudProvider):
                    parsed.append(item)
            return parsed
        return v

    @field_validator("severity", mode="before")
    @classmethod
    def parse_severity(cls, v: Any) -> FindingSeverity:
        if isinstance(v, str):
            try:
                return FindingSeverity(v.upper().strip())
            except ValueError:
                return FindingSeverity.HIGH
        return v

    @field_validator("assessment_type", mode="before")
    @classmethod
    def parse_assessment_type(cls, v: Any) -> AssessmentType:
        if isinstance(v, str):
            try:
                return AssessmentType(v.upper().strip())
            except ValueError:
                return AssessmentType.AUTOMATED
        return v

    @field_validator("automation_level", mode="before")
    @classmethod
    def parse_automation_level(cls, v: Any) -> AutomationLevel:
        if isinstance(v, str):
            try:
                return AutomationLevel(v.upper().strip())
            except ValueError:
                return AutomationLevel.FULL
        return v

    def get_framework_mapping(self, framework_name: str) -> Optional[RegulatoryMapping]:
        """Returns the specific regulatory mapping for a framework, or None."""
        for m in self.framework_mappings:
            if m.framework.lower() == framework_name.lower():
                return m
        return None

    @property
    def is_fully_automated(self) -> bool:
        """Returns True if the control is fully automated."""
        return self.automation_level == AutomationLevel.FULL and self.assessment_type == AssessmentType.AUTOMATED
