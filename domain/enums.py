# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Enumerations
Defines standardized, provider-independent enums for multi-cloud AI-SPM.
"""

from enum import Enum


class StrEnum(str, Enum):
    """String enumeration allowing direct string equality and JSON serialization."""
    def __str__(self) -> str:
        return str(self.value)


class CloudProvider(StrEnum):
    """Supported cloud infrastructure & AI platform providers."""
    GCP = "gcp"
    AWS = "aws"
    AZURE = "azure"
    MULTI_CLOUD = "multi_cloud"
    ON_PREM = "on_prem"
    UNKNOWN = "unknown"


class FindingSeverity(StrEnum):
    """Standardized finding and vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(StrEnum):
    """Lifecycle state of a security finding."""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class FindingSource(StrEnum):
    """Originating engine, sensor, or API that discovered the security anomaly."""
    GCP_SCC = "GCP Security Command Center (SCC)"
    CLOUD_ASSET_INVENTORY = "Google Cloud Asset Inventory"
    SHADOW_AI_HUNTER = "AISPR Shadow AI Hunter"
    PROMPT_SAST = "Static Prompt SAST"
    AI_RED_TEAM = "AI Red Team Simulator"
    MODEL_ARMOR = "Model Armor Guard"
    MULTI_CLOUD_SCANNER = "MultiCloud Posture Scanner"
    AI_BOM = "AI-BOM Cataloger"
    MANUAL_AUDIT = "Manual Assessment"
    EXTERNAL_FEED = "External Threat Telemetry"


class EvidenceType(StrEnum):
    """Category of technical artifact proving the deviation."""
    API_RESPONSE = "API_RESPONSE"
    CONFIGURATION = "CONFIGURATION"
    LOG = "LOG"
    LOG_ENTRY = "LOG_ENTRY"
    POLICY = "POLICY"
    IAM = "IAM"
    IAM_POLICY = "IAM_POLICY"
    NETWORK = "NETWORK"
    NETWORK_TELEMETRY = "NETWORK_TELEMETRY"
    CODE = "CODE"
    CODE_SNIPPET = "CODE_SNIPPET"
    MODEL_METADATA = "MODEL_METADATA"
    AI_BOM = "AI_BOM"
    RED_TEAM_RESULT = "RED_TEAM_RESULT"
    RUNTIME_EVENT = "RUNTIME_EVENT"
    MANUAL_ASSERTION = "MANUAL_ASSERTION"
    SIMULATION = "SIMULATION"
    CONTAINER_INSPECTION = "CONTAINER_INSPECTION"
    METRIC = "METRIC"
    HEURISTIC = "HEURISTIC"


class EvidenceStatus(StrEnum):
    """
    Epistemological confidence & verification tier of the collected evidence.
    Differentiates verified live cloud telemetry from heuristics and simulations.
    """
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    PARTIAL = "PARTIAL"
    SIMULATED = "SIMULATED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"


class ExecutionMode(StrEnum):
    """
    Runtime execution mode used to obtain the assessment data.
    Guarantees strict auditability between live cloud calls and test mocks.
    """
    LIVE = "LIVE"
    LIVE_PARTIAL = "LIVE_PARTIAL"
    SIMULATION = "SIMULATION"
    FIXTURE = "FIXTURE"
    MOCK = "MOCK"
    DEGRADED = "DEGRADED"


class ConfidenceLevel(StrEnum):
    """Statistical or algorithmic confidence in the finding detection."""
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SUSPECTED = "SUSPECTED"


class AssetType(StrEnum):
    """Classification of AI/ML inventory assets."""
    FOUNDATION_MODEL = "FOUNDATION_MODEL"
    FINE_TUNED_MODEL = "FINE_TUNED_MODEL"
    INFERENCE_ENDPOINT = "INFERENCE_ENDPOINT"
    AI_WORKBENCH_NOTEBOOK = "AI_WORKBENCH_NOTEBOOK"
    VECTOR_DATABASE = "VECTOR_DATABASE"
    STORAGE_BUCKET_RAG = "STORAGE_BUCKET_RAG"
    KUBERNETES_WORKLOAD = "KUBERNETES_WORKLOAD"
    COMPUTE_INSTANCE = "COMPUTE_INSTANCE"
    AI_AGENT = "AI_AGENT"
    API_GATEWAY = "API_GATEWAY"
    IAM_SERVICE_ACCOUNT = "IAM_SERVICE_ACCOUNT"
    MODEL_REGISTRY = "MODEL_REGISTRY"


class ControlEvaluation(StrEnum):
    """
    GRC assessment evaluation verdict for a control.
    Maps directly to legacy scoring symbols (Y/N/P/NA).
    """
    MET = "Y"
    NOT_MET = "N"
    PARTIALLY_MET = "P"
    NOT_APPLICABLE = "NA"
    UNASSESSED = "UNASSESSED"


class ControlRelationType(StrEnum):
    """
    Relationship between a security finding and GRC controls.
    Explicitly distinguishes primary root-cause controls from secondary or related controls.
    """
    PRIMARY_CONTROL = "PRIMARY_CONTROL"
    SECONDARY_CONTROL = "SECONDARY_CONTROL"
    RELATED_CONTROL = "RELATED_CONTROL"


class RiskLevel(StrEnum):
    """Aggregated risk tier based on exploitability and blast radius."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEGLIGIBLE = "NEGLIGIBLE"


class AssessmentStatus(StrEnum):
    """Execution state of an assessment engagement or run."""
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AssessmentType(StrEnum):
    """Execution modality of a security control assessment."""
    AUTOMATED = "AUTOMATED"
    SEMI_AUTOMATED = "SEMI_AUTOMATED"
    MANUAL = "MANUAL"


class AutomationLevel(StrEnum):
    """Degree of automated telemetry and verification achievable."""
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    NONE = "NONE"


class MappingConfidence(StrEnum):
    """Confidence grade in regulatory or standard mapping."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_MAPPED = "NOT_MAPPED"


class FrameworkName(StrEnum):
    """Formal security, regulatory, and adversarial frameworks."""
    GOOGLE_SAIF = "Google SAIF"
    NIST_AI_RMF = "NIST AI RMF 1.0"
    ISO_42001 = "ISO/IEC 42001"
    MITRE_ATLAS = "MITRE ATLAS"
    EU_AI_ACT = "EU AI Act"
    OWASP_LLM = "OWASP LLM"
    OWASP_AGENTIC = "OWASP Agentic Security"
    NOT_MAPPED = "NOT_MAPPED"

