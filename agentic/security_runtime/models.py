# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 7: Agentic Security Runtime - Canonical Action and Audit Data Models.
Enforces bounded, observable, and auditable agent behavior.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pydantic import Field, field_validator

from domain.enums import StrEnum, ExecutionMode, FindingSource, CloudProvider, EvidenceType, EvidenceStatus
from domain.models.base import AISPRBaseModel, utc_now
from domain.models.evidence import Evidence, compute_sha256
from domain.sanitization import sanitize_evidence_content


class AuthorizationDecision(StrEnum):
    """Deterministic authorization decision for requested agent actions."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class ActionStatus(StrEnum):
    """Lifecycle state of an executed or attempted agent action."""
    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    PENDING_APPROVAL = "PENDING_APPROVAL"


class PrivilegeLevel(StrEnum):
    """Privilege tiers for agent actions. Default is strictly READ_ONLY."""
    READ_ONLY = "READ_ONLY"
    WRITE = "WRITE"
    ADMIN = "ADMIN"


class SecurityEventType(StrEnum):
    """Categorization of security events recorded by the runtime audit engine."""
    UNAUTHORIZED_ACTION = "UNAUTHORIZED_ACTION"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    TOOL_INJECTION = "TOOL_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNTRUSTED_TOOL_OUTPUT = "UNTRUSTED_TOOL_OUTPUT"
    ACTION_EXECUTION = "ACTION_EXECUTION"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    AUDIT_EVENT = "AUDIT_EVENT"


class AgentAction(AISPRBaseModel):
    """
    Canonical record of an agent action.
    Every agent action MUST have:
      - action_id
      - agent_id
      - timestamp
      - target
      - requested_action
      - authorization_decision
      - result
      - evidence
    """
    action_id: str
    agent_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    target: str
    requested_action: str
    authorization_decision: AuthorizationDecision = Field(default=AuthorizationDecision.DENY)
    result: Optional[Dict[str, Any]] = None
    evidence: Optional[Evidence] = None

    # Extended runtime safety tracking
    privilege_level: PrivilegeLevel = Field(default=PrivilegeLevel.READ_ONLY)
    status: ActionStatus = Field(default=ActionStatus.BLOCKED)
    authorization_reason: str = ""
    is_write: bool = False
    execution_mode: ExecutionMode = Field(default=ExecutionMode.LIVE)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("authorization_decision", mode="before")
    @classmethod
    def parse_decision(cls, v: Any) -> AuthorizationDecision:
        if isinstance(v, str):
            try:
                return AuthorizationDecision(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid AuthorizationDecision: '{v}'")
        return v

    @property
    def is_authorized(self) -> bool:
        return self.authorization_decision == AuthorizationDecision.ALLOW

    def attach_evidence(
        self,
        raw_content: str,
        collection_method: str = "SECURITY_RUNTIME_INTERCEPTOR",
        status: EvidenceStatus = EvidenceStatus.VERIFIED,
    ) -> Evidence:
        """Constructs and attaches canonical Evidence with SHA-256 integrity digest."""
        sanitized = sanitize_evidence_content(raw_content)
        ev = Evidence(
            evidence_id=f"EVD-ACT-{compute_sha256(self.action_id)[:8].upper()}",
            source=FindingSource.MULTI_CLOUD_SCANNER,
            provider=CloudProvider.MULTI_CLOUD,
            resource=self.target,
            collection_method=collection_method,
            evidence_type=EvidenceType.API_RESPONSE,
            status=status,
            confidence=1.0,
            execution_mode=self.execution_mode,
            sanitized_content=sanitized,
            content_hash=compute_sha256(sanitized),
            metadata={"action_id": self.action_id, "requested_action": self.requested_action}
        )
        self.evidence = ev
        return ev


class SecurityEvent(AISPRBaseModel):
    """
    Structured security-relevant event recorded into the audit trail.
    Enforces the principle: Do not log secrets.
    """
    event_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: SecurityEventType
    agent_id: str
    action_id: Optional[str] = None
    target: str = ""
    severity: str = "HIGH"
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)
    event_hash: str = ""

    def compute_digest(self) -> str:
        """Computes SHA-256 cryptographic digest of the event payload."""
        content = f"{self.event_id}:{self.timestamp.isoformat()}:{self.event_type}:{self.agent_id}:{self.description}"
        return compute_sha256(content)
