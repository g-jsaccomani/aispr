# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Multi-Cloud Federated Connectors - Canonical Base & Contracts
"""

import re
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Set, Tuple
from pydantic import Field

from domain.enums import (
    CloudProvider,
    ExecutionMode,
    AssetType,
    FindingSeverity,
    FindingStatus,
    ConfidenceLevel,
    EvidenceType,
    EvidenceStatus,
    FindingSource,
)
from domain.models.base import AISPRBaseModel, utc_now
from domain.models.asset import AIAsset
from domain.models.evidence import Evidence, compute_sha256
from domain.models.finding import SecurityFinding
from domain.sanitization import sanitize_evidence_content, redact_string

logger = logging.getLogger("AISPR-Cloud-Connector-Base")


# ==============================================================================
# 1. SPECIALIZED CLOUD CONNECTOR EXCEPTIONS
# ==============================================================================

class CloudConnectorError(Exception):
    """Base exception for all multi-cloud connector failures."""
    def __init__(self, message: str, provider: Optional[CloudProvider] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.provider = provider
        self.details = details or {}


class CloudAuthenticationError(CloudConnectorError):
    """Raised when cloud credentials, tokens, or IAM assume-role flows fail authentication."""
    pass


class CloudPermissionDeniedError(CloudConnectorError):
    """Raised when the credential lacks sufficient read permissions (403 / AccessDenied)."""
    pass


class CloudAPIResponseError(CloudConnectorError):
    """Raised when a cloud provider API returns a malformed, corrupt, or unparseable response."""
    pass


class ReadOnlyEnforcementError(CloudConnectorError):
    """Raised when any mutation, write, create, update, or delete operation is attempted."""
    pass


class CloudSDKMissingError(CloudConnectorError):
    """Raised when a requested live discovery cannot proceed because the cloud SDK is not installed."""
    pass


# ==============================================================================
# 2. CANONICAL NORMALIZED DISCOVERY CONTAINER
# ==============================================================================

class NormalizedDiscoveryResult(AISPRBaseModel):
    """
    Standardized, strongly-typed multi-cloud discovery deliverable.
    All connectors (GCP, AWS, Azure) normalize their raw discoveries into this model.
    """
    provider: CloudProvider
    execution_mode: ExecutionMode
    account_or_project_id: str
    assets: List[AIAsset] = Field(default_factory=list)
    findings: List[SecurityFinding] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    raw_discovery: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)

    @property
    def is_live(self) -> bool:
        """Returns True if the discovery was executed via live cloud APIs."""
        return self.execution_mode == ExecutionMode.LIVE

    @property
    def total_assets(self) -> int:
        return len(self.assets)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def total_evidence(self) -> int:
        return len(self.evidence)

    @property
    def fallback_metadata(self) -> Dict[str, Any]:
        """Returns structured failure and fallback metadata if discovery degraded to fallback."""
        return self.raw_discovery.get("fallback_metadata", {})


# ==============================================================================
# 3. BASE CONNECTOR ABSTRACT CLASS
# ==============================================================================

class BaseCloudConnector(ABC):
    """
    Abstract Base Class for AISPR Cloud Discovery Connectors.
    Enforces:
      1. Explicit declaration of execution mode (LIVE, SIMULATION, MOCK, FIXTURE).
      2. Strict Read-Only operation (zero mutations permitted).
      3. Complete credential sanitization (no credentials persisted, logged, or in findings).
      4. Canonical normalization into AIAsset, SecurityFinding, Evidence.
    """

    WRITE_KEYWORDS: Set[str] = {
        "create", "update", "delete", "put", "post", "patch", "modify",
        "attach", "detach", "write", "drop", "terminate", "remove"
    }

    def __init__(
        self,
        provider: CloudProvider,
        target_identifier: str,
        execution_mode: ExecutionMode = ExecutionMode.SIMULATION,
        credentials_payload: Optional[Dict[str, Any]] = None,
    ):
        self.provider = provider
        self.target_identifier = target_identifier
        self.execution_mode = execution_mode
        self._credentials_payload = credentials_payload or {}
        self._is_read_only: bool = True

    @property
    def is_read_only(self) -> bool:
        """Connectors are strictly read-only."""
        return self._is_read_only

    def assert_read_only(self, action_name: str) -> None:
        """
        Guards against write operations. Raises ReadOnlyEnforcementError if a mutating
        action is requested.
        """
        action_lower = action_name.lower()
        if any(w in action_lower for w in self.WRITE_KEYWORDS):
            raise ReadOnlyEnforcementError(
                f"AISPR Security Violation: Write operation '{action_name}' is strictly prohibited. "
                f"Connectors are enforced read-only.",
                provider=self.provider
            )

    def sanitize_credentials(self, payload: Any) -> Any:
        """
        Deeply scrubs any potential tokens, access keys, private keys, or passwords
        from dictionaries or strings before logging or recording in evidence.
        """
        if isinstance(payload, str):
            return sanitize_evidence_content(payload)
        elif isinstance(payload, dict):
            cleaned = {}
            for k, v in payload.items():
                k_lower = k.lower()
                if any(secret_term in k_lower for secret_term in ["secret", "password", "token", "key", "credential", "auth"]):
                    cleaned[k] = "[REDACTED_CREDENTIAL]"
                else:
                    cleaned[k] = self.sanitize_credentials(v)
            return cleaned
        elif isinstance(payload, list):
            return [self.sanitize_credentials(item) for item in payload]
        return payload

    @abstractmethod
    def discover_resources(self) -> Dict[str, Any]:
        """
        Executes offline customer simulation or mock discovery.
        MUST declare execution_mode != LIVE.
        """
        pass

    @abstractmethod
    def discover_resources_live(self) -> Dict[str, Any]:
        """
        Executes real provider API calls using least-privilege credentials.
        MUST declare execution_mode == LIVE only upon successful API execution.
        """
        pass

    @abstractmethod
    def discover_canonical(self, live: bool = False) -> NormalizedDiscoveryResult:
        """
        Runs discovery and normalizes results directly into canonical models:
        (AIAsset, SecurityFinding, Evidence).
        """
        pass

    @abstractmethod
    def normalize(self, raw_data: Dict[str, Any], execution_mode: ExecutionMode) -> NormalizedDiscoveryResult:
        """
        Normalizes provider-specific raw dictionary into canonical models.
        """
        pass
