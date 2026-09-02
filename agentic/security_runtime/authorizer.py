# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 7: Agentic Security Runtime - Deterministic Action Authorizer.
Enforces:
  - Default: READ ONLY privilege
  - Any write action requires explicit authorization
  - Zero unauthorized privileged executions
  - Privilege escalation defense
"""

import re
import logging
from typing import Dict, Set, List, Any, Optional, Tuple

from .models import AuthorizationDecision, PrivilegeLevel
from .exceptions import UnauthorizedActionError, PrivilegeEscalationError

logger = logging.getLogger("AISPR-SecurityRuntime-Authorizer")


class AgentAuthorizer:
    """
    Deterministic authorization gate enforcing least-privilege for autonomous agents.
    Default policy is strictly READ ONLY.
    Write operations and destructive actions require explicit authorization.
    """

    # Keywords designating state-mutating / privileged operations
    WRITE_ACTION_KEYWORDS = [
        "create", "deploy", "provision", "launch", "spin_up",
        "update", "modify", "patch", "alter", "edit", "change",
        "delete", "destroy", "terminate", "drop", "purge", "remove", "kill",
        "put", "post", "write", "set", "upload",
        "grant", "assign", "attach", "revoke", "elevate",
        "execute", "run_command", "remediate", "apply", "install",
    ]

    # Standard read-only action keywords
    READ_ACTION_KEYWORDS = [
        "list", "get", "describe", "read", "query", "fetch", "scan", "audit", "inspect", "verify", "check"
    ]

    # Privilege escalation keywords within requested action or metadata
    ESCALATION_KEYWORDS = [
        "sudo", "admin", "root", "elevate", "bypass", "override", "impersonate",
        "iam.setIamPolicy", "resourcemanager.organizationAdmin", "roles/owner"
    ]

    def __init__(
        self,
        default_privilege: PrivilegeLevel = PrivilegeLevel.READ_ONLY,
        allowed_write_actions: Optional[Set[str]] = None,
        valid_approval_tokens: Optional[Set[str]] = None,
        agent_role_permissions: Optional[Dict[str, Set[str]]] = None
    ):
        self.default_privilege = default_privilege
        self.allowed_write_actions = set(allowed_write_actions or [])
        self.valid_approval_tokens = set(valid_approval_tokens or {"HITL-APPROVED-PROD-2026", "AUTH-TOKEN-ADMIN"})
        self.agent_role_permissions = agent_role_permissions or {}

    def is_write_action(self, action_name: str) -> bool:
        """Determines deterministically if the requested action is a write/mutating operation."""
        tokens = [t.lower() for t in re.findall(r"[A-Za-z][a-z]*|[0-9]+", action_name)]
        for kw in self.WRITE_ACTION_KEYWORDS:
            if kw in tokens:
                return True
        return False

    def check_privilege_escalation(self, agent_id: str, requested_action: str, metadata: Dict[str, Any]) -> None:
        """
        Detects attempts to bypass role boundaries or escalate permissions.
        Raises PrivilegeEscalationError if an escalation attempt is detected.
        """
        action_lower = requested_action.lower()
        for kw in self.ESCALATION_KEYWORDS:
            if kw in action_lower:
                logger.warning(f"Privilege escalation attempt detected by agent '{agent_id}' with keyword '{kw}'")
                raise PrivilegeEscalationError(
                    f"Privilege escalation attempt detected: Agent '{agent_id}' requested action '{requested_action}' containing '{kw}'",
                    details={"agent_id": agent_id, "action": requested_action, "flagged_keyword": kw}
                )

        # Check metadata for attempted role overrides
        if metadata:
            role_override = metadata.get("role") or metadata.get("privilege") or metadata.get("elevate")
            if role_override and str(role_override).upper() in ("ADMIN", "ROOT", "OWNER", "SUPERUSER"):
                raise PrivilegeEscalationError(
                    f"Unauthorized role escalation attempt in action metadata: '{role_override}'",
                    details={"agent_id": agent_id, "role_override": role_override}
                )

    def evaluate_authorization(
        self,
        agent_id: str,
        requested_action: str,
        target: str,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[AuthorizationDecision, str, bool]:
        """
        Evaluates authorization decision for the requested agent action.
        
        Returns:
            Tuple of (AuthorizationDecision, reason_str, is_write_bool)
        """
        meta = metadata or {}
        
        # 1. First line of defense: Check for privilege escalation
        self.check_privilege_escalation(agent_id, requested_action, meta)

        is_write = self.is_write_action(requested_action)

        # 2. Check role-based explicit permission constraints if configured
        if agent_id in self.agent_role_permissions:
            allowed_for_agent = self.agent_role_permissions[agent_id]
            if requested_action not in allowed_for_agent and not any(re.search(p, requested_action) for p in allowed_for_agent):
                return (
                    AuthorizationDecision.DENY,
                    f"Action '{requested_action}' is not within assigned permissions for agent '{agent_id}'",
                    is_write
                )

        # 3. Read-Only actions: Allowed by default under least-privilege READ_ONLY
        if not is_write:
            return (
                AuthorizationDecision.ALLOW,
                f"Read-only action '{requested_action}' permitted under default READ_ONLY policy",
                False
            )

        # 4. Write actions: REQUIRE EXPLICIT AUTHORIZATION
        # Case A: Action is pre-authorized in the explicitly allowed write list
        if requested_action in self.allowed_write_actions:
            return (
                AuthorizationDecision.ALLOW,
                f"Write action '{requested_action}' explicitly pre-authorized in allowed_write_actions",
                True
            )

        # Case B: Action accompanied by valid Human-In-The-Loop (HITL) approval token
        if approval_token and approval_token in self.valid_approval_tokens:
            return (
                AuthorizationDecision.ALLOW,
                f"Write action '{requested_action}' authorized via verified approval token",
                True
            )

        # Case C: Write action without explicit authorization -> STRICTLY DENY
        return (
            AuthorizationDecision.DENY,
            f"Privileged write action '{requested_action}' denied: default privilege is READ_ONLY and no valid approval token was provided",
            True
        )
