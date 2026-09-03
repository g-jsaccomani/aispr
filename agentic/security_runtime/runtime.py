# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 7: Agentic Security Runtime - Core Runtime Engine.
Enforces:
  - Bounded, observable, auditable, permission-aware execution
  - Default: READ ONLY privilege (any write requires explicit authorization)
  - Full prompt security (prompt injection, tool injection, privilege escalation, data exfiltration)
  - Tool Control: tool output is untrusted input and must not be automatically trusted
  - Zero secret logging
  - Complete canonical AgentAction structure with attached Evidence
"""

import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Callable, Set, Tuple

from domain.models.evidence import compute_sha256
from domain.enums import EvidenceStatus
from .models import (
    AgentAction,
    AuthorizationDecision,
    ActionStatus,
    PrivilegeLevel,
    SecurityEventType,
    SecurityEvent,
)
from .exceptions import (
    SecurityRuntimeError,
    UnauthorizedActionError,
    PrivilegeEscalationError,
    PromptInjectionError,
    ToolInjectionError,
    DataExfiltrationError,
    UntrustedToolOutputError,
)
from .authorizer import AgentAuthorizer
from .guardrails import RuntimePromptGuard, UntrustedToolOutputSanitizer
from .audit import AgentAuditLogger

logger = logging.getLogger("AISPR-SecurityRuntime")


class AgenticSecurityRuntime:
    """
    Central Security Runtime orchestrating boundary enforcement, permission authorization,
    input/output shielding, and cryptographic audit for autonomous AI agents.
    """

    def __init__(
        self,
        default_privilege: PrivilegeLevel = PrivilegeLevel.READ_ONLY,
        allowed_write_actions: Optional[Set[str]] = None,
        valid_approval_tokens: Optional[Set[str]] = None,
        audit_log_path: Optional[str] = None,
        raise_on_violation: bool = True
    ):
        self.raise_on_violation = raise_on_violation
        self.authorizer = AgentAuthorizer(
            default_privilege=default_privilege,
            allowed_write_actions=allowed_write_actions,
            valid_approval_tokens=valid_approval_tokens,
        )
        self.prompt_guard = RuntimePromptGuard()
        self.tool_sanitizer = UntrustedToolOutputSanitizer()
        self.audit_logger = AgentAuditLogger(log_file_path=audit_log_path)

    def execute_action(
        self,
        agent_id: str,
        requested_action: str,
        target: str,
        tool_callable: Optional[Callable[..., Any]] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentAction:
        """
        Executes an agent action within the security runtime perimeter.
        
        Every action produces an AgentAction containing:
          - action_id
          - agent_id
          - timestamp
          - target
          - requested_action
          - authorization_decision
          - result
          - evidence
        """
        now = datetime.now(timezone.utc)
        action_digest = compute_sha256(f"{agent_id}:{requested_action}:{target}:{now.isoformat()}")[:12].upper()
        action_id = f"ACT-{action_digest}"
        args = tool_args or {}
        meta = metadata or {}

        action = AgentAction(
            action_id=action_id,
            agent_id=agent_id,
            timestamp=now,
            target=target,
            requested_action=requested_action,
            authorization_decision=AuthorizationDecision.DENY,
            status=ActionStatus.BLOCKED,
            metadata=meta
        )

        try:
            # ------------------------------------------------------------------
            # 1. Prompt & Input Argument Security Inspection
            # ------------------------------------------------------------------
            # Inspect requested action name and target for injection/exfiltration
            self.prompt_guard.inspect_prompt(requested_action, strict=True)
            self.prompt_guard.inspect_prompt(target, strict=True)

            # Deep inspect all string arguments passed to the tool
            for arg_k, arg_v in args.items():
                if isinstance(arg_v, str):
                    self.prompt_guard.inspect_prompt(arg_v, strict=True)
                elif isinstance(arg_v, (list, dict)):
                    self.prompt_guard.inspect_prompt(str(arg_v), strict=True)

        except (PromptInjectionError, ToolInjectionError, DataExfiltrationError) as sec_exc:
            action.authorization_decision = AuthorizationDecision.DENY
            action.status = ActionStatus.BLOCKED
            action.authorization_reason = str(sec_exc)
            
            # Map exception to security event type
            if isinstance(sec_exc, PromptInjectionError):
                ev_type = SecurityEventType.PROMPT_INJECTION
            elif isinstance(sec_exc, ToolInjectionError):
                ev_type = SecurityEventType.TOOL_INJECTION
            else:
                ev_type = SecurityEventType.DATA_EXFILTRATION

            self.audit_logger.record_security_event(
                event_type=ev_type,
                agent_id=agent_id,
                description=f"Action blocked by Input Shield: {sec_exc}",
                details={"action_id": action_id, "target": target, "action": requested_action},
                action_id=action_id,
                severity="CRITICAL"
            )
            action.attach_evidence(
                raw_content=f"BLOCKED: {sec_exc} | Target: {target} | Action: {requested_action}",
                collection_method="RUNTIME_INPUT_SHIELD",
                status=EvidenceStatus.VERIFIED
            )
            self.audit_logger.record_action(action)
            if self.raise_on_violation:
                raise
            return action

        # ----------------------------------------------------------------------
        # 2. Deterministic Authorization Evaluation
        # ----------------------------------------------------------------------
        try:
            decision, reason, is_write = self.authorizer.evaluate_authorization(
                agent_id=agent_id,
                requested_action=requested_action,
                target=target,
                approval_token=approval_token,
                metadata=meta
            )
            action.authorization_decision = decision
            action.authorization_reason = reason
            action.is_write = is_write

            if decision != AuthorizationDecision.ALLOW:
                action.status = ActionStatus.BLOCKED
                self.audit_logger.record_security_event(
                    event_type=SecurityEventType.UNAUTHORIZED_ACTION,
                    agent_id=agent_id,
                    description=f"Unauthorized action blocked: {reason}",
                    details={"action_id": action_id, "target": target, "action": requested_action, "is_write": is_write},
                    action_id=action_id,
                    severity="HIGH"
                )
                action.attach_evidence(
                    raw_content=f"AUTHORIZATION_DENIED: {reason} | Target: {target} | IsWrite: {is_write}",
                    collection_method="RUNTIME_AUTHORIZER",
                    status=EvidenceStatus.VERIFIED
                )
                self.audit_logger.record_action(action)
                if self.raise_on_violation:
                    raise UnauthorizedActionError(reason, details={"action_id": action_id, "target": target})
                return action

        except PrivilegeEscalationError as esc_err:
            action.authorization_decision = AuthorizationDecision.DENY
            action.status = ActionStatus.BLOCKED
            action.authorization_reason = str(esc_err)
            self.audit_logger.record_security_event(
                event_type=SecurityEventType.PRIVILEGE_ESCALATION,
                agent_id=agent_id,
                description=str(esc_err),
                details={"action_id": action_id, "target": target, "action": requested_action},
                action_id=action_id,
                severity="CRITICAL"
            )
            action.attach_evidence(
                raw_content=f"BLOCKED_PRIVILEGE_ESCALATION: {esc_err}",
                collection_method="RUNTIME_AUTHORIZER",
                status=EvidenceStatus.VERIFIED
            )
            self.audit_logger.record_action(action)
            if self.raise_on_violation:
                raise
            return action

        # ----------------------------------------------------------------------
        # 3. Tool Execution with Untrusted Tool Output Defense
        # ----------------------------------------------------------------------
        raw_result: Any = None
        if tool_callable is not None:
            try:
                raw_result = tool_callable(**args)
            except Exception as tool_err:
                logger.error(f"Tool execution failed for action '{requested_action}': {tool_err}")
                action.status = ActionStatus.FAILED
                action.result = {"error": str(tool_err)}
                action.attach_evidence(
                    raw_content=f"TOOL_EXECUTION_ERROR: {tool_err}",
                    collection_method="RUNTIME_TOOL_INVOKER",
                    status=EvidenceStatus.VERIFIED
                )
                self.audit_logger.record_action(action)
                return action
        else:
            raw_result = {"status": "authorized_simulated_read", "target": target}

        # ----------------------------------------------------------------------
        # 4. Tool Control: Tool output is UNTRUSTED INPUT
        # ----------------------------------------------------------------------
        try:
            sanitized_result, safety_report = self.tool_sanitizer.sanitize(
                tool_name=requested_action,
                output=raw_result,
                raise_on_injection=True
            )
            action.result = sanitized_result if isinstance(sanitized_result, dict) else {"output": sanitized_result}
            action.status = ActionStatus.SUCCESS

            if safety_report.get("was_modified"):
                self.audit_logger.record_security_event(
                    event_type=SecurityEventType.AUDIT_EVENT,
                    agent_id=agent_id,
                    description=f"Tool output for '{requested_action}' was sanitized (credential redaction)",
                    details={"action_id": action_id, "tool_name": requested_action},
                    action_id=action_id,
                    severity="LOW"
                )

        except UntrustedToolOutputError as untrusted_err:
            action.status = ActionStatus.FAILED
            action.result = {"error": str(untrusted_err), "blocked_untrusted_output": True}
            self.audit_logger.record_security_event(
                event_type=SecurityEventType.UNTRUSTED_TOOL_OUTPUT,
                agent_id=agent_id,
                description=str(untrusted_err),
                details={"action_id": action_id, "tool_name": requested_action},
                action_id=action_id,
                severity="CRITICAL"
            )
            action.attach_evidence(
                raw_content=f"UNTRUSTED_TOOL_OUTPUT_BLOCKED: {untrusted_err}",
                collection_method="RUNTIME_TOOL_CONTROL_SHIELD",
                status=EvidenceStatus.VERIFIED
            )
            self.audit_logger.record_action(action)
            if self.raise_on_violation:
                raise
            return action

        # ----------------------------------------------------------------------
        # 5. Canonical Evidence & Audit Record
        # ----------------------------------------------------------------------
        action.attach_evidence(
            raw_content=f"SUCCESS: {requested_action} on {target} | OutputDigest: {compute_sha256(str(action.result))[:16]}",
            collection_method="SECURITY_RUNTIME_INTERCEPTOR",
            status=EvidenceStatus.VERIFIED
        )
        self.audit_logger.record_action(action)
        return action
