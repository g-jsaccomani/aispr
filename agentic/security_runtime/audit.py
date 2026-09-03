# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 7: Agentic Security Runtime - Cryptographic Audit Logger.
Guarantees:
  - Persistent record of security-relevant agent events
  - Zero secret logging (strict DLP scrubbing before persistence)
  - SHA-256 cryptographic tamper-evident chaining
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from domain.models.evidence import compute_sha256
from domain.sanitization import sanitize_evidence_content
from .models import AgentAction, SecurityEvent, SecurityEventType

logger = logging.getLogger("AISPR-SecurityRuntime-Audit")


class AgentAuditLogger:
    """
    Cryptographically verifiable, append-only security audit logger for agent actions.
    Enforces the core requirement: 'Persist security-relevant agent events. Do not log secrets.'
    """

    def __init__(self, log_file_path: Optional[str] = None):
        self.log_file_path = log_file_path
        self._in_memory_events: List[SecurityEvent] = []
        self._last_event_hash: str = "GENESIS_HASH_00000000000000000000000000000000"

        if self.log_file_path:
            os.makedirs(os.path.dirname(os.path.abspath(self.log_file_path)), exist_ok=True)

    def _scrub_secrets(self, data: Any) -> Any:
        """Deeply sanitizes dictionaries and strings to guarantee zero secret leakage."""
        if isinstance(data, str):
            return sanitize_evidence_content(data)
        elif isinstance(data, dict):
            scrubbed = {}
            for k, v in data.items():
                if any(sec_kw in k.lower() for sec_kw in ("secret", "token", "password", "key", "auth", "credential")):
                    scrubbed[k] = "[REDACTED_SECRET]"
                else:
                    scrubbed[k] = self._scrub_secrets(v)
            return scrubbed
        elif isinstance(data, list):
            return [self._scrub_secrets(item) for item in data]
        return data

    def record_security_event(
        self,
        event_type: SecurityEventType,
        agent_id: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        action_id: Optional[str] = None,
        severity: str = "HIGH"
    ) -> SecurityEvent:
        """
        Records a security-relevant event with SHA-256 integrity digest and zero secret leakage.
        """
        scrubbed_desc = sanitize_evidence_content(description)
        scrubbed_details = self._scrub_secrets(details or {})

        event_id = f"EVT-{compute_sha256(f'{agent_id}:{datetime.now(timezone.utc).isoformat()}:{event_type}')[:12].upper()}"
        
        # Construct cryptographic chaining digest
        chain_input = f"{self._last_event_hash}|{event_id}|{event_type}|{agent_id}|{scrubbed_desc}|{json.dumps(scrubbed_details, sort_keys=True)}"
        event_hash = compute_sha256(chain_input)
        self._last_event_hash = event_hash

        event = SecurityEvent(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            agent_id=agent_id,
            action_id=action_id,
            severity=severity,
            description=scrubbed_desc,
            details=scrubbed_details,
            event_hash=event_hash
        )

        self._in_memory_events.append(event)

        # Persist to disk if path configured
        if self.log_file_path:
            try:
                with open(self.log_file_path, "a", encoding="utf-8") as f:
                    f.write(event.model_dump_json() + "\n")
            except Exception as e:
                logger.error(f"Failed to persist audit log to {self.log_file_path}: {e}")

        logger.info(f"[AUDIT] {event.severity} [{event.event_type}] Agent: {event.agent_id} - {event.description}")
        return event

    def record_action(self, action: AgentAction) -> SecurityEvent:
        """
        Records an agent action lifecycle event into the audit stream.
        """
        event_type = SecurityEventType.ACTION_EXECUTION
        if action.status == "BLOCKED":
            event_type = SecurityEventType.UNAUTHORIZED_ACTION

        action_summary = {
            "action_id": action.action_id,
            "target": action.target,
            "requested_action": action.requested_action,
            "is_write": action.is_write,
            "authorization_decision": action.authorization_decision,
            "status": action.status,
            "evidence_id": action.evidence.evidence_id if action.evidence else None
        }

        return self.record_security_event(
            event_type=event_type,
            agent_id=action.agent_id,
            description=f"Agent '{action.agent_id}' attempted '{action.requested_action}' on '{action.target}' (Decision: {action.authorization_decision})",
            details=action_summary,
            action_id=action.action_id,
            severity="LOW" if action.authorization_decision == "ALLOW" else "HIGH"
        )

    def get_events(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[SecurityEventType] = None
    ) -> List[SecurityEvent]:
        """Returns recorded events filtered by agent_id or event_type."""
        filtered = self._in_memory_events
        if agent_id:
            filtered = [e for e in filtered if e.agent_id == agent_id]
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        return filtered

    def verify_integrity(self) -> bool:
        """
        Cryptographically verifies the SHA-256 chain of all recorded in-memory events.
        """
        prev_hash = "GENESIS_HASH_00000000000000000000000000000000"
        for event in self._in_memory_events:
            chain_input = f"{prev_hash}|{event.event_id}|{event.event_type}|{event.agent_id}|{event.description}|{json.dumps(event.details, sort_keys=True)}"
            expected_hash = compute_sha256(chain_input)
            if event.event_hash != expected_hash:
                logger.error(f"Audit log tampering detected at event {event.event_id}!")
                return False
            prev_hash = event.event_hash
        return True
