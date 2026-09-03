# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Licensed under the Apache License, Version 2.0.

AISPR Audit Trail Engine
Implements a tamper-evident, append-only audit log with SHA-256 hash chaining
for every security scan, evaluation, and report generation.
"""

import os
import sys
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger("AISPR-AuditTrail")

GENESIS_PREV_HASH = "0" * 64


def utc_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def compute_hash(
    entry_id: int,
    timestamp: str,
    event_type: str,
    session_id: Optional[str],
    actor: str,
    prev_hash: str,
    payload: Dict[str, Any]
) -> str:
    payload_str = canonical_json(payload)
    raw = f"{entry_id}|{timestamp}|{event_type}|{session_id or ''}|{actor}|{prev_hash}|{payload_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditEntry:
    """A single immutable entry in the hash-chained audit trail."""

    def __init__(
        self,
        entry_id: int,
        timestamp: str,
        event_type: str,
        session_id: Optional[str],
        actor: str,
        payload: Dict[str, Any],
        prev_hash: str,
        entry_hash: str
    ):
        self.entry_id = entry_id
        self.timestamp = timestamp
        self.event_type = event_type
        self.session_id = session_id
        self.actor = actor
        self.payload = payload
        self.prev_hash = prev_hash
        self.entry_hash = entry_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "session_id": self.session_id,
            "actor": self.actor,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuditEntry":
        return cls(
            entry_id=d["entry_id"],
            timestamp=d["timestamp"],
            event_type=d["event_type"],
            session_id=d.get("session_id"),
            actor=d["actor"],
            payload=d["payload"],
            prev_hash=d["prev_hash"],
            entry_hash=d["entry_hash"]
        )


class AuditTrail:
    """
    Append-only tamper-evident audit log with cryptographic hash chaining.
    """

    def __init__(self, log_path: Optional[str] = None):
        if log_path is None:
            _root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
            self.log_path = os.path.join(_root, "reports", "audit_trail.jsonl")
        else:
            self.log_path = log_path
        
        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)

    def get_entries(self) -> List[AuditEntry]:
        if not os.path.exists(self.log_path):
            return []
        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(AuditEntry.from_dict(json.loads(line)))
                    except Exception as e:
                        logger.warning(f"Failed to parse audit log line: {e}")
        return entries

    def get_latest_hash(self) -> str:
        entries = self.get_entries()
        if not entries:
            return GENESIS_PREV_HASH
        return entries[-1].entry_hash

    def log_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        session_id: Optional[str] = None,
        actor: str = "@jsaccomani"
    ) -> AuditEntry:
        """
        Appends a new event to the audit trail with hash chaining.
        """
        entries = self.get_entries()
        entry_id = len(entries)
        prev_hash = entries[-1].entry_hash if entries else GENESIS_PREV_HASH
        timestamp = utc_iso_now()

        entry_hash = compute_hash(
            entry_id=entry_id,
            timestamp=timestamp,
            event_type=event_type,
            session_id=session_id,
            actor=actor,
            prev_hash=prev_hash,
            payload=payload
        )

        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            event_type=event_type,
            session_id=session_id,
            actor=actor,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash
        )

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(canonical_json(entry.to_dict()) + "\n")

        logger.info(f"Audit event '{event_type}' recorded: #{entry_id} (Hash: {entry_hash[:12]}...)")
        return entry

    def log_scan(
        self,
        project_id: str,
        scan_type: str,
        findings_count: int,
        session_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEntry:
        payload = {
            "project_id": project_id,
            "scan_type": scan_type,
            "findings_count": findings_count,
            "details": details or {}
        }
        return self.log_event(
            event_type="SCAN_EXECUTED",
            payload=payload,
            session_id=session_id
        )

    def log_report(
        self,
        session_id: str,
        report_format: str,
        metrics: Optional[Dict[str, Any]] = None,
        output_path: Optional[str] = None
    ) -> AuditEntry:
        payload = {
            "session_id": session_id,
            "format": report_format,
            "metrics": metrics or {},
            "output_path": output_path
        }
        return self.log_event(
            event_type="REPORT_GENERATED",
            payload=payload,
            session_id=session_id
        )

    def log_assessment(
        self,
        session_id: str,
        client: str,
        scope: str,
        execution_mode: str,
        metrics: Dict[str, Any]
    ) -> AuditEntry:
        payload = {
            "session_id": session_id,
            "client": client,
            "scope": scope,
            "execution_mode": execution_mode,
            "metrics": metrics
        }
        return self.log_event(
            event_type="ASSESSMENT_COMPLETED",
            payload=payload,
            session_id=session_id
        )

    def verify_chain(self) -> Tuple[bool, Optional[str]]:
        """
        Verifies the cryptographic integrity of the entire audit chain.
        Returns (True, None) if completely tamper-free.
        Returns (False, reason) if any entry has been altered, reordered, or deleted.
        """
        if not os.path.exists(self.log_path):
            return True, None

        entries = self.get_entries()
        if not entries:
            return True, None

        for idx, entry in enumerate(entries):
            # 1. Verify sequence ID
            if entry.entry_id != idx:
                return False, f"Broken sequence: entry at index {idx} has entry_id {entry.entry_id}"

            # 2. Verify previous hash pointer
            expected_prev = GENESIS_PREV_HASH if idx == 0 else entries[idx - 1].entry_hash
            if entry.prev_hash != expected_prev:
                return False, f"Broken chain link at entry {idx}: expected prev_hash {expected_prev}, got {entry.prev_hash}"

            # 3. Verify entry hash against data
            expected_hash = compute_hash(
                entry_id=entry.entry_id,
                timestamp=entry.timestamp,
                event_type=entry.event_type,
                session_id=entry.session_id,
                actor=entry.actor,
                prev_hash=entry.prev_hash,
                payload=entry.payload
            )
            if entry.entry_hash != expected_hash:
                return False, f"Corrupted entry hash at index {idx}: expected {expected_hash}, got {entry.entry_hash}"

        return True, None
