# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 8: Controlled Adversarial Validation Engine - Safety Perimeter.
Guarantees:
  - Tests operate ONLY against explicitly authorized targets
  - Default mode: SIMULATION
  - Strict prohibition against destructive actions
"""

import re
import logging
from typing import Set, List, Optional, Any
from domain.enums import ExecutionMode

logger = logging.getLogger("AISPR-AdversarialSafety")


class AdversarialSafetyError(Exception):
    """Base exception for safety perimeter violations during adversarial testing."""
    pass


class UnauthorizedTargetError(AdversarialSafetyError):
    """Raised when an adversarial test attempts to target an unauthorized resource or endpoint."""
    pass


class DestructiveActionBlockedError(AdversarialSafetyError):
    """Raised when an adversarial test payload attempts destructive or irreversible system mutations."""
    pass


class TargetAuthorizationGate:
    """
    Safety perimeter gate ensuring that adversarial campaigns operate ONLY on
    explicitly authorized targets, in non-destructive modes, defaulting to SIMULATION.
    """

    # Non-destructive simulation target patterns permitted by default
    DEFAULT_AUTHORIZED_PATTERNS = [
        r"^sim://.*",
        r"^mock://.*",
        r"^fixture://.*",
        r"^aispr://.*",
        r"^test-.*",
        r"^https?://localhost(:\d+)?(/.*)?$",
        r"^https?://127\.0\.0\.1(:\d+)?(/.*)?$",
        r"^projects/test-[^/]+/.*",
    ]

    # Destructive commands and queries that MUST NOT be executed against targets
    DESTRUCTIVE_PAYLOAD_PATTERNS = [
        r"(?i)\brm\s+-rf\s+/",
        r"(?i)\bdrop\s+(database|table|schema)\b",
        r"(?i)\btruncate\s+(table)?\b",
        r"(?i)\bdelete\s+from\s+[^;]+\s+where\s+1=1\b",
        r"(?i)\bformat\s+[a-z]:",
        r"(?i)\bkill\s+-9\s+1\b",
        r"(?i)\bdelete\s+bucket\s+gs://",
    ]

    def __init__(
        self,
        authorized_targets: Optional[Set[str]] = None,
        authorized_patterns: Optional[List[str]] = None,
        default_mode: ExecutionMode = ExecutionMode.SIMULATION,
        allow_live_testing: bool = False,
    ):
        self.authorized_targets = set(authorized_targets or [])
        self.authorized_patterns = list(authorized_patterns or self.DEFAULT_AUTHORIZED_PATTERNS)
        self.default_mode = default_mode
        self.allow_live_testing = allow_live_testing

    def is_target_authorized(self, target: str, mode: ExecutionMode = ExecutionMode.SIMULATION) -> bool:
        """Determines if the given target is explicitly authorized for adversarial testing."""
        target_clean = str(target).strip()

        # 1. Check exact target match
        if target_clean in self.authorized_targets:
            return True

        # 2. In SIMULATION mode, check default safe simulation patterns
        if mode == ExecutionMode.SIMULATION:
            for pat in self.authorized_patterns:
                if re.match(pat, target_clean):
                    return True

        return False

    def verify_target_safety(self, target: str, mode: ExecutionMode = ExecutionMode.SIMULATION) -> None:
        """
        Validates target authorization. Raises UnauthorizedTargetError if target is unauthorized.
        """
        if not self.is_target_authorized(target, mode):
            msg = (
                f"Adversarial safety violation: Target '{target}' is NOT in the authorized targets allowlist "
                f"under execution mode '{mode}'."
            )
            logger.error(msg)
            raise UnauthorizedTargetError(msg)

    def verify_non_destructive(self, payload: str) -> None:
        """
        Validates that the test payload contains no destructive or irreversible operations.
        Raises DestructiveActionBlockedError if a destructive command pattern is detected.
        """
        payload_str = str(payload)
        for pattern in self.DESTRUCTIVE_PAYLOAD_PATTERNS:
            if re.search(pattern, payload_str):
                msg = f"Destructive adversarial payload blocked by safety gate: matches '{pattern}'"
                logger.error(msg)
                raise DestructiveActionBlockedError(msg)
