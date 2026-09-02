# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 7: Agentic Security Runtime - Exception Hierarchy.
Enforces deterministic security boundaries and zero-trust perimeter control.
"""

from typing import Optional, Dict, Any


class SecurityRuntimeError(Exception):
    """Base exception for all security runtime violations."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class UnauthorizedActionError(SecurityRuntimeError):
    """Raised when an agent attempts an unauthorized action (e.g. write without authorization)."""
    pass


class PrivilegeEscalationError(SecurityRuntimeError):
    """Raised when an agent attempts to elevate privileges or bypass role constraints."""
    pass


class PromptInjectionError(SecurityRuntimeError):
    """Raised when an input prompt contains direct prompt injection or jailbreak patterns."""
    pass


class ToolInjectionError(SecurityRuntimeError):
    """Raised when tool arguments or input contain tool injection / hidden invocation attempts."""
    pass


class DataExfiltrationError(SecurityRuntimeError):
    """Raised when an action or payload attempts to exfiltrate secrets or sensitive data."""
    pass


class UntrustedToolOutputError(SecurityRuntimeError):
    """Raised when tool output contains malicious content or indirect prompt injection."""
    pass
