# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 7: Agentic Security Runtime - Prompt & Tool Output Guardrails.
Guarantees:
  - Prompt injection defense (direct & jailbreak)
  - Tool injection defense (shell / eval / hidden tool calls)
  - Data exfiltration defense (cloud metadata / tokens / secrets)
  - Tool Control: Agents MUST NOT automatically trust tool output (untrusted input defense)
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple, Union

from .exceptions import (
    PromptInjectionError,
    ToolInjectionError,
    DataExfiltrationError,
    UntrustedToolOutputError,
)

logger = logging.getLogger("AISPR-SecurityRuntime-Guardrails")


class RuntimePromptGuard:
    """
    Real-time input shielding guard protecting the agent reasoning loop against
    prompt injection, tool injection, data exfiltration, and malicious instructions.
    """

    # Direct Prompt Injection & Jailbreak (MITRE ATLAS AML.T0051.000 / AML.T0054)
    PROMPT_INJECTION_PATTERNS = [
        r"(?i)ignore (all )?(previous|prior) (system )?(instructions|commands|rules|restrictions)",
        r"(?i)developer (unrestricted )?mode",
        r"(?i)\bDAN\b|dan mode|jailbreak|pretend to be DAN",
        r"(?i)repeat (the )?(entire )?(initialization|system) prompt",
        r"(?i)output (every single|the) instruction in plaintext",
        r"(?i)decode the following base64 payload",
        r"(?i)<system_override>.*?</system_override>",
        r"(?i)<script_injection>.*?</script_injection>",
    ]

    # Tool Injection & Command Injection (OWASP Agentic Security / LLM-08)
    TOOL_INJECTION_PATTERNS = [
        r"(?i)\b(__import__|subprocess|os\.system|exec\(|eval\()\b",
        r"(?i);\s*(rm|cat|curl|wget|bash|sh|nc|kill)\b",
        r"(?i)\$\((cat|curl|wget|env|printenv|whoami)\)",
        r"(?i)`(cat|curl|wget|env|printenv|whoami)`",
        r"(?i)\|\|\s*(rm|cat|curl|wget|bash)\b",
        r"(?i)&&\s*(rm -rf|curl http|wget http)",
    ]

    # Data & Secret Exfiltration (MITRE ATLAS AML.T0040 / AML.T0051.001)
    EXFILTRATION_PATTERNS = [
        r"(?i)print (all )?(system )?(api keys|service account credentials|passwords|environment variables)",
        r"(?i)exfil(trate)?",
        r"(?i)send (the )?user('s)? (previous )?(chat|conversations|history|tokens)",
        r"(?i)metadata\.google\.internal",
        r"(?i)169\.254\.169\.254",
        r"(?i)curl -[dF]\s+.*?https?://",
        r"(?i)cat /etc/(passwd|shadow)",
    ]

    # Malicious destructive instructions
    MALICIOUS_INSTRUCTIONS = [
        r"(?i)delete bucket gs://",
        r"(?i)drop (database|table)",
        r"(?i)rm -rf /",
        r"(?i)terminate instance",
        r"(?i)disable\s+(?:all\s+)?(?:security\s+)?(audit|logging|scc|guardrails)",
    ]

    def inspect_prompt(self, prompt: str, strict: bool = True) -> Dict[str, Any]:
        """
        Inspects input prompt against security threat patterns.
        If strict=True, raises typed exceptions. If strict=False, returns findings dict.
        """
        prompt_text = str(prompt)

        # 1. Prompt Injection Check
        for p in self.PROMPT_INJECTION_PATTERNS:
            if re.search(p, prompt_text):
                msg = f"Direct prompt injection or jailbreak detected matching pattern: '{p}'"
                logger.warning(msg)
                if strict:
                    raise PromptInjectionError(msg, details={"pattern": p, "prompt_snippet": prompt_text[:100]})
                return {"is_safe": False, "threat": "PROMPT_INJECTION", "detail": msg}

        # 2. Tool Injection Check
        for p in self.TOOL_INJECTION_PATTERNS:
            if re.search(p, prompt_text):
                msg = f"Tool injection or command injection attempt detected matching: '{p}'"
                logger.warning(msg)
                if strict:
                    raise ToolInjectionError(msg, details={"pattern": p, "prompt_snippet": prompt_text[:100]})
                return {"is_safe": False, "threat": "TOOL_INJECTION", "detail": msg}

        # 3. Data Exfiltration Check
        for p in self.EXFILTRATION_PATTERNS:
            if re.search(p, prompt_text):
                msg = f"Secret exfiltration attempt detected matching pattern: '{p}'"
                logger.warning(msg)
                if strict:
                    raise DataExfiltrationError(msg, details={"pattern": p, "prompt_snippet": prompt_text[:100]})
                return {"is_safe": False, "threat": "DATA_EXFILTRATION", "detail": msg}

        # 4. Malicious Instructions Check
        for p in self.MALICIOUS_INSTRUCTIONS:
            if re.search(p, prompt_text):
                msg = f"Malicious destructive instruction detected matching pattern: '{p}'"
                logger.warning(msg)
                if strict:
                    raise PromptInjectionError(msg, details={"pattern": p, "prompt_snippet": prompt_text[:100]})
                return {"is_safe": False, "threat": "MALICIOUS_INSTRUCTION", "detail": msg}

        return {"is_safe": True, "threat": None, "detail": "Prompt verified safe"}


class UntrustedToolOutputSanitizer:
    """
    Tool Control Guard enforcing the core principle:
    'Agents MUST NOT automatically trust tool output. Tool output is untrusted input.'
    
    Inspects tool outputs for:
      - Indirect prompt injection embedded in external data
      - Hidden exfiltration commands or shell escapes
      - Leaked secrets / keys (DLP redaction)
    """

    # Indirect Prompt Injection embedded within tool responses
    INDIRECT_INJECTION_PATTERNS = [
        r"(?i)\[SYSTEM\s*:\s*.*?\]",
        r"(?i)<!--\s*\[SYSTEM\]:.*?-->",
        r"(?i)<system_override>.*?</system_override>",
        r"(?i)SYSTEM:\s*",
        r"(?i)NEW INSTRUCTION:\s*",
        r"(?i)IMPORTANT:\s*Please exfiltrate",
        r"(?i)exfil(trate)?",
        r"(?i)metadata\.google\.internal",
        r"(?i)169\.254\.169\.254",
    ]

    # Secret / Credential patterns to redact before returning to agent memory
    SECRET_REPLACEMENT_PATTERNS = [
        (r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "aws_secret_access_key='[REDACTED_SECRET]'"),
        (r"(?i)client_secret\s*[=:]\s*['\"]?[A-Za-z0-9~._-]{20,}['\"]?", "client_secret='[REDACTED_SECRET]'"),
        (r"(?i)bearer\s+ya29\.[A-Za-z0-9_-]{30,}", "Bearer [REDACTED_TOKEN]"),
        (r"(?i)AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
        (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
        (r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]", r"\1: '[REDACTED_SECRET]'"),
    ]

    def sanitize(
        self,
        tool_name: str,
        output: Any,
        raise_on_injection: bool = True
    ) -> Tuple[Any, Dict[str, Any]]:
        """
        Evaluates untrusted tool output and scrubs any embedded injections or credentials.
        
        Returns:
            Tuple of (sanitized_output, safety_report)
        """
        threats_detected: List[str] = []

        def _scan_and_clean_text(text: str) -> str:
            cleaned = text

            # 1. Check for indirect prompt injection in tool output
            for pattern in self.INDIRECT_INJECTION_PATTERNS:
                if re.search(pattern, cleaned):
                    threat_msg = f"Indirect prompt injection detected in tool '{tool_name}' output matching: {pattern}"
                    logger.warning(threat_msg)
                    threats_detected.append(threat_msg)
                    if raise_on_injection:
                        raise UntrustedToolOutputError(threat_msg, details={"tool_name": tool_name, "pattern": pattern})
                    # Neutralize if not raising
                    cleaned = re.sub(pattern, "[NEUTRALIZED_UNTRUSTED_INJECTION]", cleaned)

            # 2. Redact leaked secrets and credentials from tool output
            for secret_pattern, replacement in self.SECRET_REPLACEMENT_PATTERNS:
                if re.search(secret_pattern, cleaned):
                    logger.info(f"Redacted sensitive secret from tool '{tool_name}' output")
                    cleaned = re.sub(secret_pattern, replacement, cleaned)

            return cleaned

        def _recursive_sanitize(data: Any) -> Any:
            if isinstance(data, str):
                return _scan_and_clean_text(data)
            elif isinstance(data, dict):
                cleaned_dict = {}
                for k, v in data.items():
                    k_lower = str(k).lower()
                    if any(sec_kw in k_lower for sec_kw in ("secret", "token", "password", "key", "auth", "credential")):
                        threats_detected.append(f"Redacted sensitive secret from tool '{tool_name}' output (key: {k})")
                        cleaned_dict[k] = "[REDACTED_SECRET]"
                    else:
                        cleaned_dict[k] = _recursive_sanitize(v)
                return cleaned_dict
            elif isinstance(data, list):
                return [_recursive_sanitize(item) for item in data]
            return data

        sanitized_output = _recursive_sanitize(output)

        safety_report = {
            "tool_name": tool_name,
            "is_untrusted_input": True,
            "threats_detected": threats_detected,
            "was_modified": len(threats_detected) > 0 or sanitized_output != output
        }

        return sanitized_output, safety_report
