# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Secret Redaction & Sanitization Engine
Ensures evidence never persists access tokens, refresh tokens, private keys, passwords, or credentials.
"""

import re
import json
from typing import Any, Dict, List, Union

# Compiled regular expressions for sensitive secrets detection and redaction
SECRET_PATTERNS = [
    # Private Keys (RSA, EC, PKCS8, OpenSSH)
    (re.compile(r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9_-]+ PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    
    # JSON Web Tokens (Bearer, OAuth2, IAP assertions)
    (re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "[REDACTED_JWT_TOKEN]"),
    
    # Google API Keys (AIza followed by 30-45 chars)
    (re.compile(r"AIza[0-9A-Za-z_-]{30,45}"), "[REDACTED_GOOGLE_API_KEY]"),
    
    # OpenAI, Anthropic, HuggingFace Tokens
    (re.compile(r"sk-[a-zA-Z0-9_-]{20,}"), "[REDACTED_AI_API_KEY]"),
    (re.compile(r"hf_[a-zA-Z0-9]{34,}"), "[REDACTED_HF_TOKEN]"),
    
    # AWS Access Key IDs
    (re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY_ID]"),
    
    # Generic Key/Secret assignment in JSON/text: "password": "...", "client_secret": "..."
    (re.compile(r'(?i)(["\']?(?:password|client_secret|secret_key|private_key|access_token|refresh_token|token|credential)["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])'), r'\1[REDACTED_SECRET]\3'),
    
    # Basic Auth in URLs: https://user:pass@example.com
    (re.compile(r"(https?://)([^:]+):([^@]+)@"), r"\1[USER]:[REDACTED_PASS]@"),
]


def redact_string(text: str) -> str:
    """Scans and redacts known secret patterns from a string."""
    if not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_value(val: Any) -> Any:
    """Recursively redacts secrets in dicts, lists, and strings."""
    if isinstance(val, str):
        return redact_string(val)
    elif isinstance(val, dict):
        sanitized_dict = {}
        for k, v in val.items():
            lower_k = str(k).lower()
            if any(secret_term in lower_k for secret_term in ("token", "password", "secret", "private_key", "credential")):
                sanitized_dict[k] = "[REDACTED_SECRET]"
            else:
                sanitized_dict[k] = sanitize_value(v)
        return sanitized_dict
    elif isinstance(val, list):
        return [sanitize_value(elem) for elem in val]
    elif isinstance(val, tuple):
        return tuple(sanitize_value(elem) for elem in val)
    return val


def sanitize_evidence_content(content: Any) -> str:
    """
    Produces a safe, sanitized string representation of evidence content for hashing and storage.
    Guarantees no plaintext secrets or credentials escape into audit evidence logs.
    """
    if content is None:
        return ""
    if isinstance(content, (dict, list)):
        sanitized_struct = sanitize_value(content)
        return json.dumps(sanitized_struct, sort_keys=True, default=str)
    return redact_string(str(content))
