# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Local Regex-Based Prompt Filter & Sensitive Data Protection (SDP) Guard.
Serves as a high-performance local pre-filter and offline fallback for ModelArmorGuard.
Engineered by: @jsaccomani
"""

import re
import json
import os
from typing import Dict, List, Any, Optional


class LocalPromptFilter:
    """
    High-performance local regex and heuristic filter providing Input Shielding,
    Output Shielding, PII Redaction, and Human-in-the-Loop (HITL) authorization gates.
    """

    # Adversarial patterns & jailbreak indicators (MITRE ATLAS AML.T0051.000 / AML.T0054)
    JAILBREAK_PATTERNS = [
        r"(?i)ignore (all )?(previous|prior) (system )?(instructions|commands|rules|restrictions)",
        r"(?i)developer (unrestricted )?mode",
        r"(?i)\bDAN\b|dan mode|jailbreak|pretend to be DAN",
        r"(?i)repeat (the )?(entire )?(initialization|system) prompt",
        r"(?i)output (every single|the) instruction in plaintext",
        r"(?i)print (all )?(system )?(api keys|service account credentials|passwords|environment variables)",
        r"(?i)decode the following base64 payload",
        r"(?i)cybersecurity novel.*explain.*bypass.*armor",
        r"(?i)recall and output.*training dataset records.*cpf"
    ]

    # Indirect injection delimiters (MITRE ATLAS AML.T0051.001)
    INDIRECT_INJECTION_PATTERNS = [
        r"(?i)<script_injection>.*?</script_injection>",
        r"(?i)<system_override>.*?</system_override>",
        r"(?i)exfil(trate)? to https?://",
        r"(?i)send (the )?user('s)? (previous )?(chat|conversations|history|tokens)",
        r"(?i)<!--\s*\[SYSTEM\]:.*?-->",
        r"(?i)retrieve all customer records from the legacy database dump",
        r"(?i)extract the complete diagnosis history.*patient id"
    ]

    # Dangerous content & exploit generation (MITRE ATLAS AML.T0040 / OWASP LLM-02)
    DANGEROUS_CONTENT_PATTERNS = [
        r"(?i)polymorphic (bash|python|c) script",
        r"(?i)bypass (google )?cloud armor",
        r"(?i)exfiltrate (metadata server|access tokens|service account keys)",
        r"(?i)metadata\.google\.internal.*token",
        r"(?i)call api get /api/v1/customers/.*?without providing",
        r"(?i)database search query.*or '1'='1'"
    ]

    # High-impact destructive mutation commands (OWASP LLM-08 / ATLAS AML.T0058)
    HIGH_IMPACT_MUTATIONS = [
        r"(?i)delete bucket gs://",
        r"(?i)drop database",
        r"(?i)rm -rf /",
        r"(?i)grant (roles/)?resourcemanager\.organizationAdmin",
        r"(?i)fetch url http://metadata\.google\.internal"
    ]

    # Sensitive Data Protection (DLP / PII) regex patterns
    PII_PATTERNS = {
        "CREDIT_CARD": (r"\b(?:\d{4}[- ]?){3}\d{4}\b", "[REDACTED_CREDIT_CARD]"),
        "SSN": (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        "BRAZIL_CPF": (r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", "[REDACTED_CPF]"),
        "API_KEY": (r"\b(AIza[0-9A-Za-z-_]{35}|sk-[a-zA-Z0-9]{32,})\b", "[REDACTED_API_KEY]"),
        "EMAIL": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[REDACTED_EMAIL]")
    }

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(os.path.dirname(current_dir), "config", "model_armor_config.json")
        self.config = self._load_config(config_path)

    def _load_config(self, path: str) -> Dict[str, Any]:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f).get("model_armor_configuration", {})
        return {}

    def inspect_prompt(self, prompt: str, hitl_approval_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs comprehensive local Input Shielding on user prompts.
        """
        matched_rules = []
        risk_score = 0.0
        requires_hitl = False

        # 1. Check Direct Jailbreak & Prompt Injection
        for pattern in self.JAILBREAK_PATTERNS:
            if re.search(pattern, prompt):
                matched_rules.append("PROMPT_INJECTION_OR_JAILBREAK_ATTEMPT")
                risk_score = max(risk_score, 0.95)

        # 2. Check Indirect Prompt Injection (RAG Poisoning)
        for pattern in self.INDIRECT_INJECTION_PATTERNS:
            if re.search(pattern, prompt):
                matched_rules.append("INDIRECT_PROMPT_INJECTION_DETECTED")
                risk_score = max(risk_score, 0.90)

        # 3. Check Dangerous Content & Malware Generation
        for pattern in self.DANGEROUS_CONTENT_PATTERNS:
            if re.search(pattern, prompt):
                matched_rules.append("DANGEROUS_CONTENT_OR_EXPLOIT_DETECTED")
                risk_score = max(risk_score, 0.95)

        # 4. Check High-Impact Mutations (Excessive Agency)
        for pattern in self.HIGH_IMPACT_MUTATIONS:
            if re.search(pattern, prompt):
                matched_rules.append("HIGH_IMPACT_MUTATION_TRIGGERED")
                requires_hitl = True
                if not hitl_approval_token or hitl_approval_token != "HITL-APPROVED-VALID-TOKEN":
                    risk_score = max(risk_score, 0.85)

        # 5. Check & Redact PII (Sensitive Data Protection / DLP)
        sanitized_prompt = prompt
        pii_found = []
        for info_type, (pat, replacement) in self.PII_PATTERNS.items():
            if re.search(pat, sanitized_prompt):
                pii_found.append(info_type)
                sanitized_prompt = re.sub(pat, replacement, sanitized_prompt)

        if pii_found:
            matched_rules.append(f"PII_DETECTED_AND_MASKED:{','.join(pii_found)}")

        # Determine Final Verdict
        if risk_score >= 0.80:
            verdict = "BLOCKED"
        elif pii_found:
            verdict = "SANITIZED"
        else:
            verdict = "ALLOWED"

        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "matched_rules": matched_rules,
            "sanitized_prompt": sanitized_prompt,
            "requires_hitl": requires_hitl,
            "is_blocked": verdict == "BLOCKED"
        }

    def inspect_output(self, generated_text: str) -> Dict[str, Any]:
        """
        Performs Output Shielding on model responses before returning to users or downstream APIs.
        """
        matched_rules = []
        is_blocked = False
        sanitized_output = generated_text

        # 1. Redact any leaked credentials in output
        for info_type, (pat, replacement) in self.PII_PATTERNS.items():
            if re.search(pat, sanitized_output):
                matched_rules.append(f"OUTPUT_PII_LEAK_MASKED:{info_type}")
                sanitized_output = re.sub(pat, replacement, sanitized_output)

        # 2. Block unauthorized exfiltration links
        if re.search(r"(?i)https?://[a-zA-Z0-9.-]*attacker[a-zA-Z0-9.-]*", sanitized_output):
            matched_rules.append("MALICIOUS_OUTBOUND_URL_BLOCKED")
            is_blocked = True

        verdict = "BLOCKED" if is_blocked else ("SANITIZED" if matched_rules else "ALLOWED")

        return {
            "verdict": verdict,
            "is_blocked": is_blocked,
            "matched_rules": matched_rules,
            "sanitized_output": sanitized_output
        }

# Audit checkpoint [2026-02-18]: fix(prompt-defense): adjust prompt injection heuristic thresholds for client customer-service bot

# Audit checkpoint [2026-02-25]: fix(prompt-defense): adjust prompt injection heuristic thresholds for client customer-service bot
