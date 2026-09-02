# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Model Armor Hybrid Defense Guard (Live API + Local Heuristic Fallback).
Engineered by: @jsaccomani
"""

import os
import sys
import logging
from typing import Dict, List, Any, Optional

from .local_prompt_filter import LocalPromptFilter
from .model_armor_client import ModelArmorClient

logger = logging.getLogger("AISPR-ModelArmor-Guard")


class ModelArmorGuard:
    """
    Hybrid semantic firewall and sensitive data protection engine.
    Tries the live Google Cloud Model Armor API (modelarmor.googleapis.com) first,
    and seamlessly falls back to the high-performance local regex filter on error or timeout.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        project_id: Optional[str] = None,
        location: str = "us-central1",
        template_id: str = "default-guardrail-template",
        use_live_api: bool = True,
        timeout: float = 3.0
    ):
        self.local_filter = LocalPromptFilter(config_path=config_path)
        self.use_live_api = use_live_api
        self.live_client = ModelArmorClient(
            project_id=project_id,
            location=location,
            template_id=template_id,
            timeout=timeout
        )
        self.config = self.local_filter.config

    # Expose class-level regex patterns for direct access / test compatibility
    JAILBREAK_PATTERNS = LocalPromptFilter.JAILBREAK_PATTERNS
    INDIRECT_INJECTION_PATTERNS = LocalPromptFilter.INDIRECT_INJECTION_PATTERNS
    DANGEROUS_CONTENT_PATTERNS = LocalPromptFilter.DANGEROUS_CONTENT_PATTERNS
    HIGH_IMPACT_MUTATIONS = LocalPromptFilter.HIGH_IMPACT_MUTATIONS
    PII_PATTERNS = LocalPromptFilter.PII_PATTERNS

    def inspect_prompt(self, prompt: str, hitl_approval_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs comprehensive Input Shielding:
        1. Tries the live Google Cloud Model Armor API first.
        2. Falls back to LocalPromptFilter on API error, network timeout, or credential absence.
        """
        if self.use_live_api:
            try:
                res = self.live_client.sanitize_user_prompt(prompt, hitl_approval_token=hitl_approval_token)
                logger.debug(f"Model Armor Live API inspection verdict: {res['verdict']}")
                res["inspection_source"] = "MODEL_ARMOR_LIVE"
                res["execution_mode"] = "LIVE"
                res["description"] = "Verdict verified by Google Cloud Model Armor API (modelarmor.googleapis.com)."
                
                # Check local high-impact mutation rules to preserve HITL authorization gates
                local_check = self.local_filter.inspect_prompt(prompt, hitl_approval_token=hitl_approval_token)
                if local_check.get("requires_hitl"):
                    res["requires_hitl"] = True
                    if local_check.get("is_blocked"):
                        res["is_blocked"] = True
                        res["verdict"] = "BLOCKED"
                        res["inspection_source"] = "LOCAL_FALLBACK"
                        res["execution_mode"] = "FALLBACK"
                        res["description"] = "Blocked by local security policy rules (high-impact mutation without valid HITL token)."
                        for rule in local_check.get("matched_rules", []):
                            if rule not in res["matched_rules"]:
                                res["matched_rules"].append(rule)
                return res
            except Exception as exc:
                logger.debug(f"Live Model Armor API call bypassed ({exc}). Using local prompt filter fallback.")
                fallback_res = self.local_filter.inspect_prompt(prompt, hitl_approval_token=hitl_approval_token)
                fallback_res["inspection_source"] = "LOCAL_FALLBACK"
                fallback_res["execution_mode"] = "FALLBACK"
                fallback_res["fallback_reason"] = f"Live Model Armor API failed: {exc}"
                fallback_res["description"] = "Verdict produced by local regex fallback. Live Model Armor was unavailable."
                return fallback_res

        # Fallback to local regex filter
        res = self.local_filter.inspect_prompt(prompt, hitl_approval_token=hitl_approval_token)
        res["inspection_source"] = "LOCAL_FALLBACK"
        res["execution_mode"] = "SIMULATION"
        res["description"] = f"Local Prompt Filter (offline fallback) verdict: {res['verdict']}"
        return res

    def inspect_output(self, generated_text: str) -> Dict[str, Any]:
        """
        Performs Output Shielding:
        1. Tries the live Google Cloud Model Armor API first.
        2. Falls back to LocalPromptFilter on API error or timeout.
        """
        if self.use_live_api:
            try:
                res = self.live_client.sanitize_model_response(generated_text)
                logger.debug(f"Model Armor Live API output inspection verdict: {res['verdict']}")
                res["inspection_source"] = "MODEL_ARMOR_LIVE"
                res["execution_mode"] = "LIVE"
                res["description"] = "Model response sanitized by Google Cloud Model Armor Live API."
                return res
            except Exception as exc:
                logger.debug(f"Live Model Armor API output shielding bypassed ({exc}). Using local fallback.")
                fallback_res = self.local_filter.inspect_output(generated_text)
                fallback_res["inspection_source"] = "LOCAL_FALLBACK"
                fallback_res["execution_mode"] = "FALLBACK"
                fallback_res["fallback_reason"] = f"Live Model Armor API failed: {exc}"
                fallback_res["description"] = "Model response evaluated via local regex fallback. Live Model Armor was unavailable."
                return fallback_res

        res = self.local_filter.inspect_output(generated_text)
        res["inspection_source"] = "LOCAL_FALLBACK"
        res["execution_mode"] = "SIMULATION"
        res["description"] = "Output evaluated via local filter in simulation mode."
        return res
