# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Google Cloud Model Armor API Client.
Interfaces directly with modelarmor.googleapis.com using google-cloud SDK or REST.
Returns normalized verdicts matching the AISPR runtime defense schema.
Engineered by: @jsaccomani
"""

import os
import sys
import logging
from typing import Dict, List, Any, Optional

# Ensure project root is in sys.path
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_agentic_dir = os.path.dirname(_cur_dir)
_root_dir = os.path.dirname(_agentic_dir)
for p in [_root_dir, _agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from config.gcp_auth import (
        get_gcp_credentials,
        get_authenticated_session,
        get_default_project_id
    )
except ImportError:
    get_gcp_credentials = None
    get_authenticated_session = None
    get_default_project_id = None

logger = logging.getLogger("AISPR-ModelArmor-Client")


class ModelArmorClient:
    """
    Client for interacting with Google Cloud Model Armor API (modelarmor.googleapis.com).
    Provides prompt sanitization, response shielding, and sensitive data protection.
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        location: str = "us-central1",
        template_id: str = "default-guardrail-template",
        credentials: Optional[Any] = None,
        timeout: float = 5.0
    ):
        self.project_id = project_id or (get_default_project_id() if get_default_project_id else "your-gcp-project-id")
        self.location = location
        self.template_id = template_id
        self.credentials = credentials
        self.timeout = timeout
        self._session = None

        if self.credentials is None and get_gcp_credentials is not None:
            self.credentials, disc_proj = get_gcp_credentials()
            if not self.project_id or self.project_id == "your-gcp-project-id":
                self.project_id = disc_proj or self.project_id

    @property
    def template_path(self) -> str:
        return f"projects/{self.project_id}/locations/{self.location}/templates/{self.template_id}"

    def _get_session(self) -> Any:
        if self._session is None and get_authenticated_session is not None:
            self._session = get_authenticated_session(credentials=self.credentials)
        return self._session

    def sanitize_user_prompt(
        self,
        user_prompt_data: str,
        hitl_approval_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Calls Google Cloud Model Armor to sanitize and inspect an incoming user prompt.

        Returns normalized verdict dictionary:
        {
            "verdict": "ALLOWED" | "BLOCKED" | "SANITIZED",
            "risk_score": float,
            "matched_rules": list,
            "sanitized_prompt": str,
            "requires_hitl": bool,
            "is_blocked": bool
        }
        """
        matched_rules: List[str] = []
        risk_score = 0.0
        requires_hitl = False
        sanitized_prompt = user_prompt_data
        is_blocked = False

        # 1. Try google-cloud-modelarmor SDK
        sdk_success = False
        try:
            from google.cloud import modelarmor_v1
            client = modelarmor_v1.ModelArmorClient(credentials=self.credentials)
            
            user_prompt = modelarmor_v1.DataItem(text=user_prompt_data)
            request = modelarmor_v1.SanitizeUserPromptRequest(
                name=self.template_path,
                user_prompt_data=user_prompt
            )
            response = client.sanitize_user_prompt(request=request, timeout=self.timeout)
            sdk_success = True
            
            # Parse SDK Sanitization Result
            sanitization_result = getattr(response, "sanitization_result", None)
            if sanitization_result:
                # Prompt Injection / Jailbreak Filter
                pi_result = getattr(sanitization_result, "pi_and_jailbreak_filter_result", None)
                if pi_result and getattr(pi_result, "match_state", None):
                    matched_rules.append("MODEL_ARMOR_JAILBREAK_DETECTED")
                    risk_score = max(risk_score, 0.95)
                    is_blocked = True

                # Responsible AI Filter
                rai_result = getattr(sanitization_result, "rai_filter_result", None)
                if rai_result and getattr(rai_result, "match_state", None):
                    matched_rules.append("MODEL_ARMOR_RAI_POLICY_VIOLATION")
                    risk_score = max(risk_score, 0.90)
                    is_blocked = True

                # Malicious URI Filter
                uri_result = getattr(sanitization_result, "malicious_uris_filter_result", None)
                if uri_result and getattr(uri_result, "match_state", None):
                    matched_rules.append("MODEL_ARMOR_MALICIOUS_URI_DETECTED")
                    risk_score = max(risk_score, 0.90)
                    is_blocked = True

                # Sensitive Data Protection (SDP / DLP)
                sdp_result = getattr(sanitization_result, "sdp_filter_result", None)
                if sdp_result:
                    deidentified_data = getattr(sdp_result, "deidentified_data", None)
                    if deidentified_data and getattr(deidentified_data, "text", None):
                        sanitized_prompt = deidentified_data.text
                        matched_rules.append("MODEL_ARMOR_SDP_PII_REDACTED")

        except (ImportError, Exception) as exc:
            logger.debug(f"Model Armor SDK sanitize_user_prompt call failed: {exc}. Trying REST...")

        # 2. REST API Fallback
        if not sdk_success:
            session = self._get_session()
            if session is None:
                raise RuntimeError("No authenticated session or SDK available for Model Armor API.")

            url = f"https://modelarmor.{self.location}.rep.googleapis.com/v1/{self.template_path}:sanitizeUserPrompt"
            payload = {
                "userPromptData": {
                    "text": user_prompt_data
                }
            }

            resp = session.post(url, json=payload, timeout=self.timeout)
            if resp.status_code != 200:
                # Try fallback global endpoint
                alt_url = f"https://modelarmor.googleapis.com/v1/{self.template_path}:sanitizeUserPrompt"
                resp = session.post(alt_url, json=payload, timeout=self.timeout)
                if resp.status_code != 200:
                    raise RuntimeError(f"Model Armor REST API returned HTTP {resp.status_code}: {resp.text}")

            data = resp.json()
            san_res = data.get("sanitizationResult", {})

            # Jailbreak match
            if san_res.get("piAndJailbreakFilterResult", {}).get("matchState") == "MATCH_FOUND":
                matched_rules.append("MODEL_ARMOR_JAILBREAK_DETECTED")
                risk_score = max(risk_score, 0.95)
                is_blocked = True

            # RAI policy match
            if san_res.get("raiFilterResult", {}).get("matchState") == "MATCH_FOUND":
                matched_rules.append("MODEL_ARMOR_RAI_POLICY_VIOLATION")
                risk_score = max(risk_score, 0.90)
                is_blocked = True

            # Malicious URI match
            if san_res.get("maliciousUrisFilterResult", {}).get("matchState") == "MATCH_FOUND":
                matched_rules.append("MODEL_ARMOR_MALICIOUS_URI_DETECTED")
                risk_score = max(risk_score, 0.90)
                is_blocked = True

            # SDP / PII redaction
            sdp = san_res.get("sdpFilterResult", {})
            if sdp.get("deidentifiedData", {}).get("text"):
                sanitized_prompt = sdp["deidentifiedData"]["text"]
                matched_rules.append("MODEL_ARMOR_SDP_PII_REDACTED")

        # Determine Final Verdict
        if is_blocked or risk_score >= 0.80:
            verdict = "BLOCKED"
        elif sanitized_prompt != user_prompt_data or any("SDP" in r for r in matched_rules):
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

    def sanitize_model_response(
        self,
        model_response_data: str
    ) -> Dict[str, Any]:
        """
        Calls Google Cloud Model Armor to sanitize and inspect a generated model response (Output Shielding).

        Returns normalized verdict dictionary:
        {
            "verdict": "ALLOWED" | "BLOCKED" | "SANITIZED",
            "is_blocked": bool,
            "matched_rules": list,
            "sanitized_output": str
        }
        """
        matched_rules: List[str] = []
        is_blocked = False
        sanitized_output = model_response_data

        sdk_success = False
        try:
            from google.cloud import modelarmor_v1
            client = modelarmor_v1.ModelArmorClient(credentials=self.credentials)
            
            model_response = modelarmor_v1.DataItem(text=model_response_data)
            request = modelarmor_v1.SanitizeModelResponseRequest(
                name=self.template_path,
                model_response_data=model_response
            )
            response = client.sanitize_model_response(request=request, timeout=self.timeout)
            sdk_success = True

            sanitization_result = getattr(response, "sanitization_result", None)
            if sanitization_result:
                rai_result = getattr(sanitization_result, "rai_filter_result", None)
                if rai_result and getattr(rai_result, "match_state", None):
                    matched_rules.append("MODEL_ARMOR_OUTPUT_RAI_VIOLATION")
                    is_blocked = True

                uri_result = getattr(sanitization_result, "malicious_uris_filter_result", None)
                if uri_result and getattr(uri_result, "match_state", None):
                    matched_rules.append("MODEL_ARMOR_OUTPUT_MALICIOUS_URI")
                    is_blocked = True

                sdp_result = getattr(sanitization_result, "sdp_filter_result", None)
                if sdp_result:
                    deidentified_data = getattr(sdp_result, "deidentified_data", None)
                    if deidentified_data and getattr(deidentified_data, "text", None):
                        sanitized_output = deidentified_data.text
                        matched_rules.append("MODEL_ARMOR_OUTPUT_PII_REDACTED")

        except (ImportError, Exception) as exc:
            logger.debug(f"Model Armor SDK sanitize_model_response failed: {exc}. Trying REST...")

        if not sdk_success:
            session = self._get_session()
            if session is None:
                raise RuntimeError("No authenticated session or SDK available for Model Armor API.")

            url = f"https://modelarmor.{self.location}.rep.googleapis.com/v1/{self.template_path}:sanitizeModelResponse"
            payload = {
                "modelResponseData": {
                    "text": model_response_data
                }
            }

            resp = session.post(url, json=payload, timeout=self.timeout)
            if resp.status_code != 200:
                alt_url = f"https://modelarmor.googleapis.com/v1/{self.template_path}:sanitizeModelResponse"
                resp = session.post(alt_url, json=payload, timeout=self.timeout)
                if resp.status_code != 200:
                    raise RuntimeError(f"Model Armor REST API returned HTTP {resp.status_code}: {resp.text}")

            data = resp.json()
            san_res = data.get("sanitizationResult", {})

            if san_res.get("raiFilterResult", {}).get("matchState") == "MATCH_FOUND":
                matched_rules.append("MODEL_ARMOR_OUTPUT_RAI_VIOLATION")
                is_blocked = True

            if san_res.get("maliciousUrisFilterResult", {}).get("matchState") == "MATCH_FOUND":
                matched_rules.append("MODEL_ARMOR_OUTPUT_MALICIOUS_URI")
                is_blocked = True

            sdp = san_res.get("sdpFilterResult", {})
            if sdp.get("deidentifiedData", {}).get("text"):
                sanitized_output = sdp["deidentifiedData"]["text"]
                matched_rules.append("MODEL_ARMOR_OUTPUT_PII_REDACTED")

        verdict = "BLOCKED" if is_blocked else ("SANITIZED" if (sanitized_output != model_response_data or matched_rules) else "ALLOWED")

        return {
            "verdict": verdict,
            "is_blocked": is_blocked,
            "matched_rules": matched_rules,
            "sanitized_output": sanitized_output
        }

    # Aliases for compatibility
    inspect_prompt = sanitize_user_prompt
    inspect_output = sanitize_model_response
