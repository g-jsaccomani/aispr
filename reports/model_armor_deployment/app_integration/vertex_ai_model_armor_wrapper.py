# -*- coding: utf-8 -*-
"""
Google Cloud Model Armor - Vertex AI GenerativeModel SDK Wrapper
Transparent pre-call prompt sanitization and post-call response shielding.
"""

import vertexai
from vertexai.generative_models import GenerativeModel
from agentic.runtime_defense.model_armor_guard import ModelArmorGuard

class GenerativeModelWithModelArmor:
    """
    Wrapper around Vertex AI GenerativeModel that enforces Model Armor guardrails.
    """
    def __init__(self, model_name: str = "gemini-1.5-pro", project_id: str = "test-enterprise-ai", location: str = "us-central1"):
        vertexai.init(project=project_id, location=location)
        self.raw_model = GenerativeModel(model_name)
        self.guard = ModelArmorGuard(project_id=project_id, location=location, template_id="secops-guardrail-prod")

    def generate_content(self, prompt: str, **kwargs):
        # 1. Pre-execution Prompt Sanitization (Input Shielding)
        in_verdict = self.guard.inspect_prompt(prompt)
        if in_verdict.get("verdict") == "BLOCKED":
            raise ValueError(f"Model Armor blocked prompt: {in_verdict.get('matched_rules')}")
        
        safe_prompt = in_verdict.get("sanitized_prompt", prompt)

        # 2. Live Model Inference
        response = self.raw_model.generate_content(safe_prompt, **kwargs)

        # 3. Post-execution Output Shielding
        out_verdict = self.guard.inspect_output(response.text)
        if out_verdict.get("verdict") == "BLOCKED":
            raise ValueError("Model Armor blocked generated output due to safety violation.")

        return out_verdict.get("sanitized_output", response.text)
