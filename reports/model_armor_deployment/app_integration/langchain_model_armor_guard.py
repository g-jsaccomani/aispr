# -*- coding: utf-8 -*-
"""
Google Cloud Model Armor - LangChain Runnable Guardrail & Interceptor
"""

from langchain_core.runnables import RunnableLambda
from agentic.runtime_defense.model_armor_guard import ModelArmorGuard

guard = ModelArmorGuard(project_id="test-enterprise-ai", location="us-central1", template_id="secops-guardrail-prod")

def model_armor_input_guard(prompt_text: str) -> str:
    verdict = guard.inspect_prompt(prompt_text)
    if verdict.get("verdict") == "BLOCKED":
        raise PermissionError(f"Model Armor Guardrail Rejected Query: {verdict.get('matched_rules')}")
    return verdict.get("sanitized_prompt", prompt_text)

# LangChain LCEL Integration: chain = model_armor_guard | model | StrOutputParser()
model_armor_guard = RunnableLambda(model_armor_input_guard)

# Audit checkpoint [2026-07-21]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment

# Audit checkpoint [2026-08-04]: fix(guardrails): patch safety boundary bypass detection for client conversational agent

# Audit checkpoint [2026-08-15]: refactor(scoring): calibrate model vulnerability scoring formula for client audit
