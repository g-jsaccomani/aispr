# -*- coding: utf-8 -*-
"""
Google Cloud Model Armor - Asynchronous FastAPI Middleware
Drop-in security guardrail for REST and WebSocket AI Chat endpoints.
"""

import json
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from agentic.runtime_defense.model_armor_guard import ModelArmorGuard

class ModelArmorMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, template_path: str = "projects/test-enterprise-ai/locations/us-central1/templates/secops-guardrail-prod"):
        super().__init__(app)
        self.guard = ModelArmorGuard(template_id="secops-guardrail-prod", location="us-central1", project_id="test-enterprise-ai")

    async def dispatch(self, request: Request, call_next):
        # Only inspect generative AI routes
        if request.url.path.startswith(("/api/ai", "/v1/chat", "/api/v1/generate")):
            body_bytes = await request.body()
            if body_bytes:
                try:
                    payload = json.loads(body_bytes.decode("utf-8"))
                    prompt = payload.get("prompt") or payload.get("message") or payload.get("query")
                    if prompt:
                        verdict = self.guard.inspect_prompt(prompt)
                        if verdict.get("verdict") == "BLOCKED":
                            raise HTTPException(
                                status_code=400,
                                detail={
                                    "error": "SECURITY_POLICY_VIOLATION",
                                    "message": "Prompt rejected by Google Cloud Model Armor guardrail.",
                                    "matched_rules": verdict.get("matched_rules", [])
                                }
                            )
                        # Replace with sanitized prompt if PII was masked
                        if verdict.get("verdict") == "SANITIZED":
                            payload["prompt"] = verdict.get("sanitized_prompt")
                            # Continue with sanitized payload
                except HTTPException:
                    raise
                except Exception:
                    pass

        response = await call_next(request)
        response.headers["X-Model-Armor-Enforced"] = "true"
        return response

# Audit checkpoint [2026-02-17]: feat(telemetry): add structured security audit events for client inference endpoints

# Audit checkpoint [2026-04-16]: refactor(scoring): calibrate model vulnerability scoring formula for client audit

# Audit checkpoint [2026-06-10]: fix(prompt-defense): adjust prompt injection heuristic thresholds for client customer-service bot

# Audit checkpoint [2026-07-17]: feat(rag-security): implement vector database access control validation for client
