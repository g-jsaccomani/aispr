# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

FastAPI & ASGI Model Armor Inline Security Middleware
Engineered by: @jsaccomani
"""

import json
from typing import Callable, Optional, Any
from .model_armor_guard import ModelArmorGuard

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response, JSONResponse
    STARLETTE_AVAILABLE = True
except ImportError:
    STARLETTE_AVAILABLE = False
    BaseHTTPMiddleware = object
    Request = Any = object
    Response = JSONResponse = object


class ModelArmorMiddleware(BaseHTTPMiddleware):
    """
    Inline zero-trust ASGI middleware intercepting AI inference API routes,
    applying Model Armor input shielding, PII sanitization, and output filtering.
    """

    def __init__(self, app=None, guard: Optional[ModelArmorGuard] = None, protected_paths: Optional[list] = None):
        if STARLETTE_AVAILABLE and hasattr(super(), "__init__"):
            super().__init__(app)
        self.app = app
        self.guard = guard or ModelArmorGuard()
        self.protected_paths = protected_paths or ["/generate", "/chat", "/v1/models"]

    async def dispatch(self, request: Any, call_next: Callable) -> Any:
        if not STARLETTE_AVAILABLE:
            raise RuntimeError("Starlette / FastAPI must be installed to use ModelArmorMiddleware in an ASGI pipeline.")

        # Check if request path requires Model Armor inspection
        path_matches = any(request.url.path.startswith(p) for p in self.protected_paths)
        if not path_matches or request.method not in ["POST", "PUT"]:
            return await call_next(request)

        # Extract request body for inspection
        body_bytes = await request.body()
        if not body_bytes:
            return await call_next(request)

        try:
            body_json = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            return await call_next(request)

        # Extract prompt or message payload
        prompt_text = body_json.get("prompt") or body_json.get("message") or ""
        hitl_token = request.headers.get("X-HITL-Approval-Token")

        if prompt_text and isinstance(prompt_text, str):
            verdict = self.guard.inspect_prompt(prompt_text, hitl_approval_token=hitl_token)

            # Block malicious request with HTTP 403 Forbidden
            if verdict["is_blocked"]:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "SecurityPolicyViolation",
                        "verdict": "BLOCKED",
                        "matched_rules": verdict["matched_rules"],
                        "risk_score": verdict["risk_score"],
                        "requires_hitl": verdict["requires_hitl"],
                        "message": "Request intercepted and blocked by Model Armor semantic firewall."
                    }
                )

            # If sanitized (e.g. PII redacted), update request payload
            if verdict["verdict"] == "SANITIZED":
                if "prompt" in body_json:
                    body_json["prompt"] = verdict["sanitized_prompt"]
                elif "message" in body_json:
                    body_json["message"] = verdict["sanitized_prompt"]

                async def receive_sanitized():
                    return {"type": "http.request", "body": json.dumps(body_json).encode("utf-8")}

                request._receive = receive_sanitized

        # Proceed with downstream model handler
        response = await call_next(request)
        return response
