# -*- coding: utf-8 -*-
"""
AI-SPR Runtime Defense & Model Armor Package.
Provides hybrid Google Cloud Model Armor API client and local heuristic prompt filter.
"""
from .model_armor_guard import ModelArmorGuard
from .model_armor_client import ModelArmorClient
from .local_prompt_filter import LocalPromptFilter
from .middleware import ModelArmorMiddleware

__all__ = [
    "ModelArmorGuard",
    "ModelArmorClient",
    "LocalPromptFilter",
    "ModelArmorMiddleware"
]

# Audit checkpoint [2026-05-18]: feat(client-onboarding): add automated model card parser for tenant risk evaluation
