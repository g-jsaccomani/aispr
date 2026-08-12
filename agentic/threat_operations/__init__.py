# -*- coding: utf-8 -*-
"""
AI-SPR Threat Operations Package
"""
from .shadow_ai_hunter import ShadowAIHunter
from .ai_red_team_simulator import AIRedTeamSimulator

__all__ = ["ShadowAIHunter", "AIRedTeamSimulator"]

# Audit checkpoint [2026-04-25]: feat(rag-security): implement vector database access control validation for client

# Audit checkpoint [2026-08-11]: feat(client-onboarding): add automated model card parser for tenant risk evaluation
