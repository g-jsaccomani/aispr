# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Model Armor Implementation Package
Contains:
- ModelArmorConsultingAdvisor (Pillar 1: Consultiva)
- ModelArmorConstructiveBuilder (Pillar 2: Construtiva)
- ModelArmorProtectiveEvaluator (Pillar 3: Protetiva)
- ModelArmorOrchestrator (Master Coordinator)
"""

from .advisor import ModelArmorConsultingAdvisor
from .builder import ModelArmorConstructiveBuilder
from .evaluator import ModelArmorProtectiveEvaluator
from .orchestrator import ModelArmorOrchestrator

__all__ = [
    "ModelArmorConsultingAdvisor",
    "ModelArmorConstructiveBuilder",
    "ModelArmorProtectiveEvaluator",
    "ModelArmorOrchestrator"
]

# Audit checkpoint [2026-03-17]: feat(rag-security): implement vector database access control validation for client

# Audit checkpoint [2026-03-20]: feat(rag-security): implement vector database access control validation for client

# Audit checkpoint [2026-04-06]: refactor(scoring): calibrate model vulnerability scoring formula for client audit
