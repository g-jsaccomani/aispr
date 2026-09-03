# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 8: Controlled Adversarial Validation Engine Package.
"""

from .models import (
    AttackOutcome,
    AdversarialCategory,
    MitreAtlasTechnique,
    AdversarialTest,
    AdversarialCampaignReport,
    CATEGORY_TO_MITRE_MAP,
)
from .safety import (
    TargetAuthorizationGate,
    AdversarialSafetyError,
    UnauthorizedTargetError,
    DestructiveActionBlockedError,
)
from .evaluator import AttackOutcomeEvaluator
from .catalog import AdversarialCatalog
from .engine import AdversarialValidationEngine

__all__ = [
    "AttackOutcome",
    "AdversarialCategory",
    "MitreAtlasTechnique",
    "AdversarialTest",
    "AdversarialCampaignReport",
    "CATEGORY_TO_MITRE_MAP",
    "TargetAuthorizationGate",
    "AdversarialSafetyError",
    "UnauthorizedTargetError",
    "DestructiveActionBlockedError",
    "AttackOutcomeEvaluator",
    "AdversarialCatalog",
    "AdversarialValidationEngine",
]
