# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 9: Enterprise Shadow AI Discovery - Multi-Vector Risk Engine.
Evaluates:
  - external exposure
  - data sensitivity
  - identity privilege
  - missing governance
  - model provenance
  - public endpoint
  - unauthorized deployment
"""

from typing import List, Dict, Any, Tuple
from domain.enums import FindingSeverity
from .models import ShadowAIRiskFactor


class ShadowAIRiskEngine:
    """
    Evaluates multi-vector risk factors for discovered unmanaged AI assets.
    """

    WEIGHTS = {
        ShadowAIRiskFactor.PUBLIC_ENDPOINT: 25.0,
        ShadowAIRiskFactor.EXTERNAL_EXPOSURE: 20.0,
        ShadowAIRiskFactor.IDENTITY_PRIVILEGE: 20.0,
        ShadowAIRiskFactor.DATA_SENSITIVITY: 15.0,
        ShadowAIRiskFactor.UNAUTHORIZED_DEPLOYMENT: 10.0,
        ShadowAIRiskFactor.MISSING_GOVERNANCE: 10.0,
        ShadowAIRiskFactor.MODEL_PROVENANCE: 10.0,
    }

    @classmethod
    def evaluate_risk(
        cls,
        is_public: bool = False,
        has_external_exposure: bool = False,
        is_high_privilege: bool = False,
        handles_sensitive_data: bool = False,
        is_unauthorized: bool = True,
        is_missing_governance: bool = True,
        is_unverified_provenance: bool = False,
    ) -> Tuple[float, FindingSeverity, List[ShadowAIRiskFactor]]:
        """
        Computes composite risk score, severity tier, and detected risk factors.
        """
        factors: List[ShadowAIRiskFactor] = []
        score = 0.0

        if is_public:
            factors.append(ShadowAIRiskFactor.PUBLIC_ENDPOINT)
            score += cls.WEIGHTS[ShadowAIRiskFactor.PUBLIC_ENDPOINT]

        if has_external_exposure or is_public:
            if ShadowAIRiskFactor.EXTERNAL_EXPOSURE not in factors:
                factors.append(ShadowAIRiskFactor.EXTERNAL_EXPOSURE)
                score += cls.WEIGHTS[ShadowAIRiskFactor.EXTERNAL_EXPOSURE]

        if is_high_privilege:
            factors.append(ShadowAIRiskFactor.IDENTITY_PRIVILEGE)
            score += cls.WEIGHTS[ShadowAIRiskFactor.IDENTITY_PRIVILEGE]

        if handles_sensitive_data:
            factors.append(ShadowAIRiskFactor.DATA_SENSITIVITY)
            score += cls.WEIGHTS[ShadowAIRiskFactor.DATA_SENSITIVITY]

        if is_unauthorized:
            factors.append(ShadowAIRiskFactor.UNAUTHORIZED_DEPLOYMENT)
            score += cls.WEIGHTS[ShadowAIRiskFactor.UNAUTHORIZED_DEPLOYMENT]

        if is_missing_governance:
            factors.append(ShadowAIRiskFactor.MISSING_GOVERNANCE)
            score += cls.WEIGHTS[ShadowAIRiskFactor.MISSING_GOVERNANCE]

        if is_unverified_provenance:
            factors.append(ShadowAIRiskFactor.MODEL_PROVENANCE)
            score += cls.WEIGHTS[ShadowAIRiskFactor.MODEL_PROVENANCE]

        # Clamp score between 0.0 and 100.0
        final_score = min(max(score, 0.0), 100.0)

        # Determine severity tier
        if final_score >= 75.0:
            severity = FindingSeverity.CRITICAL
        elif final_score >= 50.0:
            severity = FindingSeverity.HIGH
        elif final_score >= 25.0:
            severity = FindingSeverity.MEDIUM
        else:
            severity = FindingSeverity.LOW

        return final_score, severity, factors
