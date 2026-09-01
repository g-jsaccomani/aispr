# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Attack Technique Entity
"""

from typing import Optional
from pydantic import Field

from domain.models.base import AISPRBaseModel


class AttackTechnique(AISPRBaseModel):
    """
    Adversarial technique or tactic from MITRE ATLAS or OWASP GenAI Security.
    """
    technique_id: str = Field(description="Technique ID, e.g., AML.T0054 or LLM01")
    name: str = Field(description="Technique name, e.g., LLM Jailbreak or Insecure Output Handling")
    framework: str = Field(default="MITRE ATLAS", description="Taxonomy source (MITRE ATLAS, OWASP LLM)")
    tactic: Optional[str] = Field(default=None, description="Tactic category, e.g., Initial Access, Execution, Exfiltration")
    description: Optional[str] = None
    reference_url: Optional[str] = None
