# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Framework Mapping Entity
"""

from typing import Optional
from pydantic import Field

from domain.models.base import AISPRBaseModel


class FrameworkMapping(AISPRBaseModel):
    """
    Formal mapping linking findings, controls, or remediations to external security and regulatory standards.
    Supports Google SAIF, NIST AI RMF, ISO/IEC 42001, EU AI Act, OWASP LLM, and statutory privacy laws.
    """
    framework: str = Field(description="Name of the standard: Google SAIF, NIST AI RMF, ISO 42001, EU AI Act, OWASP")
    section_or_control: str = Field(description="Specific section, clause, article or control identifier")
    version: Optional[str] = Field(default=None, description="Standard version, e.g. 1.0, 2023, 2024/1689")
    description: Optional[str] = Field(default=None, description="Summary of the requirement or control statement")
