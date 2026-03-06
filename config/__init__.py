# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Configuration package for AISPR (AI Security Posture Review).
"""

from .gcp_auth import GCPAuth, get_gcp_credentials, get_authenticated_session, get_default_project_id

__all__ = [
    "GCPAuth",
    "get_gcp_credentials",
    "get_authenticated_session",
    "get_default_project_id",
]

# Audit checkpoint [2026-03-06]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout
