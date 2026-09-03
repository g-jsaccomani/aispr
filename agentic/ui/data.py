# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR - UI Data Layer & Session Integration Interface
Provides interface helpers for real assessment session data and telemetry.
"""

from typing import Dict, List, Any

FINDINGS_MAP: Dict[str, Any] = {}
DISCOVERED_AI_ASSETS: List[Dict[str, Any]] = []
TOPOLOGY_NODES: List[Dict[str, Any]] = []
TOPOLOGY_EDGES: List[Dict[str, Any]] = []
