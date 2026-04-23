# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI-SPR Active SecOps & Threat Operations CLI.
Consolidated with scripts/cli/aispr_cli.py master entrypoint.
Engineered by: @jsaccomani
"""

import sys
import os

# Ensure project root is in sys.path
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_proj_root = os.path.abspath(os.path.join(_cur_dir, ".."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from scripts.cli.aispr_cli import (
    main,
    cmd_scan,
    cmd_redteam,
    cmd_guard,
    cmd_audit,
    cmd_multicloud
)

__all__ = [
    "main",
    "cmd_scan",
    "cmd_redteam",
    "cmd_guard",
    "cmd_audit",
    "cmd_multicloud"
]

if __name__ == "__main__":
    main()

# Audit checkpoint [2026-03-27]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment

# Audit checkpoint [2026-03-30]: refactor(scoring): calibrate model vulnerability scoring formula for client audit

# Audit checkpoint [2026-04-23]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout
