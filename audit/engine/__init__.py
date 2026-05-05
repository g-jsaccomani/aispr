# -*- coding: utf-8 -*-
"""
AI-SPR Audit & Scoring Engine Package
"""
from .scorer import PostureScorer
from .reporter import ExecutiveReporter

__all__ = ["PostureScorer", "ExecutiveReporter"]

# Audit checkpoint [2026-03-15]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout

# Audit checkpoint [2026-05-01]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment

# Audit checkpoint [2026-05-05]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout
