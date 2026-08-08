# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI-SPR Posture Scoring and Risk Evaluation Engine
Engineered by: @jsaccomani
"""

from typing import Dict, List, Any, Tuple


class PostureScorer:
    """
    Evaluates assessment responses, computes domain-level and overall compliance scores,
    classifies the organizational security posture tier, and prioritizes remediation gaps.
    """

    POSTURE_TIERS = {
        "SECURE": "SECURE",
        "MODERATE": "MODERATE / DRIFT DETECTED",
        "CRITICAL": "CRITICAL / VULNERABLE"
    }

    @staticmethod
    def calculate_scores(answers: Dict[str, Dict[str, Any]], question_db: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Computes earned vs possible points per domain and overall percentage.
        Scores:
          - Yes (Y): 1.0
          - Partial (P): 0.5
          - No (N): 0.0
          - Not Applicable (NA): -1.0 (excluded from calculations)
        """
        domain_scores = {}
        overall_earned = 0.0
        overall_possible = 0.0

        for domain, questions in question_db.items():
            earned = 0.0
            possible = 0.0
            for q in questions:
                q_id = q["id"]
                ans = answers.get(q_id)
                if ans and ans.get("score") is not None and ans.get("score") != -1.0:
                    earned += float(ans["score"])
                    possible += 1.0

            percentage = (earned / possible * 100.0) if possible > 0 else 100.0
            domain_scores[domain] = {
                "earned": earned,
                "possible": possible,
                "percentage": round(percentage, 2)
            }
            overall_earned += earned
            overall_possible += possible

        overall_percentage = (overall_earned / overall_possible * 100.0) if overall_possible > 0 else 100.0
        overall_percentage = round(overall_percentage, 2)

        # Classify Posture Tier
        if overall_percentage >= 80.0:
            tier = PostureScorer.POSTURE_TIERS["SECURE"]
        elif overall_percentage >= 50.0:
            tier = PostureScorer.POSTURE_TIERS["MODERATE"]
        else:
            tier = PostureScorer.POSTURE_TIERS["CRITICAL"]

        return {
            "domains": domain_scores,
            "overall_percentage": overall_percentage,
            "overall_earned": overall_earned,
            "overall_possible": overall_possible,
            "posture_tier": tier
        }

    @staticmethod
    def extract_prioritized_gaps(answers: Dict[str, Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Extracts and prioritizes remediation gaps into:
          - Priority 1: High Criticality Gaps (Immediate Remediation required)
          - Priority 2: Medium/Low Criticality Gaps (Next 30-60 Days)
        """
        high_gaps = []
        med_gaps = []

        for q_id, ans in answers.items():
            status = ans.get("status", "").upper()
            if status in ["N", "P"]:
                item = {
                    "id": q_id,
                    "question_text": ans.get("question_text", ""),
                    "status": status,
                    "score": ans.get("score", 0.0),
                    "criticality": ans.get("criticality", "MEDIUM"),
                    "framework_mapping": ans.get("framework_mapping", ""),
                    "rationale": ans.get("rationale", ""),
                    "notes": ans.get("notes", "No specific architectural findings documented.")
                }
                if item["criticality"] == "HIGH":
                    high_gaps.append(item)
                else:
                    med_gaps.append(item)

        return high_gaps, med_gaps

# Audit checkpoint [2026-05-21]: feat(telemetry): add structured security audit events for client inference endpoints

# Audit checkpoint [2026-08-08]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment
