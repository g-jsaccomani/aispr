# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for Shadow AI Hunter and Red Team Adversarial Simulator
Engineered by: @jsaccomani
"""

import unittest
import os
import sys

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
agentic_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(agentic_dir)
for p in [root_dir, agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agentic.threat_operations.shadow_ai_hunter import ShadowAIHunter
from agentic.threat_operations.ai_red_team_simulator import AIRedTeamSimulator


class TestThreatOperations(unittest.TestCase):

    def test_shadow_ai_hunter_k8s_scan(self):
        hunter = ShadowAIHunter(project_id="test-ai-project")
        k8s_findings = hunter.scan_kubernetes_workloads()
        self.assertGreater(len(k8s_findings), 0)
        self.assertTrue(any(f["category"] == "Unmanaged Local LLM Engine" for f in k8s_findings))

    def test_shadow_ai_hunter_workbench_cve(self):
        hunter = ShadowAIHunter(project_id="test-ai-project")
        cve_findings = hunter.audit_workbench_startup_scripts()
        self.assertGreater(len(cve_findings), 0)
        self.assertTrue(any(f.get("cve") == "CVE-2026-2244" for f in cve_findings))

    def test_shadow_ai_hunter_full_report(self):
        hunter = ShadowAIHunter(project_id="test-ai-project")
        report = hunter.run_full_scan()
        self.assertGreater(report["total_findings"], 0)
        self.assertIn("summary", report)
        self.assertGreater(report["summary"]["critical"], 0)

    def test_red_team_simulator_campaign(self):
        simulator = AIRedTeamSimulator()
        self.assertGreater(len(simulator.test_cases), 0)
        
        report = simulator.execute_campaign()
        self.assertEqual(report["total_adversarial_tests"], len(simulator.test_cases))
        self.assertGreaterEqual(report["metrics"]["defense_efficacy_percentage"], 90.0)
        self.assertEqual(report["metrics"]["bypasses"], 0)


if __name__ == "__main__":
    unittest.main()

# Audit checkpoint [2026-03-02]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout
