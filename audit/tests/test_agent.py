# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

State Machine and Conversational Copilot Integration Tests
Engineered by: @jsaccomani
"""

import unittest
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
audit_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(audit_dir)
for p in [root_dir, audit_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from audit.agent.main import AISPRCopilot


class TestCopilotAgent(unittest.TestCase):

    def test_copilot_greeting_and_project_prompt(self):
        copilot = AISPRCopilot()
        state = {}
        response = copilot.on_user_message("Hello", state)
        self.assertIn("GCP Project ID", response)
        self.assertIsNone(state.get("project_id"))

    def test_copilot_scc_scan_trigger(self):
        copilot = AISPRCopilot()
        state = {}
        res1 = copilot.on_user_message("my-genai-prod-project", state)
        self.assertIn("Pre-flight security scan completed", res1)
        self.assertEqual(state.get("project_id"), "my-genai-prod-project")
        self.assertTrue(state.get("scc_scanned"))
        self.assertGreater(len(state.get("scc_findings", [])), 0)

    def test_copilot_questionnaire_loop(self):
        copilot = AISPRCopilot()
        state = {"project_id": "my-project", "scc_scanned": True}
        
        # Start Questionnaire
        res = copilot.on_user_message("Start Questionnaire", state)
        self.assertIn("Domain:", res)
        self.assertIn("[DAT-01]", res)
        self.assertTrue(state.get("quiz_active"))


if __name__ == "__main__":
    unittest.main()
