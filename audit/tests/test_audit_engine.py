# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AI-SPR Scoring Engine, Questionnaire Handler, and Reporter
Engineered by: @jsaccomani
"""

import unittest
import os
import sys
import tempfile

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
audit_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(audit_dir)
for p in [root_dir, audit_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from audit.engine.scorer import PostureScorer
from audit.engine.reporter import ExecutiveReporter
from audit.questionnaire.handler import QuestionnaireHandler


class TestAuditEngine(unittest.TestCase):

    def setUp(self):
        self.sample_question_db = {
            "Domain A": [
                {"id": "DOM-01", "question": "Question 1?", "criticality": "HIGH", "framework_mapping": "ISO 42001", "rationale": "Rationale 1"},
                {"id": "DOM-02", "question": "Question 2?", "criticality": "MEDIUM", "framework_mapping": "NIST AI RMF", "rationale": "Rationale 2"}
            ]
        }

    def test_scorer_all_yes(self):
        answers = {
            "DOM-01": {"score": 1.0, "status": "Y", "criticality": "HIGH"},
            "DOM-02": {"score": 1.0, "status": "Y", "criticality": "MEDIUM"}
        }
        result = PostureScorer.calculate_scores(answers, self.sample_question_db)
        self.assertEqual(result["overall_percentage"], 100.0)
        self.assertEqual(result["posture_tier"], "SECURE")
        self.assertEqual(result["overall_earned"], 2.0)
        self.assertEqual(result["overall_possible"], 2.0)

    def test_scorer_partial_and_no(self):
        answers = {
            "DOM-01": {"score": 0.0, "status": "N", "criticality": "HIGH", "question_text": "Q1", "notes": "Missing control"},
            "DOM-02": {"score": 0.5, "status": "P", "criticality": "MEDIUM", "question_text": "Q2", "notes": "Partially in place"}
        }
        result = PostureScorer.calculate_scores(answers, self.sample_question_db)
        self.assertEqual(result["overall_percentage"], 25.0)
        self.assertEqual(result["posture_tier"], "CRITICAL / VULNERABLE")
        
        high_gaps, med_gaps = PostureScorer.extract_prioritized_gaps(answers)
        self.assertEqual(len(high_gaps), 1)
        self.assertEqual(high_gaps[0]["id"], "DOM-01")
        self.assertEqual(len(med_gaps), 1)
        self.assertEqual(med_gaps[0]["id"], "DOM-02")

    def test_questionnaire_handler_load(self):
        handler = QuestionnaireHandler()
        self.assertGreaterEqual(handler.get_total_questions(), 100)
        self.assertTrue(any("Data Security" in k for k in handler.question_db))
        self.assertTrue(any("Governance" in k for k in handler.question_db))

    def test_executive_reporter_generation(self):
        reporter = ExecutiveReporter(client_name="Test Corp", project_name="Gemini Test")
        answers = {
            "DOM-01": {"score": 1.0, "status": "Y", "criticality": "HIGH", "notes": "Fully met", "framework_mapping": "ISO 42001", "rationale": "Rat"},
            "DOM-02": {"score": 0.0, "status": "N", "criticality": "MEDIUM", "notes": "Not met", "framework_mapping": "NIST", "rationale": "Rat"}
        }
        md = reporter.build_markdown_report(answers, self.sample_question_db)
        self.assertIn("AI Security Posture Review (AI-SPR)", md)
        self.assertIn("Consolidated Executive Report", md)
        self.assertIn("Test Corp", md)
        self.assertIn("Gemini Test", md)
        self.assertIn("Priority 2: Medium Severity", md)

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = os.path.join(tmp_dir, "test_report.md")
            reporter.save_report(answers, self.sample_question_db, output_path)
            self.assertTrue(os.path.exists(output_path))


if __name__ == "__main__":
    unittest.main()
