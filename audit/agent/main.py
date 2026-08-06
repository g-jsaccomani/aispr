# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Multi-Cloud AI-SPR Copilot Entrypoint
Engineered by: @jsaccomani
"""

import os
import sys
from typing import Dict, Any

# Ensure parent and current directories are in path
current_dir = os.path.dirname(os.path.abspath(__file__))
audit_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(audit_dir)
for p in [root_dir, audit_dir, current_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from audit.agent import tools
from audit.questionnaire.handler import QuestionnaireHandler
from audit.engine.reporter import ExecutiveReporter
from audit.engine.scorer import PostureScorer


class AISPRCopilot:
    """
    Conversational AI Copilot coordinating interactive security reviews,
    SCC risk telemetry ingest, and automated deliverable report generation.
    """

    def __init__(self, questions_path: str = None):
        self.model = "gemini-2.5-pro"
        self.questions_handler = QuestionnaireHandler(questions_path)

    def on_user_message(self, message: str, session_state: Dict[str, Any]) -> str:
        """
        Coordinates conversational loops, active GCP resource scans, and compliance evaluations.
        """
        msg = message.strip()

        # Step 1: Request Project ID
        if "project_id" not in session_state:
            session_state["project_id"] = msg if msg and not msg.lower().startswith("hello") and not msg.lower().startswith("hi") else None
            if not session_state["project_id"]:
                return (
                    "Welcome. I am your **AI Security Posture Review (AI-SPR)** Copilot, engineered by @jsaccomani.\n\n"
                    "To begin evaluating your environment's posture against Google SAIF, NIST AI RMF, and ISO 42001, "
                    "please enter your **GCP Project ID**."
                )

        # Step 2: Trigger SCC Scan for Project ID
        if session_state.get("project_id") and not session_state.get("scc_scanned", False):
            project_id = session_state["project_id"]
            session_state["scc_scanned"] = True
            
            findings = tools.fetch_scc_ai_findings(project_id)
            session_state["scc_findings"] = findings
            
            return (
                f"✅ Pre-flight security scan completed for project `{project_id}`.\n\n"
                f"🚨 Detected **{len(findings)} active risks** in Security Command Center AI Protection:\n"
                + "\n".join([f"  • {f}" for f in findings]) + "\n\n"
                "We are ready to start the interactive AI-SPR Questionnaire.\n"
                "Type **'Start Questionnaire'** to begin."
            )

        # Step 3: Report Generation
        if msg.lower() == "generate report" or msg.lower() == "report":
            answers = session_state.get("answers", {})
            if not answers:
                return "⚠️ No questionnaire answers recorded yet. Please complete the assessment first by typing **'Start Questionnaire'**."
            
            reporter = ExecutiveReporter(
                client_name=session_state.get("client_name", "Enterprise Customer"),
                project_name=session_state.get("project_id", "GenAI Workload")
            )
            report_md = reporter.build_markdown_report(answers, self.questions_handler.question_db)
            session_state["last_report"] = report_md
            
            scores = PostureScorer.calculate_scores(answers, self.questions_handler.question_db)
            return (
                f"📄 **Executive Assessment Report Compiled Successfully!**\n\n"
                f"• Overall Score: `{scores['overall_percentage']}%` ({scores['posture_tier']})\n"
                f"• Points: `{scores['overall_earned']} / {scores['overall_possible']}`\n\n"
                "```markdown\n"
                + report_md[:1200] + "\n...\n[Report truncated for chat display. Full deliverable saved to state.]\n```"
            )

        # Step 4: Questionnaire Progression
        if session_state.get("quiz_active", False) or msg.lower() == "start questionnaire":
            session_state["quiz_active"] = True
            return self.questions_handler.get_next_step(msg, session_state)
            
        return "Command not recognized. Type **'Start Questionnaire'**, **'Generate Report'**, or enter your **GCP Project ID**."

# Audit checkpoint [2026-04-30]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout

# Audit checkpoint [2026-08-03]: feat(rag-security): implement vector database access control validation for client

# Audit checkpoint [2026-08-06]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout
