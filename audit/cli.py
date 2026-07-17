# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI-SPR Assessment CLI Utility
Consolidated with scripts/cli/aispr_cli.py
Engineered by: @jsaccomani
"""

import sys
import os
import argparse
from typing import Dict, Any

# Ensure project root is in sys.path
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_proj_root = os.path.abspath(os.path.join(_cur_dir, ".."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from audit.questionnaire.handler import QuestionnaireHandler
from audit.engine.scorer import PostureScorer
from audit.engine.reporter import ExecutiveReporter


class AISPRAssessmentCLI:
    """
    Interactive and automated CLI tool for executing AI Security Posture Reviews at enterprise clients.
    """

    def __init__(self, client_name: str = "Enterprise Customer", project_name: str = "Gemini AI Core", assessor_name: str = "@jsaccomani"):
        self.client_name = client_name
        self.project_name = project_name
        self.assessor_name = assessor_name
        self.handler = QuestionnaireHandler()
        self.answers: Dict[str, Dict[str, Any]] = {}

    def print_banner(self):
        print("=" * 80)
        print("      @jsaccomani's AI-SPR (AI Security Posture Review) Assessment Tool       ")
        print("        Aligned with Google SAIF, NIST AI RMF 1.0, ISO 42001, & MITRE ATLAS    ")
        print("=" * 80)

    def run_interactive(self, output_file: str):
        self.print_banner()
        print(f"\n[+] Starting AI-SPR for Client: '{self.client_name}' - Scope: '{self.project_name}'")
        print(f"[+] Lead Assessor: {self.assessor_name}")
        print("[+] Instructions: For each question, answer [Y]es (fully met), [N]o (not met), [P]artial, or [NA] (Not Applicable).\n")

        for domain, questions in self.handler.question_db.items():
            print(f"\n{'='*20} Domain: {domain} {'='*20}")
            for q in questions:
                q_id = q["id"]
                crit = q.get("criticality", "MEDIUM")
                print(f"\n🔹 Control ID: [{q_id}] (Criticality: {crit})")
                print(f"   Question: {q['question']}")
                print(f"   Mapping : {q.get('framework_mapping', 'N/A')}")
                print(f"   Rationale: {q.get('rationale', 'N/A')}")

                status = ""
                while status not in ["y", "n", "p", "na"]:
                    status = input("   👉 Status (Y/N/P/NA): ").strip().lower()

                notes = input("   📝 Findings / Architectural Evidence: ").strip()
                self.handler.record_answer(q_id, status, notes, self.answers)

        self._finalize_and_report(output_file)

    def run_mock_demo(self, output_file: str):
        """
        Executes a pre-seeded mock assessment demonstrating automated scoring and report generation.
        """
        self.print_banner()
        print("\n[!] Running in Automated Demonstration / Mock Mode...")
        print(f"[+] Target Client: {self.client_name}")
        print(f"[+] Scope: {self.project_name}")

        mock_data = {
            "DAT-01": ("Y", "Lineage tracked in Cloud Data Catalog. Data originates from vetted internal databases."),
            "DAT-02": ("P", "Auditing configured at GCP project layer, but lacks pipeline-level metadata tracing for fine-tuning."),
            "DAT-03": ("N", "No active classification metadata schema is configured for prompt repositories."),
            "DAT-04": ("Y", "Untrusted user inputs and RAG reference corpus are strictly partitioned in memory scratchpads."),
            "MOD-01": ("Y", "Strict vetting of pre-trained models. Using standard Vertex Model Hub weights only."),
            "MOD-02": ("Y", "Leveraging Vertex AI Model Registry with automated semantic versioning."),
            "MOD-03": ("N", "Models are stored in GCS buckets lacking object creator ownership locks (vulnerable to Pickle hijack)."),
            "MOD-04": ("P", "Internal red-teaming performed once before launch, but no automated regression testing scheduled."),
            "APP-01": ("N", "Prompts are sent directly to the Vertex API without inline validation or screening."),
            "APP-02": ("N", "Model Armor is not yet configured or deployed for this project endpoint."),
            "APP-03": ("P", "Standard regex filters in place, but lacks Advanced DLP inspection (PII exfiltration not actively monitored)."),
            "APP-04": ("Y", "Tool bindings are restricted under OpenAPI strict JSON schemas."),
            "INF-01": ("Y", "Cloud Security Posture Review (CSPR) conducted in Q1 2026. Baseline controls validated."),
            "INF-02": ("P", "Vertex endpoints isolated with PSC, but training buckets are accessible over the internet via scoped SAs."),
            "INF-03": ("Y", "Service accounts adhere to least-privilege using role/aiplatform.user."),
            "INF-04": ("N", "Google-managed default encryption keys used. CMEK not configured."),
            "ASR-01": ("P", "Standard audit logs saved to Cloud Logging, but Prompt I/O streaming is not integrated into SecOps SIEM."),
            "ASR-02": ("N", "No detection alerts configured for model responses or input jailbreak spikes."),
            "ASR-03": ("N", "Incidents fall back to general IT playbooks. No AI-specific playbook defined."),
            "GOV-01": ("Y", "AI Ethics committee established and roles defined across the organization."),
            "GOV-02": ("N", "Supply chain not tracked. No AI-BOM exists for third-party libraries."),
            "GOV-03": ("P", "GDPR compliance evaluated for backend SQL datasets, but model weight retention policies are undocumented.")
        }

        for q_id, (status, notes) in mock_data.items():
            self.handler.record_answer(q_id, status, notes, self.answers)

        self._finalize_and_report(output_file)

    def _finalize_and_report(self, output_file: str):
        scores = PostureScorer.calculate_scores(self.answers, self.handler.question_db)
        reporter = ExecutiveReporter(
            client_name=self.client_name,
            project_name=self.project_name,
            assessor_name=self.assessor_name
        )
        saved_path = reporter.save_report(self.answers, self.handler.question_db, output_file)
        print("\n" + "=" * 80)
        print("                     AI-SPR ASSESSMENT SUMMARY RESULTS                          ")
        print("=" * 80)
        print(f"📊 Overall Score   : {scores['overall_percentage']}%")
        print(f"🛡️  Posture Tier    : {scores['posture_tier']}")
        print(f"📈 Points Earned   : {scores['overall_earned']} / {scores['overall_possible']}")
        print(f"\n✅ Executive Assessment Report saved successfully to:")
        print(f"   👉 {os.path.abspath(saved_path)}\n")


def main():
    """Delegates to the consolidated unified CLI entrypoint."""
    from scripts.cli.aispr_cli import main as master_main
    if len(sys.argv) > 1 and sys.argv[1] not in ["audit", "scan", "redteam", "guard", "multicloud", "dashboard", "-h", "--help"]:
        sys.argv.insert(1, "audit")
    elif len(sys.argv) == 1:
        sys.argv.append("audit")
    master_main()


if __name__ == "__main__":
    main()

# Audit checkpoint [2026-07-17]: fix(prompt-defense): adjust prompt injection heuristic thresholds for client customer-service bot
