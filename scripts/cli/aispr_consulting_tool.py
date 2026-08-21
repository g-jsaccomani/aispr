# -*- coding: utf-8 -*-
"""
@jsaccomani's AI-SPR Consulting & Posture Assessment Tool
Format: Python 3 CLI Utility
Version: 1.0.0
Author: @jsaccomani
Purpose: Structured, non-agentic interactive assessment framework for PSO consultants to execute at clients.
        Covers the 6 core Google PSO AI-SPR domains, calculates risk scores, and generates deliverable markdown reports.
"""

import json
import os
import datetime
from typing import Dict, List, Any

# Embedded core questions database representative of the 104 AI-SPR Technical Questionnaire
AI_SPR_QUESTION_DB = {
    "1. Data Security & Integrity": [
        {
            "id": "DAT-01",
            "question": "Do you know the origin, lineage, and authenticity of the private data used for model tuning, training, or RAG data augmentation?",
            "framework_mapping": "ISO 42001 (A.8.2.1), NIST AI RMF (GOVERN 1.2)",
            "rationale": "Prevents data poisoning and lineage corruption in active prompt/retrieval perimeters.",
            "criticality": "HIGH"
        },
        {
            "id": "DAT-02",
            "question": "Do you have a clear, centralized audit log of data access and modification activities for model training and fine-tuning pipelines?",
            "framework_mapping": "ISO 42001 (A.8.4), NIST AI RMF (MEASURE 2.10)",
            "rationale": "Ensures traceability of fine-tuning pipelines and compliance with audit standards.",
            "criticality": "HIGH"
        },
        {
            "id": "DAT-03",
            "question": "Do you have a data classification schema that is reflected and tracked in the application classification and lineage?",
            "framework_mapping": "ISO 42001 (A.8.2), NIST AI RMF (MEASURE 2.7)",
            "rationale": "Directs the setup of Sensitive Data Protection (DLP) inline redaction rules and access control.",
            "criticality": "MEDIUM"
        },
        {
            "id": "DAT-04",
            "question": "Do you mix untrusted and trusted data in the same application, potentially leading to inconsistent or contaminated results?",
            "framework_mapping": "ISO 42001 (A.8.2), OWASP LLM-06",
            "rationale": "Mixing data tiers without clear logical boundaries is a major RAG poisoning vector.",
            "criticality": "HIGH"
        }
    ],
    "2. Model Hardening & Management": [
        {
            "id": "MOD-01",
            "question": "How do you select and evaluate pre-trained foundation models, considering security, licenses, and suitability?",
            "framework_mapping": "ISO 42001 (A.8.3), NIST AI RMF (MAP 1.5)",
            "rationale": "Minimizes third-party supply chain risk from unvetted or vulnerable neural weights.",
            "criticality": "MEDIUM"
        },
        {
            "id": "MOD-02",
            "question": "Do you have a defined, version-controlled process for managing and cataloging your models (e.g., Vertex AI Model Registry)?",
            "framework_mapping": "ISO 42001 (A.8.4), NIST AI RMF (MANAGE 2.1)",
            "rationale": "Ensures reproducibility, rapid rollback, and strict control over model deployment states.",
            "criticality": "HIGH"
        },
        {
            "id": "MOD-03",
            "question": "Do you validate the integrity of your training data and protect your trained model files from unauthorized modifications or serialization hijack (e.g., Pickle-in-the-Middle)?",
            "framework_mapping": "ISO 42001 (A.8.4.1), OWASP LLM-03",
            "rationale": "Protects against malicious model uploads causing Cross-Tenant RCE or backdoor deployments.",
            "criticality": "HIGH"
        },
        {
            "id": "MOD-04",
            "question": "Do you conduct regular security assessments, red-teaming exercises, or adversarial testing on your deployed models?",
            "framework_mapping": "ISO 42001 (A.10.2.1), MITRE ATLAS",
            "rationale": "Verifies empirical model resilience against evasion, prompt injection, and extraction attacks.",
            "criticality": "MEDIUM"
        }
    ],
    "3. Application Security & Protection": [
        {
            "id": "APP-01",
            "question": "Do you validate and sanitize user input prompts to prevent prompt injection, jailbreaking, and malicious formatting?",
            "framework_mapping": "NIST AI RMF (MANAGE 2.4), OWASP LLM-01",
            "rationale": "Core application-layer boundary protection against semantic bypass attacks.",
            "criticality": "HIGH"
        },
        {
            "id": "APP-02",
            "question": "Do you use a Web Application Firewall (WAF) or semantic gateway (such as Model Armor) to protect your AI endpoints?",
            "framework_mapping": "SAIF Pillar 1, OWASP LLM-01",
            "rationale": "Provides a robust inline filtering layer for both input prompts and model output responses.",
            "criticality": "HIGH"
        },
        {
            "id": "APP-03",
            "question": "How do you detect and prevent confidential data/PII leakage in prompt queries or generated output responses?",
            "framework_mapping": "ISO 42001 (A.8.5), NIST AI RMF (MEASURE 2.10)",
            "rationale": "Prevents accidental exfiltration of regulated information to third-party endpoints or unauthorized users.",
            "criticality": "HIGH"
        },
        {
            "id": "APP-04",
            "question": "If you utilize agents, plugins, or tool calling, do you enforce strict input/output schema validation and rate limiting?",
            "framework_mapping": "ISO 42001 (A.8.3.2), OWASP LLM-07 (Excessive Agency)",
            "rationale": "Limits the blast radius if an LLM generates unexpected tool parameters or is forced into infinite loops.",
            "criticality": "HIGH"
        }
    ],
    "4. Infrastructure Security & Isolation": [
        {
            "id": "INF-01",
            "question": "Have you completed a Cloud Security Posture Review (CSPR) to validate project isolation and identity boundaries?",
            "framework_mapping": "GCP Security Blueprint, SAIF Pillar 1",
            "rationale": "Infrastructure security is the foundation. Misconfigured IAM or networking compromises the AI layer.",
            "criticality": "HIGH"
        },
        {
            "id": "INF-02",
            "question": "Do you utilize VPC Service Controls (VPC-SC) or private endpoints (PSC) to isolate model endpoints and sensitive databases?",
            "framework_mapping": "NIST AI RMF (MEASURE 2.10), SAIF Pillar 1",
            "rationale": "Guarantees network-level isolation, preventing data exfiltration outside the defined enterprise perimeter.",
            "criticality": "HIGH"
        },
        {
            "id": "INF-03",
            "question": "Do you follow IAM best practices of least privilege for AI service accounts and enforce application-user authentication?",
            "framework_mapping": "ISO 42001 (A.8.1.1), NIST AI RMF (GOVERN 1.1)",
            "rationale": "Prevents elevation of privilege where a compromised web application leaks high-privilege credentials.",
            "criticality": "HIGH"
        },
        {
            "id": "INF-04",
            "question": "How do you manage encryption keys (e.g., Customer-Managed Encryption Keys - CMEK) for persistent disks, databases, and model registry artifacts?",
            "framework_mapping": "ISO 42001 (A.8.2.2), NIST AI RMF (MEASURE 2.10)",
            "rationale": "Ensures cryptographic sovereignty over training data and custom model weights.",
            "criticality": "MEDIUM"
        }
    ],
    "5. Security Assurance & Monitoring": [
        {
            "id": "ASR-01",
            "question": "What types of logs (e.g., Prompt I/O, Tool Call traces, Admin logs) do you collect, and are they centralized in a secure SIEM/SOAR?",
            "framework_mapping": "ISO 42001 (A.9.2), NIST AI RMF (MEASURE 2.4)",
            "rationale": "Ensures sufficient forensic data is available for post-incident analysis and real-time monitoring.",
            "criticality": "HIGH"
        },
        {
            "id": "ASR-02",
            "question": "Do you have active detection rules or security metrics to trigger alerts on input/output validation failures, jailbreaks, or anomalous behavior?",
            "framework_mapping": "ISO 42001 (A.9.1.2), NIST AI RMF (MEASURE 3.1)",
            "rationale": "Allows SOC and SecOps teams to detect and respond to live campaigns of adversarial exploitation.",
            "criticality": "HIGH"
        },
        {
            "id": "ASR-03",
            "question": "Do you have dedicated playbooks or runbooks for responding to AI-specific security incidents (e.g., model poisoning, data leakage)?",
            "framework_mapping": "ISO 42001 (A.9.2.1), NIST AI RMF (MANAGE 2.3)",
            "rationale": "Ensures standard Incident Response processes can mitigate semantic and algorithmic risks effectively.",
            "criticality": "MEDIUM"
        }
    ],
    "6. AI Governance & Compliance": [
        {
            "id": "GOV-01",
            "question": "Have you documented clear organizational roles, responsibilities, and decision-making lines across the AI lifecycle?",
            "framework_mapping": "ISO 42001 (Clause 5.3), NIST AI RMF (GOVERN 1.1)",
            "rationale": "Avoids accountability gaps where no specific entity is responsible for data drift or model behavior.",
            "criticality": "HIGH"
        },
        {
            "id": "GOV-02",
            "question": "Do you maintain a centralized, updated inventory (AI-BOM) of all AI services, third-party APIs, and libraries used?",
            "framework_mapping": "ISO 42001 (A.8.1), NIST AI RMF (GOVERN 1.2)",
            "rationale": "Critical first step in managing supply chain risks and tracking vulnerabilities (like CVEs).",
            "criticality": "HIGH"
        },
        {
            "id": "GOV-03",
            "question": "Does your corporate risk management framework include AI-specific risks, impact assessments, and regulatory mapping (e.g., GDPR, CCPA)?",
            "framework_mapping": "ISO 42001 (Clause 6.1.2), NIST AI RMF (GOVERN 1.4)",
            "rationale": "Maintains continuous compliance with international laws and internal ethical guidelines.",
            "criticality": "HIGH"
        }
    ]
}

class AISPRConsultingTool:
    def __init__(self):
        self.client_name = ""
        self.project_name = ""
        self.assessor_name = "@jsaccomani"
        self.answers = {}  # Format: {question_id: {"score": 0/1/0.5, "status": "Y/N/P", "notes": "..."}}
        self.date = datetime.datetime.now().strftime("%Y-%m-%d")

    def print_header(self):
        print("================================================================================")
        print("          @jsaccomani's AI-SPR (AI Security Posture Review) Consulting Tool      ")
        print("                 Aligned with NIST AI RMF 1.0, ISO 42001, & SAIF                ")
        print("================================================================================")

    def start_assessment(self):
        self.print_header()
        self.client_name = input("Client Name: ").strip() or "Enterprise Customer"
        self.project_name = input("AI Project/Application Scope: ").strip() or "Gemini Platform Core"
        print(f"\n[+] Starting AI-SPR for {self.client_name} - Scope: {self.project_name}")
        print("[+] Instructions: For each question, answer [Y]es (fully met), [N]o (not met), or [P]artial.")
        print("    Add any qualitative findings, gaps, or architectural notes.\n")

        for domain, questions in AI_SPR_QUESTION_DB.items():
            print(f"\n--- Domain: {domain} ---")
            for q in questions:
                print(f"\nID: {q['id']} [Criticality: {q['criticality']}]")
                print(f"Question: {q['question']}")
                print(f"Mapping: {q['framework_mapping']}")
                print(f"Rationale: {q['rationale']}")
                
                # Input loop
                status = ""
                while status not in ["y", "n", "p", "na"]:
                    status = input("Answer (Y/N/P/NA): ").strip().lower()
                
                notes = input("Findings/Architectural Notes: ").strip()
                
                # Scoring mapping
                score = 0.0
                if status == "y":
                    score = 1.0
                elif status == "p":
                    score = 0.5
                elif status == "na":
                    score = -1.0 # Exclude from calculations
                    
                self.answers[q["id"]] = {
                    "status": status.upper(),
                    "score": score,
                    "notes": notes if notes else "No specific comments documented.",
                    "criticality": q["criticality"],
                    "question_text": q["question"],
                    "framework_mapping": q["framework_mapping"],
                    "rationale": q["rationale"]
                }
        
        print("\n[+] Assessment Walkthrough Completed!")
        self.generate_report()

    def calculate_scores(self) -> Dict[str, Any]:
        domain_scores = {}
        overall_earned = 0.0
        overall_possible = 0.0

        for domain, questions in AI_SPR_QUESTION_DB.items():
            earned = 0.0
            possible = 0.0
            for q in questions:
                ans = self.answers.get(q["id"])
                if ans and ans["score"] != -1.0:
                    earned += ans["score"]
                    possible += 1.0
            
            percentage = (earned / possible * 100) if possible > 0 else 100.0
            domain_scores[domain] = {
                "earned": earned,
                "possible": possible,
                "percentage": round(percentage, 2)
            }
            overall_earned += earned
            overall_possible += possible

        overall_percentage = (overall_earned / overall_possible * 100) if overall_possible > 0 else 100.0
        return {
            "domains": domain_scores,
            "overall_percentage": round(overall_percentage, 2),
            "overall_earned": overall_earned,
            "overall_possible": overall_possible
        }

    def generate_report(self):
        scores = self.calculate_scores()
        filename = f"aispr_assessment_report_{self.client_name.lower().replace(' ', '_')}.md"
        report_path = os.path.join("/workspace/out", filename)

        # Build Markdown Document
        md = []
        md.append(f"# AI Security Posture Review (AI-SPR) Executive Assessment Report")
        md.append(f"**Client Name:** {self.client_name}  ")
        md.append(f"**Assessment Scope:** {self.project_name}  ")
        md.append(f"**Lead Assessor & Security Architect:** {self.assessor_name}  ")
        md.append(f"**Date:** {self.date}  ")
        md.append(f"**Methodology Alignment:** Google's Secure AI Framework (SAIF), NIST AI RMF 1.0, and ISO/IEC 42001 (AIMS)  \n")
        
        md.append("---")
        md.append("## 1. Executive Summary")
        md.append(f"Google Cloud Professional Services conducted a structured AI Security Posture Review (AI-SPR) for **{self.client_name}** covering the critical workloads of **{self.project_name}**. This assessment focuses strictly on identifying logical, developmental, and architectural vulnerabilities specific to artificial intelligence pipelines and Large Language Models (LLMs) rather than generic cloud infrastructure setups.")
        
        posture_tier = "SECURE"
        if scores["overall_percentage"] < 50.0:
            posture_tier = "CRITICAL / VULNERABLE"
        elif scores["overall_percentage"] < 80.0:
            posture_tier = "MODERATE / DRIFT DETECTED"
            
        md.append(f"\n### Overall Assessment Score: **{scores['overall_percentage']}%**  ")
        md.append(f"### Current Security Posture Tier: **{posture_tier}**  \n")
        md.append("This score reflects the ratio of fully implemented critical controls versus identified gaps across the 6 major domains of AI security. Gaps in 'HIGH' criticality controls represent active attack pathways that should be mitigated immediately before promotion to production environments.\n")

        md.append("## 2. Posture Score Dashboard")
        md.append("| Assessment Domain | Fully Met Controls | Evaluated Controls | Compliance Percentage |")
        md.append("| :--- | :---: | :---: | :---: |")
        for dom, stats in scores["domains"].items():
            md.append(f"| {dom} | {stats['earned']} | {stats['possible']} | {stats['percentage']}% |")
        md.append(f"| **OVERALL COMPLIANCE SCORE** | **{scores['overall_earned']}** | **{scores['overall_possible']}** | **{scores['overall_percentage']}%** |  \n")

        md.append("## 3. Prioritized Actionable Roadmap (CAPA)")
        md.append("Below is the prioritized roadmap detailing the critical corrective actions required to harden the application's boundaries:\n")
        
        # Pull high severity gaps
        high_gaps = []
        med_gaps = []
        for q_id, ans in self.answers.items():
            if ans["status"] in ["N", "P"]:
                if ans["criticality"] == "HIGH":
                    high_gaps.append((q_id, ans))
                else:
                    med_gaps.append((q_id, ans))

        md.append("### 🔴 Priority 1: High Severity Vulnerabilities (Immediate Remediation)")
        if not high_gaps:
            md.append("No active High Severity gaps identified. Excellent posture!")
        else:
            for q_id, ans in high_gaps:
                md.append(f"#### **[{q_id}] - Remediation for: {ans['question_text']}**")
                md.append(f"- **Identified Gap / Finding:** {ans['notes']}")
                md.append(f"- **Target Compliance Control:** {ans['framework_mapping']}")
                md.append(f"- **Recommended Corrective Action:** Implement secure validation boundaries (e.g. Model Armor templates, least-privilege IAM scopes, or private endpoint isolations).\n")

        md.append("### 🟡 Priority 2: Medium Severity Gaps (Next 30-60 Days)")
        if not med_gaps:
            md.append("No active Medium Severity gaps identified.\n")
        else:
            for q_id, ans in med_gaps:
                md.append(f"#### **[{q_id}] - Upgrade recommendation: {ans['question_text']}**")
                md.append(f"- **Identified Gap / Finding:** {ans['notes']}")
                md.append(f"- **Target Compliance Control:** {ans['framework_mapping']}")
                md.append(f"- **Recommended Corrective Action:** Set up version-control registries, document metadata schemas, and schedule regular tabletop exercises.\n")

        md.append("## 4. Comprehensive Findings & Client Artifact Log")
        md.append("This section contains the raw, unedited evidence gathered during the workshop interview session:\n")
        
        for domain, questions in AI_SPR_QUESTION_DB.items():
            md.append(f"### {domain}")
            for q in questions:
                ans = self.answers.get(q["id"])
                if ans:
                    md.append(f"**[{q['id']}] {q['question']}**  ")
                    md.append(f"- **Implementation Status:** {ans['status']} (Value: {ans['score']})  ")
                    md.append(f"- **Framework Mapping:** {q['framework_mapping']}  ")
                    md.append(f"- **Audit Notes:** {ans['notes']}  \n")

        # Save Markdown File to disk
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md))

        print(f"\n[SUCCESS] AI-SPR Executive Report compiled successfully!")
        print(f"[+] Output delivered to client: {filename}")
        print("You can download the generated report directly from the Studio panel.")

if __name__ == "__main__":
    tool = AISPRConsultingTool()
    # If run in non-interactive environment, save a mock sample demonstrating execution
    # This prevents script hang if standard input is not attached in the agent container
    import sys
    if not sys.stdin.isatty():
        print("[!] Non-interactive mode detected. Pre-seeding a mock walkthrough...")
        tool.client_name = "Acme Global Bank"
        tool.project_name = "Gemini Credit Underwriting Agent"
        
        # Populate Mock Answers
        tool.answers = {
            "DAT-01": {"status": "Y", "score": 1.0, "notes": "Lineage tracked in Catalog. Data originates from vetted internal DBs.", "question_text": "Do you know the origin...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (A.8.2.1)"},
            "DAT-02": {"status": "P", "score": 0.5, "notes": "Auditing done at GCP project layer, but lacks application-specific logging of training pipelines.", "question_text": "Do you have clear logs...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (A.8.4)"},
            "DAT-03": {"status": "N", "score": 0.0, "notes": "No active classification metadata schema is configured.", "question_text": "Do you have a data classification...?", "criticality": "MEDIUM", "framework_mapping": "ISO 42001 (A.8.2)"},
            "DAT-04": {"status": "Y", "score": 1.0, "notes": "Untrusted user inputs and RAG reference corpus are strictly separated in memory scratchpads.", "question_text": "Do you mix untrusted...?", "criticality": "HIGH", "framework_mapping": "OWASP LLM-06"},
            
            "MOD-01": {"status": "Y", "score": 1.0, "notes": "Strict vetting of pre-trained models. Using standard Vertex Model Hub weights.", "question_text": "How do you select...?", "criticality": "MEDIUM", "framework_mapping": "ISO 42001 (A.8.3)"},
            "MOD-02": {"status": "Y", "score": 1.0, "notes": "Leveraging Vertex AI Model Registry with automated semantic versioning.", "question_text": "Do you have a defined...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (A.8.4)"},
            "MOD-03": {"status": "N", "score": 0.0, "notes": "Models are saved as standard serializations in GCS bucket but lacks object ownership lockouts (vulnerable to Pickle hijack).", "question_text": "Do you validate the integrity...?", "criticality": "HIGH", "framework_mapping": "OWASP LLM-03"},
            "MOD-04": {"status": "P", "score": 0.5, "notes": "Internal red-teaming performed once before launch, but no automated or regression testing scheduled.", "question_text": "Do you conduct regular...?", "criticality": "MEDIUM", "framework_mapping": "MITRE ATLAS"},
            
            "APP-01": {"status": "N", "score": 0.0, "notes": "Prompts are sent directly to the Vertex API without inline validation or screening.", "question_text": "Do you validate and sanitize...?", "criticality": "HIGH", "framework_mapping": "OWASP LLM-01"},
            "APP-02": {"status": "N", "score": 0.0, "notes": "Model Armor is not yet configured or deployed for this project endpoint.", "question_text": "Do you use a WAF...?", "criticality": "HIGH", "framework_mapping": "SAIF Pillar 1"},
            "APP-03": {"status": "P", "score": 0.5, "notes": "Client uses standard WAF regexes, but lacks Advanced DLP inspection (PII exfiltration not actively monitored).", "question_text": "How do you detect...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (A.8.5)"},
            "APP-04": {"status": "Y", "score": 1.0, "notes": "Tool bindings are restricted under OpenAPI strict JSON schemas.", "question_text": "If you utilize agents...?", "criticality": "HIGH", "framework_mapping": "OWASP LLM-07"},
            
            "INF-01": {"status": "Y", "score": 1.0, "notes": "Cloud Security Posture Review (CSPR) conducted in Q1 2026. Controls validated.", "question_text": "Have you completed a CSPR...?", "criticality": "HIGH", "framework_mapping": "GCP Security Blueprint"},
            "INF-02": {"status": "P", "score": 0.5, "notes": "Vertex endpoints isolated with PSC, but training buckets are accessible over the internet via scoped service accounts.", "question_text": "Do you utilize VPC-SC...?", "criticality": "HIGH", "framework_mapping": "SAIF Pillar 1"},
            "INF-03": {"status": "Y", "score": 1.0, "notes": "Service accounts adhere to least-privilege using role/aiplatform.user.", "question_text": "Do you follow IAM...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (A.8.1.1)"},
            "INF-04": {"status": "N", "score": 0.0, "notes": "Google-managed default encryption keys used. CMEK not configured.", "question_text": "How do you manage encryption keys...?", "criticality": "MEDIUM", "framework_mapping": "ISO 42001 (A.8.2.2)"},
            
            "ASR-01": {"status": "P", "score": 0.5, "notes": "Standard audit logs saved to Cloud Logging, but Prompt I/O streaming is not integrated into SecOps Chronicle SIEM.", "question_text": "What types of logs...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (A.9.2)"},
            "ASR-02": {"status": "N", "score": 0.0, "notes": "No detection alerts configured for model responses or input jailbreak spikes.", "question_text": "Do you have active detection...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (A.9.1.2)"},
            "ASR-03": {"status": "N", "score": 0.0, "notes": "Incidents fall back to general IT playbooks. No AI-specific playbook defined.", "question_text": "Do you have dedicated playbooks...?", "criticality": "MEDIUM", "framework_mapping": "ISO 42001 (A.9.2.1)"},
            
            "GOV-01": {"status": "Y", "score": 1.0, "notes": "AI Ethics committee established and roles defined.", "question_text": "Have you documented...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (Clause 5.3)"},
            "GOV-02": {"status": "N", "score": 0.0, "notes": "Supply chain not tracked. No AI-BOM exists for third-party libraries.", "question_text": "Do you maintain a centralized...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (A.8.1)"},
            "GOV-03": {"status": "P", "score": 0.5, "notes": "GDPR compliance evaluated for backend SQL datasets, but model weight retention policies are undocumented.", "question_text": "Does your corporate risk...?", "criticality": "HIGH", "framework_mapping": "ISO 42001 (Clause 6.1.2)"}
        }
        tool.generate_report()
    else:
        tool.start_assessment()
