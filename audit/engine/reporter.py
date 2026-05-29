# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI-SPR Enterprise Deliverable & Dual Reporting Engine:
1. Consolidated Executive Posture Report (AI Topology, GRC & Regulatory Exposure)
2. Cloud-Specific Tactical Engineering Report (GCP, AWS, Azure Breakdowns)
"""

import os
import datetime
from typing import Dict, List, Any
from .scorer import PostureScorer
from agentic.threat_operations.ai_interconnection_graph import AIInterconnectionGraph


class ExecutiveReporter:
    """
    Compiles structured AI-SPR assessment data into formal executive and cloud-specific deliverables.
    """

    def __init__(self, client_name: str = "Enterprise Customer", project_name: str = "your-gcp-project-id", assessor_name: str = "Joabson Saccomani (@jsaccomani)"):
        self.client_name = client_name
        self.project_name = project_name
        self.assessor_name = assessor_name
        self.date = datetime.datetime.now().strftime("%Y-%m-%d")
        self.graph_engine = AIInterconnectionGraph(client_name=client_name)

    @staticmethod
    def build_regulatory_gap_table(failed_controls: List[Dict[str, Any]]) -> str:
        """
        Synthesizes a legal and regulatory impact matrix linking failed AI controls
        to EU AI Act, ISO/IEC 42001, and LGPD.
        """
        if not failed_controls:
            return "**No critical regulatory gaps identified.** The architecture aligns with ISO 42001, EU AI Act, and GDPR/LGPD requirements.\n"

        lines = [
            "### Cross-Framework Regulatory Compliance & Legal Impact Matrix",
            "The following table correlates identified technical deviations with statutory and regulatory exposure:\n",
            "| Control ID | Identified Technical Gap | ISO 42001 (AIMS) | EU AI Act Article | Statutory Privacy Exposure (GDPR/LGPD) |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ]

        for ctrl in failed_controls:
            cid = ctrl.get("id", "N/A")
            q_text = ctrl.get("question_text", ctrl.get("question", ""))[:45] + "..."
            
            if cid.startswith("DAT"):
                iso_ref = "A.8.2 (Data Security) / A.8.5"
                eu_ref = "Art. 10 (Data Governance & Bias)"
                lgpd_ref = "Art. 6 (Security) & Art. 33 (Transfer)"
            elif cid.startswith("MOD"):
                iso_ref = "A.8.3 (AI Development Lifecycle)"
                eu_ref = "Art. 15 (Accuracy, Robustness & Security)"
                lgpd_ref = "Art. 46 (Security Standards)"
            elif cid.startswith("APP"):
                iso_ref = "A.8.4.3 / A.10.2 (Human Oversight)"
                eu_ref = "Art. 14 (Human Oversight)"
                lgpd_ref = "Art. 20 (Automated Decision Review)"
            elif cid.startswith("INF"):
                iso_ref = "A.8.1 (Cloud Infrastructure Isolation)"
                eu_ref = "Art. 15 (Cybersecurity & Perimeter)"
                lgpd_ref = "Art. 46 (Technical Measures)"
            elif cid.startswith("ASR"):
                iso_ref = "A.9.2 (AI Telemetry & Logging)"
                eu_ref = "Art. 12 (Record-Keeping & Logs)"
                lgpd_ref = "Art. 37 (Treatment Records)"
            else:
                iso_ref = "Clause 5.3 (AI Governance & Accountability)"
                eu_ref = "Art. 9 (Risk Management System)"
                lgpd_ref = "Art. 50 (Governance Best Practices)"

            lines.append(f"| **{cid}** | {q_text} | `{iso_ref}` | `{eu_ref}` | `{lgpd_ref}` |")

        lines.append("")
        return "\n".join(lines)

    def build_markdown_report(self, answers: Dict[str, Dict[str, Any]], question_db: Dict[str, List[Dict[str, Any]]]) -> str:
        """Alias for consolidated report."""
        return self.build_consolidated_report(answers, question_db)

    def build_consolidated_report(self, answers: Dict[str, Dict[str, Any]], question_db: Dict[str, List[Dict[str, Any]]]) -> str:
        """
        Generates the complete Consolidated Executive AI-SPR Report with topology graph, GRC scores, and CAPA.
        """
        scores = PostureScorer.calculate_scores(answers, question_db)
        high_gaps, med_gaps = PostureScorer.extract_prioritized_gaps(answers)
        all_failed = high_gaps + med_gaps
        mermaid_diagram = self.graph_engine.generate_mermaid_diagram()

        md = []
        md.append("# AI Security Posture Review (AI-SPR) • Consolidated Executive Report")
        md.append(f"**Organization:** {self.client_name}  ")
        md.append(f"**Assessed Scope:** {self.project_name} (Multi-Cloud Federated AI Estate)  ")
        md.append(f"**Lead Consultant:** {self.assessor_name}  ")
        md.append(f"**Issue Date:** {self.date}  ")
        md.append("**Normative Baselines:** Google SAIF • NIST AI RMF 1.0 • ISO/IEC 42001 • MITRE ATLAS • EU AI Act  \n")
        
        md.append("---")
        md.append("## 1. Executive Summary & AI Threat Landscape")
        md.append(
            f"The AI security evaluation was conducted by Google Cloud Security Consulting "
            f"for **{self.client_name}**. The review diagnosed autonomous agents, foundation models, "
            f"inference endpoints, and RAG knowledge bases across Google Cloud, AWS, and Microsoft Azure.\n"
        )
        
        md.append(f"### Overall Compliance Index: **{scores['overall_percentage']}%**  ")
        md.append(f"### Posture Classification: **{scores['posture_tier']}**  \n")
        
        md.append("### AI Interconnection Topology & Data Flow")
        md.append("The following architectural diagram illustrates model connections, RAG ingestion, tool execution, and monitored vectors:\n")
        md.append(mermaid_diagram)
        md.append("")

        md.append("## 2. Domain Scoring Dashboard")
        md.append("| Evaluation Domain | Earned Points | Possible Points | Compliance % |")
        md.append("| :--- | :---: | :---: | :---: |")
        for dom, stats in scores["domains"].items():
            md.append(f"| {dom} | {stats['earned']} | {stats['possible']} | {stats['percentage']}% |")
        md.append(f"| **CONSOLIDATED INDEX** | **{scores['overall_earned']}** | **{scores['overall_possible']}** | **{scores['overall_percentage']}%** |  \n")

        md.append(self.build_regulatory_gap_table(all_failed))

        md.append("## 3. Corrective Action Plan & Strategic Roadmap (CAPA)")
        md.append("### Priority 1: High Severity Vulnerabilities (Immediate Remediation)")
        if not high_gaps:
            md.append("No High Severity gaps identified.\n")
        else:
            for gap in high_gaps:
                md.append(f"#### **[{gap['id']}] {gap['question_text']}**")
                md.append(f"- **Implementation Status:** {gap['status']} (Criticality: HIGH)")
                md.append(f"- **Identified Finding:** {gap['notes']}")
                md.append(f"- **Target Control:** {gap['framework_mapping']}")
                md.append(f"- **Security Rationale:** {gap['rationale']}")
                md.append(f"- **Recommended Mitigation:** Deploy Google Cloud Model Armor, Cloud KMS CMEK, and VPC Service Controls perimeter.\n")

        md.append("### Priority 2: Medium Severity Gaps (Next 30-60 Days)")
        if not med_gaps:
            md.append("No Medium Severity gaps identified.\n")
        else:
            for gap in med_gaps:
                md.append(f"#### **[{gap['id']}] {gap['question_text']}**")
                md.append(f"- **Implementation Status:** {gap['status']} (Criticality: MEDIUM)")
                md.append(f"- **Identified Finding:** {gap['notes']}")
                md.append(f"- **Target Control:** {gap['framework_mapping']}")
                md.append(f"- **Recommended Mitigation:** Strengthen continuous telemetry and drift detection.\n")

        return "\n".join(md)

    def build_cloud_specific_report(self, answers: Dict[str, Dict[str, Any]]) -> str:
        """
        Generates the Cloud-Specific Tactical Engineering Report broken down by GCP, AWS, and Azure.
        """
        md = []
        md.append("# AI-SPR Cloud-by-Cloud Tactical Engineering Report")
        md.append(f"**Organization:** {self.client_name}  ")
        md.append(f"**Issue Date:** {self.date}  ")
        md.append("**Audited Environments:** Google Cloud Platform (GCP) • Amazon Web Services (AWS) • Microsoft Azure  \n")
        md.append("---")

        # Section 1: Google Cloud Platform
        md.append("## 1. Google Cloud Platform (GCP) AI Security Assessment")
        md.append(f"**Primary Scope:** `{self.project_name}` (Vertex AI, GKE, Cloud KMS, SCC AI Protection)\n")
        md.append("| Asset / Resource | Type | CMEK Key | Guardrail | Threat / Vulnerability | Recommended Remediation |")
        md.append("| :--- | :--- | :---: | :---: | :--- | :--- |")
        md.append("| `example-endpoint-01` | Vertex Endpoint | Missing | Missing | Unprotected Prompt Injection target | Deploy Model Armor policy |")
        md.append("| `example-model-01` | Foundation Model | Cloud KMS | Missing | Jailbreak risk in financial queries | Integrate Model Armor Guardrail |")
        md.append("| `example-workbench-01` | Vertex Workbench | Default | N/A | CVE-2026-2244: Public IP & Token Exposure | Force `disable_public_ip = true` via Terraform |")
        md.append("| `k8s://example-shadow-ai` | GKE Shadow AI | Default | Missing | Unprotected LLM Daemon Port 11434 | Apply NetworkPolicy to isolate port 11434 |")
        md.append("| `gs://example-rag-storage` | Cloud Storage RAG | Default | IAM | Vector store without dedicated encryption | Attach CMEK key `example-ai-cmek-key` |  \n")

        # Section 2: Amazon Web Services
        md.append("## 2. Amazon Web Services (AWS) AI Security Assessment")
        md.append("**Primary Scope:** `aws-fintech-bedrock-prod` (Amazon Bedrock, SageMaker, KMS, Guardrails for Amazon Bedrock)\n")
        md.append("| Asset / Resource | Type | KMS Key | Guardrail | Threat / Vulnerability | Recommended Remediation |")
        md.append("| :--- | :--- | :---: | :---: | :--- | :--- |")
        md.append("| `anthropic.claude-3-sonnet` | Bedrock Model | AWS KMS | Active | Prompt Injection & Sensitive PII Leakage | Enforce Bedrock Guardrails high strength |")
        md.append("| `sagemaker-fraud-xgb-v1` | SageMaker Endpoint | Default | Missing | Unencrypted model artifacts in S3 | Enforce customer KMS key and VPC endpoint |  \n")

        # Section 3: Microsoft Azure
        md.append("## 3. Microsoft Azure AI Security Assessment")
        md.append("**Primary Scope:** `azure-openai-enterprise-eastus` (Azure OpenAI Service, Content Safety, Key Vault)\n")
        md.append("| Asset / Resource | Type | Key Vault CMEK | Guardrail | Threat / Vulnerability | Recommended Remediation |")
        md.append("| :--- | :--- | :---: | :---: | :--- | :--- |")
        md.append("| `gpt-4o-customer-chat` | Azure OpenAI | Enforced | Active | Document Injection in RAG index | Deploy Azure AI Content Safety Prompt Shields |")
        md.append("| `azure-search-kb-index` | AI Search Index | Default | Missing | Plaintext PII in vector embeddings | Configure Customer-Managed Key encryption |  \n")

        return "\n".join(md)

    def save_report(self, answers: Dict[str, Dict[str, Any]], question_db: Dict[str, List[Dict[str, Any]]], output_path: str) -> str:
        md = self.build_markdown_report(answers, question_db)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md)
        return output_path

# Audit checkpoint [2026-03-17]: feat(telemetry): add structured security audit events for client inference endpoints

# Audit checkpoint [2026-04-15]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment

# Audit checkpoint [2026-04-28]: fix(guardrails): patch safety boundary bypass detection for client conversational agent

# Audit checkpoint [2026-05-05]: feat(rag-security): implement vector database access control validation for client

# Audit checkpoint [2026-05-29]: fix(prompt-defense): adjust prompt injection heuristic thresholds for client customer-service bot
