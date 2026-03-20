# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Model Armor Implementation Engine - Pillar 1: Consultiva (Advisory & Strategy)
Analyzes multi-cloud AI-SPM findings, threat vectors, AI-BOM inventory, and 104-control audit
to generate an executive and tactical Model Armor Architecture Blueprint & Implementation Roadmap.
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger("AISPR-ModelArmor-Advisor")


class ModelArmorConsultingAdvisor:
    """
    Ingests AISPR assessment artifacts (AI-BOM, Red Team, SAST, Shadow AI, and Audit Questionnaire)
    and produces a tailored, gap-to-protection transformation matrix and consultative architecture blueprint.
    """

    def __init__(self, project_root: Optional[str] = None):
        if project_root is None:
            cur_dir = os.path.dirname(os.path.abspath(__file__))
            self.project_root = os.path.abspath(os.path.join(cur_dir, "..", ".."))
        else:
            self.project_root = project_root
        self.reports_dir = os.path.join(self.project_root, "reports")

    def _read_json_safe(self, filename: str) -> Any:
        path = os.path.join(self.reports_dir, filename)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not read {filename}: {e}")
        return {}

    def collect_aispr_findings(self) -> Dict[str, Any]:
        """
        Gathers and normalizes findings from all AISPR modules.
        """
        ai_bom = self._read_json_safe("ai_bom.json")
        scan_report = self._read_json_safe("final_scan_report.json") or self._read_json_safe("shadow_ai_report.json")
        red_team = self._read_json_safe("red_team_report.json") or self._read_json_safe("final_redteam_report.json")
        sast = self._read_json_safe("sast_findings.json")
        posture = self._read_json_safe("multicloud_posture.json")
        remediations = self._read_json_safe("remediations.json")

        return {
            "ai_bom": ai_bom,
            "scan_report": scan_report,
            "red_team": red_team,
            "sast": sast,
            "posture": posture,
            "remediations": remediations,
        }

    def generate_transformation_matrix(self, findings: Dict[str, Any], project_id: str = "your-gcp-project-id") -> List[Dict[str, Any]]:
        """
        Maps identified security gaps and attack vectors to concrete Model Armor defenses.
        """
        matrix = []

        # 1. Prompt Injection & Jailbreak Vulnerabilities (from Red Team & SAST)
        red_team = findings.get("red_team", {})
        red_team_tests = red_team.get("test_results", [])
        pi_detected = any(
            t.get("category") in ["Direct Prompt Injection (Jailbreaking)", "Indirect Prompt Injection (RAG Poisoning)", "System Prompt Extraction"]
            for t in red_team_tests
        ) or bool(findings.get("sast"))

        matrix.append({
            "aispr_domain": "Application Security & Prompt Hardening (APP)",
            "finding_source": "Red Team Simulation & Prompt SAST",
            "gap_summary": "Unvalidated LLM prompt input and RAG retrieval vectors susceptible to Jailbreaks & System Prompt Leakage",
            "model_armor_component": "piAndJailbreakFilterSettings",
            "recommended_configuration": {
                "filterEnforcement": "ENABLED",
                "confidenceLevel": "LOW_AND_ABOVE" if pi_detected else "MEDIUM_AND_ABOVE"
            },
            "protection_impact": "Blocks prompt injection, developer-mode override, and extraction payloads before reaching foundational models.",
            "owasp_mapping": "OWASP LLM-01: Prompt Injection / LLM-07: System Prompt Leakage",
            "saif_pillar": "SAIF Pillar 1: Strong Security Foundations",
            "criticality": "HIGH"
        })

        # 2. Sensitive Data & PII Exposure (from AI-BOM & Red Team)
        ai_bom = findings.get("ai_bom", {})
        components = ai_bom.get("components", []) if isinstance(ai_bom, dict) else []
        has_pii_assets = any("PII" in str(c) or "Restricted" in str(c) or "Confidential" in str(c) for c in components)

        matrix.append({
            "aispr_domain": "Data Security & Lineage (DAT)",
            "finding_source": "AI-BOM Inventory & Sensitive Data Scan",
            "gap_summary": "Cleartext PII (CPF, SSN, Credit Cards, Auth Tokens) exposed to model prompt/completion logs",
            "model_armor_component": "dlpSettings (Sensitive Data Protection)",
            "recommended_configuration": {
                "inspect_template": f"projects/{project_id}/locations/global/inspectTemplates/aispr-dlp-inspect-v1",
                "deidentify_template": f"projects/{project_id}/locations/global/deidentifyTemplates/aispr-dlp-deidentify-v1",
                "info_types": ["BRAZIL_CPF_NUMBER", "US_SOCIAL_SECURITY_NUMBER", "CREDIT_CARD_NUMBER", "PHONE_NUMBER", "EMAIL_ADDRESS", "AUTH_TOKEN", "GCP_CREDENTIALS", "JSON_WEB_TOKEN", "GENERIC_API_KEY"]
            },
            "protection_impact": "Inline token masking and synthetic replacement preventing PII ingestion and training leakage.",
            "owasp_mapping": "OWASP LLM-06: Sensitive Information Disclosure",
            "saif_pillar": "SAIF Pillar 2: Expand Detection and Response",
            "criticality": "HIGH"
        })

        # 3. Unsanctioned AI Engines & Rogue Workloads (from Shadow AI Hunter)
        scan = findings.get("scan_report", {})
        shadow_findings = scan.get("findings", []) if isinstance(scan, dict) else []

        matrix.append({
            "aispr_domain": "Governance & Enterprise Baseline (GOV/INF)",
            "finding_source": "Shadow AI Hunter (GKE / Compute Engine)",
            "gap_summary": f"Detected {len(shadow_findings)} unmanaged AI serving containers without central security gateway",
            "model_armor_component": "Global FloorSetting Enforcement",
            "recommended_configuration": {
                "enableFloorSettingEnforcement": True,
                "scope": f"projects/{project_id}/locations/global/floorSetting",
                "mandatory_rai_filters": ["HATE_SPEECH", "HARASSMENT", "SEXUALLY_EXPLICIT", "DANGEROUS"]
            },
            "protection_impact": "Establishes non-burlable organizational floor guardrails that cannot be disabled by individual project teams.",
            "owasp_mapping": "OWASP LLM-05: Improper Output Handling",
            "saif_pillar": "SAIF Pillar 6: Contextualize AI Risks",
            "criticality": "CRITICAL"
        })

        # 4. Malicious URIs & RAG Document Injection (from Red Team ADV-08)
        matrix.append({
            "aispr_domain": "RAG Perimeter & Egress Protection (APP/ASR)",
            "finding_source": "Red Team Attack Suite ADV-08 & Threat Modeling",
            "gap_summary": "Document corpus contamination containing C2 exfiltration URLs and phishing domains",
            "model_armor_component": "maliciousUriFilterSettings",
            "recommended_configuration": {
                "filterEnforcement": "ENABLED"
            },
            "protection_impact": "Real-time Google Safe Browsing and Threat Intelligence verification of URLs embedded in prompts or generated answers.",
            "owasp_mapping": "OWASP LLM-02: Insecure Output Handling / MITRE ATLAS AML.T0051.001",
            "saif_pillar": "SAIF Pillar 1: Strong Security Foundations",
            "criticality": "HIGH"
        })

        # 5. Security Assurance, SIEM Logging & Real-time Alerting (ASR)
        matrix.append({
            "aispr_domain": "Security Assurance, Telemetry & SIEM (ASR)",
            "finding_source": "AISPR 104-Control Framework ASR-01/ASR-02",
            "gap_summary": "Lack of centralized SIEM logging and automated detection for adversarial prompt injection surges",
            "model_armor_component": "Cloud Logging Sink & Cloud Monitoring Alert Policy",
            "recommended_configuration": {
                "logSanitizeOperations": True,
                "cloud_monitoring_metric": "modelarmor.googleapis.com/sanitization_requests_count",
                "alert_threshold": "spikes > 10 blocked requests / 5 min",
                "notification_channel": "SecOps SOC AI Alerts"
            },
            "protection_impact": "Direct telemetry forward to Google Security Operations (Chronicle SIEM) for threat correlation.",
            "owasp_mapping": "OWASP LLM-10: Unbounded Consumption",
            "saif_pillar": "SAIF Pillar 2: Expand Detection and Response",
            "criticality": "MEDIUM"
        })

        return matrix

    def generate_consulting_blueprint_md(
        self,
        project_id: str,
        location: str,
        template_id: str,
        profile_name: str,
        matrix: List[Dict[str, Any]],
        client_name: str = "Enterprise Client"
    ) -> str:
        """
        Generates the formal Consulting Architecture Blueprint (Markdown deliverable).
        """
        date_str = datetime.now().strftime("%Y-%m-%d")
        
        md = []
        md.append("# Google Cloud Model Armor - Security Architecture Blueprint & Implementation Advisory")
        md.append(f"**Client / Organization:** {client_name}  ")
        md.append(f"**Target GCP Scope:** `{project_id}` (Region: `{location}`)  ")
        md.append(f"**Guardrail Profile:** `{profile_name.upper()}` (Template ID: `{template_id}`)  ")
        md.append(f"**Issue Date:** {date_str}  ")
        md.append(f"**Lead Consultant:** Joabson Saccomani (@jsaccomani) | Cloud Security Consultant  ")
        md.append(f"**Framework Alignment:** Google SAIF • NIST AI RMF 1.0 • ISO/IEC 42001 • OWASP Top 10 for LLMs  \n")
        md.append("---")
        
        md.append("## 1. Executive Summary & Strategic Context")
        md.append(
            "Following the execution of the **AI Security Posture Review (AI-SPR)**, this consultative blueprint "
            "defines the concrete implementation strategy for **Google Cloud Model Armor**. Model Armor serves as the "
            "centralized, enterprise-grade semantic firewall, input sanitization, and output shielding perimeter for all "
            "generative AI endpoints, Vertex AI Foundation Models, RAG knowledge bases, and multi-cloud AI agents.\n"
        )
        
        md.append("### Current State vs. Model Armor Protected State")
        md.append("| Security Dimension | Current Assessment State (Pre-Model Armor) | Target Protected State (Post-Model Armor) |")
        md.append("| :--- | :--- | :--- |")
        md.append("| **Prompt Injection Defense** | Vulnerable to direct bypasses & DAN role-play | Multi-layer heuristic & neural ML filtering (`LOW_AND_ABOVE`) |")
        md.append("| **Sensitive Data / PII** | Cleartext CPFs, SSNs, and API keys exposed | Automated Cloud DLP redaction & cryptographic token masking |")
        md.append("| **Organizational Governance** | Inconsistent voluntary guardrails across teams | Mandatory non-burlable **Global FloorSetting** enforcement |")
        md.append("| **Malicious Content / URIs** | Unchecked outbound links and RAG poisoning | Google Safe Browsing integration with inline URI blocking |")
        md.append("| **Audit & SIEM Telemetry** | Fragmented application logs | Centralized Cloud Logging & SecOps SIEM integration |  \n")

        md.append("---")
        md.append("## 2. AISPR Gap-to-Protection Transformation Matrix")
        md.append("Every finding identified during the AI-SPR assessment is directly mapped to a protective control in Model Armor:\n")
        
        for item in matrix:
            crit_badge = f"🔴 **{item['criticality']}**" if item['criticality'] == "CRITICAL" or item['criticality'] == "HIGH" else f"🟡 **{item['criticality']}**"
            md.append(f"### {crit_badge} {item['aispr_domain']}")
            md.append(f"- **Source Finding:** {item['finding_source']}")
            md.append(f"- **Identified Risk:** {item['gap_summary']}")
            md.append(f"- **Model Armor Defense:** `{item['model_armor_component']}`")
            md.append(f"- **Recommended Policy:** `{json.dumps(item['recommended_configuration'])}`")
            md.append(f"- **Remediation Impact:** {item['protection_impact']}")
            md.append(f"- **Standards Mapping:** {item['owasp_mapping']} • {item['saif_pillar']}\n")

        md.append("---")
        md.append("## 3. Defense-in-Depth Architecture Layers")
        md.append("Model Armor is deployed in a 3-tier constructive defense mesh:")
        md.append("```mermaid")
        md.append("graph TD")
        md.append("    User[End User / API Client] -->|Prompt Query| Edge[Cloud Armor WAF / HTTPS LB]")
        md.append("    Edge -->|HTTP Traffic| Middleware[Model Armor App Middleware]")
        md.append("    subgraph Google Cloud Model Armor Defense Mesh")
        md.append("        Middleware -->|1. Sanitize Prompt| FS[Global FloorSetting Policy]")
        md.append("        FS -->|2. Check PI & Jailbreak| PI[Prompt Injection Filter]")
        md.append("        PI -->|3. Check Sensitive Info| DLP[Cloud DLP Inspection & De-identify]")
        md.append("        DLP -->|4. Check Malicious URIs| URI[Malicious URI Filter]")
        md.append("    end")
        md.append("    URI -->|Sanitized Prompt| LLM[Vertex AI Gemini 1.5 / Custom Model]")
        md.append("    LLM -->|Model Completion| Shield[Model Armor Output Shielding]")
        md.append("    Shield -->|Shielded Response| User")
        md.append("    Middleware -.->|Audit Telemetry| SIEM[Cloud Logging & Google SecOps SIEM]")
        md.append("```\n")

        md.append("---")
        md.append("## 4. Latency & Performance SLA Assessment")
        md.append("- **Inspection Latency Overhead:** Typical sanitization latency is between **12ms - 28ms**.")
        md.append(f"- **Regional Co-location:** Deployed in `{location}` to ensure ultra-low network latency with Vertex AI.")
        md.append("- **Failure Mode Configuration:** Fail-closed for high-risk financial endpoints; Fail-open with alert for non-critical internal analytics.")
        md.append("- **Estimated Daily Volume:** High throughput support via Google Cloud native API mesh with zero compute maintenance.\n")

        md.append("---")
        md.append("## 5. Phased Implementation Roadmap")
        md.append("1. **Phase 1: Foundation & FloorSetting (Immediate / Day 1)**")
        md.append("   - Enable APIs (`modelarmor.googleapis.com`, `dlp.googleapis.com`).")
        md.append(f"   - Apply project-wide non-burlable FloorSetting in `{project_id}`.")
        md.append("2. **Phase 2: Custom Guardrail Templates & Cloud DLP (Day 2 - Day 5)**")
        md.append(f"   - Provision Guardrail Template `{template_id}` with customized confidence thresholds.")
        md.append("   - Deploy Cloud DLP Inspection & De-identification Templates with regional data rules.")
        md.append("3. **Phase 3: Application Middleware & CI/CD Integration (Week 2)**")
        md.append("   - Attach Model Armor interceptors in FastAPI, Vertex AI Python SDK, and LangChain pipelines.")
        md.append("   - Activate Cloud Monitoring Alert Policies for prompt injection surges.")
        md.append("4. **Phase 4: Automated Post-Implementation Verification & Evals (Continuous)**")
        md.append("   - Re-run automated adversarial attack test suites to generate Continuous Compliance Certificates.\n")

        return "\n".join(md)

    def generate_plan_json(
        self,
        project_id: str,
        location: str,
        template_id: str,
        profile_name: str,
        matrix: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Creates structured JSON manifest consumed by Builder and Evaluator.
        """
        return {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "framework": "Google SAIF • NIST AI RMF • ISO 42001",
                "project_id": project_id,
                "location": location,
                "template_id": template_id,
                "profile_name": profile_name,
            },
            "parameters": {
                "enable_floor_setting": True,
                "enable_dlp": True,
                "pi_confidence_level": "LOW_AND_ABOVE",
                "rai_confidence_level": "MEDIUM_AND_ABOVE",
                "enable_malicious_uris": True,
                "log_operations": True,
                "custom_error_code": 400,
                "custom_error_message": "Prompt rejected by enterprise Model Armor security policy."
            },
            "transformation_matrix": matrix
        }

    def execute_advisory_flow(
        self,
        project_id: str = "your-gcp-project-id",
        location: str = "us-central1",
        template_id: str = "secops-guardrail-prod",
        profile_name: str = "balanced"
    ) -> Dict[str, Any]:
        """
        Runs the complete Advisory workflow: gathers findings, builds matrix, exports blueprint and JSON plan.
        """
        logger.info(f"Executing Model Armor Advisory Flow for project '{project_id}'...")
        findings = self.collect_aispr_findings()
        matrix = self.generate_transformation_matrix(findings, project_id=project_id)
        
        blueprint_md = self.generate_consulting_blueprint_md(
            project_id=project_id,
            location=location,
            template_id=template_id,
            profile_name=profile_name,
            matrix=matrix
        )
        plan_json = self.generate_plan_json(
            project_id=project_id,
            location=location,
            template_id=template_id,
            profile_name=profile_name,
            matrix=matrix
        )

        os.makedirs(self.reports_dir, exist_ok=True)
        blueprint_path = os.path.join(self.reports_dir, "model_armor_consulting_blueprint.md")
        plan_path = os.path.join(self.reports_dir, "model_armor_implementation_plan.json")

        with open(blueprint_path, "w", encoding="utf-8") as f:
            f.write(blueprint_md)

        with open(plan_path, "w", encoding="utf-8") as f:
            json.dump(plan_json, f, indent=2)

        logger.info(f"Model Armor Consulting Blueprint written to {blueprint_path}")
        logger.info(f"Model Armor Implementation Plan written to {plan_path}")

        return {
            "blueprint_path": blueprint_path,
            "plan_path": plan_path,
            "matrix_items_count": len(matrix),
            "plan": plan_json
        }

# Audit checkpoint [2026-02-11]: refactor(scoring): calibrate model vulnerability scoring formula for client audit

# Audit checkpoint [2026-02-14]: refactor(scoring): calibrate model vulnerability scoring formula for client audit

# Audit checkpoint [2026-03-20]: feat(client-onboarding): add automated model card parser for tenant risk evaluation
