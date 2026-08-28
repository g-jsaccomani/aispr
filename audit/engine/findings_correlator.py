# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI-SPR - Cloud Findings & Control Correlator Engine
Bridges real-time multi-cloud telemetry (GCP, AWS, Azure, SCC, Shadow AI, SAST, AI-BOM)
directly into the 104 AI-SPR GRC Controls and Assessment Questionnaires.
Engineered by: @jsaccomani
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional, Union

logger = logging.getLogger("AISPR-FindingsCorrelator")


class CloudFindingsCorrelator:
    """
    Correlates technical findings from cloud discovery scanners, Security Command Center (SCC),
    Shadow AI hunters, AST SAST scanners, and AI-BOM catalogues into corresponding
    AI-SPR questionnaire controls (DAT-xx, MOD-xx, APP-xx, INF-xx, ASR-xx, GOV-xx).
    """

    # Static taxonomy mapping keyword/resource patterns to Control IDs
    FINDING_CONTROL_TAXONOMY: Dict[str, List[str]] = {
        # 1. Data Security & Integrity (DAT)
        "DAT-01": ["lineage", "origin", "authenticity", "rag_storage", "training_data", "dataset"],
        "DAT-02": ["data_access", "fine_tuning_audit", "audit_log", "pipeline_log"],
        "DAT-03": ["dlp", "pii", "cleartext", "ssn", "cpf", "classification", "sensitive_data"],
        "DAT-04": ["rag_poisoning", "untrusted_data", "corpus_partition", "mixing_data"],
        "DAT-05": ["sql_dump", "database_masking", "deidentification", "unmasked_pii"],
        # 2. Model Hardening & Management (MOD)
        "MOD-01": ["pre_trained", "foundation_model", "supply_chain", "unvetted_weights"],
        "MOD-02": ["model_registry", "vertex_model_registry", "versioning", "catalog"],
        "MOD-03": ["pickle", "serialization", "model_tampering", "unauthorized_modification", "creator_lock"],
        "MOD-04": ["red_teaming", "adversarial_testing", "mitre_atlas", "jailbreak_testing"],
        # 3. Application Security & Protection (APP)
        "APP-01": ["prompt_injection", "jailbreak", "input_sanitization", "guardrail", "bedrock_guardrail", "bola", "idor"],
        "APP-02": ["model_armor", "waf", "semantic_gateway", "content_safety", "azure_content_safety"],
        "APP-03": ["output_leakage", "pii_redaction", "prompt_leakage", "system_prompt_exfiltration"],
        "APP-04": ["excessive_agency", "tool_calling", "schema_validation", "rate_limiting", "plugin_boundary"],
        # 4. Infrastructure Security & Isolation (INF)
        "INF-01": ["cspr", "project_isolation", "cve-2026-2244", "startup_script", "token_exposure", "workbench_cve"],
        "INF-02": ["vpc_sc", "vpc_service_controls", "psc", "private_service_connect", "public_ip", "network_perimeter"],
        "INF-03": ["least_privilege", "roles/editor", "roles/owner", "service_account_iam", "excessive_iam"],
        "INF-04": ["cmek", "kms", "customer_managed_key", "default_encryption", "unencrypted_bucket", "flow_logs"],
        # 5. Security Assurance & Monitoring (ASR)
        "ASR-01": ["prompt_logging", "invocation_logging", "siem", "soar", "centralized_logging", "telemetry_gap"],
        "ASR-02": ["detection_rules", "jailbreak_alert", "validation_alert", "anomaly_detection"],
        "ASR-03": ["incident_response", "ai_playbook", "runbook", "containment_strategy"],
        # 6. AI Governance & Compliance (GOV)
        "GOV-01": ["accountability", "ethics_committee", "roles_responsibilities", "governance_policy"],
        "GOV-02": ["ai_bom", "shadow_ai", "ollama", "vllm", "tgi", "rogue_model", "inventory_gap", "cyclonedx"],
        "GOV-03": ["iso_42001", "nist_ai_rmf", "eu_ai_act", "regulatory_mapping", "risk_assessment"]
    }

    def __init__(
        self,
        project_id: str = "your-gcp-project-id",
        scc_findings: Optional[List[Union[str, Dict[str, Any]]]] = None,
        shadow_findings: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
        sast_findings: Optional[List[Dict[str, Any]]] = None,
        multicloud_findings: Optional[Dict[str, Any]] = None,
        ai_bom: Optional[Dict[str, Any]] = None,
        reports_dir: Optional[str] = None
    ):
        self.project_id = project_id
        self.raw_findings: List[Dict[str, Any]] = []
        self.correlated_map: Dict[str, Dict[str, Any]] = {}

        # 1. Ingest explicit sources
        if scc_findings:
            self.ingest_scc_findings(scc_findings)
        if shadow_findings:
            self.ingest_shadow_findings(shadow_findings)
        if sast_findings:
            self.ingest_sast_findings(sast_findings)
        if multicloud_findings:
            self.ingest_multicloud_findings(multicloud_findings)
        if ai_bom:
            self.ingest_ai_bom(ai_bom)

        # 2. Ingest auto-detected reports if directory provided or default exists
        if reports_dir and os.path.isdir(reports_dir):
            self.ingest_reports_directory(reports_dir)

    def add_raw_finding(
        self,
        source: str,
        category: str,
        severity: str,
        resource: str,
        description: str,
        suggested_control_id: Optional[str] = None
    ):
        """Adds a normalized finding entry to the correlator."""
        self.raw_findings.append({
            "source": source,
            "category": category,
            "severity": severity.upper(),
            "resource": resource,
            "description": description,
            "suggested_control_id": suggested_control_id
        })

    def ingest_scc_findings(self, scc_findings: List[Union[str, Dict[str, Any]]]):
        """Normalizes and ingests findings from Security Command Center AI Protection."""
        for f in scc_findings:
            if isinstance(f, str):
                # Format: "AI-SEC-001: Excessive Agency - Unrestricted IAM role assigned..."
                sev = "HIGH"
                if "CRITICAL" in f.upper():
                    sev = "CRITICAL"
                elif "MEDIUM" in f.upper():
                    sev = "MEDIUM"
                elif "LOW" in f.upper():
                    sev = "LOW"
                
                # Check for control hints in text
                ctrl_id = None
                if "AI-SEC-001" in f or "IAM" in f or "Excessive Agency" in f:
                    ctrl_id = "INF-03"
                elif "AI-SEC-002" in f or "Public ingress" in f or "PSC" in f:
                    ctrl_id = "INF-02"
                elif "AI-SEC-003" in f or "CMEK" in f or "encryption" in f.lower():
                    ctrl_id = "INF-04"

                self.add_raw_finding(
                    source="GCP Security Command Center (SCC)",
                    category="SCC AI Protection",
                    severity=sev,
                    resource=f"projects/{self.project_id}",
                    description=f,
                    suggested_control_id=ctrl_id
                )
            elif isinstance(f, dict):
                sev = f.get("severity", "HIGH")
                desc = f.get("description") or f.get("category", "SCC AI Finding")
                res = f.get("resource_name") or f.get("resource", f"projects/{self.project_id}")
                self.add_raw_finding(
                    source="GCP Security Command Center (SCC)",
                    category=f.get("category", "SCC Finding"),
                    severity=sev,
                    resource=res,
                    description=desc,
                    suggested_control_id=f.get("control_id")
                )

    def ingest_shadow_findings(self, shadow_findings: Union[Dict[str, Any], List[Dict[str, Any]]]):
        """Ingests Shadow AI and Workbench CVE scan findings."""
        items: List[Dict[str, Any]] = []
        if isinstance(shadow_findings, dict):
            # Check nested structure
            findings_dict = shadow_findings.get("findings", {})
            if isinstance(findings_dict, dict):
                for sublist in findings_dict.values():
                    if isinstance(sublist, list):
                        items.extend(sublist)
            elif isinstance(findings_dict, list):
                items.extend(findings_dict)
            
            # Check direct shadow_ai / vulnerabilities keys
            if "shadow_ai" in shadow_findings and isinstance(shadow_findings["shadow_ai"], list):
                items.extend(shadow_findings["shadow_ai"])
            if "vulnerabilities" in shadow_findings and isinstance(shadow_findings["vulnerabilities"], list):
                items.extend(shadow_findings["vulnerabilities"])
        elif isinstance(shadow_findings, list):
            items = shadow_findings

        for item in items:
            sev = item.get("severity", "HIGH")
            engine = item.get("engine") or item.get("type") or item.get("vulnerability_type") or "Shadow AI"
            cve_id = item.get("cve")
            cluster = item.get("cluster") or item.get("resource_name") or item.get("resource") or "Compute Instance"
            risk = item.get("risk") or item.get("description") or "Unmanaged AI Workload"
            
            # Determine mapped control
            ctrl_id = "GOV-02"
            if "cve" in str(item).lower() or "token" in str(item).lower() or "startup" in str(item).lower():
                ctrl_id = "INF-01"
            elif "public ip" in str(item).lower() or "internet access" in str(item).lower():
                ctrl_id = "INF-02"
            elif "ollama" in str(item).lower() or "vllm" in str(item).lower() or "shadow" in str(item).lower():
                ctrl_id = "GOV-02"

            tag = f"[{cve_id}] " if cve_id else f"[{engine}] "
            self.add_raw_finding(
                source="AISPR Shadow AI Hunter",
                category=engine,
                severity=sev,
                resource=cluster,
                description=f"{tag}{risk}",
                suggested_control_id=ctrl_id
            )

    def ingest_sast_findings(self, sast_findings: List[Dict[str, Any]]):
        """Ingests AST Static Application Security Testing (SAST) prompt findings."""
        for f in sast_findings:
            sev = f.get("severity", "HIGH")
            file_path = f.get("file", "app.py")
            line = f.get("line", 1)
            msg = f.get("message") or f.get("issue") or "Insecure Prompt Interpolation"
            ctrl_id = "APP-01"
            if "tool" in msg.lower() or "function" in msg.lower():
                ctrl_id = "APP-04"

            self.add_raw_finding(
                source="AISPR Prompt SAST Scanner",
                category="AST Prompt Injection Risk",
                severity=sev,
                resource=f"{file_path}:{line}",
                description=f"SAST Finding at line {line}: {msg}",
                suggested_control_id=ctrl_id
            )

    def ingest_multicloud_findings(self, multicloud_data: Dict[str, Any]):
        """Ingests findings from GCP, AWS, and Azure multi-cloud posture scanner."""
        for cloud_name, cloud_obj in multicloud_data.items():
            if isinstance(cloud_obj, dict) and "findings" in cloud_obj:
                for f in cloud_obj.get("findings", []):
                    ctrl_id = f.get("id") or f.get("control_id")
                    issue = f.get("issue") or f.get("description") or f.get("control", "Configuration Deviation")
                    sev = f.get("severity", "MEDIUM")
                    if sev == "INFO":
                        continue
                    self.add_raw_finding(
                        source=f"{cloud_name.upper()} Posture Scanner",
                        category=f.get("control", f"{cloud_name.upper()} Policy"),
                        severity=sev,
                        resource=f"{cloud_name.upper()} AI Infrastructure",
                        description=issue,
                        suggested_control_id=ctrl_id
                    )

    def ingest_ai_bom(self, ai_bom: Dict[str, Any]):
        """Ingests AI-BOM model and endpoint inventory gaps (e.g., missing Model Armor or CMEK)."""
        # 1. Models without Model Armor / CMEK
        for model in ai_bom.get("discovered_models", []):
            name = model.get("name", "model")
            provider = model.get("provider", "GCP").upper()
            if not model.get("model_armor_enabled", False) and not model.get("guardrails_enabled", False):
                self.add_raw_finding(
                    source=f"{provider} AI-BOM Discovery",
                    category="Missing AI Guardrails",
                    severity="HIGH",
                    resource=name,
                    description=f"{provider} Foundation Model '{name}' deployed without active Model Armor / Guardrails protection.",
                    suggested_control_id="APP-02"
                )
            if not model.get("cmek_enabled", True):
                self.add_raw_finding(
                    source=f"{provider} AI-BOM Discovery",
                    category="Cryptographic Sovereignty Gap",
                    severity="HIGH",
                    resource=name,
                    description=f"Model artifacts for '{name}' encrypted with default Google-managed keys rather than Customer-Managed Keys (CMEK).",
                    suggested_control_id="INF-04"
                )

        # 2. Shadow AI findings in BOM
        if "shadow_ai_findings" in ai_bom:
            self.ingest_shadow_findings(ai_bom["shadow_ai_findings"])

        # 3. Vulnerabilities in BOM
        if "vulnerabilities" in ai_bom:
            for v in ai_bom.get("vulnerabilities", []):
                self.add_raw_finding(
                    source="AI-BOM Vulnerability Scanner",
                    category=v.get("cve", "CVE Misconfiguration"),
                    severity=v.get("severity", "CRITICAL"),
                    resource=v.get("resource", "Cloud Resource"),
                    description=v.get("description", "Vulnerability detected on AI infrastructure."),
                    suggested_control_id="INF-01"
                )

    def ingest_reports_directory(self, reports_dir: str):
        """Scans reports/ directory for existing JSON artifacts and ingests them."""
        # 1. Shadow AI findings
        shadow_path = os.path.join(reports_dir, "shadow_ai_findings.json")
        if os.path.exists(shadow_path):
            try:
                with open(shadow_path, "r", encoding="utf-8") as f:
                    self.ingest_shadow_findings(json.load(f))
            except Exception as e:
                logger.debug(f"Could not load {shadow_path}: {e}")

        # 2. SAST findings
        sast_path = os.path.join(reports_dir, "sast_findings.json")
        if os.path.exists(sast_path):
            try:
                with open(sast_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.ingest_sast_findings(data)
            except Exception as e:
                logger.debug(f"Could not load {sast_path}: {e}")

        # 3. Multi-cloud posture
        mc_path = os.path.join(reports_dir, "multicloud_posture.json")
        if os.path.exists(mc_path):
            try:
                with open(mc_path, "r", encoding="utf-8") as f:
                    self.ingest_multicloud_findings(json.load(f))
            except Exception as e:
                logger.debug(f"Could not load {mc_path}: {e}")

        # 4. CI scan report
        ci_path = os.path.join(reports_dir, "ci_scan_report.json")
        if os.path.exists(ci_path):
            try:
                with open(ci_path, "r", encoding="utf-8") as f:
                    self.ingest_shadow_findings(json.load(f))
            except Exception as e:
                logger.debug(f"Could not load {ci_path}: {e}")

    def correlate(self) -> Dict[str, Dict[str, Any]]:
        """
        Executes correlation between all ingested findings and the 104 AI-SPR Control IDs.
        Returns a mapping:
        {
            "CONTROL-ID": {
                "has_finding": True,
                "findings": [ { "source": "...", "resource": "...", "description": "...", "severity": "HIGH" }, ... ],
                "summary": "Consolidated summary string...",
                "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
                "suggested_status": "N" | "P" | "Y",
                "suggested_notes": "Findings notes to pre-populate assessment..."
            }
        }
        """
        correlated: Dict[str, Dict[str, Any]] = {}

        for finding in self.raw_findings:
            desc = finding["description"]
            desc_lower = desc.lower()
            res_lower = finding["resource"].lower()
            cat_lower = finding["category"].lower()
            combined_text = f"{desc_lower} {res_lower} {cat_lower}"
            sev = finding["severity"]

            # 1. First priority: Explicit suggested control ID
            target_ids = []
            if finding.get("suggested_control_id"):
                target_ids.append(finding["suggested_control_id"])

            # 2. Second priority: Taxonomy keywords matching
            for ctrl_id, keywords in self.FINDING_CONTROL_TAXONOMY.items():
                if ctrl_id not in target_ids:
                    for kw in keywords:
                        if kw.lower() in combined_text:
                            target_ids.append(ctrl_id)
                            break

            # Fallback if unassigned
            if not target_ids:
                if sev in ["CRITICAL", "HIGH"]:
                    target_ids.append("INF-01")
                else:
                    target_ids.append("GOV-03")

            for cid in target_ids:
                if cid not in correlated:
                    correlated[cid] = {
                        "has_finding": True,
                        "findings": [],
                        "severity": "LOW",
                        "suggested_status": "N",
                        "summary": "",
                        "suggested_notes": ""
                    }

                correlated[cid]["findings"].append(finding)

                # Escalate severity if higher
                sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                curr_sev = correlated[cid]["severity"]
                if sev_order.get(sev, 1) > sev_order.get(curr_sev, 1):
                    correlated[cid]["severity"] = sev

        # Build summaries and suggested notes for each correlated control
        for cid, entry in correlated.items():
            f_list = entry["findings"]
            summaries = []
            for idx, f in enumerate(f_list):
                summaries.append(f"[{f['severity']}] {f['source']}: {f['description']} (Target: {f['resource']})")
            
            entry["summary"] = " | ".join(summaries)
            entry["suggested_notes"] = f"Cloud Scan Evidence: {entry['summary']}"
            if entry["severity"] in ["CRITICAL", "HIGH"]:
                entry["suggested_status"] = "N"
            else:
                entry["suggested_status"] = "P"

        self.correlated_map = correlated
        return correlated

    def get_findings_map_dict(self) -> Dict[str, str]:
        """
        Returns a simplified Dict[str, str] compatible with UI FINDINGS_MAP:
        { "INF-01": "Scan Finding: ...", "DAT-01": "Scan Finding: ..." }
        """
        if not self.correlated_map:
            self.correlate()

        result: Dict[str, str] = {}
        for cid, data in self.correlated_map.items():
            result[cid] = f"Scan Finding: {data['summary']}"
        return result

    def get_finding_for_control(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Returns the correlated finding record for a specific Control ID if present."""
        if not self.correlated_map:
            self.correlate()
        return self.correlated_map.get(control_id)


def build_unified_cloud_findings(
    project_id: str = "your-gcp-project-id",
    scc_findings: Optional[List[Any]] = None,
    shadow_findings: Optional[Any] = None,
    reports_dir: Optional[str] = None
) -> Dict[str, str]:
    """Convenience helper returning a flat Dict[control_id, finding_text]."""
    correlator = CloudFindingsCorrelator(
        project_id=project_id,
        scc_findings=scc_findings,
        shadow_findings=shadow_findings,
        reports_dir=reports_dir
    )
    return correlator.get_findings_map_dict()
