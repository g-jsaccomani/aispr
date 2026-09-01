# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Findings Correlator - Step 3: Control Mapper
Deterministically maps security findings to the 104 AI-SPR GRC Controls.
Enforces strict precedence:
1. Explicit Control Mapping
2. Control Metadata
3. Deterministic Finding Type Mapping
4. Attack Technique Mapping (MITRE ATLAS / OWASP)
5. Keyword Heuristic (strict fallback only)
"""

from typing import Dict, List, Optional, Tuple
from domain.models import SecurityFinding
from domain.enums import ControlRelationType


class ControlMapper:
    """
    Orchestrates deterministic control mapping across the 104-Control AI-SPR taxonomy,
    differentiating Primary Root-Cause, Secondary, and Related controls.
    """

    # Level 3: Deterministic Finding Type Mapping
    DETERMINISTIC_TYPE_MAP: Dict[str, Dict[str, Any]] = {
        "cve-2026-2244": {
            "primary": "INF-01",
            "secondary": ["INF-03"],
            "related": ["GOV-02"],
            "rationale": "Vertex Workbench CVE token leakage in startup log"
        },
        "startup_script_token": {
            "primary": "INF-01",
            "secondary": ["INF-03"],
            "related": [],
            "rationale": "OAuth token exposure in startup script"
        },
        "shadow_ai": {
            "primary": "GOV-02",
            "secondary": ["INF-01"],
            "related": ["ASR-01"],
            "rationale": "Uncataloged rogue LLM daemon / container detected"
        },
        "missing_guardrails": {
            "primary": "APP-02",
            "secondary": ["APP-01"],
            "related": ["ASR-02"],
            "rationale": "Foundation model deployed without Model Armor or Bedrock Guardrails"
        },
        "cmek_missing": {
            "primary": "INF-04",
            "secondary": ["DAT-01"],
            "related": ["GOV-03"],
            "rationale": "Cryptographic sovereignty gap: Default cloud keys used instead of CMEK"
        },
        "public_ingress": {
            "primary": "INF-02",
            "secondary": ["INF-01"],
            "related": ["ASR-01"],
            "rationale": "AI endpoint allows public ingress without VPC Service Controls"
        },
        "ast_prompt_injection": {
            "primary": "APP-01",
            "secondary": ["APP-03"],
            "related": ["MOD-04"],
            "rationale": "AST static analysis detected raw prompt string concatenation"
        },
        "ast_excessive_agency": {
            "primary": "APP-04",
            "secondary": ["INF-03"],
            "related": ["GOV-01"],
            "rationale": "Tool calling without authorization schema boundary"
        },
        "unrestricted_iam": {
            "primary": "INF-03",
            "secondary": ["APP-04"],
            "related": ["GOV-01"],
            "rationale": "Excessive IAM privileges attached to AI service account"
        },
        "dlp_pii_leak": {
            "primary": "DAT-03",
            "secondary": ["DAT-05"],
            "related": ["APP-03"],
            "rationale": "Unmasked personal data (PII) exposed to model ingestion"
        },
        "rag_poisoning": {
            "primary": "DAT-04",
            "secondary": ["DAT-01"],
            "related": ["APP-01"],
            "rationale": "Indirect prompt injection via contaminated RAG knowledge store"
        }
    }

    # Level 4: Attack Technique Mapping (MITRE ATLAS & OWASP GenAI)
    ATTACK_TECHNIQUE_MAP: Dict[str, Dict[str, Any]] = {
        "AML.T0054": {"primary": "APP-01", "secondary": ["APP-02"], "rationale": "MITRE ATLAS LLM Jailbreak"},
        "AML.T0051.000": {"primary": "APP-01", "secondary": ["APP-02"], "rationale": "MITRE ATLAS Direct Prompt Injection"},
        "AML.T0051.001": {"primary": "DAT-04", "secondary": ["APP-01"], "rationale": "MITRE ATLAS Indirect Prompt Injection (RAG)"},
        "AML.T0058": {"primary": "APP-04", "secondary": ["INF-03"], "rationale": "MITRE ATLAS Excessive Agency"},
        "AML.T0057": {"primary": "DAT-03", "secondary": ["APP-03"], "rationale": "MITRE ATLAS LLM Data Extraction"},
        "AML.T0040": {"primary": "INF-01", "secondary": ["INF-02"], "rationale": "MITRE ATLAS ML Exploit / Infrastructure Vulnerability"},
        "AML.T0024": {"primary": "APP-03", "secondary": ["APP-01"], "rationale": "MITRE ATLAS System Prompt Extraction"},
        "LLM01": {"primary": "APP-01", "secondary": ["APP-02"], "rationale": "OWASP LLM01: Prompt Injection"},
        "LLM02": {"primary": "APP-03", "secondary": ["APP-04"], "rationale": "OWASP LLM02: Insecure Output Handling"},
        "LLM06": {"primary": "DAT-03", "secondary": ["DAT-05"], "rationale": "OWASP LLM06: Sensitive Information Disclosure"},
        "LLM07": {"primary": "APP-03", "secondary": ["APP-01"], "rationale": "OWASP LLM07: System Prompt Leakage"},
        "LLM08": {"primary": "APP-04", "secondary": ["INF-03"], "rationale": "OWASP LLM08: Excessive Agency"},
    }

    # Level 5: Fallback Keyword Taxonomy (Strict fallback only)
    FALLBACK_TAXONOMY: Dict[str, List[str]] = {
        "DAT-01": ["lineage", "origin", "authenticity", "training_data"],
        "DAT-02": ["data_access", "fine_tuning_audit", "audit_log"],
        "DAT-03": ["dlp", "pii", "ssn", "cpf", "classification"],
        "DAT-04": ["rag_poisoning", "untrusted_data", "corpus_partition"],
        "DAT-05": ["sql_dump", "database_masking", "deidentification"],
        "MOD-01": ["pre_trained", "foundation_model", "supply_chain"],
        "MOD-02": ["model_registry", "versioning", "catalog"],
        "MOD-03": ["pickle", "serialization", "model_tampering"],
        "MOD-04": ["red_teaming", "adversarial_testing", "jailbreak_testing"],
        "APP-01": ["prompt_injection", "jailbreak", "input_sanitization", "guardrail"],
        "APP-02": ["model_armor", "waf", "semantic_gateway", "content_safety"],
        "APP-03": ["output_leakage", "pii_redaction", "prompt_leakage"],
        "APP-04": ["excessive_agency", "tool_calling", "schema_validation"],
        "INF-01": ["cspr", "project_isolation", "cve-2026-2244", "startup_script"],
        "INF-02": ["vpc_sc", "vpc_service_controls", "psc", "private_service_connect", "public_ip"],
        "INF-03": ["least_privilege", "roles/editor", "roles/owner", "service_account_iam"],
        "INF-04": ["cmek", "kms", "customer_managed_key", "default_encryption"],
        "ASR-01": ["prompt_logging", "invocation_logging", "siem", "telemetry_gap"],
        "ASR-02": ["detection_rules", "jailbreak_alert", "validation_alert"],
        "ASR-03": ["incident_response", "ai_playbook", "runbook"],
        "GOV-01": ["accountability", "ethics_committee", "roles_responsibilities"],
        "GOV-02": ["ai_bom", "shadow_ai", "ollama", "vllm", "tgi", "rogue_model"],
        "GOV-03": ["iso_42001", "nist_ai_rmf", "eu_ai_act", "regulatory_mapping"]
    }

    def map_controls(self, finding: SecurityFinding) -> SecurityFinding:
        """
        Evaluates control mapping in strict order of precedence:
        1. Explicit mapping
        2. Control metadata
        3. Deterministic finding type mapping
        4. Attack technique mapping
        5. Keyword heuristic fallback
        """
        # Step 1: Explicit Control Mapping
        explicit_cid = finding.metadata.get("suggested_control_id")
        if explicit_cid:
            finding.set_primary_control(explicit_cid, "Explicit scanner mapping")
            return finding

        # If already has a primary control link, keep it
        if finding.primary_control_id:
            return finding

        # Step 2: Control Metadata Mapping
        if "control_id" in finding.metadata:
            finding.set_primary_control(finding.metadata["control_id"], "Metadata control specification")
            return finding

        # Step 3: Deterministic Finding Type Mapping
        desc_lower = finding.description.lower()
        cat_lower = str(finding.metadata.get("category", "")).lower()
        combined = f"{desc_lower} {cat_lower}"

        for type_key, rule in self.DETERMINISTIC_TYPE_MAP.items():
            if type_key.lower() in combined or type_key.replace("_", " ") in combined:
                finding.set_primary_control(rule["primary"], rule["rationale"])
                for sec in rule.get("secondary", []):
                    finding.add_secondary_control(sec, rule["rationale"])
                for rel in rule.get("related", []):
                    finding.add_related_control(rel, rule["rationale"])
                finding.metadata["mapping_level"] = "DETERMINISTIC_TYPE"
                return finding

        # Step 4: Attack Technique Mapping
        for tech in finding.attack_techniques:
            tid = tech.technique_id.strip()
            if tid in self.ATTACK_TECHNIQUE_MAP:
                rule = self.ATTACK_TECHNIQUE_MAP[tid]
                finding.set_primary_control(rule["primary"], rule["rationale"])
                for sec in rule.get("secondary", []):
                    finding.add_secondary_control(sec, rule["rationale"])
                finding.metadata["mapping_level"] = "ATTACK_TECHNIQUE"
                return finding

        # Step 5: Keyword Heuristic as Strict Fallback Only
        res_lower = finding.asset.resource_uri.lower()
        search_text = f"{desc_lower} {cat_lower} {res_lower}"

        matched_cids: List[str] = []
        for cid, keywords in self.FALLBACK_TAXONOMY.items():
            for kw in keywords:
                if kw in search_text:
                    matched_cids.append(cid)
                    break

        if matched_cids:
            finding.set_primary_control(matched_cids[0], "Heuristic fallback keyword match")
            for secondary_cid in matched_cids[1:3]:
                finding.add_secondary_control(secondary_cid, "Secondary heuristic correlation")
            finding.metadata["mapping_level"] = "KEYWORD_HEURISTIC_FALLBACK"
            return finding

        # Final generic fallback based on severity
        if finding.severity in ("CRITICAL", "HIGH"):
            finding.set_primary_control("INF-01", "Default high-severity cloud perimeter fallback")
        else:
            finding.set_primary_control("GOV-03", "Default risk assessment governance fallback")
        finding.metadata["mapping_level"] = "DEFAULT_SEVERITY_FALLBACK"
        return finding
