# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
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

from audit.engine.correlator import (
    FindingNormalizer,
    FindingDeduplicator,
    ControlMapper,
    SeverityEngine,
    EvidenceValidator,
    DeterministicCorrelator,
)

logger = logging.getLogger("AISPR-FindingsCorrelator")


class CloudFindingsCorrelator:
    """
    Correlates technical findings from cloud discovery scanners, Security Command Center (SCC),
    Shadow AI hunters, AST SAST scanners, and AI-BOM catalogues into corresponding
    AI-SPR questionnaire controls (DAT-xx, MOD-xx, APP-xx, INF-xx, ASR-xx, GOV-xx).
    Acts as the entrypoint facade delegating to the deterministic 5-stage correlation pipeline.
    """

    # Static taxonomy reference preserved for direct backward compatibility
    FINDING_CONTROL_TAXONOMY: Dict[str, List[str]] = ControlMapper.FALLBACK_TAXONOMY

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
        self.pipeline = DeterministicCorrelator(project_id=project_id)
        self.raw_findings = self.pipeline.raw_inputs
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
        self.pipeline.add_raw_finding(
            source=source,
            category=category,
            severity=severity,
            resource=resource,
            description=description,
            suggested_control_id=suggested_control_id
        )

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
                self.add_raw_finding(
                    source="GCP Security Command Center (SCC)",
                    category="SCC AI Protection",
                    severity=sev,
                    resource=f"projects/{self.project_id}",
                    description=f,
                    suggested_control_id=None
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

            tag = f"[{cve_id}] " if cve_id else f"[{engine}] "
            self.add_raw_finding(
                source="AISPR Shadow AI Hunter",
                category=engine,
                severity=sev,
                resource=cluster,
                description=f"{tag}{risk}",
                suggested_control_id=item.get("control_id")
            )

    def ingest_sast_findings(self, sast_findings: List[Dict[str, Any]]):
        """Ingests AST Static Application Security Testing (SAST) prompt findings."""
        for f in sast_findings:
            sev = f.get("severity", "HIGH")
            file_path = f.get("file", "app.py")
            line = f.get("line", 1)
            msg = f.get("message") or f.get("issue") or "Insecure Prompt Interpolation"

            self.add_raw_finding(
                source="AISPR Prompt SAST Scanner",
                category="AST Prompt Injection Risk",
                severity=sev,
                resource=f"{file_path}:{line}",
                description=f"SAST Finding at line {line}: {msg}",
                suggested_control_id=f.get("control_id")
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
                    category="missing_guardrails",
                    severity="HIGH",
                    resource=name,
                    description=f"{provider} Foundation Model '{name}' deployed without active Model Armor / Guardrails protection.",
                    suggested_control_id=model.get("control_id")
                )
            if not model.get("cmek_enabled", True):
                self.add_raw_finding(
                    source=f"{provider} AI-BOM Discovery",
                    category="cmek_missing",
                    severity="HIGH",
                    resource=name,
                    description=f"Model artifacts for '{name}' encrypted with default Google-managed keys rather than Customer-Managed Keys (CMEK).",
                    suggested_control_id=model.get("control_id")
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
                    suggested_control_id=v.get("control_id")
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
        Executes deterministic 5-stage correlation pipeline between all ingested findings
        and the 104 AI-SPR Control IDs.
        """
        self.correlated_map = self.pipeline.correlate()
        return self.correlated_map

    def get_findings_map_dict(self) -> Dict[str, str]:
        """
        Returns a simplified Dict[str, str] compatible with UI FINDINGS_MAP:
        { "INF-01": "Scan Finding: ...", "DAT-01": "Scan Finding: ..." }
        """
        return self.pipeline.get_findings_map_dict()

    def get_finding_for_control(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Returns the correlated finding record for a specific Control ID if present."""
        return self.pipeline.get_finding_for_control(control_id)

    def to_canonical_findings(self) -> List[Any]:
        """
        Converts all raw ingested findings into strongly-typed canonical SecurityFinding instances,
        linking each to primary/secondary controls, AIAsset, and Evidence with epistemological status.
        """
        return self.pipeline.to_canonical_findings()

    def get_findings_by_cloud(self) -> Dict[str, List[Any]]:
        """Groups canonical findings by cloud provider (GCP, AWS, AZURE)."""
        return self.pipeline.get_findings_by_cloud()


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
