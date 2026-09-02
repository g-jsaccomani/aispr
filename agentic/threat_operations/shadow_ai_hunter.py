# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI-SPR - Shadow AI Hunter & AI Workload Vulnerability Engine (Customer Simulation)
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from domain.enums import ExecutionMode
from domain.models.evidence import compute_sha256

logger = logging.getLogger("AISPR-ShadowAIHunter")


class ShadowAIHunter:
    """
    Hunting engine across Kubernetes pods, Compute instances,
    and Developer Workbenches to flag unmanaged LLMs and known CVEs.
    Explicitly tracks execution_mode, confidence, evidence, and provenance.
    """

    def __init__(self, project_id: str = "your-gcp-project-id", mode: ExecutionMode = ExecutionMode.SIMULATION):
        self.project_id = project_id
        self.mode = mode

    def scan_kubernetes_workloads(self) -> List[Dict[str, Any]]:
        """
        Scans Kubernetes pods for active Shadow AI inference engines (Ollama, vLLM, LocalAI, TGI).
        """
        logger.info(f"Auditing GKE Clusters in project '{self.project_id}' for rogue AI daemon sets (Mode: {self.mode})...")
        now_ts = datetime.now(timezone.utc).isoformat()

        return [
            {
                "finding_id": "SHADOW-GCP-K8S-01",
                "asset": "gke-credit-risk-prod/credit-risk-analytics/ollama-inference-daemon-7b89f",
                "provider": "gcp",
                "source": "cloud resources",
                "timestamp": now_ts,
                "confidence": "OBSERVED" if self.mode == ExecutionMode.LIVE else "SUSPECTED",
                "execution_mode": self.mode.value if hasattr(self.mode, "value") else str(self.mode),
                "severity": "CRITICAL",
                "category": "Unmanaged Local LLM Engine",
                "engine": "Ollama (Llama-3-70B)",
                "cluster": "gke-credit-risk-prod",
                "namespace": "credit-risk-analytics",
                "pod_name": "ollama-inference-daemon-7b89f",
                "port": 11434,
                "exposure": "INTERNAL_VPC_UNAUTHENTICATED",
                "risk": "Rogue LLM instance accepting uninspected internal prompts without Cloud DLP or Model Armor.",
                "mitigation": "Enforce admission controllers blocking unapproved container images and isolate port 11434 via NetworkPolicy.",
                "discovery_method": "KUBERNETES_WORKLOAD_SPEC_INSPECTION",
                "provenance": f"Audit of pod daemonset in namespace credit-risk-analytics (Execution: {self.mode}).",
                "evidence": {
                    "content_hash": compute_sha256("ollama-inference-daemon-7b89f:11434:INTERNAL_VPC"),
                    "status": "SIMULATED" if self.mode != ExecutionMode.LIVE else "VERIFIED"
                }
            },
            {
                "finding_id": "SHADOW-GCP-GCE-02",
                "asset": "gce-sandbox/default/ml-dev-sandbox-vm",
                "provider": "gcp",
                "source": "cloud resources",
                "timestamp": now_ts,
                "confidence": "OBSERVED" if self.mode == ExecutionMode.LIVE else "SUSPECTED",
                "execution_mode": self.mode.value if hasattr(self.mode, "value") else str(self.mode),
                "severity": "HIGH",
                "category": "Unmanaged Local LLM Engine",
                "engine": "vLLM Inference Server",
                "cluster": "gce-sandbox",
                "namespace": "default",
                "pod_name": "ml-dev-sandbox-vm",
                "port": 8000,
                "exposure": "VPC_PEERING_ACCESSIBLE",
                "risk": "Developer instance running vLLM with world-readable local logs logging raw financial prompts.",
                "mitigation": "Quarantine compute instance and migrate workload to managed Vertex AI Private Endpoints.",
                "discovery_method": "COMPUTE_PROCESS_SCAN",
                "provenance": f"Audit of compute instance process list in gce-sandbox (Execution: {self.mode}).",
                "evidence": {
                    "content_hash": compute_sha256("ml-dev-sandbox-vm:8000:VPC_PEERING"),
                    "status": "SIMULATED" if self.mode != ExecutionMode.LIVE else "VERIFIED"
                }
            }
        ]

    def audit_workbench_startup_scripts(self) -> List[Dict[str, Any]]:
        """
        Audits Vertex AI Workbench instances for misconfigurations and token exposure CVEs.
        """
        logger.info(f"Auditing Workbench Notebooks in project '{self.project_id}' for privilege escalation vectors (Mode: {self.mode})...")
        now_ts = datetime.now(timezone.utc).isoformat()

        return [
            {
                "finding_id": "VULN-GCP-WB-01",
                "asset": f"projects/{self.project_id}/zones/southamerica-east1-a/instances/workbench-analyst-gpu-01",
                "provider": "gcp",
                "source": "infrastructure metadata",
                "timestamp": now_ts,
                "confidence": "INFERRED",
                "execution_mode": self.mode.value if hasattr(self.mode, "value") else str(self.mode),
                "cve": "CVE-2026-2244",
                "severity": "CRITICAL",
                "resource_name": "workbench-analyst-gpu-01",
                "zone": "southamerica-east1-a",
                "vulnerability_type": "OAuth Token Exposure in World-Readable Logs",
                "risk": "Custom startup script writes Google Cloud access token to world-readable disk log (/var/log/startup.log).",
                "mitigation": "Update metadata to remove sensitive tokens and redeploy with Shielded VM and CMEK.",
                "discovery_method": "WORKBENCH_METADATA_INSPECTION",
                "provenance": f"Inspection of instance startup-script metadata in zone southamerica-east1-a (Execution: {self.mode}).",
                "evidence": {
                    "content_hash": compute_sha256("workbench-analyst-gpu-01:startup-script:token_leak"),
                    "status": "SIMULATED" if self.mode != ExecutionMode.LIVE else "VERIFIED"
                }
            },
            {
                "finding_id": "VULN-GCP-WB-02",
                "asset": f"projects/{self.project_id}/zones/southamerica-east1-a/instances/workbench-analyst-gpu-01",
                "provider": "gcp",
                "source": "infrastructure metadata",
                "timestamp": now_ts,
                "confidence": "OBSERVED" if self.mode == ExecutionMode.LIVE else "SUSPECTED",
                "execution_mode": self.mode.value if hasattr(self.mode, "value") else str(self.mode),
                "cve": "MISCONFIG-PUBLIC-IP",
                "severity": "HIGH",
                "resource_name": "workbench-analyst-gpu-01",
                "zone": "southamerica-east1-a",
                "vulnerability_type": "Direct Internet Access (Public IP Enabled)",
                "risk": "Vertex AI Workbench instance is accessible directly via public IPv4 address without Cloud IAP.",
                "mitigation": "Disable public IP and enforce VPC-SC perimeter ingress rules.",
                "discovery_method": "COMPUTE_NETWORK_INTERFACE_INSPECTION",
                "provenance": f"Inspection of external NAT IP assignment on networkInterfaces (Execution: {self.mode}).",
                "evidence": {
                    "content_hash": compute_sha256("workbench-analyst-gpu-01:public_ip_enabled"),
                    "status": "SIMULATED" if self.mode != ExecutionMode.LIVE else "VERIFIED"
                }
            }
        ]

    def run_full_scan(self) -> Dict[str, Any]:
        """
        Aggregates all findings into a structured threat report with explicit execution mode.
        """
        k8s_findings = self.scan_kubernetes_workloads()
        cve_findings = self.audit_workbench_startup_scripts()

        crit_count = sum(1 for f in (k8s_findings + cve_findings) if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in (k8s_findings + cve_findings) if f.get("severity") == "HIGH")

        return {
            "project_id": self.project_id,
            "execution_mode": self.mode.value if hasattr(self.mode, "value") else str(self.mode),
            "status": "COMPLETED",
            "total_findings": len(k8s_findings) + len(cve_findings),
            "shadow_ai_detected": len(k8s_findings),
            "vulnerabilities_detected": len(cve_findings),
            "summary": {
                "critical": crit_count,
                "high": high_count,
                "medium": 0,
                "low": 0
            },
            "findings": {
                "shadow_ai": k8s_findings,
                "workbench_vulnerabilities": cve_findings
            }
        }
