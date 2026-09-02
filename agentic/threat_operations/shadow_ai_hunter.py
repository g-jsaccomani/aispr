# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI-SPR - Shadow AI Hunter & AI Workload Vulnerability Engine
Supports:
  - SIMULATION: Uses offline scenario fixtures with SIMULATED evidence.
  - LIVE: Uses read-only live GCP discovery via GCPConnector (or injected connector double).
  - FALLBACK: Triggered on live discovery failure when fallback_on_error=True.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

from domain.enums import ExecutionMode
from domain.models.evidence import compute_sha256

logger = logging.getLogger("AISPR-ShadowAIHunter")


class ShadowAIHunter:
    """
    Threat operations engine across Kubernetes pods, Compute instances,
    and Developer Workbenches to evaluate unmanaged LLM and CVE detection logic.
    
    In SIMULATION mode:
      - Employs synthetic scenario fixtures with explicit SIMULATED evidence.
      - NEVER marks evidence as VERIFIED.
      - Confidence is SUSPECTED or INFERRED.
      
    In LIVE mode:
      - Uses read-only cloud API discovery via GCPConnector (or injected connector double).
      - NEVER converts hardcoded fixtures into LIVE observations.
      - If provider discovery fails:
        - If fallback_on_error=True: enters FALLBACK mode without fabricating LIVE assets.
        - If fallback_on_error=False: raises the underlying discovery exception.
    """

    def __init__(
        self,
        project_id: str = "demo-gcp-project",
        mode: ExecutionMode = ExecutionMode.SIMULATION,
        connector: Optional[Any] = None,
        fallback_on_error: bool = False,
    ):
        self.project_id = project_id
        self.mode = mode
        self.fallback_on_error = fallback_on_error
        self._connector = connector
        self.fallback_metadata: Optional[Dict[str, Any]] = None

    def _get_connector(self) -> Any:
        if self._connector is not None:
            return self._connector
        from agentic.connectors.gcp_connector import GCPConnector
        self._connector = GCPConnector(project_id=self.project_id)
        return self._connector

    def _execute_live_discovery(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Executes read-only live discovery via the configured connector.
        Returns (workloads, vulnerabilities).
        """
        conn = self._get_connector()
        now_ts = datetime.now(timezone.utc).isoformat()
        try:
            raw = conn.discover_resources_live()
            live_workloads: List[Dict[str, Any]] = []
            live_vulns: List[Dict[str, Any]] = []

            # Process live shadow AI findings or workloads returned by provider
            raw_shadow = raw.get("shadow_ai", []) or raw.get("workloads", [])
            for idx, item in enumerate(raw_shadow):
                asset_name = item.get("asset") or item.get("name") or item.get("resource") or f"projects/{self.project_id}/workload-{idx}"
                live_workloads.append({
                    "finding_id": item.get("finding_id") or f"LIVE-SHADOW-{idx+1:02d}",
                    "asset": asset_name,
                    "provider": item.get("provider", "gcp"),
                    "source": "cloud resources",
                    "timestamp": item.get("timestamp") or now_ts,
                    "confidence": "OBSERVED",
                    "execution_mode": "LIVE",
                    "status": "OBSERVED",
                    "severity": item.get("severity", "CRITICAL"),
                    "category": item.get("category", "Unmanaged Local LLM Engine"),
                    "engine": item.get("engine", "Discovered Live AI Workload"),
                    "cluster": item.get("cluster"),
                    "namespace": item.get("namespace"),
                    "pod_name": item.get("pod_name"),
                    "port": item.get("port", 8000),
                    "exposure": item.get("exposure", "INTERNAL_VPC"),
                    "risk": item.get("risk", "Live discovered unmanaged AI workload."),
                    "mitigation": item.get("mitigation", "Enforce admission controllers and migrate to managed endpoints."),
                    "discovery_method": "LIVE_GCP_API_DISCOVERY",
                    "provenance": f"Discovered via read-only live GCP API for project '{self.project_id}'.",
                    "evidence": {
                        "content_hash": compute_sha256(str(asset_name)),
                        "status": "VERIFIED",
                        "collected_from": asset_name,
                    }
                })

            # Process live vulnerabilities returned by provider
            raw_vulns = raw.get("vulnerabilities", [])
            for idx, item in enumerate(raw_vulns):
                asset_name = item.get("asset") or item.get("resource") or item.get("resource_name") or f"projects/{self.project_id}/instance-{idx}"
                live_vulns.append({
                    "finding_id": item.get("finding_id") or f"LIVE-VULN-{idx+1:02d}",
                    "asset": asset_name,
                    "provider": item.get("provider", "gcp"),
                    "source": "infrastructure metadata",
                    "timestamp": item.get("timestamp") or now_ts,
                    "confidence": "OBSERVED",
                    "execution_mode": "LIVE",
                    "status": "OBSERVED",
                    "cve": item.get("cve", "MISCONFIG"),
                    "severity": item.get("severity", "HIGH"),
                    "resource_name": item.get("resource_name", asset_name),
                    "zone": item.get("zone", "global"),
                    "vulnerability_type": item.get("vulnerability_type", "Security Misconfiguration"),
                    "risk": item.get("risk", item.get("description", "Live discovered vulnerability.")),
                    "mitigation": item.get("mitigation", "Remediate according to security best practices."),
                    "discovery_method": "LIVE_GCP_API_DISCOVERY",
                    "provenance": f"Discovered via read-only live GCP API for project '{self.project_id}'.",
                    "evidence": {
                        "content_hash": compute_sha256(str(asset_name)),
                        "status": "VERIFIED",
                        "collected_from": asset_name,
                    }
                })

            return live_workloads, live_vulns

        except Exception as exc:
            if self.fallback_on_error:
                logger.warning(
                    f"Shadow AI live discovery failed ({exc}). Entering FALLBACK mode without synthetic VERIFIED evidence."
                )
                self.mode = ExecutionMode.FALLBACK
                self.fallback_metadata = {
                    "provider": "gcp",
                    "attempted_operation": "gcp:shadow_ai_live_discovery",
                    "failure_reason": str(exc),
                    "fallback_source": "DEGRADED_LOCAL_SCAN",
                    "timestamp": now_ts,
                }
                # Fallback: NO fabricated LIVE assets, NO VERIFIED evidence
                return [], []
            else:
                raise

    def scan_kubernetes_workloads(self) -> List[Dict[str, Any]]:
        """
        Scans Kubernetes pods for active Shadow AI inference engines (Ollama, vLLM, LocalAI, TGI).
        """
        if self.mode == ExecutionMode.LIVE:
            workloads, _ = self._execute_live_discovery()
            return workloads
        elif self.mode == ExecutionMode.FALLBACK:
            return []

        # SIMULATION mode: Uses synthetic scenario fixtures with explicit SIMULATED evidence
        logger.info(f"Auditing GKE Clusters in project '{self.project_id}' for rogue AI daemon sets (Mode: {self.mode})...")
        now_ts = datetime.now(timezone.utc).isoformat()

        return [
            {
                "finding_id": "SHADOW-GCP-K8S-01",
                "asset": "gke-credit-risk-prod/credit-risk-analytics/ollama-inference-daemon-7b89f",
                "provider": "gcp",
                "source": "cloud resources",
                "timestamp": now_ts,
                "confidence": "SUSPECTED",
                "execution_mode": "SIMULATION",
                "fixture_classification": "SIMULATION_SCENARIO",
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
                "discovery_method": "SIMULATED_WORKLOAD_SPEC_INSPECTION",
                "provenance": "Simulation fixture scenario in namespace credit-risk-analytics.",
                "evidence": {
                    "content_hash": compute_sha256("ollama-inference-daemon-7b89f:11434:INTERNAL_VPC"),
                    "status": "SIMULATED"
                }
            },
            {
                "finding_id": "SHADOW-GCP-GCE-02",
                "asset": "gce-sandbox/default/ml-dev-sandbox-vm",
                "provider": "gcp",
                "source": "cloud resources",
                "timestamp": now_ts,
                "confidence": "SUSPECTED",
                "execution_mode": "SIMULATION",
                "fixture_classification": "SIMULATION_SCENARIO",
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
                "discovery_method": "SIMULATED_COMPUTE_PROCESS_SCAN",
                "provenance": "Simulation fixture scenario in gce-sandbox.",
                "evidence": {
                    "content_hash": compute_sha256("ml-dev-sandbox-vm:8000:VPC_PEERING"),
                    "status": "SIMULATED"
                }
            }
        ]

    def audit_workbench_startup_scripts(self) -> List[Dict[str, Any]]:
        """
        Audits Vertex AI Workbench instances for misconfigurations and token exposure CVEs.
        """
        if self.mode == ExecutionMode.LIVE:
            _, vulns = self._execute_live_discovery()
            return vulns
        elif self.mode == ExecutionMode.FALLBACK:
            return []

        # SIMULATION mode: Uses synthetic scenario fixtures with explicit SIMULATED evidence
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
                "execution_mode": "SIMULATION",
                "fixture_classification": "SIMULATION_SCENARIO",
                "cve": "CVE-2026-2244",
                "severity": "CRITICAL",
                "resource_name": "workbench-analyst-gpu-01",
                "zone": "southamerica-east1-a",
                "vulnerability_type": "OAuth Token Exposure in World-Readable Logs",
                "risk": "Custom startup script writes Google Cloud access token to world-readable disk log (/var/log/startup.log).",
                "mitigation": "Update metadata to remove sensitive tokens and redeploy with Shielded VM and CMEK.",
                "discovery_method": "SIMULATED_WORKBENCH_METADATA_INSPECTION",
                "provenance": "Simulation fixture scenario in zone southamerica-east1-a.",
                "evidence": {
                    "content_hash": compute_sha256("workbench-analyst-gpu-01:startup-script:token_leak"),
                    "status": "SIMULATED"
                }
            },
            {
                "finding_id": "VULN-GCP-WB-02",
                "asset": f"projects/{self.project_id}/zones/southamerica-east1-a/instances/workbench-analyst-gpu-01",
                "provider": "gcp",
                "source": "infrastructure metadata",
                "timestamp": now_ts,
                "confidence": "SUSPECTED",
                "execution_mode": "SIMULATION",
                "fixture_classification": "SIMULATION_SCENARIO",
                "cve": "MISCONFIG-PUBLIC-IP",
                "severity": "HIGH",
                "resource_name": "workbench-analyst-gpu-01",
                "zone": "southamerica-east1-a",
                "vulnerability_type": "Direct Internet Access (Public IP Enabled)",
                "risk": "Vertex AI Workbench instance is accessible directly via public IPv4 address without Cloud IAP.",
                "mitigation": "Disable public IP and enforce VPC-SC perimeter ingress rules.",
                "discovery_method": "SIMULATED_NETWORK_INTERFACE_INSPECTION",
                "provenance": "Simulation fixture scenario of networkInterfaces.",
                "evidence": {
                    "content_hash": compute_sha256("workbench-analyst-gpu-01:public_ip_enabled"),
                    "status": "SIMULATED"
                }
            }
        ]

    def run_full_scan(self) -> Dict[str, Any]:
        """
        Aggregates all findings into a structured threat report with explicit execution mode.
        """
        if self.mode == ExecutionMode.LIVE:
            k8s_findings, cve_findings = self._execute_live_discovery()
            exec_mode_str = "LIVE" if self.mode == ExecutionMode.LIVE else "FALLBACK"
            engine_cls = "LIVE_ENTERPRISE_DISCOVERY" if self.mode == ExecutionMode.LIVE else "DEGRADED_FALLBACK_HARNESS"
        elif self.mode == ExecutionMode.FALLBACK:
            k8s_findings = []
            cve_findings = []
            exec_mode_str = "FALLBACK"
            engine_cls = "DEGRADED_FALLBACK_HARNESS"
        else:
            k8s_findings = self.scan_kubernetes_workloads()
            cve_findings = self.audit_workbench_startup_scripts()
            exec_mode_str = "SIMULATION"
            engine_cls = "OFFLINE_SIMULATION_HARNESS"

        crit_count = sum(1 for f in (k8s_findings + cve_findings) if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in (k8s_findings + cve_findings) if f.get("severity") == "HIGH")

        report = {
            "project_id": self.project_id,
            "execution_mode": exec_mode_str,
            "engine_classification": engine_cls,
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
        if self.fallback_metadata:
            report["fallback_metadata"] = self.fallback_metadata
        return report
