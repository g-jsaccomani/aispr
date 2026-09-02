# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Findings Correlator - Step 1: Normalizer
Transforms heterogeneous findings from multi-cloud providers, scanners, and threat sensors
into canonical SecurityFinding instances.
"""

import re
from typing import Dict, List, Any, Optional, Union

from domain.enums import (
    CloudProvider,
    FindingSeverity,
    FindingStatus,
    FindingSource,
    EvidenceType,
    EvidenceStatus,
    ExecutionMode,
    ConfidenceLevel,
    AssetType,
)
from domain.models import (
    SecurityFinding,
    AIAsset,
    Evidence,
    AttackTechnique,
)


class FindingNormalizer:
    """
    Normalizes diverse finding representations (SCC, Shadow AI, AST SAST, Multi-Cloud, AI-BOM)
    into strongly-typed canonical SecurityFinding domain objects.
    """

    def __init__(self, default_project_id: str = "your-gcp-project-id"):
        self.default_project_id = default_project_id

    def infer_provider(self, resource: str, source: str = "") -> CloudProvider:
        """Infers the cloud provider from resource strings and source metadata."""
        combined = f"{resource} {source}".lower()
        if any(term in combined for term in ("aws", "bedrock", "s3://", "sagemaker", "arn:aws:")):
            return CloudProvider.AWS
        if any(term in combined for term in ("azure", "openai.azure", "cognitive", "subscriptions/")):
            return CloudProvider.AZURE
        if any(term in combined for term in ("gcp", "google", "projects/", "gs://", "vertex", "scc")):
            return CloudProvider.GCP
        return CloudProvider.GCP

    def infer_asset_type(self, resource: str, category: str = "") -> AssetType:
        """Infers asset classification from resource identifiers and categories."""
        combined = f"{resource} {category}".lower()
        if any(t in combined for t in ("workbench", "notebook", "jupyter")):
            return AssetType.AI_WORKBENCH_NOTEBOOK
        if any(t in combined for t in ("bucket", "gs://", "s3://", "rag_storage", "storage")):
            return AssetType.STORAGE_BUCKET_RAG
        if any(t in combined for t in ("gke", "k8s", "pod", "daemonset", "cluster")):
            return AssetType.KUBERNETES_WORKLOAD
        if any(t in combined for t in ("endpoint", "inference", "chat", "api/v1")):
            return AssetType.INFERENCE_ENDPOINT
        if any(t in combined for t in ("vector", "chroma", "pinecone", "weaviate")):
            return AssetType.VECTOR_DATABASE
        if any(t in combined for t in ("service_account", "iam", "serviceaccount")):
            return AssetType.IAM_SERVICE_ACCOUNT
        return AssetType.FOUNDATION_MODEL

    def normalize_raw_finding(
        self,
        source: str,
        category: str,
        severity: str,
        resource: str,
        description: str,
        suggested_control_id: Optional[str] = None,
        assessment_id: Optional[str] = None,
        execution_mode: Optional[ExecutionMode] = None,
    ) -> SecurityFinding:
        """Constructs a canonical SecurityFinding from generic raw finding arguments."""
        provider = self.infer_provider(resource, source)
        asset_type = self.infer_asset_type(resource, category)

        asset = AIAsset(
            name=resource,
            asset_type=asset_type,
            provider=provider,
            resource_uri=resource
        )

        if execution_mode is not None:
            exec_mode = execution_mode
        elif "FALLBACK" in source.upper():
            exec_mode = ExecutionMode.FALLBACK
        elif any(t in source for t in ("Live", "SCC", "GCP Compute API")):
            exec_mode = ExecutionMode.LIVE
        else:
            exec_mode = ExecutionMode.SIMULATION

        if exec_mode == ExecutionMode.LIVE:
            ev_status = EvidenceStatus.VERIFIED
        elif exec_mode == ExecutionMode.FALLBACK:
            ev_status = EvidenceStatus.UNVERIFIED
        else:
            ev_status = EvidenceStatus.SIMULATED

        evidence = Evidence(
            source=source,
            provider=provider,
            resource=resource,
            evidence_type=EvidenceType.API_RESPONSE if "API" in source or "SCC" in source else EvidenceType.CONFIGURATION,
            status=ev_status,
            execution_mode=exec_mode,
            sanitized_content=description,
            confidence=1.0 if exec_mode == ExecutionMode.LIVE else 0.5
        )

        finding = SecurityFinding(
            assessment_id=assessment_id or f"ASM-{self.default_project_id}",
            source=source,
            provider=provider,
            asset=asset,
            title=f"[{category}] {description[:80]}",
            description=description,
            severity=severity,
            confidence=ConfidenceLevel.HIGH,
            status=FindingStatus.OPEN,
            execution_mode=exec_mode,
            evidence=[evidence],
            metadata={
                "category": category,
                "suggested_control_id": suggested_control_id
            }
        )

        # Extract MITRE ATLAS techniques if present in description
        atlas_matches = re.findall(r"AML\.T\d{4}(?:\.\d{3})?", description)
        for tech in atlas_matches:
            finding.add_attack_technique(technique_id=tech, name=category)

        return finding

    def normalize_scc_finding(self, scc_item: Union[str, Dict[str, Any]]) -> SecurityFinding:
        """Normalizes a Security Command Center finding."""
        if isinstance(scc_item, str):
            sev = "HIGH"
            if "CRITICAL" in scc_item.upper():
                sev = "CRITICAL"
            elif "MEDIUM" in scc_item.upper():
                sev = "MEDIUM"
            elif "LOW" in scc_item.upper():
                sev = "LOW"

            ctrl_id = None
            if "AI-SEC-001" in scc_item or "IAM" in scc_item or "Excessive Agency" in scc_item:
                ctrl_id = "INF-03"
            elif "AI-SEC-002" in scc_item or "Public ingress" in scc_item or "PSC" in scc_item:
                ctrl_id = "INF-02"
            elif "AI-SEC-003" in scc_item or "CMEK" in scc_item or "encryption" in scc_item.lower():
                ctrl_id = "INF-04"

            return self.normalize_raw_finding(
                source=FindingSource.GCP_SCC,
                category="SCC AI Protection",
                severity=sev,
                resource=f"projects/{self.default_project_id}",
                description=scc_item,
                suggested_control_id=ctrl_id
            )
        else:
            sev = scc_item.get("severity", "HIGH")
            desc = scc_item.get("description") or scc_item.get("category", "SCC AI Finding")
            res = scc_item.get("resource_name") or scc_item.get("resource", f"projects/{self.default_project_id}")
            return self.normalize_raw_finding(
                source=FindingSource.GCP_SCC,
                category=scc_item.get("category", "SCC Finding"),
                severity=sev,
                resource=res,
                description=desc,
                suggested_control_id=scc_item.get("control_id")
            )

    def normalize_shadow_finding(self, item: Dict[str, Any]) -> SecurityFinding:
        """Normalizes Shadow AI container, rogue LLM, or Workbench CVE findings."""
        sev = item.get("severity", "HIGH")
        engine = item.get("engine") or item.get("type") or item.get("vulnerability_type") or "Shadow AI"
        cve_id = item.get("cve")
        cluster = item.get("cluster") or item.get("resource_name") or item.get("resource") or "Compute Instance"
        risk = item.get("risk") or item.get("description") or "Unmanaged AI Workload"

        ctrl_id = "GOV-02"
        if cve_id or "cve" in str(item).lower() or "startup" in str(item).lower():
            ctrl_id = "INF-01"
        elif "public ip" in str(item).lower() or "internet access" in str(item).lower():
            ctrl_id = "INF-02"
        elif "ollama" in str(item).lower() or "vllm" in str(item).lower() or "shadow" in str(item).lower():
            ctrl_id = "GOV-02"

        tag = f"[{cve_id}] " if cve_id else f"[{engine}] "
        finding = self.normalize_raw_finding(
            source=FindingSource.SHADOW_AI_HUNTER,
            category=engine,
            severity=sev,
            resource=cluster,
            description=f"{tag}{risk}",
            suggested_control_id=ctrl_id
        )
        if cve_id:
            finding.metadata["cve"] = cve_id
        return finding

    def normalize_sast_finding(self, item: Dict[str, Any]) -> SecurityFinding:
        """Normalizes AST SAST code-level prompt injection findings."""
        sev = item.get("severity", "HIGH")
        file_path = item.get("file", "app.py")
        line = item.get("line", 1)
        msg = item.get("message") or item.get("issue") or "Insecure Prompt Interpolation"
        
        ctrl_id = "APP-01"
        if "tool" in msg.lower() or "function" in msg.lower():
            ctrl_id = "APP-04"

        finding = self.normalize_raw_finding(
            source=FindingSource.PROMPT_SAST,
            category="AST Prompt Injection Risk",
            severity=sev,
            resource=f"{file_path}:{line}",
            description=f"SAST Finding at line {line}: {msg}",
            suggested_control_id=ctrl_id
        )
        finding.asset.asset_type = AssetType.AI_AGENT
        return finding
