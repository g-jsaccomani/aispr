# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Findings Correlator - Step 6: Deterministic Correlator Pipeline Orchestrator
Executes the deterministic 5-stage pipeline:
Normalizer → Deduplicator → ControlMapper → SeverityEngine → EvidenceValidator → Correlator
Provides cross-cloud correlation, multi-control linking, and backward-compatible mapping structures.
"""

from typing import Dict, List, Any, Optional, Union

from domain.models import SecurityFinding
from domain.enums import FindingSeverity, CloudProvider

from audit.engine.correlator.normalizer import FindingNormalizer
from audit.engine.correlator.deduplicator import FindingDeduplicator
from audit.engine.correlator.control_mapper import ControlMapper
from audit.engine.correlator.severity_engine import SeverityEngine
from audit.engine.correlator.evidence_validator import EvidenceValidator


class DeterministicCorrelator:
    """
    Main pipeline coordinator that executes the deterministic correlation flow.
    Supports cross-cloud correlation across GCP, AWS, and Azure AI estates.
    """

    def __init__(self, project_id: str = "your-gcp-project-id"):
        self.project_id = project_id
        
        # Pipeline components
        self.normalizer = FindingNormalizer(default_project_id=project_id)
        self.deduplicator = FindingDeduplicator()
        self.control_mapper = ControlMapper()
        self.severity_engine = SeverityEngine()
        self.evidence_validator = EvidenceValidator()

        # State
        self.raw_inputs: List[Dict[str, Any]] = []
        self.canonical_findings: List[SecurityFinding] = []
        self.correlated_map: Dict[str, Dict[str, Any]] = {}

    def add_raw_finding(
        self,
        source: str,
        category: str,
        severity: str,
        resource: str,
        description: str,
        suggested_control_id: Optional[str] = None
    ):
        """Buffers raw finding data for pipeline processing."""
        self.raw_inputs.append({
            "source": source,
            "category": category,
            "severity": severity,
            "resource": resource,
            "description": description,
            "suggested_control_id": suggested_control_id
        })

    def add_canonical_finding(self, finding: SecurityFinding):
        """Directly ingests a pre-built canonical SecurityFinding into the pipeline."""
        self.canonical_findings.append(finding)

    PIPELINE_ORDER = [
        "NORMALIZE",
        "EVIDENCE_VALIDATION",
        "DEDUPLICATION",
        "CONTROL_MAPPING",
        "SEVERITY",
        "CANONICAL_FINDING"
    ]

    def execute_pipeline(self) -> List[SecurityFinding]:
        """
        Executes the canonical 6-stage deterministic pipeline in exact order:
        Stage 1: Normalize (Raw to Canonical)
        Stage 2: Evidence Validation (Cryptographic Hashing & Epistemological Health)
        Stage 3: Deduplication (Deterministic Fingerprint & Evidence Merging)
        Stage 4: Control Mapping (5-Level Precedence Mapping)
        Stage 5: Severity (Risk Analysis & Conflict Resolution)
        Stage 6: Canonical Finding (Final Canonical Aggregation)
        """
        self.execution_order: List[str] = []

        # Stage 1: Normalize raw inputs into canonical findings
        self.execution_order.append("NORMALIZE")
        normalized_list = list(self.canonical_findings)
        for raw in self.raw_inputs:
            f = self.normalizer.normalize_raw_finding(
                source=raw["source"],
                category=raw["category"],
                severity=raw["severity"],
                resource=raw["resource"],
                description=raw["description"],
                suggested_control_id=raw.get("suggested_control_id"),
                assessment_id=f"ASM-{self.project_id}"
            )
            normalized_list.append(f)

        # Stage 2: Evidence Validation (Validate evidence on normalized findings)
        self.execution_order.append("EVIDENCE_VALIDATION")
        evidence_validated = self.evidence_validator.validate_all(normalized_list)

        # Stage 3: Deduplicate (Deterministically merge duplicate findings without evidence loss)
        self.execution_order.append("DEDUPLICATION")
        deduplicated = self.deduplicator.deduplicate(evidence_validated)

        # Stage 4: Map Controls (Primary, Secondary, Related)
        self.execution_order.append("CONTROL_MAPPING")
        mapped = [self.control_mapper.map_controls(f) for f in deduplicated]

        # Stage 5: Evaluate Severity & Conflict Resolution
        self.execution_order.append("SEVERITY")
        severity_assessed = [self.severity_engine.evaluate_finding_severity(f) for f in mapped]

        # Stage 6: Canonical Finding (Final verified canonical findings)
        self.execution_order.append("CANONICAL_FINDING")
        for f in severity_assessed:
            f.metadata["pipeline_stages"] = list(self.execution_order)

        self.canonical_findings = severity_assessed
        return severity_assessed

    def correlate(self) -> Dict[str, Dict[str, Any]]:
        """
        Runs the pipeline and performs cross-cloud correlation, mapping findings
        to the 104 AI-SPR Control IDs.
        """
        findings = self.execute_pipeline()
        correlated: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            # Multi-control support: map to all linked control IDs
            target_controls = finding.control_ids
            if not target_controls:
                target_controls = ["INF-01" if finding.severity in ("CRITICAL", "HIGH") else "GOV-03"]

            for cid in target_controls:
                if cid not in correlated:
                    correlated[cid] = {
                        "has_finding": True,
                        "findings": [],
                        "severity": FindingSeverity.LOW,
                        "suggested_status": "N",
                        "summary": "",
                        "suggested_notes": "",
                        "cross_cloud_providers": set(),
                        "canonical_findings": []
                    }

                entry = correlated[cid]
                entry["canonical_findings"].append(finding)
                entry["cross_cloud_providers"].add(str(finding.provider).upper())

                # Add legacy dictionary finding item
                legacy_dict = {
                    "source": str(finding.source),
                    "resource": finding.asset.resource_uri,
                    "description": finding.description,
                    "severity": str(finding.severity),
                    "confidence": finding.propagated_confidence,
                    "execution_mode": str(finding.execution_mode)
                }
                entry["findings"].append(legacy_dict)

                # Resolve severity conflicts using SeverityEngine
                severities = [f["severity"] for f in entry["findings"]]
                resolved_sev = self.severity_engine.resolve_conflicting_severities(severities)
                entry["severity"] = resolved_sev
                entry["suggested_status"] = self.severity_engine.suggest_control_status(resolved_sev)

        # Build summaries, suggested notes, and finalize provider lists
        for cid, entry in correlated.items():
            f_list = entry["findings"]
            summaries = []
            for f in f_list:
                summaries.append(f"[{f['severity']}] {f['source']}: {f['description']} (Target: {f['resource']})")

            entry["summary"] = " | ".join(summaries)
            entry["suggested_notes"] = f"Cloud Scan Evidence: {entry['summary']}"
            entry["cross_cloud_providers"] = sorted(list(entry["cross_cloud_providers"]))

        self.correlated_map = correlated
        return correlated

    def get_findings_map_dict(self) -> Dict[str, str]:
        """
        Returns flat Dict[control_id, formatted_finding_string] for UI and assessment handler:
        { "INF-01": "Scan Finding: ...", "APP-01": "Scan Finding: ..." }
        """
        if not self.correlated_map:
            self.correlate()

        result: Dict[str, str] = {}
        for cid, data in self.correlated_map.items():
            result[cid] = f"Scan Finding: {data['summary']}"
        return result

    def get_finding_for_control(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Returns correlated findings for a specific Control ID."""
        if not self.correlated_map:
            self.correlate()
        return self.correlated_map.get(control_id)

    def to_canonical_findings(self) -> List[SecurityFinding]:
        """Returns the fully validated list of canonical SecurityFinding objects."""
        if not self.canonical_findings:
            self.execute_pipeline()
        return self.canonical_findings

    def get_findings_by_cloud(self) -> Dict[str, List[SecurityFinding]]:
        """Groups canonical findings by cloud provider (GCP, AWS, AZURE)."""
        findings = self.to_canonical_findings()
        grouped: Dict[str, List[SecurityFinding]] = {"GCP": [], "AWS": [], "AZURE": [], "MULTI_CLOUD": []}
        for f in findings:
            prov_key = str(f.provider).upper()
            if prov_key not in grouped:
                grouped[prov_key] = []
            grouped[prov_key].append(f)
        return grouped
