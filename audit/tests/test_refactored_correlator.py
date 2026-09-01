# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Unit Tests for AISPR Phase 3: Deterministic Findings Correlator Pipeline
Tests all 10 required scenarios:
1. duplicate findings
2. same finding across clouds
3. one finding → multiple controls
4. one control → multiple findings
5. explicit mapping precedence
6. heuristic fallback
7. conflicting severity resolution
8. simulation vs live
9. missing evidence handling
10. cross-cloud correlation
"""

import os
import sys
import unittest

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
audit_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(audit_dir)
for p in [root_dir, audit_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

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
from audit.engine.correlator import (
    FindingNormalizer,
    FindingDeduplicator,
    ControlMapper,
    SeverityEngine,
    EvidenceValidator,
    DeterministicCorrelator,
)
from audit.engine.findings_correlator import CloudFindingsCorrelator


class TestRefactoredCorrelatorPipeline(unittest.TestCase):

    def setUp(self):
        self.project_id = "fintech-security-prod"
        self.correlator = DeterministicCorrelator(project_id=self.project_id)

    def test_duplicate_findings_deduplication_and_merging(self):
        """1. Duplicate findings must be merged without losing evidence or dropping context."""
        f1 = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.CLOUD_ASSET_INVENTORY,
            provider=CloudProvider.GCP,
            asset=AIAsset(name="projects/test/endpoints/ep1", resource_uri="projects/test/endpoints/ep1", asset_type=AssetType.INFERENCE_ENDPOINT),
            title="Public Ingress Allowed",
            description="AI endpoint allows unrestricted 0.0.0.0/0 traffic",
            severity=FindingSeverity.HIGH,
            evidence=[Evidence(sanitized_content="Evidence snapshot A")]
        )
        f2 = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.CLOUD_ASSET_INVENTORY,
            provider=CloudProvider.GCP,
            asset=AIAsset(name="projects/test/endpoints/ep1", resource_uri="projects/test/endpoints/ep1", asset_type=AssetType.INFERENCE_ENDPOINT),
            title="Public Ingress Allowed (Duplicate Scan)",
            description="AI endpoint allows unrestricted 0.0.0.0/0 traffic",
            severity=FindingSeverity.CRITICAL,  # Conflicting higher severity
            evidence=[Evidence(sanitized_content="Evidence snapshot B")]
        )

        deduplicator = FindingDeduplicator()
        deduped = deduplicator.deduplicate([f1, f2])

        self.assertEqual(len(deduped), 1)
        merged = deduped[0]
        # Should escalate to CRITICAL
        self.assertEqual(merged.severity, FindingSeverity.CRITICAL)
        # Should merge both evidences
        self.assertEqual(len(merged.evidence), 2)
        # Should record duplicate count
        self.assertEqual(merged.metadata["duplicate_count"], 2)

    def test_same_finding_across_clouds_remains_distinct(self):
        """2. Same vulnerability pattern across GCP and AWS must not be erroneously deduplicated."""
        f_gcp = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.GCP_SCC,
            provider=CloudProvider.GCP,
            asset=AIAsset(name="gs://fintech-rag-corpus", resource_uri="gs://fintech-rag-corpus", asset_type=AssetType.STORAGE_BUCKET_RAG),
            title="Default Cloud Encryption",
            description="Bucket lacks Customer-Managed Encryption Key (CMEK)",
            severity=FindingSeverity.HIGH,
        )
        f_aws = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.MULTI_CLOUD_SCANNER,
            provider=CloudProvider.AWS,
            asset=AIAsset(name="s3://fintech-aws-rag", resource_uri="s3://fintech-aws-rag", asset_type=AssetType.STORAGE_BUCKET_RAG),
            title="Default Cloud Encryption",
            description="Bucket lacks Customer-Managed Encryption Key (CMEK)",
            severity=FindingSeverity.HIGH,
        )

        deduplicator = FindingDeduplicator()
        deduped = deduplicator.deduplicate([f_gcp, f_aws])
        self.assertEqual(len(deduped), 2, "Findings in different clouds/resources must remain distinct!")

    def test_one_finding_to_multiple_controls(self):
        """3. One finding must support mapping to primary, secondary, and related controls."""
        finding = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.SHADOW_AI_HUNTER,
            provider=CloudProvider.GCP,
            asset=AIAsset(name="workbench-instance-1", resource_uri="projects/p/zones/z/instances/workbench-1", asset_type=AssetType.AI_WORKBENCH_NOTEBOOK),
            title="Vertex Workbench Startup Script Token Exposure",
            description="CVE-2026-2244 detected: startup_script_token exposed in serial logs",
            severity=FindingSeverity.HIGH
        )

        mapper = ControlMapper()
        mapped = mapper.map_controls(finding)

        self.assertEqual(mapped.primary_control_id, "INF-01")
        self.assertIn("INF-03", mapped.secondary_control_ids)
        self.assertIn("GOV-02", mapped.related_control_ids)

        # Correlator should index it under all associated controls
        self.correlator.add_canonical_finding(mapped)
        correlated = self.correlator.correlate()
        self.assertIn("INF-01", correlated)
        self.assertIn("INF-03", correlated)
        self.assertIn("GOV-02", correlated)

    def test_one_control_to_multiple_findings(self):
        """4. One control must aggregate multiple distinct findings and build consolidated summaries."""
        self.correlator.add_raw_finding(
            source="SCC",
            category="IAM Privileges",
            severity="HIGH",
            resource="serviceAccount:sa-agent@fintech.iam.gserviceaccount.com",
            description="Overprivileged roles/editor assigned to AI agent",
            suggested_control_id="INF-03"
        )
        self.correlator.add_raw_finding(
            source="SCC",
            category="IAM Privileges",
            severity="CRITICAL",
            resource="serviceAccount:sa-eval@fintech.iam.gserviceaccount.com",
            description="Owner permissions assigned to model evaluation worker",
            suggested_control_id="INF-03"
        )

        res = self.correlator.correlate()
        entry = res["INF-03"]
        self.assertEqual(len(entry["findings"]), 2)
        self.assertEqual(entry["severity"], FindingSeverity.CRITICAL)
        self.assertEqual(entry["suggested_status"], "N")
        self.assertIn("sa-agent", entry["summary"])
        self.assertIn("sa-eval", entry["summary"])

    def test_explicit_mapping_precedence_over_keywords(self):
        """5. Explicit control mapping must take precedence over keyword heuristic matching."""
        # This finding mentions keywords like 'cve', 'public ip', and 'cmek', but has an explicit mapping to DAT-01
        finding = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.MANUAL_AUDIT,
            provider=CloudProvider.GCP,
            asset=AIAsset(name="dataset-rag-01", resource_uri="gs://rag-data", asset_type=AssetType.STORAGE_BUCKET_RAG),
            title="Lineage Gap with CVE & Public IP keywords",
            description="Dataset training lineage missing even though cve and public ip are mentioned",
            severity=FindingSeverity.MEDIUM,
            metadata={"suggested_control_id": "DAT-01"}
        )

        mapper = ControlMapper()
        mapped = mapper.map_controls(finding)
        self.assertEqual(mapped.primary_control_id, "DAT-01")
        self.assertNotEqual(mapped.primary_control_id, "INF-01")

    def test_heuristic_fallback_when_no_rules_match(self):
        """6. Keyword heuristic must trigger only as a fallback when deterministic rules don't match."""
        finding = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.MANUAL_AUDIT,
            provider=CloudProvider.GCP,
            asset=AIAsset(name="rag-doc-store", resource_uri="gs://doc-store", asset_type=AssetType.STORAGE_BUCKET_RAG),
            title="Generic Storage Audit",
            description="Sensitive cleartext PII and SSN data detected in model corpus",
            severity=FindingSeverity.HIGH,
        )

        mapper = ControlMapper()
        mapped = mapper.map_controls(finding)
        self.assertEqual(mapped.primary_control_id, "DAT-03")
        self.assertEqual(mapped.metadata.get("mapping_level"), "KEYWORD_HEURISTIC_FALLBACK")

    def test_conflicting_severity_resolution(self):
        """7. SeverityEngine must deterministically escalate to the most conservative risk tier."""
        engine = SeverityEngine()
        resolved = engine.resolve_conflicting_severities([
            FindingSeverity.LOW,
            FindingSeverity.MEDIUM,
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH
        ])
        self.assertEqual(resolved, FindingSeverity.CRITICAL)

        # String inputs resolution
        resolved_str = engine.resolve_conflicting_severities(["LOW", "HIGH", "MEDIUM"])
        self.assertEqual(resolved_str, FindingSeverity.HIGH)

    def test_simulation_vs_live_findings_handling(self):
        """8. Live and simulation findings must preserve their epistemological execution mode."""
        live_ev = Evidence(
            source=FindingSource.CLOUD_ASSET_INVENTORY,
            provider=CloudProvider.GCP,
            resource="projects/prod/endpoints/live-ep",
            evidence_type=EvidenceType.API_RESPONSE,
            status=EvidenceStatus.VERIFIED,
            execution_mode=ExecutionMode.LIVE,
            confidence=0.99,
            sanitized_content="Live telemetry verified"
        )
        live_f = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.CLOUD_ASSET_INVENTORY,
            provider=CloudProvider.GCP,
            asset=AIAsset(name="projects/prod/endpoints/live-ep", resource_uri="projects/prod/endpoints/live-ep", asset_type=AssetType.INFERENCE_ENDPOINT),
            title="Live Verified Public Ingress",
            description="Live Asset Inventory confirms public endpoint",
            severity=FindingSeverity.HIGH,
            execution_mode=ExecutionMode.LIVE,
            evidence=[live_ev]
        )

        sim_ev = Evidence(
            source=FindingSource.SHADOW_AI_HUNTER,
            status=EvidenceStatus.SIMULATED,
            execution_mode=ExecutionMode.SIMULATION,
            sanitized_content="Simulated Ollama pod"
        )
        sim_f = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.SHADOW_AI_HUNTER,
            provider=CloudProvider.GCP,
            asset=AIAsset(name="simulated-ollama", resource_uri="k8s://pod-sim", asset_type=AssetType.KUBERNETES_WORKLOAD),
            title="Simulated Rogue Container",
            description="Offline simulation finding",
            severity=FindingSeverity.MEDIUM,
            execution_mode=ExecutionMode.SIMULATION,
            evidence=[sim_ev]
        )

        self.correlator.add_canonical_finding(live_f)
        self.correlator.add_canonical_finding(sim_f)
        res = self.correlator.correlate()

        canonical = self.correlator.to_canonical_findings()
        live_items = [f for f in canonical if f.execution_mode == ExecutionMode.LIVE]
        sim_items = [f for f in canonical if f.execution_mode == ExecutionMode.SIMULATION]

        self.assertEqual(len(live_items), 1)
        self.assertEqual(len(sim_items), 1)
        self.assertTrue(live_items[0].is_live_verified)
        self.assertTrue(sim_items[0].is_simulated)

    def test_missing_evidence_handling(self):
        """9. Findings without empirical evidence must receive degraded confidence and never pass."""
        unverified_finding = SecurityFinding(
            assessment_id="ASM-01",
            source=FindingSource.MANUAL_AUDIT,
            provider=CloudProvider.GCP,
            asset=AIAsset(name="unverified-asset", resource_uri="projects/p/assets/a", asset_type=AssetType.FOUNDATION_MODEL),
            title="Asserted Vulnerability Without Telemetry",
            description="Auditor assertion without attached evidence logs or API responses",
            severity=FindingSeverity.HIGH,
            evidence=[]  # Zero evidence attached
        )

        validator = EvidenceValidator()
        validated = validator.validate_finding_evidence(unverified_finding)

        self.assertEqual(validated.confidence, ConfidenceLevel.LOW)
        self.assertEqual(validated.metadata.get("evidence_health"), "MISSING_EVIDENCE")
        self.assertEqual(validated.status, FindingStatus.OPEN, "Absence of evidence must never convert finding to PASS/RESOLVED!")
        self.assertEqual(len(validated.evidence), 1)
        self.assertEqual(validated.evidence[0].status, EvidenceStatus.UNVERIFIED)

    def test_cross_cloud_correlation(self):
        """10. Findings from GCP, AWS, and Azure must correlate across clouds and allow grouping."""
        facade = CloudFindingsCorrelator(project_id=self.project_id)
        
        # Add GCP finding
        facade.add_raw_finding(
            source="GCP Security Command Center (SCC)",
            category="CMEK Key Missing",
            severity="HIGH",
            resource="projects/gcp-prod/locations/us-central1/keyRings/ai-ring",
            description="CMEK encryption key missing on Vertex AI dataset",
            suggested_control_id="INF-04"
        )
        # Add AWS finding
        facade.add_raw_finding(
            source="AWS Posture Scanner",
            category="KMS Encryption Gap",
            severity="HIGH",
            resource="arn:aws:s3:::fintech-bedrock-prod-bucket",
            description="Default KMS encryption used on Bedrock training data",
            suggested_control_id="INF-04"
        )
        # Add Azure finding
        facade.add_raw_finding(
            source="Azure Posture Scanner",
            category="Key Vault Gap",
            severity="HIGH",
            resource="subscriptions/sub-123/resourceGroups/rg-ai/vaults/kv-ai",
            description="Azure OpenAI search index not encrypted with Customer-Managed Key",
            suggested_control_id="INF-04"
        )

        res = facade.correlate()
        inf04 = res["INF-04"]

        # All three clouds correlated under INF-04
        self.assertEqual(len(inf04["findings"]), 3)
        self.assertIn("GCP", inf04["cross_cloud_providers"])
        self.assertIn("AWS", inf04["cross_cloud_providers"])
        self.assertIn("AZURE", inf04["cross_cloud_providers"])

        # Cloud grouping
        by_cloud = facade.get_findings_by_cloud()
        self.assertGreaterEqual(len(by_cloud["GCP"]), 1)
        self.assertGreaterEqual(len(by_cloud["AWS"]), 1)
        self.assertGreaterEqual(len(by_cloud["AZURE"]), 1)


if __name__ == "__main__":
    unittest.main()
