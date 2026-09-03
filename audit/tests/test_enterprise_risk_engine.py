# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

PHASE 5 — ENTERPRISE AI RISK ENGINE TEST SUITE
Exhaustively tests all requirements of Phase 5:
1. Zero findings baseline
2. One critical finding
3. Multiple low findings
4. Critical + Low findings (NO DILUTION guarantee)
5. Missing evidence penalty
6. Simulated evidence assurance ceiling (max 50%)
7. Mixed live and simulation evidence
8. N/A controls (justified vs unjustified penalty)
9. Partial controls handling
10. High asset criticality multiplier
11. Public exposure multiplier
12. Privileged identity multiplier
13. Sensitive data multiplier
14. Attack path and chained MITRE ATLAS tactics
15. Duplicate findings deduplication
16. Absolute determinism and reproducibility
17. Versioning and machine-readable calculation traces
"""

import os
import sys
import unittest
from datetime import datetime

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
    AssetCriticality,
    DataSensitivity,
    EnvironmentExposure,
    IdentityPrivilege,
    RiskLevel,
    PostureTier,
    AssessmentType,
    AutomationLevel,
)
from domain.models import (
    AIAsset,
    SecurityFinding,
    Evidence,
    AttackTechnique,
    EnterpriseRiskResult,
    EnterpriseRiskMetrics,
    FindingRiskAssessment,
)
from audit.engine.risk_engine import EnterpriseRiskEngine
from audit.contracts.registry import ControlContractRegistry


class TestEnterpriseRiskEngine(unittest.TestCase):

    def setUp(self):
        self.engine = EnterpriseRiskEngine()
        self.sample_asset = AIAsset(
            name="vertex-gemini-pro-endpoint",
            resource_uri="projects/enterprise-ai/locations/us-central1/endpoints/12345",
            asset_type=AssetType.INFERENCE_ENDPOINT,
            provider=CloudProvider.GCP,
            is_private_endpoint=True,
            cmek_enabled=True,
            classification="INTERNAL",
        )

    def test_zero_findings(self):
        """1. Zero findings must yield zero residual risk, negligible tier, and pristine floor."""
        result = self.engine.evaluate(
            assessment_id="ASM-ZERO",
            findings=[],
            assets=[self.sample_asset],
            control_evaluations={},
        )
        self.assertEqual(result.metrics.residual_risk_score, 0.0)
        self.assertEqual(result.metrics.unmitigated_finding_floor, 0.0)
        self.assertEqual(result.metrics.residual_risk_tier, RiskLevel.NEGLIGIBLE)
        self.assertEqual(len(result.finding_assessments), 0)

    def test_one_critical_finding(self):
        """2. A single critical finding must produce high residual risk (>=80) and critical tier."""
        ev = Evidence(
            source=FindingSource.GCP_SCC,
            resource="projects/enterprise-ai/locations/us-central1/endpoints/12345",
            execution_mode=ExecutionMode.LIVE,
            status=EvidenceStatus.VERIFIED,
            sanitized_content="Live SCC finding: RCE vulnerability in endpoint runtime container.",
        )
        crit_finding = SecurityFinding(
            title="Remote Code Execution on Production Model Server",
            asset=self.sample_asset,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.CRITICAL,
            execution_mode=ExecutionMode.LIVE,
            evidence=[ev],
            primary_control_id="APP-01",
        )

        result = self.engine.evaluate(
            assessment_id="ASM-CRIT-ONE",
            findings=[crit_finding],
            assets=[self.sample_asset],
        )

        self.assertGreaterEqual(result.metrics.residual_risk_score, 80.0)
        self.assertEqual(result.metrics.residual_risk_tier, RiskLevel.CRITICAL)
        self.assertEqual(result.metrics.security_posture_tier, PostureTier.CRITICAL_VULNERABLE)
        self.assertEqual(
            result.metrics.unmitigated_finding_floor,
            result.finding_assessments[0].residual_risk,
        )

    def test_multiple_low_findings(self):
        """3. Multiple low findings accumulate with diminishing returns but remain within moderate bounds."""
        low_findings = []
        for i in range(10):
            ev = Evidence(
                source=FindingSource.PROMPT_SAST,
                resource=f"repo/app/prompt_{i}.txt",
                execution_mode=ExecutionMode.SIMULATION,
                status=EvidenceStatus.SIMULATED,
                sanitized_content="Minor linting style issue in prompt template.",
            )
            low_findings.append(
                SecurityFinding(
                    title=f"Minor Prompt Format Anomaly #{i}",
                    asset=self.sample_asset,
                    source=FindingSource.PROMPT_SAST,
                    severity=FindingSeverity.LOW,
                    execution_mode=ExecutionMode.SIMULATION,
                    evidence=[ev],
                    primary_control_id="APP-05",
                )
            )

        result = self.engine.evaluate(
            assessment_id="ASM-LOWS",
            findings=low_findings,
            assets=[self.sample_asset],
        )

        # Risk accumulates without jumping to Critical
        self.assertLess(result.metrics.residual_risk_score, 75.0)
        self.assertIn(result.metrics.residual_risk_tier, [RiskLevel.MEDIUM, RiskLevel.HIGH])

    def test_critical_plus_low_findings_no_dilution(self):
        """4. NO DILUTION GUARANTEE: A single CRITICAL finding MUST NOT be diluted by hundreds of LOW findings."""
        ev_crit = Evidence(
            source=FindingSource.GCP_SCC,
            resource="projects/p1/models/m1",
            execution_mode=ExecutionMode.LIVE,
            status=EvidenceStatus.VERIFIED,
            sanitized_content="Live root compromise finding",
        )
        crit_finding = SecurityFinding(
            title="Unauthenticated Model Weights Exfiltration via Open Gateway",
            asset=self.sample_asset,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.CRITICAL,
            execution_mode=ExecutionMode.LIVE,
            evidence=[ev_crit],
            primary_control_id="INF-01",
        )

        # First evaluate the standalone critical finding
        crit_result = self.engine.evaluate(
            assessment_id="ASM-STANDALONE-CRIT",
            findings=[crit_finding],
            assets=[self.sample_asset],
        )
        baseline_crit_risk = crit_result.metrics.residual_risk_score

        # Now flood the assessment with 50 low findings
        findings_flood = [crit_finding]
        for i in range(50):
            ev_low = Evidence(
                source=FindingSource.PROMPT_SAST,
                resource=f"repo/app/prompt_{i}.txt",
                execution_mode=ExecutionMode.SIMULATION,
                status=EvidenceStatus.SIMULATED,
                sanitized_content="Minor comment inconsistency",
            )
            findings_flood.append(
                SecurityFinding(
                    title=f"Minor Comment Inconsistency #{i}",
                    asset=self.sample_asset,
                    source=FindingSource.PROMPT_SAST,
                    severity=FindingSeverity.LOW,
                    execution_mode=ExecutionMode.SIMULATION,
                    evidence=[ev_low],
                    primary_control_id="APP-10",
                )
            )

        flooded_result = self.engine.evaluate(
            assessment_id="ASM-FLOODED",
            findings=findings_flood,
            assets=[self.sample_asset],
        )

        # The flooded result MUST NOT be diluted below the single critical finding's risk
        self.assertGreaterEqual(
            flooded_result.metrics.residual_risk_score,
            baseline_crit_risk,
            f"Dilution detected! Flooded risk {flooded_result.metrics.residual_risk_score} was lower than baseline {baseline_crit_risk}",
        )
        self.assertEqual(flooded_result.metrics.residual_risk_tier, RiskLevel.CRITICAL)
        self.assertEqual(flooded_result.metrics.security_posture_tier, PostureTier.CRITICAL_VULNERABLE)
        self.assertGreaterEqual(flooded_result.metrics.unmitigated_finding_floor, baseline_crit_risk)

    def test_missing_evidence_penalty(self):
        """5. CRITICAL RULE: Missing evidence != PASS. Missing evidence applies uncertainty penalty."""
        # Simulation finding with zero evidence items
        finding_no_ev = SecurityFinding(
            title="Potential Token Exposure without Telemetry Evidence",
            asset=self.sample_asset,
            source=FindingSource.PROMPT_SAST,
            severity=FindingSeverity.HIGH,
            execution_mode=ExecutionMode.SIMULATION,
            evidence=[],
            primary_control_id="APP-02",
        )

        result = self.engine.evaluate(
            assessment_id="ASM-NO-EVD",
            findings=[finding_no_ev],
            assets=[self.sample_asset],
        )

        self.assertEqual(result.metrics.missing_evidence_count, 1)
        # Evidence confidence heavily penalized
        self.assertEqual(result.metrics.evidence_confidence_score, 0.0)

        # Check that uncertainty penalty rule was logged in trace
        self.assertTrue(
            any(t.rule_id == "RULE-EVD-MISSING-PENALTY-01" for t in result.calculation_trace)
        )

    def test_simulated_evidence_assurance_ceiling(self):
        """6. CRITICAL RULE: Simulation != Production assurance. Simulation evidence capped at 50% assurance."""
        sim_ev = Evidence(
            source=FindingSource.AI_RED_TEAM,
            resource="test-model",
            execution_mode=ExecutionMode.SIMULATION,
            status=EvidenceStatus.SIMULATED,
            sanitized_content="Synthetic prompt injection test payload succeeded.",
        )
        sim_finding = SecurityFinding(
            title="Prompt Injection Simulation Vulnerability",
            asset=self.sample_asset,
            source=FindingSource.AI_RED_TEAM,
            severity=FindingSeverity.HIGH,
            execution_mode=ExecutionMode.SIMULATION,
            evidence=[sim_ev],
            primary_control_id="APP-01",
        )

        result = self.engine.evaluate(
            assessment_id="ASM-SIM",
            findings=[sim_finding],
            assets=[self.sample_asset],
        )

        fa = result.finding_assessments[0]
        # Simulation evidence cannot reduce residual risk below 50% of inherent risk
        self.assertGreaterEqual(fa.residual_risk, round(0.50 * fa.inherent_risk, 2))
        self.assertEqual(fa.evidence_confidence_factor, 0.50)

    def test_mixed_live_and_simulation(self):
        """7. Mixed live and simulation evidence produces weighted confidence ratio."""
        ev_live = Evidence(
            source=FindingSource.GCP_SCC,
            resource="res-live",
            execution_mode=ExecutionMode.LIVE,
            status=EvidenceStatus.VERIFIED,
            sanitized_content="Live SCC verified audit event.",
        )
        f_live = SecurityFinding(
            title="Live Finding",
            asset=self.sample_asset,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.MEDIUM,
            execution_mode=ExecutionMode.LIVE,
            evidence=[ev_live],
            primary_control_id="INF-03",
        )

        ev_sim = Evidence(
            source=FindingSource.AI_RED_TEAM,
            resource="res-sim",
            execution_mode=ExecutionMode.SIMULATION,
            status=EvidenceStatus.SIMULATED,
            sanitized_content="Simulated payload.",
        )
        f_sim = SecurityFinding(
            title="Simulated Finding",
            asset=self.sample_asset,
            source=FindingSource.AI_RED_TEAM,
            severity=FindingSeverity.MEDIUM,
            execution_mode=ExecutionMode.SIMULATION,
            evidence=[ev_sim],
            primary_control_id="APP-03",
        )

        result = self.engine.evaluate(
            assessment_id="ASM-MIXED",
            findings=[f_live, f_sim],
            assets=[self.sample_asset],
        )

        self.assertEqual(result.metrics.live_evidence_count, 1)
        self.assertEqual(result.metrics.simulated_evidence_count, 1)
        # Weighted: (1.0 * 1 + 0.5 * 1) / 2 = 1.5 / 2 = 75%
        self.assertEqual(result.metrics.evidence_confidence_score, 75.0)

    def test_na_controls_justified_vs_unjustified(self):
        """8. CRITICAL RULE: N/A controls must only be excluded when explicitly justified."""
        # Case A: Explicitly justified N/A
        evals_justified = {
            "INF-05": {
                "status": "NA",
                "justification": "Organization does not deploy self-hosted GPU clusters on bare metal.",
            }
        }
        res_a = self.engine.evaluate(
            assessment_id="ASM-NA-A",
            control_evaluations=evals_justified,
        )
        self.assertEqual(res_a.metrics.justified_na_count, 1)
        self.assertEqual(res_a.metrics.unjustified_na_count, 0)

        # Case B: Unjustified N/A (missing justification)
        evals_unjustified = {
            "INF-05": {
                "status": "NA",
                "justification": "",  # Empty justification!
            }
        }
        res_b = self.engine.evaluate(
            assessment_id="ASM-NA-B",
            control_evaluations=evals_unjustified,
        )
        self.assertEqual(res_b.metrics.justified_na_count, 0)
        self.assertEqual(res_b.metrics.unjustified_na_count, 1)
        # The unjustified N/A must be counted as a penalty (0 earned, 1 possible)
        self.assertTrue(
            any(t.rule_id == "RULE-NA-UNJUSTIFIED-PENALTY-02" for t in res_b.calculation_trace)
        )

    def test_partial_controls_handling(self):
        """9. Partial controls award 0.5 points and contribute half weight to coverage."""
        evals = {
            "APP-01": {"status": "P", "notes": "Model Armor enabled on ingress but not egress"},
            "APP-02": {"status": "Y", "notes": "CMEK enabled"},
            "APP-03": {"status": "N", "notes": "No logging"},
        }
        result = self.engine.evaluate(
            assessment_id="ASM-PARTIAL",
            control_evaluations=evals,
        )
        # Domain APP points: 1.0 (Y) + 0.5 (P) + 0.0 (N) + 0.0 * 16 unassessed = 1.5 / 19 = 7.89%
        self.assertAlmostEqual(result.metrics.compliance_percentage_by_domain["APP"], 7.89, places=1)

    def test_high_asset_criticality_multiplier(self):
        """10. Asset criticality elevates inherent and residual risk."""
        asset_crit = AIAsset(
            name="crown-jewel-model",
            resource_uri="projects/p/models/gemini-crown",
            asset_type=AssetType.FOUNDATION_MODEL,
            classification="CONFIDENTIAL",
            metadata={"criticality": "TIER_1_CRITICAL"},
        )
        asset_dev = AIAsset(
            name="dev-sandbox-model",
            resource_uri="projects/p/models/dev-sandbox",
            asset_type=AssetType.FOUNDATION_MODEL,
            classification="PUBLIC",
            metadata={"criticality": "TIER_4_DEVELOPMENT"},
        )

        f_crit = SecurityFinding(
            title="Same CVE on Critical Asset",
            asset=asset_crit,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.HIGH,
            primary_control_id="MOD-01",
        )
        f_dev = SecurityFinding(
            title="Same CVE on Dev Asset",
            asset=asset_dev,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.HIGH,
            primary_control_id="MOD-01",
        )

        eval_crit = self.engine.evaluate_finding(f_crit, {asset_crit.name: asset_crit})
        eval_dev = self.engine.evaluate_finding(f_dev, {asset_dev.name: asset_dev})

        self.assertGreater(eval_crit.inherent_risk, eval_dev.inherent_risk)
        self.assertEqual(eval_crit.asset_criticality_multiplier, 1.40)
        self.assertEqual(eval_dev.asset_criticality_multiplier, 0.75)

    def test_public_exposure_multiplier(self):
        """11. Public internet exposure elevates exposure multiplier and attack surface risk."""
        asset_pub = AIAsset(
            name="public-agent",
            resource_uri="projects/p/endpoints/public",
            is_private_endpoint=False,
            metadata={"exposure": "PUBLIC_INTERNET"},
        )
        asset_priv = AIAsset(
            name="private-agent",
            resource_uri="projects/p/endpoints/private",
            is_private_endpoint=True,
            metadata={"exposure": "ISOLATED_AIR_GAPPED"},
        )

        f_pub = SecurityFinding(
            title="Public Exposed Finding",
            asset=asset_pub,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.HIGH,
            primary_control_id="INF-01",
        )
        f_priv = SecurityFinding(
            title="Private Finding",
            asset=asset_priv,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.HIGH,
            primary_control_id="INF-01",
        )

        eval_pub = self.engine.evaluate_finding(f_pub, {asset_pub.name: asset_pub})
        eval_priv = self.engine.evaluate_finding(f_priv, {asset_priv.name: asset_priv})

        self.assertEqual(eval_pub.exposure_multiplier, 1.40)
        self.assertEqual(eval_priv.exposure_multiplier, 0.70)
        self.assertGreater(eval_pub.inherent_risk, eval_priv.inherent_risk)

    def test_privileged_identity_multiplier(self):
        """12. Privileged admin/owner access in finding elevates privilege multiplier."""
        f_admin = SecurityFinding(
            title="Wildcard roles/owner Assigned to Agent Service Account",
            asset=self.sample_asset,
            source=FindingSource.GCP_SCC,
            description="Service account has roles/owner across organization",
            severity=FindingSeverity.HIGH,
            primary_control_id="INF-03",
        )
        f_viewer = SecurityFinding(
            title="Viewer Role Assigned",
            asset=self.sample_asset,
            source=FindingSource.GCP_SCC,
            description="Service account has viewer role only",
            severity=FindingSeverity.HIGH,
            primary_control_id="INF-03",
        )

        eval_admin = self.engine.evaluate_finding(f_admin, {})
        eval_viewer = self.engine.evaluate_finding(f_viewer, {})

        self.assertEqual(eval_admin.privilege_multiplier, 1.40)
        self.assertEqual(eval_viewer.privilege_multiplier, 0.90)
        self.assertGreater(eval_admin.inherent_risk, eval_viewer.inherent_risk)

    def test_sensitive_data_multiplier(self):
        """13. Restricted PII/Secrets classification elevates data sensitivity multiplier."""
        asset_pii = AIAsset(
            name="patient-records-rag",
            resource_uri="gs://hospital-records",
            classification="RESTRICTED",
        )
        asset_pub = AIAsset(
            name="public-docs-rag",
            resource_uri="gs://public-docs",
            classification="PUBLIC",
        )

        f_pii = SecurityFinding(
            title="Plaintext Data Leakage",
            asset=asset_pii,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.MEDIUM,
            primary_control_id="DAT-03",
        )
        f_pub = SecurityFinding(
            title="Plaintext Data Leakage",
            asset=asset_pub,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.MEDIUM,
            primary_control_id="DAT-03",
        )

        eval_pii = self.engine.evaluate_finding(f_pii, {asset_pii.name: asset_pii})
        eval_pub = self.engine.evaluate_finding(f_pub, {asset_pub.name: asset_pub})

        self.assertEqual(eval_pii.data_sensitivity_multiplier, 1.40)
        self.assertEqual(eval_pub.data_sensitivity_multiplier, 0.80)
        self.assertGreater(eval_pii.inherent_risk, eval_pub.inherent_risk)

    def test_attack_path_and_chained_tactics(self):
        """14. Findings mapped to chained MITRE ATLAS tactics receive attack path multiplier."""
        f_chained = SecurityFinding(
            title="Chained Multi-Stage Attack on Autonomous Agent",
            asset=self.sample_asset,
            source=FindingSource.AI_RED_TEAM,
            severity=FindingSeverity.HIGH,
            primary_control_id="APP-01",
        )
        f_chained.add_attack_technique("AML.T0054", "LLM Jailbreak", tactic="Initial Access")
        f_chained.add_attack_technique("AML.T0043", "Prompt Injection RCE", tactic="Execution")
        f_chained.add_attack_technique("AML.T0035", "Model Inversion Exfiltration", tactic="Exfiltration")

        eval_chained = self.engine.evaluate_finding(f_chained, {})
        self.assertEqual(eval_chained.attack_path_multiplier, 1.20)
        self.assertGreater(eval_chained.exploitability_multiplier, 1.00)

    def test_duplicate_findings_deduplication(self):
        """15. Submitting identical findings does not artificially inflate risk."""
        f1 = SecurityFinding(
            finding_id="F-DUP-01",
            title="Duplicate Misconfiguration",
            asset=self.sample_asset,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.HIGH,
            primary_control_id="INF-02",
        )
        f2 = SecurityFinding(
            finding_id="F-DUP-02",
            title="Duplicate Misconfiguration",  # Identical signature
            asset=self.sample_asset,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.HIGH,
            primary_control_id="INF-02",
        )

        res_single = self.engine.evaluate(
            assessment_id="ASM-SINGLE",
            findings=[f1],
            assets=[self.sample_asset],
        )

        res_duplicate = self.engine.evaluate(
            assessment_id="ASM-DUP",
            findings=[f1, f2],
            assets=[self.sample_asset],
        )

        self.assertEqual(
            res_single.metrics.residual_risk_score,
            res_duplicate.metrics.residual_risk_score,
        )
        self.assertEqual(len(res_duplicate.finding_assessments), 1)
        self.assertTrue(
            any(t.rule_id == "RULE-DEDUP-DROP-01" for t in res_duplicate.calculation_trace)
        )

    def test_absolute_determinism_and_reproducibility(self):
        """16. Identical inputs MUST produce bit-for-bit identical results and traces."""
        f = SecurityFinding(
            title="Determinism Test Finding",
            asset=self.sample_asset,
            source=FindingSource.GCP_SCC,
            severity=FindingSeverity.HIGH,
            primary_control_id="APP-01",
        )
        evals = {"APP-01": {"status": "Y"}, "INF-01": {"status": "N"}}

        res1 = self.engine.evaluate(
            assessment_id="ASM-DET",
            findings=[f],
            assets=[self.sample_asset],
            control_evaluations=evals,
        )
        res2 = self.engine.evaluate(
            assessment_id="ASM-DET",
            findings=[f],
            assets=[self.sample_asset],
            control_evaluations=evals,
        )

        self.assertEqual(res1.metrics.compliance_score, res2.metrics.compliance_score)
        self.assertEqual(res1.metrics.residual_risk_score, res2.metrics.residual_risk_score)
        self.assertEqual(res1.metrics.attack_surface_risk_score, res2.metrics.attack_surface_risk_score)
        self.assertEqual(res1.metrics.security_posture_score, res2.metrics.security_posture_score)
        self.assertEqual(res1.metrics.evidence_confidence_score, res2.metrics.evidence_confidence_score)
        self.assertEqual(res1.metrics.control_coverage_score, res2.metrics.control_coverage_score)
        self.assertEqual(len(res1.calculation_trace), len(res2.calculation_trace))

    def test_versioning_and_trace_integrity(self):
        """17. Verifies calculation trace format and version identification."""
        result = self.engine.evaluate(
            assessment_id="ASM-VER",
            findings=[],
            assets=[self.sample_asset],
        )

        self.assertEqual(result.risk_model_version, "1.0.0")
        self.assertEqual(result.formula_version, "2026.1-enterprise")
        self.assertGreater(len(result.calculation_trace), 0)

        for entry in result.calculation_trace:
            self.assertTrue(hasattr(entry, "rule_id"))
            self.assertTrue(hasattr(entry, "input_value"))
            self.assertTrue(hasattr(entry, "normalized_value"))
            self.assertTrue(hasattr(entry, "calculation_result"))
            # Ensure no chain of thought narrative is leaked
            self.assertNotIn("chain of thought", str(entry.description).lower())
            self.assertNotIn("thought:", str(entry.description).lower())


if __name__ == "__main__":
    unittest.main()
