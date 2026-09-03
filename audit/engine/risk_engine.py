# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

PHASE 5 — ENTERPRISE AI RISK ENGINE
Deterministic, explainable, reproducible, and versioned risk calculation engine.

Strict Separation of Metrics:
1. Compliance Score (0.0 - 100.0)
2. Security Posture (Score 0.0 - 100.0 & Tier)
3. Residual Risk (Score 0.0 - 100.0 & Tier, with Unmitigated Finding Floor)
4. Attack Surface Risk (Score 0.0 - 100.0 & Tier)
5. Evidence Confidence (Score 0.0 - 100.0)
6. Control Coverage (Score 0.0 - 100.0)

CRITICAL RULES ENFORCED:
- Missing evidence != PASS
- Unknown != Secure
- Simulation != Production assurance
- A single CRITICAL finding MUST NOT be diluted by hundreds of LOW findings
- N/A controls must only be excluded when explicitly justified
- Manual controls MUST NOT be counted as automated
- Zero LLM dependencies in core mathematics
"""

import math
from typing import List, Dict, Optional, Any, Set, Tuple
from domain.enums import (
    FindingSeverity,
    FindingStatus,
    RiskLevel,
    PostureTier,
    ExecutionMode,
    EvidenceStatus,
    AssetType,
    AssetCriticality,
    DataSensitivity,
    EnvironmentExposure,
    IdentityPrivilege,
    AssessmentType,
    AutomationLevel,
    ControlEvaluation,
)
from domain.models import (
    AIAsset,
    SecurityFinding,
    Evidence,
    SecurityControlContract,
    Assessment,
    RiskTraceEntry,
    FindingRiskAssessment,
    EnterpriseRiskMetrics,
    EnterpriseRiskResult,
)
from audit.contracts.registry import ControlContractRegistry


def _str(val: Any) -> str:
    if hasattr(val, "value"):
        return str(val.value)
    return str(val)


class EnterpriseRiskEngine:
    """
    Enterprise AI Risk Engine implementing deterministic, versioned, explainable risk calculations.
    """

    RISK_MODEL_VERSION: str = "1.0.0"
    FORMULA_VERSION: str = "2026.1-enterprise"

    # Base severity score mapping (0.0 to 100.0 scale)
    SEVERITY_BASE_SCORES: Dict[FindingSeverity, Tuple[float, float]] = {
        FindingSeverity.CRITICAL: (90.0, 10.0),
        FindingSeverity.HIGH: (70.0, 7.5),
        FindingSeverity.MEDIUM: (45.0, 5.0),
        FindingSeverity.LOW: (20.0, 2.0),
        FindingSeverity.INFO: (5.0, 0.5),
    }

    # Asset Criticality multipliers
    CRITICALITY_MULTIPLIERS: Dict[AssetCriticality, float] = {
        AssetCriticality.TIER_1_CRITICAL: 1.40,
        AssetCriticality.TIER_2_PRODUCTION: 1.20,
        AssetCriticality.TIER_3_INTERNAL: 1.00,
        AssetCriticality.TIER_4_DEVELOPMENT: 0.75,
    }

    # Exposure multipliers
    EXPOSURE_MULTIPLIERS: Dict[EnvironmentExposure, float] = {
        EnvironmentExposure.PUBLIC_INTERNET: 1.40,
        EnvironmentExposure.VPC_INTERNAL: 1.00,
        EnvironmentExposure.ISOLATED_AIR_GAPPED: 0.70,
    }

    # Data Sensitivity multipliers
    DATA_SENSITIVITY_MULTIPLIERS: Dict[DataSensitivity, float] = {
        DataSensitivity.RESTRICTED_PII_SECRETS: 1.40,
        DataSensitivity.CONFIDENTIAL: 1.20,
        DataSensitivity.INTERNAL: 1.00,
        DataSensitivity.PUBLIC: 0.80,
    }

    # IAM Privilege multipliers
    PRIVILEGE_MULTIPLIERS: Dict[IdentityPrivilege, float] = {
        IdentityPrivilege.ADMIN_OWNER: 1.40,
        IdentityPrivilege.WRITE_EXECUTE: 1.20,
        IdentityPrivilege.READ_ONLY: 0.90,
    }

    def __init__(self, registry: Optional[ControlContractRegistry] = None):
        self.registry = registry or ControlContractRegistry()

    def evaluate(
        self,
        assessment_id: str,
        findings: Optional[List[SecurityFinding]] = None,
        assets: Optional[List[AIAsset]] = None,
        control_evaluations: Optional[Dict[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EnterpriseRiskResult:
        """
        Executes the deterministic enterprise risk evaluation pipeline.
        Produces explainable metrics and complete machine-readable traces.
        """
        trace: List[RiskTraceEntry] = []
        raw_findings = findings or []
        asset_list = assets or []
        eval_map = control_evaluations or {}

        # 1. Deduplicate findings deterministically before calculation
        deduped_findings, dedup_trace = self._deduplicate_findings(raw_findings)
        trace.extend(dedup_trace)

        # 2. Build asset lookup map for correlation
        asset_lookup: Dict[str, AIAsset] = {a.name: a for a in asset_list}
        for a in asset_list:
            if a.resource_uri:
                asset_lookup[a.resource_uri] = a

        # 3. Evaluate risk for each individual finding
        finding_assessments: List[FindingRiskAssessment] = []
        for finding in deduped_findings:
            f_eval = self.evaluate_finding(finding, asset_lookup)
            finding_assessments.append(f_eval)
            trace.extend(f_eval.trace)

        # 4. Calculate separated enterprise metrics
        metrics, metric_trace = self.calculate_metrics(
            finding_assessments=finding_assessments,
            findings=deduped_findings,
            assets=asset_list,
            control_evaluations=eval_map,
        )
        trace.extend(metric_trace)

        return EnterpriseRiskResult(
            assessment_id=assessment_id,
            risk_model_version=self.RISK_MODEL_VERSION,
            formula_version=self.FORMULA_VERSION,
            metrics=metrics,
            finding_assessments=finding_assessments,
            calculation_trace=trace,
            metadata=metadata or {},
        )

    def _deduplicate_findings(
        self, findings: List[SecurityFinding]
    ) -> Tuple[List[SecurityFinding], List[RiskTraceEntry]]:
        """
        Deduplicates identical findings to avoid double-counting risk.
        """
        trace: List[RiskTraceEntry] = []
        seen_keys: Set[str] = set()
        deduped: List[SecurityFinding] = []

        for f in findings:
            asset_key = f.asset.resource_uri if (f.asset and f.asset.resource_uri) else (f.asset.name if f.asset else "")
            key = f"{f.primary_control_id}::{asset_key}::{f.title.strip().lower()}::{_str(f.severity)}"
            if key in seen_keys:
                trace.append(
                    RiskTraceEntry(
                        rule_id="RULE-DEDUP-DROP-01",
                        input_value={"finding_id": f.finding_id, "key": key},
                        normalized_value="DUPLICATE",
                        calculation_result=0.0,
                        description=f"Deduplicated finding '{f.finding_id}' with duplicate signature '{key}'.",
                    )
                )
            else:
                seen_keys.add(key)
                deduped.append(f)

        trace.append(
            RiskTraceEntry(
                rule_id="RULE-DEDUP-SUMMARY-02",
                input_value=len(findings),
                normalized_value=len(deduped),
                calculation_result=len(deduped),
                description=f"Deduplication processed {len(findings)} findings into {len(deduped)} distinct findings.",
            )
        )
        return deduped, trace

    def evaluate_finding(
        self, finding: SecurityFinding, asset_lookup: Dict[str, AIAsset]
    ) -> FindingRiskAssessment:
        """
        Deterministically profiles inherent and residual risk for a single canonical finding.
        """
        trace: List[RiskTraceEntry] = []
        fid = finding.finding_id

        # 1. Severity Base Score
        sev = finding.severity if isinstance(finding.severity, FindingSeverity) else FindingSeverity(finding.severity)
        sev_str = _str(sev)
        base_score, sev_num = self.SEVERITY_BASE_SCORES.get(sev, (45.0, 5.0))
        trace.append(
            RiskTraceEntry(
                rule_id=f"RULE-SEV-{sev_str}-01",
                input_value=sev_str,
                normalized_value=sev_num,
                calculation_result=base_score,
                description=f"Base severity score {base_score} for {sev_str}.",
            )
        )

        # Resolve asset for context
        asset = finding.asset
        if not asset and finding.resource:
            asset = asset_lookup.get(finding.resource)

        # 2. Asset Criticality Multiplier
        crit = self._resolve_asset_criticality(asset, finding)
        crit_mult = self.CRITICALITY_MULTIPLIERS.get(crit, 1.10)
        trace.append(
            RiskTraceEntry(
                rule_id="RULE-ASSET-CRITICALITY-02",
                input_value=crit.value if hasattr(crit, "value") else str(crit),
                normalized_value=crit_mult,
                calculation_result=crit_mult,
                description=f"Asset criticality multiplier {crit_mult} for {crit}.",
            )
        )

        # 3. Exposure Multiplier
        exp = self._resolve_exposure(asset, finding)
        exp_mult = self.EXPOSURE_MULTIPLIERS.get(exp, 1.10)
        trace.append(
            RiskTraceEntry(
                rule_id="RULE-EXPOSURE-03",
                input_value=exp.value if hasattr(exp, "value") else str(exp),
                normalized_value=exp_mult,
                calculation_result=exp_mult,
                description=f"Environment exposure multiplier {exp_mult} for {exp}.",
            )
        )

        # 4. Data Sensitivity Multiplier
        data_sens = self._resolve_data_sensitivity(asset, finding)
        data_mult = self.DATA_SENSITIVITY_MULTIPLIERS.get(data_sens, 1.10)
        trace.append(
            RiskTraceEntry(
                rule_id="RULE-DATA-SENSITIVITY-04",
                input_value=data_sens.value if hasattr(data_sens, "value") else str(data_sens),
                normalized_value=data_mult,
                calculation_result=data_mult,
                description=f"Data sensitivity multiplier {data_mult} for {data_sens}.",
            )
        )

        # 5. IAM Privilege Multiplier
        priv = self._resolve_privilege(finding)
        priv_mult = self.PRIVILEGE_MULTIPLIERS.get(priv, 1.00)
        trace.append(
            RiskTraceEntry(
                rule_id="RULE-PRIVILEGE-05",
                input_value=priv.value if hasattr(priv, "value") else str(priv),
                normalized_value=priv_mult,
                calculation_result=priv_mult,
                description=f"IAM privilege multiplier {priv_mult} for {priv}.",
            )
        )

        # 6. Exploitability & Attack Techniques
        exploit_mult, exploit_trace = self._resolve_exploitability(finding)
        trace.extend(exploit_trace)

        # 7. Attack Path / Chained Tactics
        attack_path_mult, attack_path_trace = self._resolve_attack_path(finding)
        trace.extend(attack_path_trace)

        # Calculate Inherent Risk
        raw_inherent = (
            base_score
            * crit_mult
            * exp_mult
            * data_mult
            * priv_mult
            * exploit_mult
            * attack_path_mult
        )
        # Inherent risk is bounded at 100.0, but preserved strictly for high severities
        inherent_risk = round(min(100.0, max(base_score, raw_inherent)), 2)
        trace.append(
            RiskTraceEntry(
                rule_id="RULE-INHERENT-CALC-08",
                input_value={
                    "base_score": base_score,
                    "crit_mult": crit_mult,
                    "exp_mult": exp_mult,
                    "data_mult": data_mult,
                    "priv_mult": priv_mult,
                    "exploit_mult": exploit_mult,
                    "attack_path_mult": attack_path_mult,
                },
                normalized_value=raw_inherent,
                calculation_result=inherent_risk,
                description=f"Calculated inherent risk: {inherent_risk}.",
            )
        )

        # 8. Remediation State Multiplier
        remed_mult, remed_trace = self._resolve_remediation_multiplier(finding)
        trace.extend(remed_trace)

        # 9. Control Weakness Factor
        ctrl_weakness = self._resolve_control_weakness(finding)
        trace.append(
            RiskTraceEntry(
                rule_id="RULE-CTRL-WEAKNESS-10",
                input_value=finding.primary_control_id,
                normalized_value=ctrl_weakness,
                calculation_result=ctrl_weakness,
                description=f"Control weakness factor {ctrl_weakness}.",
            )
        )

        # 10. Evidence Confidence & Epistemological Health
        ev_factor, ev_uncertainty_penalty, ev_trace = self._resolve_evidence_assurance(finding)
        trace.extend(ev_trace)

        # Calculate Residual Risk
        if remed_mult == 0.0:
            residual_risk = 0.0
        else:
            raw_residual = inherent_risk * remed_mult * ctrl_weakness * ev_uncertainty_penalty
            # CRITICAL RULE: "Simulation != Production assurance"
            # If evidence is simulation only, residual risk CANNOT drop below 50% of inherent risk
            if ev_factor == 0.5:
                sim_floor = round(0.50 * inherent_risk, 2)
                raw_residual = max(raw_residual, sim_floor)
                trace.append(
                    RiskTraceEntry(
                        rule_id="RULE-SIMULATION-ASSURANCE-FLOOR-11",
                        input_value="SIMULATION_EVIDENCE",
                        normalized_value=sim_floor,
                        calculation_result=raw_residual,
                        description=f"Simulation evidence cannot provide >50% assurance. Residual risk bounded at floor {sim_floor}.",
                    )
                )

            residual_risk = round(min(100.0, max(0.0, raw_residual)), 2)

        trace.append(
            RiskTraceEntry(
                rule_id="RULE-RESIDUAL-CALC-12",
                input_value={
                    "inherent_risk": inherent_risk,
                    "remed_mult": remed_mult,
                    "ctrl_weakness": ctrl_weakness,
                    "ev_uncertainty_penalty": ev_uncertainty_penalty,
                },
                normalized_value=raw_residual if remed_mult != 0.0 else 0.0,
                calculation_result=residual_risk,
                description=f"Calculated residual risk: {residual_risk}.",
            )
        )

        return FindingRiskAssessment(
            finding_id=fid,
            title=finding.title,
            severity=sev,
            base_severity_score=base_score,
            exploitability_multiplier=exploit_mult,
            exposure_multiplier=exp_mult,
            asset_criticality_multiplier=crit_mult,
            data_sensitivity_multiplier=data_mult,
            privilege_multiplier=priv_mult,
            attack_path_multiplier=attack_path_mult,
            control_weakness_factor=ctrl_weakness,
            evidence_confidence_factor=ev_factor,
            inherent_risk=inherent_risk,
            residual_risk=residual_risk,
            trace=trace,
        )

    def calculate_metrics(
        self,
        finding_assessments: List[FindingRiskAssessment],
        findings: List[SecurityFinding],
        assets: List[AIAsset],
        control_evaluations: Dict[str, Dict[str, Any]],
    ) -> Tuple[EnterpriseRiskMetrics, List[RiskTraceEntry]]:
        """
        Calculates the 6 strictly separated enterprise metrics:
        1. Compliance Score
        2. Security Posture
        3. Residual Risk (with Unmitigated Finding Floor)
        4. Attack Surface Risk
        5. Evidence Confidence
        6. Control Coverage
        """
        trace: List[RiskTraceEntry] = []

        # -------------------------------------------------------------
        # 1. COMPLIANCE SCORE (0.0 to 100.0)
        # Evaluates controls; N/A controls only excluded if justified.
        # -------------------------------------------------------------
        domain_points: Dict[str, Dict[str, float]] = {
            "DAT": {"earned": 0.0, "possible": 0.0},
            "MOD": {"earned": 0.0, "possible": 0.0},
            "APP": {"earned": 0.0, "possible": 0.0},
            "INF": {"earned": 0.0, "possible": 0.0},
            "ASR": {"earned": 0.0, "possible": 0.0},
            "GOV": {"earned": 0.0, "possible": 0.0},
        }

        justified_na_count = 0
        unjustified_na_count = 0

        # Iterate all 104 registered contracts
        all_contracts = self.registry.list_contracts()
        for contract in all_contracts:
            cid = contract.control_id
            prefix = cid.split("-")[0]
            domain_bucket = domain_points.get(prefix, {"earned": 0.0, "possible": 0.0})

            evaluation_entry = control_evaluations.get(cid, {})
            verdict = evaluation_entry.get("status", evaluation_entry.get("evaluation"))
            verdict_str = str(verdict).upper() if verdict else ""

            # Check NA justification
            if verdict_str in ("NA", "NOT_APPLICABLE"):
                justification = (
                    evaluation_entry.get("justification")
                    or evaluation_entry.get("na_justification")
                    or evaluation_entry.get("rationale")
                    or ""
                ).strip()
                if justification:
                    # Explicitly justified exclusion
                    justified_na_count += 1
                    trace.append(
                        RiskTraceEntry(
                            rule_id="RULE-NA-JUSTIFIED-01",
                            input_value={"control_id": cid, "justification": justification},
                            normalized_value="EXCLUDED",
                            calculation_result=0.0,
                            description=f"Control {cid} legitimately excluded: '{justification}'.",
                        )
                    )
                    continue  # Excluded from possible points
                else:
                    # CRITICAL RULE: "N/A controls must only be excluded when explicitly justified"
                    # Unjustified N/A is rejected, penalized as NOT_MET (0 earned, 1 possible)
                    unjustified_na_count += 1
                    domain_bucket["possible"] += 1.0
                    trace.append(
                        RiskTraceEntry(
                            rule_id="RULE-NA-UNJUSTIFIED-PENALTY-02",
                            input_value={"control_id": cid, "justification": ""},
                            normalized_value="UNJUSTIFIED_NA_PENALIZED",
                            calculation_result=0.0,
                            description=f"Control {cid} marked NA without justification! Penalized as NOT_MET.",
                        )
                    )
                    continue

            # Evaluate standard verdicts
            if verdict_str in ("Y", "MET", "PASS"):
                domain_bucket["earned"] += 1.0
                domain_bucket["possible"] += 1.0
            elif verdict_str in ("P", "PARTIAL", "PARTIALLY_MET"):
                domain_bucket["earned"] += 0.5
                domain_bucket["possible"] += 1.0
            elif verdict_str in ("N", "NOT_MET", "FAIL"):
                domain_bucket["earned"] += 0.0
                domain_bucket["possible"] += 1.0
            else:
                # CRITICAL RULE: "Missing evidence != PASS. Unknown != Secure."
                # Unassessed control counts as 0 earned, 1 possible
                domain_bucket["earned"] += 0.0
                domain_bucket["possible"] += 1.0

        total_earned = sum(d["earned"] for d in domain_points.values())
        total_possible = sum(d["possible"] for d in domain_points.values())
        compliance_score = round(
            (total_earned / total_possible * 100.0) if total_possible > 0 else 100.0, 2
        )

        domain_percentages: Dict[str, float] = {}
        for pfx, d in domain_points.items():
            domain_percentages[pfx] = round(
                (d["earned"] / d["possible"] * 100.0) if d["possible"] > 0 else 100.0, 2
            )

        trace.append(
            RiskTraceEntry(
                rule_id="RULE-COMPLIANCE-METRIC-03",
                input_value={"earned": total_earned, "possible": total_possible},
                normalized_value=f"{total_earned}/{total_possible}",
                calculation_result=compliance_score,
                description=f"Overall compliance score: {compliance_score}%.",
            )
        )

        # -------------------------------------------------------------
        # 2. CONTROL COVERAGE (0.0 to 100.0)
        # Preserves automated vs manual distinction.
        # -------------------------------------------------------------
        automated_count = 0
        manual_count = 0
        implemented_count = 0
        partial_count = 0
        declared_count = 0

        for contract in all_contracts:
            cid = contract.control_id
            eval_override = control_evaluations.get(cid, {}) if control_evaluations else {}

            if contract.assessment_type == AssessmentType.AUTOMATED:
                automated_count += 1
            else:
                manual_count += 1

            override_status = eval_override.get("implementation_status")
            if override_status:
                st = str(override_status).upper()
                if st == "IMPLEMENTED":
                    implemented_count += 1
                elif st == "PARTIAL":
                    partial_count += 1
                else:
                    declared_count += 1
                continue

            # Inspect test definitions for implementation status
            has_implemented = False
            has_partial = False
            for t in contract.test_definitions:
                status_val = (
                    t.implementation_status.value
                    if hasattr(t.implementation_status, "value")
                    else str(t.implementation_status)
                )
                if status_val == "IMPLEMENTED":
                    has_implemented = True
                elif status_val == "PARTIAL":
                    has_partial = True

            if has_implemented:
                implemented_count += 1
            elif has_partial:
                partial_count += 1
            else:
                declared_count += 1

        total_contracts = len(all_contracts)
        # Truthful separation: DECLARED_ONLY controls receive 0.0 implemented coverage
        implementation_coverage = round(
            (
                (1.0 * implemented_count + 0.5 * partial_count)
                / total_contracts
                * 100.0
            )
            if total_contracts > 0
            else 0.0,
            2,
        )
        control_coverage_score = implementation_coverage
        declared_coverage = round(
            (declared_count / total_contracts * 100.0)
            if total_contracts > 0
            else 0.0,
            2,
        )
        assessment_coverage = round(
            ((automated_count + manual_count) / total_contracts * 100.0)
            if total_contracts > 0
            else 0.0,
            2,
        )

        trace.append(
            RiskTraceEntry(
                rule_id="RULE-CONTROL-COVERAGE-04",
                input_value={
                    "total": total_contracts,
                    "implemented": implemented_count,
                    "partial": partial_count,
                    "declared": declared_count,
                    "automated": automated_count,
                    "manual": manual_count,
                    "implementation_coverage": implementation_coverage,
                    "declared_coverage": declared_coverage,
                },
                normalized_value=control_coverage_score,
                calculation_result=control_coverage_score,
                description=f"Control coverage score {control_coverage_score}% (Implemented: {implementation_coverage}%, Declared: {declared_coverage}%).",
            )
        )

        # -------------------------------------------------------------
        # 3. EVIDENCE CONFIDENCE (0.0 to 100.0)
        # Weights LIVE vs SIMULATION vs MISSING evidence.
        # -------------------------------------------------------------
        live_ev_count = 0
        sim_ev_count = 0
        missing_ev_count = 0

        for f in findings:
            if not f.evidence:
                missing_ev_count += 1
            else:
                has_live = any(
                    ev.execution_mode == ExecutionMode.LIVE
                    and ev.status == EvidenceStatus.VERIFIED
                    for ev in f.evidence
                )
                if has_live:
                    live_ev_count += 1
                else:
                    sim_ev_count += 1

        # Also count evidence from control evaluations
        for eval_item in control_evaluations.values():
            mode = eval_item.get("execution_mode", "")
            if mode in ("LIVE", ExecutionMode.LIVE):
                live_ev_count += 1
            elif mode in ("SIMULATION", ExecutionMode.SIMULATION, "FIXTURE", "MOCK"):
                sim_ev_count += 1
            elif not mode:
                missing_ev_count += 1

        total_ev_items = live_ev_count + sim_ev_count + missing_ev_count
        if total_ev_items == 0:
            evidence_confidence_score = 0.0
        else:
            # LIVE verified = 1.0; SIMULATION = 0.5; MISSING = 0.0
            weighted_ev = 1.0 * live_ev_count + 0.5 * sim_ev_count + 0.0 * missing_ev_count
            evidence_confidence_score = round((weighted_ev / total_ev_items) * 100.0, 2)

        trace.append(
            RiskTraceEntry(
                rule_id="RULE-EVIDENCE-CONFIDENCE-05",
                input_value={
                    "live": live_ev_count,
                    "simulated": sim_ev_count,
                    "missing": missing_ev_count,
                },
                normalized_value=evidence_confidence_score,
                calculation_result=evidence_confidence_score,
                description=f"Evidence confidence score {evidence_confidence_score}%.",
            )
        )

        # -------------------------------------------------------------
        # 4. RESIDUAL RISK & NO-DILUTION GUARANTEE (0.0 to 100.0)
        # CRITICAL RULE: A single CRITICAL finding MUST NOT be diluted
        # by hundreds of LOW findings.
        # -------------------------------------------------------------
        active_risks = [fa.residual_risk for fa in finding_assessments if fa.residual_risk > 0.0]

        if not active_risks:
            residual_risk_score = 0.0
            unmitigated_floor = 0.0
        else:
            # Floor is strictly the highest single residual risk
            unmitigated_floor = round(max(active_risks), 2)

            # Determine severity ceiling based on highest finding severity present
            highest_sev = (
                max(
                    (f.severity if isinstance(f.severity, FindingSeverity) else FindingSeverity(f.severity) for f in findings),
                    key=lambda s: self.SEVERITY_BASE_SCORES.get(s, (0, 0))[1],
                )
                if findings
                else FindingSeverity.LOW
            )

            if highest_sev == FindingSeverity.CRITICAL:
                ceiling = 100.0
            elif highest_sev == FindingSeverity.HIGH:
                ceiling = 80.0
            elif highest_sev == FindingSeverity.MEDIUM:
                ceiling = 55.0
            elif highest_sev == FindingSeverity.LOW:
                ceiling = 35.0
            else:
                ceiling = 15.0

            # Accumulate secondary risks with diminishing returns towards severity ceiling
            # If a single critical finding is present, ceiling is 100.0 and floor is >= 80.0.
            # Low findings alone cannot cross the low ceiling (35.0).
            secondary_pool = sum(r for r in active_risks if r < unmitigated_floor)
            if ceiling > unmitigated_floor and secondary_pool > 0.0:
                secondary_add = (ceiling - unmitigated_floor) * (1.0 - math.exp(-secondary_pool / 100.0))
            elif len(active_risks) > 1 and ceiling > unmitigated_floor:
                secondary_add = (ceiling - unmitigated_floor) * (1.0 - math.exp(-len(active_risks) / 10.0))
            else:
                secondary_add = 0.0

            # NO-DILUTION GUARANTEE: Final score is at least the unmitigated finding floor!
            residual_risk_score = round(
                min(ceiling, max(unmitigated_floor, unmitigated_floor + secondary_add)), 2
            )

        # Classify Residual Risk Tier
        if residual_risk_score >= 75.0:
            residual_tier = RiskLevel.CRITICAL
        elif residual_risk_score >= 50.0:
            residual_tier = RiskLevel.HIGH
        elif residual_risk_score >= 25.0:
            residual_tier = RiskLevel.MEDIUM
        elif residual_risk_score > 5.0:
            residual_tier = RiskLevel.LOW
        else:
            residual_tier = RiskLevel.NEGLIGIBLE

        trace.append(
            RiskTraceEntry(
                rule_id="RULE-RESIDUAL-RISK-NO-DILUTION-06",
                input_value={"active_risks_count": len(active_risks), "max_single_risk": unmitigated_floor},
                normalized_value=f"Floor={unmitigated_floor}",
                calculation_result=residual_risk_score,
                description=f"Residual risk {residual_risk_score} (Tier: {_str(residual_tier)}, Unmitigated Floor: {unmitigated_floor}).",
            )
        )

        # -------------------------------------------------------------
        # 5. ATTACK SURFACE RISK (0.0 to 100.0)
        # Evaluates public exposure, privileged identities, sensitive data, attack paths.
        # -------------------------------------------------------------
        total_assets = len(assets)
        if total_assets == 0:
            # Conservative default when no assets cataloged
            public_exp_ratio = 0.5
            sensitive_data_ratio = 0.5
        else:
            public_assets = sum(
                1 for a in assets if not a.is_private_endpoint or a.metadata.get("exposure") == "PUBLIC_INTERNET"
            )
            public_exp_ratio = public_assets / total_assets

            sensitive_assets = sum(
                1
                for a in assets
                if (
                    not a.cmek_enabled
                    or a.classification in ("RESTRICTED", "PII", "SECRET", "CONFIDENTIAL")
                )
            )
            sensitive_data_ratio = sensitive_assets / total_assets

        # Privileged identities in findings
        privileged_count = sum(
            1
            for f in findings
            if any(
                term in f.description.lower() or term in f.title.lower()
                for term in ("admin", "owner", "roles/owner", "roles/editor", "full_access")
            )
        )
        privilege_ratio = min(1.0, (privileged_count / max(1, len(findings))))

        # Attack techniques / chains
        all_techniques: Set[str] = set()
        for f in findings:
            for t in f.attack_techniques:
                all_techniques.add(t.technique_id)
        attack_path_ratio = min(1.0, len(all_techniques) / 5.0)

        raw_attack_surface = (
            30.0 * public_exp_ratio
            + 25.0 * privilege_ratio
            + 25.0 * sensitive_data_ratio
            + 20.0 * attack_path_ratio
        )
        attack_surface_score = round(min(100.0, max(0.0, raw_attack_surface)), 2)

        if attack_surface_score >= 70.0:
            attack_surface_tier = RiskLevel.CRITICAL
        elif attack_surface_score >= 45.0:
            attack_surface_tier = RiskLevel.HIGH
        elif attack_surface_score >= 20.0:
            attack_surface_tier = RiskLevel.MEDIUM
        else:
            attack_surface_tier = RiskLevel.LOW

        trace.append(
            RiskTraceEntry(
                rule_id="RULE-ATTACK-SURFACE-07",
                input_value={
                    "public_exp_ratio": public_exp_ratio,
                    "privilege_ratio": privilege_ratio,
                    "sensitive_data_ratio": sensitive_data_ratio,
                    "attack_path_ratio": attack_path_ratio,
                },
                normalized_value=raw_attack_surface,
                calculation_result=attack_surface_score,
                description=f"Attack surface risk {attack_surface_score} (Tier: {_str(attack_surface_tier)}).",
            )
        )

        # -------------------------------------------------------------
        # 6. SECURITY POSTURE (0.0 to 100.0 & Tier)
        # Inverted risk + compliance + control coverage, with CRITICAL override.
        # -------------------------------------------------------------
        inverted_residual = 100.0 - residual_risk_score
        inverted_attack_surface = 100.0 - attack_surface_score

        raw_posture = (
            0.35 * compliance_score
            + 0.35 * inverted_residual
            + 0.15 * inverted_attack_surface
            + 0.15 * control_coverage_score
        )
        posture_score = round(min(100.0, max(0.0, raw_posture)), 2)

        # Hard Critical Override: If active residual risk is critical, posture CANNOT be SECURE or ADEQUATE
        if residual_risk_score >= 75.0 or posture_score < 45.0:
            posture_tier = PostureTier.CRITICAL_VULNERABLE
        elif residual_risk_score >= 50.0 or posture_score < 65.0:
            posture_tier = PostureTier.ELEVATED_RISK
        elif posture_score < 80.0:
            posture_tier = PostureTier.ADEQUATE
        else:
            posture_tier = PostureTier.SECURE

        trace.append(
            RiskTraceEntry(
                rule_id="RULE-POSTURE-METRIC-08",
                input_value={
                    "compliance": compliance_score,
                    "inverted_residual": inverted_residual,
                    "inverted_attack_surface": inverted_attack_surface,
                    "coverage": control_coverage_score,
                },
                normalized_value=raw_posture,
                calculation_result=posture_score,
                description=f"Security posture score {posture_score} (Tier: {_str(posture_tier)}).",
            )
        )

        metrics = EnterpriseRiskMetrics(
            compliance_score=compliance_score,
            compliance_percentage_by_domain=domain_percentages,
            security_posture_score=posture_score,
            security_posture_tier=posture_tier,
            residual_risk_score=residual_risk_score,
            residual_risk_tier=residual_tier,
            unmitigated_finding_floor=unmitigated_floor,
            attack_surface_risk_score=attack_surface_score,
            attack_surface_risk_tier=attack_surface_tier,
            evidence_confidence_score=evidence_confidence_score,
            live_evidence_count=live_ev_count,
            simulated_evidence_count=sim_ev_count,
            missing_evidence_count=missing_ev_count,
            control_coverage_score=control_coverage_score,
            implementation_coverage=implementation_coverage,
            declared_coverage=declared_coverage,
            evidence_coverage=evidence_confidence_score,
            assessment_coverage=assessment_coverage,
            automated_controls_count=automated_count,
            manual_controls_count=manual_count,
            implemented_controls_count=implemented_count,
            partial_controls_count=partial_count,
            declared_controls_count=declared_count,
            justified_na_count=justified_na_count,
            unjustified_na_count=unjustified_na_count,
        )

        return metrics, trace

    # -----------------------------------------------------------------
    # Helper Resolution Methods (Fully deterministic, Explainable)
    # -----------------------------------------------------------------

    def _resolve_asset_criticality(
        self, asset: Optional[AIAsset], finding: SecurityFinding
    ) -> AssetCriticality:
        """Resolves asset criticality or applies conservative default."""
        if asset:
            crit_val = asset.metadata.get("criticality") or asset.tags.get("criticality")
            if crit_val:
                try:
                    return AssetCriticality(crit_val.upper())
                except ValueError:
                    pass
            # Default by asset type
            if asset.asset_type in (AssetType.FOUNDATION_MODEL, AssetType.FINE_TUNED_MODEL):
                return AssetCriticality.TIER_1_CRITICAL
            if asset.asset_type == AssetType.INFERENCE_ENDPOINT:
                return AssetCriticality.TIER_2_PRODUCTION

        finding_crit = finding.metadata.get("asset_criticality")
        if finding_crit:
            try:
                return AssetCriticality(finding_crit.upper())
            except ValueError:
                pass

        # CRITICAL RULE: "Unknown != Secure"
        return AssetCriticality.TIER_2_PRODUCTION

    def _resolve_exposure(
        self, asset: Optional[AIAsset], finding: SecurityFinding
    ) -> EnvironmentExposure:
        """Resolves environment exposure or applies conservative default."""
        if asset:
            exp_val = asset.metadata.get("exposure")
            if exp_val:
                try:
                    return EnvironmentExposure(exp_val.upper())
                except ValueError:
                    pass
            if not asset.is_private_endpoint:
                return EnvironmentExposure.PUBLIC_INTERNET
            return EnvironmentExposure.VPC_INTERNAL

        desc = (finding.description + " " + finding.title).lower()
        if "public" in desc or "internet" in desc or "external" in desc:
            return EnvironmentExposure.PUBLIC_INTERNET
        if "air-gap" in desc or "isolated" in desc:
            return EnvironmentExposure.ISOLATED_AIR_GAPPED
        return EnvironmentExposure.VPC_INTERNAL

    def _resolve_data_sensitivity(
        self, asset: Optional[AIAsset], finding: SecurityFinding
    ) -> DataSensitivity:
        """Resolves data sensitivity or applies conservative default."""
        if asset:
            if asset.classification in ("RESTRICTED", "PII", "SECRET", "HIGHLY_CONFIDENTIAL"):
                return DataSensitivity.RESTRICTED_PII_SECRETS
            if asset.classification in ("CONFIDENTIAL",):
                return DataSensitivity.CONFIDENTIAL
            if asset.classification in ("PUBLIC",):
                return DataSensitivity.PUBLIC

        desc = (finding.description + " " + finding.title).lower()
        if "pii" in desc or "secret" in desc or "token" in desc or "credential" in desc:
            return DataSensitivity.RESTRICTED_PII_SECRETS
        if "confidential" in desc:
            return DataSensitivity.CONFIDENTIAL
        return DataSensitivity.INTERNAL

    def _resolve_privilege(self, finding: SecurityFinding) -> IdentityPrivilege:
        """Resolves IAM privilege associated with the finding."""
        desc = (finding.description + " " + finding.title).lower()
        if (
            "roles/owner" in desc
            or "admin" in desc
            or "root" in desc
            or "full_control" in desc
            or "roles/resourcemanager.organizationadmin" in desc
        ):
            return IdentityPrivilege.ADMIN_OWNER
        if "roles/editor" in desc or "write" in desc or "modify" in desc or "creator" in desc:
            return IdentityPrivilege.WRITE_EXECUTE
        if "viewer" in desc or "read" in desc:
            return IdentityPrivilege.READ_ONLY
        return IdentityPrivilege.WRITE_EXECUTE

    def _resolve_exploitability(
        self, finding: SecurityFinding
    ) -> Tuple[float, List[RiskTraceEntry]]:
        """Calculates exploitability based on CVE CVSS, PoC, or MITRE ATLAS techniques."""
        trace: List[RiskTraceEntry] = []
        mult = 1.0
        cve = finding.cve
        if cve:
            mult = 1.25
            trace.append(
                RiskTraceEntry(
                    rule_id="RULE-EXPLOIT-CVE-01",
                    input_value=cve,
                    normalized_value=mult,
                    calculation_result=mult,
                    description=f"Associated CVE '{cve}' increases exploitability to {mult}x.",
                )
            )

        if finding.attack_techniques:
            tech_mult = round(1.0 + 0.10 * min(3, len(finding.attack_techniques)), 2)
            mult = max(mult, tech_mult)
            trace.append(
                RiskTraceEntry(
                    rule_id="RULE-EXPLOIT-ATLAS-02",
                    input_value=[t.technique_id for t in finding.attack_techniques],
                    normalized_value=tech_mult,
                    calculation_result=mult,
                    description=f"MITRE ATLAS techniques increase exploitability to {mult}x.",
                )
            )

        if mult == 1.0:
            trace.append(
                RiskTraceEntry(
                    rule_id="RULE-EXPLOIT-BASE-03",
                    input_value="NO_KNOWN_EXPLOIT",
                    normalized_value=1.0,
                    calculation_result=1.0,
                    description="Standard baseline exploitability 1.0x.",
                )
            )
        return mult, trace

    def _resolve_attack_path(
        self, finding: SecurityFinding
    ) -> Tuple[float, List[RiskTraceEntry]]:
        """Calculates attack path / chained tactics multiplier."""
        trace: List[RiskTraceEntry] = []
        tactics = {t.tactic for t in finding.attack_techniques if t.tactic}
        if len(tactics) >= 2:
            mult = 1.20
            trace.append(
                RiskTraceEntry(
                    rule_id="RULE-ATTACK-PATH-CHAINED-01",
                    input_value=sorted(list(tactics)),
                    normalized_value=mult,
                    calculation_result=mult,
                    description=f"Chained attack path across {len(tactics)} tactics yields {mult}x multiplier.",
                )
            )
            return mult, trace
        return 1.0, trace

    def _resolve_remediation_multiplier(
        self, finding: SecurityFinding
    ) -> Tuple[float, List[RiskTraceEntry]]:
        """Calculates remediation state multiplier."""
        trace: List[RiskTraceEntry] = []
        status = finding.status if isinstance(finding.status, FindingStatus) else FindingStatus(finding.status)
        status_str = _str(status)
        if status in (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE):
            mult = 0.0
        elif status == FindingStatus.IN_PROGRESS:
            mult = 0.70
        elif status == FindingStatus.SUPPRESSED:
            mult = 0.85
        else:
            mult = 1.00

        trace.append(
            RiskTraceEntry(
                rule_id=f"RULE-REMED-{status_str}-01",
                input_value=status_str,
                normalized_value=mult,
                calculation_result=mult,
                description=f"Remediation state '{status_str}' yields {mult}x multiplier.",
            )
        )
        return mult, trace

    def _resolve_control_weakness(self, finding: SecurityFinding) -> float:
        """Calculates control weakness factor based on finding's mapped control."""
        ctrl_eval = finding.metadata.get("control_evaluation")
        if ctrl_eval in ("MET", "Y", "PASS"):
            return 0.30
        if ctrl_eval in ("PARTIALLY_MET", "P"):
            return 0.65
        return 1.00

    def _resolve_evidence_assurance(
        self, finding: SecurityFinding
    ) -> Tuple[float, float, List[RiskTraceEntry]]:
        """
        Evaluates epistemological assurance of the attached evidence.
        Returns: (confidence_factor, uncertainty_penalty, trace)
        """
        trace: List[RiskTraceEntry] = []
        # CRITICAL RULE: "Missing evidence != PASS"
        if not finding.evidence:
            trace.append(
                RiskTraceEntry(
                    rule_id="RULE-EVD-MISSING-PENALTY-01",
                    input_value="NO_EVIDENCE",
                    normalized_value=0.10,
                    calculation_result=1.20,
                    description="Finding lacks empirical evidence! Applied +20% uncertainty penalty to residual risk.",
                )
            )
            return (0.10, 1.20, trace)

        has_live = any(
            ev.execution_mode == ExecutionMode.LIVE and ev.status == EvidenceStatus.VERIFIED
            for ev in finding.evidence
        )
        if has_live:
            trace.append(
                RiskTraceEntry(
                    rule_id="RULE-EVD-LIVE-VERIFIED-02",
                    input_value="LIVE_VERIFIED",
                    normalized_value=1.00,
                    calculation_result=1.00,
                    description="Finding confirmed by verified live cloud telemetry.",
                )
            )
            return (1.00, 1.00, trace)

        # Simulation or fixture only
        trace.append(
            RiskTraceEntry(
                rule_id="RULE-EVD-SIMULATION-ASSURANCE-03",
                input_value="SIMULATION_OR_MOCK",
                normalized_value=0.50,
                calculation_result=1.00,
                description="Simulation evidence provides capped assurance (0.50).",
            )
        )
        return (0.50, 1.00, trace)
