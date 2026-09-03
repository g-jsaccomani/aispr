# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 8: Controlled Adversarial Validation Engine - Core Engine.
Orchestrates:
  - Target safety authorization (default: SIMULATION, no destructive operations)
  - Execution across all 9 scoped attack categories
  - 4-way outcome separation: ATTACK_ATTEMPTED, ATTACK_BLOCKED, ATTACK_SUCCEEDED, INCONCLUSIVE
  - MITRE ATLAS technique mapping (strictly for implemented tests)
  - Cryptographic Evidence generation (SHA-256)
  - Objective proof-of-impact requirement before declaring any attack successful
  - False positive and false negative analysis
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Callable, Set

from domain.enums import ExecutionMode, FindingSeverity, EvidenceStatus
from domain.models.evidence import compute_sha256
from .models import (
    AdversarialTest,
    AdversarialCampaignReport,
    AdversarialCategory,
    MitreAtlasTechnique,
    AttackOutcome,
    CATEGORY_TO_MITRE_MAP,
)
from .safety import TargetAuthorizationGate, AdversarialSafetyError
from .evaluator import AttackOutcomeEvaluator
from .catalog import AdversarialCatalog
from agentic.security_runtime import AgenticSecurityRuntime, AgentAction

logger = logging.getLogger("AISPR-AdversarialEngine")


class AdversarialValidationEngine:
    """
    Controlled Adversarial Testing Engine for AI systems.
    Evaluates defensive efficacy against MITRE ATLAS and OWASP GenAI threat vectors.
    """

    def __init__(
        self,
        default_mode: ExecutionMode = ExecutionMode.SIMULATION,
        authorized_targets: Optional[Set[str]] = None,
        security_runtime: Optional[AgenticSecurityRuntime] = None,
    ):
        self.default_mode = default_mode
        self.safety_gate = TargetAuthorizationGate(
            authorized_targets=authorized_targets,
            default_mode=default_mode,
        )
        self.evaluator = AttackOutcomeEvaluator()
        self.security_runtime = security_runtime or AgenticSecurityRuntime()

    def run_single_test(
        self,
        attack_id: str,
        category: AdversarialCategory,
        technique: str,
        target: str,
        payload: str,
        expected_defense: str,
        severity: FindingSeverity = FindingSeverity.HIGH,
        success_criteria: Optional[str] = None,
        execution_mode: Optional[ExecutionMode] = None,
        target_invoker: Optional[Callable[[str, str], Any]] = None,
        is_adversarial: bool = True,
    ) -> AdversarialTest:
        """
        Executes a single controlled adversarial attack against the target within safety bounds.
        """
        mode = execution_mode or self.default_mode

        # 1. Safety Verification: Target MUST be explicitly authorized
        self.safety_gate.verify_target_safety(target, mode=mode)

        # 2. Safety Verification: Payload MUST NOT be destructive
        self.safety_gate.verify_non_destructive(payload)

        # 3. Initialize canonical test record
        test_record = AdversarialTest(
            attack_id=attack_id,
            technique=technique,
            target=target,
            payload=payload,
            expected_defense=expected_defense,
            observed_result=AttackOutcome.ATTACK_ATTEMPTED,
            execution_mode=mode,
            severity=severity,
            category=category,
            mitre_technique_id=technique.split(":")[0] if ":" in technique else technique,
            details={"is_adversarial": is_adversarial}
        )

        # 4. Dispatch attack payload against target or defense layer
        response_payload: Any = None
        caught_exception: Optional[Exception] = None

        if target_invoker is not None:
            try:
                response_payload = target_invoker(target, payload)
            except Exception as e:
                caught_exception = e
        else:
            # Default to evaluating against the AgenticSecurityRuntime perimeter
            try:
                action = self.security_runtime.execute_action(
                    agent_id=f"redteam-{attack_id.lower()}",
                    requested_action=payload if len(payload) < 50 else payload[:50],
                    target=target,
                    tool_callable=lambda **kw: {"response": "execution_permitted", "payload": payload},
                    tool_args={"input": payload},
                )
                response_payload = action.result
            except Exception as sec_e:
                caught_exception = sec_e

        # 5. Objective Outcome Evaluation
        # Enforces invariant: Do not describe an attack as successful unless evidence proves impact!
        outcome, reason, impact_proof = self.evaluator.evaluate(
            response_payload=response_payload,
            expected_defense=expected_defense,
            success_criteria=success_criteria,
            error=caught_exception,
        )

        test_record.observed_result = outcome
        test_record.defense_reason = reason
        test_record.impact_proof = impact_proof

        # Quality metrics (False Positives / False Negatives)
        quality = self.evaluator.evaluate_test_quality(is_adversarial, outcome)
        test_record.details.update(quality)

        # 6. Evidence Capture
        evidence_content = (
            f"ADVERSARIAL_TEST: {attack_id} | Technique: {technique} | Target: {target} | "
            f"Outcome: {outcome} | Reason: {reason} | ImpactProof: {impact_proof}"
        )
        test_record.attach_evidence(
            raw_content=evidence_content,
            collection_method="ADVERSARIAL_VALIDATION_ENGINE",
            status=EvidenceStatus.SIMULATED if mode == ExecutionMode.SIMULATION else EvidenceStatus.VERIFIED,
        )

        logger.info(f"[{attack_id}] Outcome: {test_record.observed_result} | Reason: {reason}")
        return test_record

    def run_campaign(
        self,
        target: str = "sim://aispr/agentic-runtime",
        mode: Optional[ExecutionMode] = None,
        custom_tests: Optional[List[Dict[str, Any]]] = None,
        target_invoker: Optional[Callable[[str, str], Any]] = None,
    ) -> AdversarialCampaignReport:
        """
        Executes a complete adversarial testing campaign across the 9 mandated categories.
        """
        exec_mode = mode or self.default_mode
        campaign_id = f"CMP-{compute_sha256(f'{target}:{datetime.now(timezone.utc).isoformat()}')[:12].upper()}"

        test_specs = custom_tests or AdversarialCatalog.get_standard_suite(target=target, mode=exec_mode)
        executed_tests: List[AdversarialTest] = []

        attempted = 0
        blocked = 0
        succeeded = 0
        inconclusive = 0
        mitre_coverage: Dict[str, str] = {}

        for spec in test_specs:
            test = self.run_single_test(
                attack_id=spec["attack_id"],
                category=spec["category"],
                technique=spec["technique"],
                target=spec.get("target", target),
                payload=spec["payload"],
                expected_defense=spec["expected_defense"],
                severity=spec.get("severity", FindingSeverity.HIGH),
                success_criteria=spec.get("success_criteria"),
                execution_mode=exec_mode,
                target_invoker=target_invoker,
                is_adversarial=spec.get("is_adversarial", True),
            )
            executed_tests.append(test)
            attempted += 1

            if test.observed_result == AttackOutcome.ATTACK_BLOCKED:
                blocked += 1
            elif test.observed_result == AttackOutcome.ATTACK_SUCCEEDED:
                succeeded += 1
            elif test.observed_result == AttackOutcome.INCONCLUSIVE:
                inconclusive += 1

            # Only record MITRE ATLAS technique if the test is an implemented adversarial test
            if spec.get("is_adversarial", True) and ":" in test.technique:
                tech_id = test.technique.split(":")[0].strip()
                tech_name = test.technique.split(":")[1].strip()
                mitre_coverage[tech_id] = tech_name

        total_adversarial = attempted - 1 if any(not t.details.get("is_adversarial", True) for t in executed_tests) else attempted
        defense_efficacy = round((blocked / max(total_adversarial, 1)) * 100.0, 2)

        return AdversarialCampaignReport(
            campaign_id=campaign_id,
            timestamp=datetime.now(timezone.utc),
            execution_mode=exec_mode,
            total_tests=attempted,
            attempted_count=attempted,
            blocked_count=blocked,
            succeeded_count=succeeded,
            inconclusive_count=inconclusive,
            mitre_atlas_coverage=mitre_coverage,
            tests=executed_tests,
            defense_efficacy_pct=defense_efficacy,
        )
