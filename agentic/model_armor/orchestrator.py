# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Model Armor Implementation Engine - Master Orchestrator
Coordinates the 3 Pillars of Model Armor Implementation:
1. Consultiva (Advisory Blueprint & Transformation Matrix)
2. Construtiva (Production Terraform, Cloud Shell, Middleware & Live Deploy)
3. Protetiva (Attack Evals Replay & Protection Assurance Certificate)
"""

import os
import sys
import json
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger("AISPR-ModelArmor-Orchestrator")

from .advisor import ModelArmorConsultingAdvisor
from .builder import ModelArmorConstructiveBuilder
from .evaluator import ModelArmorProtectiveEvaluator


class ModelArmorOrchestrator:
    """
    Unified entrypoint for the complete data-driven Model Armor Implementation Journey.
    """

    def __init__(self, project_root: Optional[str] = None):
        if project_root is None:
            cur_dir = os.path.dirname(os.path.abspath(__file__))
            self.project_root = os.path.abspath(os.path.join(cur_dir, "..", ".."))
        else:
            self.project_root = project_root

        self.advisor = ModelArmorConsultingAdvisor(self.project_root)
        self.builder = ModelArmorConstructiveBuilder(self.project_root)
        self.evaluator = ModelArmorProtectiveEvaluator(self.project_root)

    def run_full_implementation_flow(
        self,
        project_id: str = "your-gcp-project-id",
        location: str = "us-central1",
        template_id: str = "secops-guardrail-prod",
        profile_name: str = "balanced",
        client_name: str = "Enterprise Client",
        deploy_live: bool = False
    ) -> Dict[str, Any]:
        """
        Executes all 3 phases sequentially, feeding findings directly from AISPR into Model Armor.
        """
        logger.info("=" * 80)
        logger.info(f"STARTING AISPR MODEL ARMOR FULL IMPLEMENTATION JOURNEY FOR '{project_id}'")
        logger.info("=" * 80)

        # 1. Pillar 1: Consultiva (Advisory & Architecture Blueprint)
        logger.info("\n▶️ [PHASE 1/3: CONSULTIVA] Generating Architecture Blueprint & Transformation Matrix...")
        adv_res = self.advisor.execute_advisory_flow(
            project_id=project_id,
            location=location,
            template_id=template_id,
            profile_name=profile_name
        )
        plan = adv_res["plan"]

        # 2. Pillar 2: Construtiva (Terraform, Cloud Shell, Middleware)
        logger.info("\n▶️ [PHASE 2/3: CONSTRUTIVA] Generating Infrastructure-as-Code & Application Interceptors...")
        build_res = self.builder.execute_constructive_flow(plan=plan, deploy_live=deploy_live)

        # 3. Pillar 3: Protetiva (Attack Evals & Protection Certificate)
        logger.info("\n▶️ [PHASE 3/3: PROTETIVA] Executing Attack Evals & Issuing Protection Certificate...")
        eval_res = self.evaluator.execute_protective_flow(
            project_id=project_id,
            location=location,
            template_id=template_id,
            client_name=client_name
        )

        logger.info("=" * 80)
        logger.info("🎉 AISPR MODEL ARMOR IMPLEMENTATION COMPLETED WITH 100% SUCCESS!")
        logger.info(f"   • Consulting Blueprint: {adv_res['blueprint_path']}")
        logger.info(f"   • Terraform Package:    {build_res['terraform_package_dir']}")
        logger.info(f"   • Cloud Shell Script:   {build_res['cloud_shell_script']}")
        logger.info(f"   • Protection Cert:      {eval_res['certificate_path']}")
        logger.info("=" * 80)

        return {
            "status": "SUCCESS",
            "scope": {
                "project_id": project_id,
                "location": location,
                "template_id": template_id,
                "profile_name": profile_name
            },
            "advisory": adv_res,
            "constructive": build_res,
            "protective": eval_res
        }
