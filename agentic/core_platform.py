# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Agentic: Enterprise Multi-Cloud AI-SPM & Governance Orchestrator
Engineered by: @jsaccomani
"""

import logging
from typing import Dict, List, Any, Optional, Callable

from .connectors.gcp_connector import GCPConnector
from .connectors.aws_connector import AWSConnector
from .connectors.azure_connector import AzureConnector
from .connectors.base import NormalizedDiscoveryResult
from .dynamic_assessment import DynamicAssessmentEngine
from .remediation_engine import RemediationEngine
from .threat_operations.ai_red_team_simulator import AIRedTeamSimulator
from domain.enums import ExecutionMode
from .runtime_defense.model_armor_guard import ModelArmorGuard
from .security_runtime import AgenticSecurityRuntime, AgentAction
from .adversarial_engine import AdversarialValidationEngine, AdversarialCampaignReport
from .shadow_ai import EnterpriseShadowAIDiscoveryEngine, ShadowAIDiscoveryReport

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AISPR-Agentic-Core")


class AISPRAgenticCore:
    """
    Proprietary, framework-agnostic core engine that orchestrates multi-cloud
    AI-SPM discovery, dynamic GRC questioning, adversarial red teaming, and inline remediations.
    """

    def __init__(self, tenant_id: str = "enterprise-tenant-default"):
        self.tenant_id = tenant_id
        self.connectors: Dict[str, Any] = {}
        self.guard = ModelArmorGuard()
        self.security_runtime = AgenticSecurityRuntime()
        logger.info(f"Initialized AISPR Agentic Core for tenant: {tenant_id}")

    def register_cloud_connector(self, cloud_provider: str, credentials_payload: Optional[Dict[str, Any]] = None):
        """
        Registers federated connectors (GCP Workload Identity / ADC, AWS STS AssumeRole, Azure Entra ID).
        """
        provider = cloud_provider.lower()
        creds = credentials_payload or {}
        
        if provider == "gcp":
            project_id = creds.get("project_id", "your-gcp-project-id")
            self.connectors["gcp"] = GCPConnector(project_id=project_id, credentials_payload=creds)
        elif provider == "aws":
            account_id = creds.get("account_id", "123456789012")
            self.connectors["aws"] = AWSConnector(account_id=account_id)
        elif provider == "azure":
            subscription_id = creds.get("subscription_id", "sub-000-111-222")
            self.connectors["azure"] = AzureConnector(subscription_id=subscription_id)
        else:
            raise ValueError(f"Unsupported cloud provider: {cloud_provider}")

        logger.info(f"Registered connector for cloud provider: {provider.upper()}")

    def run_multi_cloud_discovery(self, live: bool = False) -> Dict[str, Any]:
        """
        Executes scanning across registered GCP, AWS, and Azure estates, building the unified AI-BOM.
        
        Args:
            live: If True, executes live API discovery (e.g. via ADC on GCP) where supported.
                  If False, runs offline simulated discovery.
        """
        # Ensure default connectors if none registered
        if not self.connectors:
            self.register_cloud_connector("gcp", {"project_id": "your-gcp-project-id"})
            self.register_cloud_connector("aws", {"account_id": "123456789012"})
            self.register_cloud_connector("azure", {"subscription_id": "sub-000-111-222"})

        ai_bom = {
            "tenant_id": self.tenant_id,
            "discovered_models": [],
            "discovered_endpoints": [],
            "shadow_ai_findings": [],
            "vulnerabilities": []
        }

        for provider, connector in self.connectors.items():
            logger.info(f"Invoking {provider.upper()} {'LIVE' if live else 'simulated'} active discovery engine...")
            if live and hasattr(connector, "discover_resources_live"):
                res = connector.discover_resources_live()
            else:
                res = connector.discover_resources()
                
            ai_bom["discovered_models"].extend(res.get("models", []))
            ai_bom["discovered_endpoints"].extend(res.get("endpoints", []))
            ai_bom["shadow_ai_findings"].extend(res.get("shadow_ai", []))
            ai_bom["vulnerabilities"].extend(res.get("vulnerabilities", []))

        return ai_bom

    def run_canonical_discovery(self, live: bool = False) -> Dict[str, NormalizedDiscoveryResult]:
        """
        Executes discovery and returns strongly-typed NormalizedDiscoveryResults containing
        canonical AIAsset, SecurityFinding, and Evidence entities for each registered provider.
        """
        if not self.connectors:
            self.register_cloud_connector("gcp", {"project_id": "your-gcp-project-id"})
            self.register_cloud_connector("aws", {"account_id": "123456789012"})
            self.register_cloud_connector("azure", {"subscription_id": "sub-000-111-222"})

        results: Dict[str, NormalizedDiscoveryResult] = {}
        for provider, connector in self.connectors.items():
            if hasattr(connector, "discover_canonical"):
                results[provider] = connector.discover_canonical(live=live)
        return results

    def generate_progressive_questions(self, ai_bom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Synthesizes AI-BOM findings into context-aware, targeted dynamic assessment questions.
        """
        return DynamicAssessmentEngine.generate_questions(ai_bom)

    def run_adversarial_simulation(self, hitl_approval_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes MITRE ATLAS adversarial attack simulation with Human-in-the-Loop approval gate.
        """
        logger.info("Initiating automated adversarial red teaming with Model Armor verification...")
        simulator = AIRedTeamSimulator(guard=self.guard)
        return simulator.execute_campaign()

    def generate_active_remediations(self, failed_controls: List[str]) -> Dict[str, Any]:
        """
        Generates production-ready remediation configurations across GCP, AWS, Azure, and Terraform.
        """
        return RemediationEngine.generate_remediations(failed_controls)

    def execute_controlled_action(
        self,
        agent_id: str,
        requested_action: str,
        target: str,
        tool_callable: Optional[Callable[..., Any]] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentAction:
        """
        Executes an agent action within the controlled Agentic Security Runtime perimeter.
        Enforces least-privilege (READ_ONLY by default), prompt injection shielding,
        untrusted tool output defense, and cryptographic audit logging.
        """
        return self.security_runtime.execute_action(
            agent_id=agent_id,
            requested_action=requested_action,
            target=target,
            tool_callable=tool_callable,
            tool_args=tool_args,
            approval_token=approval_token,
            metadata=metadata
        )

    def run_adversarial_validation_campaign(
        self,
        target: str = "sim://aispr/agentic-runtime",
        mode: Optional[ExecutionMode] = None,
        custom_tests: Optional[List[Dict[str, Any]]] = None,
    ) -> AdversarialCampaignReport:
        """
        Executes a controlled adversarial testing campaign using Phase 8 AdversarialValidationEngine.
        Enforces target authorization, MITRE ATLAS mapping, 4-way outcome separation,
        and evidence proof-of-impact.
        """
        engine = AdversarialValidationEngine(
            default_mode=mode or ExecutionMode.SIMULATION,
            security_runtime=self.security_runtime,
        )
        return engine.run_campaign(target=target, mode=mode, custom_tests=custom_tests)

    def discover_shadow_ai(
        self,
        cloud_resources: Optional[List[Dict[str, Any]]] = None,
        network_flows: Optional[List[Dict[str, Any]]] = None,
        host_processes: Optional[List[Dict[str, Any]]] = None,
        saas_records: Optional[List[Dict[str, Any]]] = None,
        api_logs: Optional[List[Dict[str, Any]]] = None,
        model_endpoints: Optional[List[Dict[str, Any]]] = None,
        infrastructure_metadata: Optional[List[Dict[str, Any]]] = None,
        execution_mode: Optional[ExecutionMode] = None,
    ) -> ShadowAIDiscoveryReport:
        """
        Executes enterprise Shadow AI discovery across all 7 mandated detection sources.
        Guarantees provenance, canonical evidence, multi-vector risk evaluation,
        and confidence differentiation (OBSERVED, INFERRED, SUSPECTED).
        """
        engine = EnterpriseShadowAIDiscoveryEngine(
            default_mode=execution_mode or ExecutionMode.SIMULATION
        )
        return engine.discover(
            cloud_resources=cloud_resources,
            network_flows=network_flows,
            host_processes=host_processes,
            saas_records=saas_records,
            api_logs=api_logs,
            model_endpoints=model_endpoints,
            infrastructure_metadata=infrastructure_metadata,
            execution_mode=execution_mode,
        )


