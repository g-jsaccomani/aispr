# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 9: Enterprise Shadow AI Discovery - Multi-Source Sensor Detectors.
Supports:
  1. cloud resources
  2. network indicators
  3. endpoints
  4. SaaS integrations
  5. API usage
  6. model endpoints
  7. infrastructure metadata
"""

import re
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from domain.enums import CloudProvider, ExecutionMode, AssetType
from domain.models.asset import AIAsset
from domain.models.evidence import compute_sha256
from .models import (
    ShadowAIDiscovery,
    ShadowConfidence,
    DetectionSource,
    ShadowAIRiskFactor,
)
from .risk_engine import ShadowAIRiskEngine


class ShadowAIDetectors:
    """
    Multi-sensor detection suite for identifying unmanaged AI workloads.
    Strictly differentiates OBSERVED (direct facts) from INFERRED (behavioral) and SUSPECTED.
    """

    KNOWN_EXTERNAL_AI_DOMAINS = [
        "api.openai.com",
        "api.anthropic.com",
        "api.cohere.ai",
        "api.groq.com",
        "huggingface.co",
        "api.replicate.com",
        "api.together.xyz",
    ]

    AI_PROCESS_NAMES = [
        "ollama", "vllm", "localai", "lmstudio", "text-generation-launcher", "tgi"
    ]

    @classmethod
    def detect_cloud_resources(
        cls,
        resources: List[Dict[str, Any]],
        mode: ExecutionMode = ExecutionMode.SIMULATION,
    ) -> List[ShadowAIDiscovery]:
        """1. Detects unmanaged AI cloud resources (GKE pods, VMs, storage buckets)."""
        discoveries = []
        for r in resources:
            name = r.get("name", "unknown-resource")
            provider_str = r.get("provider", "gcp")
            provider = CloudProvider(provider_str.lower()) if provider_str.lower() in CloudProvider else CloudProvider.MULTI_CLOUD
            
            # Check for AI container images or model weight buckets
            image = r.get("image", "").lower()
            is_model_bucket = any(ext in str(r.get("files", [])).lower() for ext in [".gguf", ".safetensors", ".bin"])
            is_ai_container = any(proc in image for proc in cls.AI_PROCESS_NAMES)

            if is_ai_container or is_model_bucket:
                is_public = r.get("is_public", False)
                risk_score, severity, risk_factors = ShadowAIRiskEngine.evaluate_risk(
                    is_public=is_public,
                    has_external_exposure=is_public,
                    is_high_privilege=r.get("privileged", False),
                    handles_sensitive_data=r.get("sensitive_data", False),
                    is_unauthorized=True,
                    is_missing_governance=True,
                    is_unverified_provenance=True,
                )

                asset = AIAsset(
                    asset_id=f"AST-{compute_sha256(name)[:8].upper()}",
                    name=name,
                    asset_type=AssetType.INFERENCE_ENDPOINT if is_ai_container else AssetType.STORAGE_BUCKET_RAG,
                    provider=provider,
                    resource_uri=r.get("resource_uri", f"cloud://{provider}/{name}"),
                    is_private_endpoint=not is_public,
                    model_armor_enabled=False,
                    tags={"governance": "unmanaged", "shadow_ai": "true"},
                )

                disc = ShadowAIDiscovery(
                    discovery_id=f"DSC-CLD-{compute_sha256(name)[:8].upper()}",
                    asset=asset,
                    provider=provider,
                    source=DetectionSource.CLOUD_RESOURCE,
                    confidence=ShadowConfidence.OBSERVED if is_ai_container else ShadowConfidence.INFERRED,
                    execution_mode=mode,
                    provenance=f"Cloud asset inventory scan identified unmanaged AI container '{image}'." if is_ai_container else f"Inferred AI workload from model weight artifacts in storage bucket '{name}'.",
                    risk_factors=risk_factors,
                    risk_score=risk_score,
                    severity=severity,
                    is_public=is_public,
                    details=r,
                )
                disc.attach_evidence(f"Discovered unmanaged cloud asset: {name} | Metadata: {r}")
                discoveries.append(disc)
        return discoveries

    @classmethod
    def detect_network_indicators(
        cls,
        flow_logs: List[Dict[str, Any]],
        mode: ExecutionMode = ExecutionMode.SIMULATION,
    ) -> List[ShadowAIDiscovery]:
        """2. Detects network indicators: outbound egress to external AI domains or listening ports."""
        discoveries = []
        for flow in flow_logs:
            dest_host = flow.get("destination_host", "").lower()
            dest_port = flow.get("destination_port", 0)
            src_ip = flow.get("source_ip", "unknown")

            # Check outbound call to external AI domain
            is_ai_domain = any(domain in dest_host for domain in cls.KNOWN_EXTERNAL_AI_DOMAINS)
            # Check internal traffic to known AI ports (11434 Ollama, 8000 vLLM)
            is_ai_port = dest_port in [11434, 8000, 8080] and flow.get("protocol_signature") == "HTTP_GENAI"

            if is_ai_domain or is_ai_port:
                target_name = dest_host or f"{flow.get('destination_ip')}:{dest_port}"
                is_public = not (dest_host.endswith(".internal") or str(flow.get("destination_ip", "")).startswith(("10.", "172.16.", "192.168.")))
                
                risk_score, severity, risk_factors = ShadowAIRiskEngine.evaluate_risk(
                    is_public=is_public,
                    has_external_exposure=is_public,
                    is_high_privilege=False,
                    handles_sensitive_data=flow.get("contains_pii", False),
                    is_unauthorized=True,
                    is_missing_governance=True,
                )

                asset = AIAsset(
                    asset_id=f"AST-NET-{compute_sha256(target_name)[:8].upper()}",
                    name=f"network-ai-{target_name}",
                    asset_type=AssetType.FOUNDATION_MODEL if is_ai_domain else AssetType.INFERENCE_ENDPOINT,
                    provider=CloudProvider.MULTI_CLOUD,
                    resource_uri=f"net://{src_ip}->{target_name}",
                    is_private_endpoint=not is_public,
                )

                # IMPORTANT: Network traffic INFERRED service usage - do not classify as direct fact
                disc = ShadowAIDiscovery(
                    discovery_id=f"DSC-NET-{compute_sha256(f'{src_ip}:{target_name}')[:8].upper()}",
                    asset=asset,
                    provider=CloudProvider.MULTI_CLOUD,
                    source=DetectionSource.NETWORK_INDICATOR,
                    confidence=ShadowConfidence.INFERRED,
                    execution_mode=mode,
                    provenance=f"Network flow telemetry observed outbound session to AI indicator '{target_name}' from source '{src_ip}'.",
                    risk_factors=risk_factors,
                    risk_score=risk_score,
                    severity=severity,
                    is_public=is_public,
                    details=flow,
                )
                disc.attach_evidence(f"Network flow telemetry: {flow}")
                discoveries.append(disc)
        return discoveries

    @classmethod
    def detect_endpoints(
        cls,
        process_list: List[Dict[str, Any]],
        mode: ExecutionMode = ExecutionMode.SIMULATION,
    ) -> List[ShadowAIDiscovery]:
        """3. Detects active processes on developer workstations or servers (OBSERVED)."""
        discoveries = []
        for proc in process_list:
            cmd = proc.get("command", "").lower()
            hostname = proc.get("hostname", "localhost")
            pid = proc.get("pid", 0)

            matched_proc = next((p for p in cls.AI_PROCESS_NAMES if p in cmd), None)
            if matched_proc:
                is_public = proc.get("listening_address", "").startswith("0.0.0.0")
                risk_score, severity, risk_factors = ShadowAIRiskEngine.evaluate_risk(
                    is_public=is_public,
                    has_external_exposure=is_public,
                    is_high_privilege=proc.get("user", "").lower() in ("root", "admin", "system"),
                    handles_sensitive_data=False,
                    is_unauthorized=True,
                    is_missing_governance=True,
                    is_unverified_provenance=True,
                )

                asset = AIAsset(
                    asset_id=f"AST-EP-{compute_sha256(f'{hostname}:{pid}')[:8].upper()}",
                    name=f"{matched_proc}@{hostname}",
                    asset_type=AssetType.INFERENCE_ENDPOINT,
                    provider=CloudProvider.ON_PREM,
                    resource_uri=f"endpoint://{hostname}/{pid}/{matched_proc}",
                    is_private_endpoint=not is_public,
                )

                disc = ShadowAIDiscovery(
                    discovery_id=f"DSC-EP-{compute_sha256(f'{hostname}:{pid}')[:8].upper()}",
                    asset=asset,
                    provider=CloudProvider.ON_PREM,
                    source=DetectionSource.ENDPOINT,
                    confidence=ShadowConfidence.OBSERVED,
                    execution_mode=mode,
                    provenance=f"Host process table inspection verified active process '{matched_proc}' (PID: {pid}) on '{hostname}'.",
                    risk_factors=risk_factors,
                    risk_score=risk_score,
                    severity=severity,
                    is_public=is_public,
                    details=proc,
                )
                disc.attach_evidence(f"Process telemetry: {proc}")
                discoveries.append(disc)
        return discoveries

    @classmethod
    def detect_saas_integrations(
        cls,
        saas_records: List[Dict[str, Any]],
        mode: ExecutionMode = ExecutionMode.SIMULATION,
    ) -> List[ShadowAIDiscovery]:
        """4. Detects third-party SaaS GenAI plugins and OAuth grants."""
        discoveries = []
        for s in saas_records:
            app_name = s.get("application_name", "unnamed-saas")
            scopes = s.get("scopes", [])
            user_email = s.get("user_email", "unknown")

            if any(ai_term in app_name.lower() for ai_term in ["gpt", "copilot", "claude", "gemini", "notion ai", "ai assistant"]):
                is_high_scope = any("admin" in sc.lower() or "mail" in sc.lower() or "drive" in sc.lower() for sc in scopes)
                risk_score, severity, risk_factors = ShadowAIRiskEngine.evaluate_risk(
                    is_public=True,
                    has_external_exposure=True,
                    is_high_privilege=is_high_scope,
                    handles_sensitive_data=is_high_scope,
                    is_unauthorized=s.get("approved_by_it", False) is False,
                    is_missing_governance=True,
                )

                asset = AIAsset(
                    asset_id=f"AST-SAAS-{compute_sha256(app_name)[:8].upper()}",
                    name=app_name,
                    asset_type=AssetType.FOUNDATION_MODEL,
                    provider=CloudProvider.MULTI_CLOUD,
                    resource_uri=f"saas://integrations/{app_name}",
                    is_private_endpoint=False,
                )

                disc = ShadowAIDiscovery(
                    discovery_id=f"DSC-SAAS-{compute_sha256(f'{app_name}:{user_email}')[:8].upper()}",
                    asset=asset,
                    provider=CloudProvider.MULTI_CLOUD,
                    source=DetectionSource.SAAS_INTEGRATION,
                    confidence=ShadowConfidence.OBSERVED,
                    execution_mode=mode,
                    provenance=f"IdP OAuth grant audit verified third-party SaaS AI integration '{app_name}' granted by '{user_email}'.",
                    risk_factors=risk_factors,
                    risk_score=risk_score,
                    severity=severity,
                    is_public=True,
                    details=s,
                )
                disc.attach_evidence(f"SaaS OAuth record: {s}")
                discoveries.append(disc)
        return discoveries

    @classmethod
    def detect_api_usage(
        cls,
        api_logs: List[Dict[str, Any]],
        mode: ExecutionMode = ExecutionMode.SIMULATION,
    ) -> List[ShadowAIDiscovery]:
        """5. Detects direct uninspected API usage bypassing enterprise gateway."""
        discoveries = []
        for entry in api_logs:
            endpoint = entry.get("endpoint", "")
            caller_ip = entry.get("caller_ip", "")
            has_api_key = bool(entry.get("api_key"))

            if any(domain in endpoint.lower() for domain in cls.KNOWN_EXTERNAL_AI_DOMAINS):
                risk_score, severity, risk_factors = ShadowAIRiskEngine.evaluate_risk(
                    is_public=True,
                    has_external_exposure=True,
                    is_high_privilege=False,
                    handles_sensitive_data=entry.get("payload_pii", False),
                    is_unauthorized=True,
                    is_missing_governance=True,
                )

                asset = AIAsset(
                    asset_id=f"AST-API-{compute_sha256(endpoint)[:8].upper()}",
                    name=f"unmanaged-api-call-{endpoint}",
                    asset_type=AssetType.FOUNDATION_MODEL,
                    provider=CloudProvider.MULTI_CLOUD,
                    resource_uri=f"api://direct/{endpoint}",
                    is_private_endpoint=False,
                )

                disc = ShadowAIDiscovery(
                    discovery_id=f"DSC-API-{compute_sha256(f'{caller_ip}:{endpoint}')[:8].upper()}",
                    asset=asset,
                    provider=CloudProvider.MULTI_CLOUD,
                    source=DetectionSource.API_USAGE,
                    confidence=ShadowConfidence.OBSERVED,
                    execution_mode=mode,
                    provenance=f"Egress proxy inspection observed direct unmanaged AI API request to '{endpoint}' from '{caller_ip}'.",
                    risk_factors=risk_factors,
                    risk_score=risk_score,
                    severity=severity,
                    is_public=True,
                    details=entry,
                )
                disc.attach_evidence(f"API telemetry entry: {entry}")
                discoveries.append(disc)
        return discoveries

    @classmethod
    def detect_model_endpoints(
        cls,
        endpoints: List[Dict[str, Any]],
        mode: ExecutionMode = ExecutionMode.SIMULATION,
    ) -> List[ShadowAIDiscovery]:
        """6. Detects shadow or unmanaged inference model endpoints."""
        discoveries = []
        for ep in endpoints:
            url = ep.get("url", "")
            is_public = ep.get("is_public", False)
            models = ep.get("models", [])
            headers = ep.get("headers", {})

            # False Positive Filtering: Verify AI signature (/v1/models, Ollama, vLLM, FastChat)
            has_ai_signature = bool(models) or "ollama" in str(headers).lower() or "/v1/models" in url
            if not has_ai_signature:
                continue  # Discard non-AI web services on port 8000/8080

            risk_score, severity, risk_factors = ShadowAIRiskEngine.evaluate_risk(
                is_public=is_public,
                has_external_exposure=is_public,
                is_high_privilege=ep.get("is_admin", False),
                handles_sensitive_data=False,
                is_unauthorized=True,
                is_missing_governance=True,
                is_unverified_provenance=True,
            )

            asset = AIAsset(
                asset_id=f"AST-MEP-{compute_sha256(url)[:8].upper()}",
                name=f"shadow-endpoint-{url}",
                asset_type=AssetType.INFERENCE_ENDPOINT,
                provider=CloudProvider.MULTI_CLOUD,
                resource_uri=url,
                is_private_endpoint=not is_public,
                model_armor_enabled=False,
            )

            disc = ShadowAIDiscovery(
                discovery_id=f"DSC-MEP-{compute_sha256(url)[:8].upper()}",
                asset=asset,
                provider=CloudProvider.MULTI_CLOUD,
                source=DetectionSource.MODEL_ENDPOINT,
                confidence=ShadowConfidence.OBSERVED,
                execution_mode=mode,
                provenance=f"Network service probe verified active AI model endpoint at '{url}' serving models: {models}.",
                risk_factors=risk_factors,
                risk_score=risk_score,
                severity=severity,
                is_public=is_public,
                details=ep,
            )
            disc.attach_evidence(f"Model endpoint probe response: {ep}")
            discoveries.append(disc)
        return discoveries

    @classmethod
    def detect_infrastructure_metadata(
        cls,
        metadata_records: List[Dict[str, Any]],
        mode: ExecutionMode = ExecutionMode.SIMULATION,
    ) -> List[ShadowAIDiscovery]:
        """7. Detects unmanaged AI from infrastructure metadata (startup scripts, IaC, env vars)."""
        discoveries = []
        for item in metadata_records:
            name = item.get("resource_name", "unknown-vm")
            env_vars = item.get("env_vars", {})
            startup_script = item.get("startup_script", "").lower()

            has_ai_env = any(k.startswith(("OPENAI_", "ANTHROPIC_", "HUGGINGFACE_")) for k in env_vars.keys())
            has_ai_script = any(proc in startup_script for proc in cls.AI_PROCESS_NAMES)

            if has_ai_env or has_ai_script:
                risk_score, severity, risk_factors = ShadowAIRiskEngine.evaluate_risk(
                    is_public=False,
                    has_external_exposure=False,
                    is_high_privilege=item.get("privileged", False),
                    handles_sensitive_data=False,
                    is_unauthorized=True,
                    is_missing_governance=True,
                )

                asset = AIAsset(
                    asset_id=f"AST-META-{compute_sha256(name)[:8].upper()}",
                    name=f"inferred-ai-{name}",
                    asset_type=AssetType.AI_WORKBENCH_NOTEBOOK,
                    provider=CloudProvider.GCP,
                    resource_uri=f"gcp://compute/{name}",
                    is_private_endpoint=True,
                )

                # Metadata indicates potential AI usage -> INFERRED or SUSPECTED
                disc = ShadowAIDiscovery(
                    discovery_id=f"DSC-META-{compute_sha256(name)[:8].upper()}",
                    asset=asset,
                    provider=CloudProvider.GCP,
                    source=DetectionSource.INFRASTRUCTURE_METADATA,
                    confidence=ShadowConfidence.INFERRED if has_ai_env else ShadowConfidence.SUSPECTED,
                    execution_mode=mode,
                    provenance=f"Infrastructure metadata inspection found AI environment configurations or startup scripts on '{name}'.",
                    risk_factors=risk_factors,
                    risk_score=risk_score,
                    severity=severity,
                    is_public=False,
                    details=item,
                )
                disc.attach_evidence(f"Infrastructure metadata record: {item}")
                discoveries.append(disc)
        return discoveries
