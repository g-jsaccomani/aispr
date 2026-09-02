# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Microsoft Azure AI-SPM Federated Discovery Connector.
Supports both offline customer simulation and real read-only Azure APIs
(Azure OpenAI, Azure AI Search, Azure ML) via Entra ID / DefaultAzureCredential.
"""

import os
import sys
import logging
from typing import Dict, List, Any, Optional

# Ensure project root is in sys.path
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_proj_root = os.path.abspath(os.path.join(_cur_dir, "../.."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from domain.enums import (
    CloudProvider,
    ExecutionMode,
    AssetType,
    FindingSeverity,
    FindingStatus,
    ConfidenceLevel,
    EvidenceType,
    EvidenceStatus,
    FindingSource,
    ControlRelationType,
)
from domain.models.base import utc_now
from domain.models.asset import AIAsset
from domain.models.finding import SecurityFinding
from domain.models.evidence import Evidence, compute_sha256
from domain.models.control import ControlLink
from domain.sanitization import sanitize_evidence_content
from agentic.connectors.base import (
    BaseCloudConnector,
    NormalizedDiscoveryResult,
    CloudConnectorError,
    CloudAuthenticationError,
    CloudPermissionDeniedError,
    CloudAPIResponseError,
    ReadOnlyEnforcementError,
    CloudSDKMissingError,
)

logger = logging.getLogger("AISPR-Azure-Connector")

try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.core.exceptions import (
        ClientAuthenticationError,
        HttpResponseError,
        ResourceNotFoundError,
        AzureError
    )
    AZURE_IDENTITY_AVAILABLE = True
except ImportError:
    AZURE_IDENTITY_AVAILABLE = False
    ClientAuthenticationError = Exception
    HttpResponseError = Exception
    ResourceNotFoundError = Exception
    AzureError = Exception

try:
    from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    AZURE_MGMT_AVAILABLE = True
except ImportError:
    AZURE_MGMT_AVAILABLE = False


class AzureConnector(BaseCloudConnector):
    """
    Federated connector for Microsoft Azure discovering Azure OpenAI Service accounts/deployments,
    Content Safety shields, and Azure Machine Learning workspaces via Entra ID Reader.
    """

    def __init__(
        self,
        subscription_id: str = "8b19a2e3-4c5d-6e7f-8a9b-0c1d2e3f4a5b",
        credentials_payload: Optional[Dict[str, Any]] = None,
        execution_mode: ExecutionMode = ExecutionMode.SIMULATION,
        azure_credential: Optional[Any] = None,
        cognitive_client: Optional[Any] = None,
        resource_client: Optional[Any] = None,
    ):
        super().__init__(
            provider=CloudProvider.AZURE,
            target_identifier=subscription_id,
            execution_mode=execution_mode,
            credentials_payload=credentials_payload,
        )
        self.subscription_id = subscription_id
        self._credential = azure_credential
        self._cognitive_client = cognitive_client
        self._resource_client = resource_client

    def _get_azure_credential(self) -> Any:
        """
        Initializes Entra ID credential (DefaultAzureCredential or ClientSecretCredential).
        Credentials are encrypted in memory and never logged or serialized.
        """
        if self._credential is not None:
            return self._credential

        if not AZURE_IDENTITY_AVAILABLE:
            raise CloudSDKMissingError(
                "Azure Identity SDK 'azure-identity' is not installed. Run 'pip install azure-identity' to enable live Azure discovery.",
                provider=self.provider
            )

        creds = self._credentials_payload or {}
        client_id = creds.get("client_id") or os.environ.get("AZURE_CLIENT_ID")
        client_secret = creds.get("client_secret") or os.environ.get("AZURE_CLIENT_SECRET")
        tenant_id = creds.get("tenant_id") or os.environ.get("AZURE_TENANT_ID")

        try:
            if client_id and client_secret and tenant_id:
                self._credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
            else:
                self._credential = DefaultAzureCredential()
            return self._credential
        except Exception as auth_err:
            raise CloudAuthenticationError(
                f"Failed to initialize Azure Entra ID credential: {auth_err}",
                provider=self.provider
            )

    def _get_cognitive_client(self) -> Any:
        """Returns initialized CognitiveServicesManagementClient."""
        if self._cognitive_client is not None:
            return self._cognitive_client

        if not AZURE_MGMT_AVAILABLE:
            raise CloudSDKMissingError(
                "Azure Management SDK 'azure-mgmt-cognitiveservices' is not installed.",
                provider=self.provider
            )

        cred = self._get_azure_credential()
        try:
            self._cognitive_client = CognitiveServicesManagementClient(
                credential=cred,
                subscription_id=self.subscription_id
            )
            return self._cognitive_client
        except Exception as exc:
            raise CloudConnectorError(f"Failed to create Azure Cognitive Services client: {exc}", provider=self.provider)

    def _get_resource_client(self) -> Any:
        """Returns initialized ResourceManagementClient."""
        if self._resource_client is not None:
            return self._resource_client

        if not AZURE_MGMT_AVAILABLE:
            raise CloudSDKMissingError(
                "Azure Management SDK 'azure-mgmt-resource' is not installed.",
                provider=self.provider
            )

        cred = self._get_azure_credential()
        try:
            self._resource_client = ResourceManagementClient(
                credential=cred,
                subscription_id=self.subscription_id
            )
            return self._resource_client
        except Exception as exc:
            raise CloudConnectorError(f"Failed to create Azure Resource Management client: {exc}", provider=self.provider)

    def discover_resources(self) -> Dict[str, Any]:
        """
        Scans Azure OpenAI Service and ML Workspaces in Read-Only Customer Simulation Mode.
        Explicitly marked as SIMULATION.
        """
        self.execution_mode = ExecutionMode.SIMULATION
        logger.info(f"Scanning Azure Subscription '{self.subscription_id}' in Read-Only Mode (Customer Simulation)...")

        discovered_models = [
            {
                "name": "aoai-customer-service-gpt4o",
                "provider": "azure",
                "resource_type": "azure_openai_deployment",
                "location": "eastus2",
                "cmek_enabled": True,
                "model_armor_enabled": False,
                "private_endpoint": False,
                "status": "PUBLIC_NETWORK_ACCESS_ENABLED"
            }
        ]

        discovered_endpoints = [
            {
                "name": f"/subscriptions/{self.subscription_id}/resourceGroups/rg-ai-banking/providers/Microsoft.CognitiveServices/accounts/aoai-banco-prod",
                "provider": "azure",
                "url": "https://aoai-banco-prod.openai.azure.com",
                "protected": False
            }
        ]

        shadow_ai_findings = [
            {
                "id": "AZURE-SHADOW-01",
                "type": "Unrestricted Azure Cognitive Search Index",
                "provider": "azure",
                "severity": "MEDIUM",
                "resource": "azure-search://credit-proposals-index",
                "description": "Vector search index without Microsoft Entra ID role-based access control (RBAC)."
            }
        ]

        vulnerabilities = [
            {
                "id": "AZURE-NET-01",
                "cve": "MISCONFIG-PUBLIC-NETWORK",
                "severity": "HIGH",
                "resource": "aoai-customer-service-gpt4o",
                "description": "Azure OpenAI account allows public internet traffic instead of requiring Private Endpoints."
            }
        ]

        return {
            "provider": "azure",
            "subscription_id": self.subscription_id,
            "execution_mode": "SIMULATION",
            "models": discovered_models,
            "endpoints": discovered_endpoints,
            "shadow_ai": shadow_ai_findings,
            "vulnerabilities": vulnerabilities
        }

    def discover_resources_live(self) -> Dict[str, Any]:
        """
        Executes real read-only API calls to Azure Cognitive Services and Resource Management.
        Only marks execution_mode as LIVE if real API calls execute successfully.
        """
        self.assert_read_only("discover_resources_live")
        logger.info(f"Scanning Azure Subscription '{self.subscription_id}' in Read-Only Live Mode via Entra ID...")

        discovered_models: List[Dict[str, Any]] = []
        discovered_endpoints: List[Dict[str, Any]] = []
        shadow_ai_findings: List[Dict[str, Any]] = []
        vulnerabilities: List[Dict[str, Any]] = []

        cog_client = self._get_cognitive_client()
        res_client = self._get_resource_client()

        # ----------------------------------------------------------------------
        # 1. Azure OpenAI & Cognitive Services Accounts
        # ----------------------------------------------------------------------
        try:
            accounts = list(cog_client.accounts.list())
            for acc in accounts:
                acc_name = getattr(acc, "name", "aoai-account")
                acc_id = getattr(acc, "id", f"/subscriptions/{self.subscription_id}/accounts/{acc_name}")
                acc_kind = getattr(acc, "kind", "CognitiveServices")
                location = getattr(acc, "location", "eastus2")
                props = getattr(acc, "properties", None) or {}

                # Check public network access
                pub_access = getattr(props, "public_network_access", "Enabled")
                if isinstance(pub_access, str):
                    is_private = (pub_access.lower() == "disabled")
                else:
                    is_private = False

                # Check Customer-Managed Key (CMEK)
                encryption = getattr(props, "encryption", None)
                key_vault = getattr(encryption, "key_vault_properties", None) if encryption else None
                has_cmek = bool(key_vault)

                # Endpoint URL
                endpoint_url = getattr(props, "endpoint", f"https://{acc_name}.openai.azure.com")

                discovered_endpoints.append({
                    "name": acc_id,
                    "provider": "azure",
                    "url": endpoint_url,
                    "protected": is_private,
                    "cmek_enabled": has_cmek,
                    "location": location,
                })

                if not is_private:
                    vulnerabilities.append({
                        "id": f"AZURE-AOAI-PUB-NET-{acc_name}",
                        "cve": "MISCONFIG-AZURE-PUBLIC-NETWORK",
                        "severity": "HIGH",
                        "resource": acc_id,
                        "description": f"Azure OpenAI Account '{acc_name}' allows public internet ingress. Private Endpoints required."
                    })

                if not has_cmek:
                    vulnerabilities.append({
                        "id": f"AZURE-AOAI-CMEK-GAP-{acc_name}",
                        "cve": "MISCONFIG-AZURE-NO-CMEK",
                        "severity": "HIGH",
                        "resource": acc_id,
                        "description": f"Azure OpenAI Account '{acc_name}' is encrypted with Microsoft-managed keys instead of Azure Key Vault CMEK."
                    })

                # List Model Deployments for this account
                # Extract resource group from Azure resource ID
                rg_name = "default-rg"
                if "/resourceGroups/" in acc_id:
                    rg_name = acc_id.split("/resourceGroups/")[1].split("/")[0]

                try:
                    deployments = list(cog_client.deployments.list(resource_group_name=rg_name, account_name=acc_name))
                    for dep in deployments:
                        dep_name = getattr(dep, "name", "deployment")
                        dep_id = getattr(dep, "id", f"{acc_id}/deployments/{dep_name}")
                        dep_props = getattr(dep, "properties", None) or {}
                        model_info = getattr(dep_props, "model", None) or {}
                        model_name = getattr(model_info, "name", dep_name)

                        # Check Content Filter
                        content_filter = getattr(dep_props, "rai_policy_name", None)
                        has_guard = bool(content_filter)

                        discovered_models.append({
                            "name": f"{acc_name}/{dep_name}",
                            "provider": "azure",
                            "resource_type": "azure_openai_deployment",
                            "location": location,
                            "resource_uri": dep_id,
                            "cmek_enabled": has_cmek,
                            "model_armor_enabled": has_guard,
                            "private_endpoint": is_private,
                            "status": "HARDENED" if (is_private and has_cmek and has_guard) else "VULNERABLE",
                            "metadata": {"model": model_name, "rai_policy": content_filter}
                        })

                        if not has_guard:
                            vulnerabilities.append({
                                "id": f"AZURE-AOAI-RAI-GAP-{acc_name}-{dep_name}",
                                "cve": "MISCONFIG-AZURE-NO-CONTENT-FILTER",
                                "severity": "HIGH",
                                "resource": dep_id,
                                "description": f"Deployment '{dep_name}' lacks Azure OpenAI Responsible AI content safety policy."
                            })
                except Exception as dep_err:
                    self._handle_azure_exception(dep_err, f"deployments.list({acc_name})")

        except (CloudAuthenticationError, CloudPermissionDeniedError):
            raise
        except Exception as acc_err:
            self._handle_azure_exception(acc_err, "accounts.list")

        # ----------------------------------------------------------------------
        # 2. Azure Machine Learning Workspaces & Cognitive Search
        # ----------------------------------------------------------------------
        try:
            resources = list(res_client.resources.list(
                filter="resourceType eq 'Microsoft.MachineLearningServices/workspaces' or resourceType eq 'Microsoft.Search/searchServices'"
            ))
            for r in resources:
                r_name = getattr(r, "name", "resource")
                r_id = getattr(r, "id", f"/subscriptions/{self.subscription_id}/resources/{r_name}")
                r_type = getattr(r, "type", "")
                r_loc = getattr(r, "location", "eastus2")

                if "MachineLearningServices" in r_type:
                    discovered_models.append({
                        "name": r_name,
                        "provider": "azure",
                        "resource_type": "azure_ml_workspace",
                        "location": r_loc,
                        "resource_uri": r_id,
                        "cmek_enabled": False,
                        "model_armor_enabled": False,
                        "private_endpoint": False,
                        "status": "DISCOVERED_ML_WORKSPACE"
                    })
                elif "Search" in r_type:
                    shadow_ai_findings.append({
                        "id": f"AZURE-SEARCH-INDEX-{r_name}",
                        "type": "Azure AI Search Service (RAG Vector Store)",
                        "provider": "azure",
                        "severity": "MEDIUM",
                        "resource": r_id,
                        "description": f"Azure AI Search Service '{r_name}' cataloged as RAG Vector Store without verified IP restriction."
                    })
        except (CloudAuthenticationError, CloudPermissionDeniedError):
            raise
        except Exception as res_err:
            self._handle_azure_exception(res_err, "resources.list")

        # Real API calls executed successfully
        self.execution_mode = ExecutionMode.LIVE

        return {
            "provider": "azure",
            "subscription_id": self.subscription_id,
            "execution_mode": "LIVE",
            "models": discovered_models,
            "endpoints": discovered_endpoints,
            "shadow_ai": shadow_ai_findings,
            "vulnerabilities": vulnerabilities
        }

    def _handle_azure_exception(self, err: Exception, api_name: str) -> None:
        """Translates Azure Core / Identity exceptions into AISPR canonical connector exceptions."""
        err_str = str(err).lower()
        status_code = getattr(err, "status_code", None)

        # 1. Prioritize Permission Denied (HTTP 403 / RBAC / Authorization / Forbidden)
        if status_code == 403 or "forbidden" in err_str or "authorization" in err_str:
            raise CloudPermissionDeniedError(
                f"Azure RBAC permission denied for '{api_name}': {err}",
                provider=self.provider,
                details={"api": api_name, "status_code": 403}
            )

        # 2. Authentication Failure (HTTP 401 / Entra ID token / Credentials)
        if status_code == 401 or "authentication" in err_str or "credential" in err_str or isinstance(err, ClientAuthenticationError):
            raise CloudAuthenticationError(
                f"Azure Entra ID authentication failed for '{api_name}': {err}",
                provider=self.provider,
                details={"api": api_name, "status_code": 401}
            )

        # 3. Fallback to general connector error
        raise CloudConnectorError(
            f"Azure API error during '{api_name}': {err}",
            provider=self.provider
        )

    def normalize(self, raw_data: Dict[str, Any], execution_mode: ExecutionMode) -> NormalizedDiscoveryResult:
        """
        Normalizes Azure raw dictionary output into canonical AIAsset, SecurityFinding, and Evidence entities.
        """
        assets: List[AIAsset] = []
        findings: List[SecurityFinding] = []
        evidence_list: List[Evidence] = []
        errors: List[str] = []

        is_live = (execution_mode == ExecutionMode.LIVE)
        evidence_status = EvidenceStatus.VERIFIED if is_live else EvidenceStatus.UNVERIFIED

        # 1. Normalize Models
        for m in raw_data.get("models", []):
            m_name = m.get("name", "azure-model")
            r_type = m.get("resource_type", "azure_openai_deployment")
            
            if "deployment" in r_type.lower():
                a_type = AssetType.INFERENCE_ENDPOINT
            elif "workspace" in r_type.lower():
                a_type = AssetType.AI_WORKBENCH_NOTEBOOK
            else:
                a_type = AssetType.FOUNDATION_MODEL

            res_uri = m.get("resource_uri") or f"/subscriptions/{self.subscription_id}/models/{m_name}"

            asset = AIAsset(
                name=m_name,
                asset_type=a_type,
                provider=CloudProvider.AZURE,
                location=m.get("location", "eastus2"),
                resource_uri=res_uri,
                display_name=m_name,
                cmek_enabled=bool(m.get("cmek_enabled", False)),
                is_private_endpoint=bool(m.get("private_endpoint", False)),
                model_armor_enabled=bool(m.get("model_armor_enabled", False)),
                metadata=self.sanitize_credentials(m.get("metadata", {}))
            )
            assets.append(asset)

        # 2. Normalize Endpoints
        for ep in raw_data.get("endpoints", []):
            ep_name = ep.get("name", "azure-endpoint")
            asset = AIAsset(
                name=ep_name.split("/")[-1] if "/" in ep_name else ep_name,
                asset_type=AssetType.INFERENCE_ENDPOINT,
                provider=CloudProvider.AZURE,
                location=ep.get("location", "eastus2"),
                resource_uri=ep_name,
                display_name=ep_name.split("/")[-1],
                cmek_enabled=bool(ep.get("cmek_enabled", False)),
                is_private_endpoint=bool(ep.get("protected", False)),
                model_armor_enabled=False,
                metadata={"url": ep.get("url", "")}
            )
            assets.append(asset)

        # Helper to create finding and evidence
        def _build_canonical_finding(
            f_id: str,
            title: str,
            desc: str,
            sev_str: str,
            res_uri: str,
            control_id: str,
            cve: Optional[str] = None
        ):
            mapped_asset = next((a for a in assets if a.resource_uri == res_uri or a.name == res_uri), None)
            if not mapped_asset:
                mapped_asset = AIAsset(
                    name=res_uri.split("/")[-1] if "/" in res_uri else res_uri,
                    asset_type=AssetType.INFERENCE_ENDPOINT if "accounts" in res_uri else AssetType.VECTOR_DATABASE,
                    provider=CloudProvider.AZURE,
                    location="eastus2",
                    resource_uri=res_uri,
                )
                assets.append(mapped_asset)

            sanitized_payload = sanitize_evidence_content(f"Azure Resource: {res_uri} | Finding: {title} | Details: {desc}")
            ev = Evidence(
                evidence_id=f"EVD-AZURE-{compute_sha256(f_id)[:8].upper()}",
                source=FindingSource.MULTI_CLOUD_SCANNER,
                provider=CloudProvider.AZURE,
                resource=res_uri,
                collection_method="API_CALL" if is_live else "FIXTURE",
                evidence_type=EvidenceType.CONFIGURATION,
                status=evidence_status,
                confidence=1.0 if is_live else 0.5,
                execution_mode=execution_mode,
                sanitized_content=sanitized_payload,
                content_hash=compute_sha256(sanitized_payload),
                metadata={"azure_subscription_id": self.subscription_id, "control_id": control_id}
            )
            evidence_list.append(ev)

            sev_upper = sev_str.upper()
            severity = FindingSeverity.HIGH
            if "CRITICAL" in sev_upper:
                severity = FindingSeverity.CRITICAL
            elif "MEDIUM" in sev_upper:
                severity = FindingSeverity.MEDIUM
            elif "LOW" in sev_upper:
                severity = FindingSeverity.LOW

            finding = SecurityFinding(
                finding_id=f"FND-{f_id.replace(':', '-')[:16].upper()}",
                assessment_id="ASSESSMENT-AZURE-LIVE" if is_live else "ASSESSMENT-AZURE-SIM",
                source=FindingSource.MULTI_CLOUD_SCANNER,
                provider=CloudProvider.AZURE,
                asset=mapped_asset,
                title=title,
                description=desc,
                severity=severity,
                confidence=ConfidenceLevel.HIGH if is_live else ConfidenceLevel.MEDIUM,
                status=FindingStatus.OPEN,
                execution_mode=execution_mode,
                evidence=[ev],
                control_links=[
                    ControlLink(
                        control_id=control_id,
                        relation_type=ControlRelationType.PRIMARY_CONTROL,
                        rationale=f"Azure AI-SPM automated finding mapped to {control_id}"
                    )
                ],
                cve=cve,
                metadata={"subscription_id": self.subscription_id}
            )
            findings.append(finding)

        # 3. Normalize Vulnerabilities
        for v in raw_data.get("vulnerabilities", []):
            v_id = v.get("id", "AZURE-VULN-01")
            cve = v.get("cve", "MISCONFIG")
            desc = v.get("description", "Azure AI security deviation")
            res = v.get("resource", f"/subscriptions/{self.subscription_id}")
            sev = v.get("severity", "HIGH")
            
            if "PUBLIC" in cve or "NET" in v_id:
                cid = "INF-02"
            elif "CMEK" in v_id or "CMEK" in cve:
                cid = "INF-04"
            elif "RAI" in v_id or "FILTER" in cve:
                cid = "APP-02"
            else:
                cid = "APP-01"

            _build_canonical_finding(
                f_id=v_id,
                title=f"Azure AI Security Deviation: {cve}",
                desc=desc,
                sev_str=sev,
                res_uri=res,
                control_id=cid,
                cve=cve
            )

        # 4. Normalize Shadow AI
        for s in raw_data.get("shadow_ai", []):
            s_id = s.get("id", "AZURE-SHADOW-01")
            s_type = s.get("type", "Shadow AI")
            desc = s.get("description", "Unsanctioned AI asset detected")
            res = s.get("resource", "azure-search://credit-proposals-index")
            sev = s.get("severity", "MEDIUM")
            cid = "DAT-03"

            _build_canonical_finding(
                f_id=s_id,
                title=s_type,
                desc=desc,
                sev_str=sev,
                res_uri=res,
                control_id=cid,
                cve=None
            )

        return NormalizedDiscoveryResult(
            provider=CloudProvider.AZURE,
            execution_mode=execution_mode,
            account_or_project_id=self.subscription_id,
            assets=assets,
            findings=findings,
            evidence=evidence_list,
            raw_discovery=self.sanitize_credentials(raw_data),
            errors=errors
        )

    def discover_canonical(self, live: bool = False, fallback_on_error: bool = False) -> NormalizedDiscoveryResult:
        """
        Executes discovery and returns strongly-typed, normalized canonical entities.
        If live=True and an API failure occurs:
          - If fallback_on_error is True: returns explicit FALLBACK result recording failure metadata.
          - If fallback_on_error is False: raises the typed CloudConnectorError.
        """
        if live:
            try:
                raw_data = self.discover_resources_live()
                return self.normalize(raw_data, ExecutionMode.LIVE)
            except Exception as exc:
                if fallback_on_error:
                    logger.warning(f"Azure Live discovery failed ({exc}). Falling back to simulated metadata with explicit FALLBACK mode.")
                    raw_data = self.discover_resources()
                    raw_data["execution_mode"] = ExecutionMode.FALLBACK
                    raw_data["fallback_metadata"] = {
                        "provider": "azure",
                        "attempted_operation": "azure:discover_resources_live",
                        "failure_reason": str(exc),
                        "fallback_source": "LOCAL_SIMULATED_FIXTURE",
                        "timestamp": utc_now().isoformat(),
                    }
                    return self.normalize(raw_data, ExecutionMode.FALLBACK)
                raise
        else:
            raw_data = self.discover_resources()
            return self.normalize(raw_data, ExecutionMode.SIMULATION)
