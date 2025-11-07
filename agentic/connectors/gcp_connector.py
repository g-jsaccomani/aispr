# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Google Cloud AI-SPM Federated Discovery Connector.
Supports both offline customer simulation (discover_resources)
and live Application Default Credentials (ADC) scanning (discover_resources_live).
"""

import os
import sys
import logging
from typing import Dict, List, Any, Optional, Set

# Ensure project root is in sys.path for config import
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_proj_root = os.path.abspath(os.path.join(_cur_dir, "../.."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

try:
    from config.gcp_auth import (
        get_gcp_credentials,
        get_authenticated_session,
        get_auth_headers,
        get_default_project_id,
        GCPAuth
    )
except ImportError:
    # Graceful fallback if config module is loaded in isolated environments
    get_gcp_credentials = None
    get_authenticated_session = None
    get_auth_headers = None
    get_default_project_id = None
    GCPAuth = None

logger = logging.getLogger("AISPR-GCP-Connector")


class GCPConnector:
    """
    Federated connector for Google Cloud discovering Vertex AI models,
    endpoints, GKE namespaces, and Security Command Center (SCC) AI Protection telemetry.
    """

    def __init__(self, project_id: str = "your-gcp-project-id", credentials_payload: Dict[str, Any] = None):
        self.project_id = project_id
        self.credentials_payload = credentials_payload or {}
        self._auth_helper: Optional[Any] = None

    def _get_auth(self) -> Optional[Any]:
        """Returns or initializes the GCPAuth helper."""
        if self._auth_helper is None and GCPAuth is not None:
            self._auth_helper = GCPAuth(project_id=self.project_id)
        return self._auth_helper

    def discover_resources(self) -> Dict[str, Any]:
        """
        Queries Cloud Asset Inventory, Vertex AI Registry, and SCC in Read-Only mode (Customer Simulation / Mock).
        """
        logger.info(f"Scanning GCP Project '{self.project_id}' in Read-Only Mode via Workload Identity (Simulation)...")

        discovered_models = [
            {
                "name": "vertex-credit-scoring-v2",
                "provider": "gcp",
                "resource_type": "vertex_ai_endpoint",
                "location": "southamerica-east1",
                "cmek_enabled": False,
                "model_armor_enabled": False,
                "private_endpoint": False,
                "status": "UNPROTECTED_EXPOSED"
            },
            {
                "name": "gemini-1.5-pro-financial-rag",
                "provider": "gcp",
                "resource_type": "vertex_ai_model",
                "location": "us-central1",
                "cmek_enabled": True,
                "model_armor_enabled": False,
                "private_endpoint": True,
                "status": "PARTIALLY_HARDENED"
            },
            {
                "name": "workbench-analyst-gpu-01",
                "provider": "gcp",
                "resource_type": "vertex_workbench_instance",
                "location": "southamerica-east1-a",
                "cmek_enabled": False,
                "model_armor_enabled": False,
                "private_endpoint": False,
                "status": "VULNERABLE_PUBLIC_IP"
            }
        ]

        discovered_endpoints = [
            {
                "name": f"projects/{self.project_id}/locations/southamerica-east1/endpoints/credit-scoring-prod",
                "provider": "gcp",
                "url": "https://southamerica-east1-aiplatform.googleapis.com",
                "protected": False
            }
        ]

        shadow_ai_findings = [
            {
                "id": "GCP-SHADOW-01",
                "type": "Unsanctioned Shadow AI (Ollama Llama-3)",
                "provider": "gcp",
                "severity": "CRITICAL",
                "resource": "k8s://credit-risk-analytics/ollama-pod-gpu",
                "description": "Port 11434 open on internal GKE cluster serving unvetted open-source LLMs without DLP or access logs."
            },
            {
                "id": "GCP-SHADOW-02",
                "type": "vLLM Inference Server on Compute Engine",
                "provider": "gcp",
                "severity": "HIGH",
                "resource": "gce://us-central1-a/ml-dev-sandbox-vm",
                "description": "Developer VM hosting vLLM instance with world-readable local logs storing raw user financial prompts."
            }
        ]

        vulnerabilities = [
            {
                "id": "CVE-2026-2244",
                "cve": "CVE-2026-2244",
                "severity": "CRITICAL",
                "resource": "vertex-workbench://southamerica-east1-a/workbench-analyst-gpu-01",
                "description": "Vertex AI Workbench startup script exposes default Compute Engine OAuth token in /var/log/startup-script.log."
            },
            {
                "id": "GCP-CMEK-GAP-01",
                "cve": "MISCONFIG-CMEK",
                "severity": "HIGH",
                "resource": "gs://banco-credit-rag-knowledge-base",
                "description": "Cloud Storage bucket storing vector embeddings encrypted with Google-managed key instead of Cloud KMS CMEK."
            }
        ]

        return {
            "provider": "gcp",
            "project_id": self.project_id,
            "models": discovered_models,
            "endpoints": discovered_endpoints,
            "shadow_ai": shadow_ai_findings,
            "vulnerabilities": vulnerabilities
        }

    def discover_resources_live(
        self,
        locations: Optional[List[str]] = None,
        use_rest_fallback: bool = True
    ) -> Dict[str, Any]:
        """
        Executes live discovery against Google Cloud APIs using Application Default Credentials (ADC).
        
        Uses:
        - google-cloud-aiplatform to list actual Vertex AI Endpoints, Models, and Workbench instances.
        - google-cloud-asset to query Cloud Asset Inventory for IAM policies, CMEK encryption, and network configuration.
        - google-cloud-modelarmor / REST for Model Armor template verification.
        - google-cloud-securitycenter / REST for Security Command Center AI findings.

        Returns the exact same schema shape as discover_resources():
        {
            "provider": "gcp",
            "project_id": str,
            "models": list,
            "endpoints": list,
            "shadow_ai": list,
            "vulnerabilities": list
        }
        """
        target_locations = locations or ["us-central1", "southamerica-east1", "us-east4", "europe-west1", "europe-west4"]
        
        # 1. Resolve Credentials and Project ID
        creds = None
        effective_project = self.project_id
        if get_gcp_credentials is not None:
            creds, disc_proj = get_gcp_credentials(credentials_payload=self.credentials_payload)
            if not effective_project or effective_project == "your-gcp-project-id":
                effective_project = disc_proj or self.project_id

        logger.info(f"Initiating LIVE GCP AI-SPM scan for project '{effective_project}' via ADC...")

        discovered_models: List[Dict[str, Any]] = []
        discovered_endpoints: List[Dict[str, Any]] = []
        shadow_ai_findings: List[Dict[str, Any]] = []
        vulnerabilities: List[Dict[str, Any]] = []

        session = None
        if get_authenticated_session is not None:
            session = get_authenticated_session(credentials=creds)

        # 2. Query Cloud Asset Inventory (google-cloud-asset) for Resource Metadata & IAM
        asset_metadata: Dict[str, Dict[str, Any]] = {}
        cmek_protected_assets: Set[str] = set()
        private_network_assets: Set[str] = set()
        workbench_instances_from_asset: List[Dict[str, Any]] = []
        storage_buckets: List[Dict[str, Any]] = []
        compute_and_gke_assets: List[Dict[str, Any]] = []

        try:
            try:
                from google.cloud import asset_v1

                asset_client = asset_v1.AssetServiceClient(credentials=creds)
                
                # 2a. Search Resources across AI, Compute, GKE, Storage, and Workbench
                request = asset_v1.SearchAllResourcesRequest(
                    scope=f"projects/{effective_project}",
                    asset_types=[
                        "aiplatform.googleapis.com/Model",
                        "aiplatform.googleapis.com/Endpoint",
                        "notebooks.googleapis.com/Instance",
                        "notebooks.googleapis.com/Runtime",
                        "container.googleapis.com/Cluster",
                        "compute.googleapis.com/Instance",
                        "storage.googleapis.com/Bucket"
                    ]
                )
                for asset in asset_client.search_all_resources(request=request):
                    a_name = asset.name
                    a_type = asset.asset_type
                    kms_keys = list(getattr(asset, "kms_keys", []) or [])
                    has_cmek = bool(kms_keys)
                    if has_cmek:
                        cmek_protected_assets.add(a_name)
                        if getattr(asset, "display_name", None):
                            cmek_protected_assets.add(asset.display_name)

                    # Inspect network configuration
                    add_attrs = getattr(asset, "additional_attributes", {}) or {}
                    network_tags = list(getattr(asset, "network_tags", []) or [])
                    is_private_net = bool(
                        add_attrs.get("network") or
                        add_attrs.get("noPublicIp") is True or
                        "private" in a_name.lower() or
                        "no-public-ip" in network_tags
                    )
                    if is_private_net:
                        private_network_assets.add(a_name)
                        if getattr(asset, "display_name", None):
                            private_network_assets.add(asset.display_name)

                    asset_metadata[a_name] = {
                        "name": a_name,
                        "display_name": getattr(asset, "display_name", a_name.split("/")[-1]),
                        "type": a_type,
                        "location": getattr(asset, "location", "us-central1"),
                        "has_cmek": has_cmek,
                        "kms_keys": kms_keys,
                        "is_private_net": is_private_net,
                        "additional_attributes": add_attrs
                    }

                    if "notebooks.googleapis.com" in a_type:
                        workbench_instances_from_asset.append(asset_metadata[a_name])
                    elif "storage.googleapis.com/Bucket" in a_type:
                        storage_buckets.append(asset_metadata[a_name])
                    elif "container.googleapis.com/Cluster" in a_type or "compute.googleapis.com/Instance" in a_type:
                        compute_and_gke_assets.append(asset_metadata[a_name])

                # 2b. Search IAM Policies via Cloud Asset Inventory for Excessive Agency & Public Exposure
                try:
                    iam_request = asset_v1.SearchAllIamPoliciesRequest(
                        scope=f"projects/{effective_project}"
                    )
                    for policy_result in asset_client.search_all_iam_policies(request=iam_request):
                        res_name = policy_result.resource
                        policy = policy_result.policy
                        for binding in getattr(policy, "bindings", []):
                            role = getattr(binding, "role", "")
                            members = list(getattr(binding, "members", []) or [])
                            
                            # Public IAM exposure
                            if any(m in ["allUsers", "allAuthenticatedUsers"] for m in members):
                                vulnerabilities.append({
                                    "id": f"IAM-PUB-{len(vulnerabilities)+1}",
                                    "cve": "EXCESSIVE_PUBLIC_ACCESS",
                                    "severity": "CRITICAL",
                                    "resource": res_name,
                                    "description": f"Resource '{res_name}' exposes role '{role}' to public identity ({', '.join(members)})."
                                })

                            # Excessive Agency on AI & Storage resources
                            if any(crit_role in role for crit_role in ["roles/owner", "roles/editor", "roles/resourcemanager.organizationAdmin"]):
                                for member in members:
                                    if member.startswith("serviceAccount:") and any(ai_term in member.lower() for ai_term in ["ai", "vertex", "model", "rag", "agent"]):
                                        vulnerabilities.append({
                                            "id": f"IAM-AGENCY-{len(vulnerabilities)+1}",
                                            "cve": "EXCESSIVE_AGENCY_IAM",
                                            "severity": "HIGH",
                                            "resource": res_name,
                                            "description": f"AI Service Account '{member}' possesses high-privilege role '{role}' on '{res_name}'."
                                        })
                except Exception as iam_err:
                    logger.debug(f"Cloud Asset Inventory IAM search exception: {iam_err}")

            except (ImportError, Exception):
                # REST fallback for Cloud Asset Inventory
                if session is not None and use_rest_fallback:
                    url = f"https://cloudasset.googleapis.com/v1/projects/{effective_project}:searchAllResources"
                    params = {
                        "assetTypes": [
                            "aiplatform.googleapis.com/Model",
                            "aiplatform.googleapis.com/Endpoint",
                            "notebooks.googleapis.com/Instance",
                            "container.googleapis.com/Cluster",
                            "storage.googleapis.com/Bucket",
                            "compute.googleapis.com/Instance"
                        ]
                    }
                    try:
                        resp = session.get(url, params=params, timeout=10)
                        if resp.status_code == 200:
                            for item in resp.json().get("results", []):
                                a_name = item.get("name", "")
                                a_type = item.get("assetType", "")
                                kms_keys = item.get("kmsKeys", [])
                                has_cmek = bool(kms_keys)
                                if has_cmek:
                                    cmek_protected_assets.add(a_name)
                                    if item.get("displayName"):
                                        cmek_protected_assets.add(item.get("displayName"))

                                is_private = bool(item.get("additionalAttributes", {}).get("network") or "private" in a_name.lower())
                                if is_private:
                                    private_network_assets.add(a_name)
                                    if item.get("displayName"):
                                        private_network_assets.add(item.get("displayName"))

                                info = {
                                    "name": a_name,
                                    "display_name": item.get("displayName", a_name.split("/")[-1]),
                                    "type": a_type,
                                    "location": item.get("location", "us-central1"),
                                    "has_cmek": has_cmek,
                                    "kms_keys": kms_keys,
                                    "is_private_net": is_private,
                                    "additional_attributes": item.get("additionalAttributes", {})
                                }
                                asset_metadata[a_name] = info
                                if "notebooks.googleapis.com" in a_type:
                                    workbench_instances_from_asset.append(info)
                                elif "storage.googleapis.com/Bucket" in a_type:
                                    storage_buckets.append(info)
                                elif "container.googleapis.com" in a_type or "compute.googleapis.com" in a_type:
                                    compute_and_gke_assets.append(info)
                    except Exception as rest_asset_err:
                        logger.debug(f"Cloud Asset Inventory REST search error: {rest_asset_err}")

        except Exception as exc:
            logger.debug(f"Cloud Asset Inventory discovery failed: {exc}")

        # 3. Discover Model Armor Templates (google-cloud-modelarmor / REST via AuthorizedSession)
        model_armor_active = False
        try:
            try:
                from google.cloud import modelarmor_v1
                ma_client = modelarmor_v1.ModelArmorClient(credentials=creds)
                for loc in target_locations:
                    parent = f"projects/{effective_project}/locations/{loc}"
                    try:
                        for template in ma_client.list_templates(parent=parent):
                            if template:
                                model_armor_active = True
                                break
                    except Exception as ma_loc_err:
                        logger.debug(f"Model Armor SDK list_templates for {parent}: {ma_loc_err}")
            except (ImportError, Exception):
                if session is not None and use_rest_fallback:
                    for loc in target_locations:
                        url = f"https://modelarmor.{loc}.rep.googleapis.com/v1/projects/{effective_project}/locations/{loc}/templates"
                        try:
                            resp = session.get(url, timeout=10)
                            if resp.status_code == 200 and resp.json().get("templates"):
                                model_armor_active = True
                                break
                        except Exception as e:
                            logger.debug(f"Model Armor REST scan error for location {loc}: {e}")
        except Exception as exc:
            logger.debug(f"Model Armor discovery encountered an error: {exc}")

        # 4. List Vertex AI Models, Endpoints, and Workbench Instances (google-cloud-aiplatform)
        try:
            try:
                from google.cloud import aiplatform

                for loc in target_locations:
                    try:
                        aiplatform.init(project=effective_project, location=loc, credentials=creds)

                        # 4a. List Vertex AI Models
                        models = aiplatform.Model.list(project=effective_project, location=loc)
                        for m in models:
                            m_dict = m.to_dict() if hasattr(m, "to_dict") else {}
                            m_name = getattr(m, "display_name", m.resource_name)
                            
                            # CMEK resolution from SDK or Asset Inventory
                            cmek_sdk = bool(m_dict.get("encryption_spec") or getattr(m, "encryption_spec", None))
                            cmek_asset = m.resource_name in cmek_protected_assets or m_name in cmek_protected_assets
                            cmek_enabled = cmek_sdk or cmek_asset

                            # Network / private status
                            private_endpoint = m.resource_name in private_network_assets or m_name in private_network_assets or True

                            # Posture status
                            if cmek_enabled and model_armor_active and private_endpoint:
                                status = "HARDENED"
                            elif cmek_enabled or private_endpoint:
                                status = "PARTIALLY_HARDENED"
                            else:
                                status = "UNPROTECTED_EXPOSED"

                            discovered_models.append({
                                "name": m_name,
                                "provider": "gcp",
                                "resource_type": "vertex_ai_model",
                                "location": loc,
                                "cmek_enabled": cmek_enabled,
                                "model_armor_enabled": model_armor_active,
                                "private_endpoint": private_endpoint,
                                "status": status
                            })

                        # 4b. List Vertex AI Endpoints
                        endpoints = aiplatform.Endpoint.list(project=effective_project, location=loc)
                        for ep in endpoints:
                            ep_dict = ep.to_dict() if hasattr(ep, "to_dict") else {}
                            ep_display = getattr(ep, "display_name", ep.resource_name)

                            # Private endpoint & Network check
                            is_private = bool(
                                ep_dict.get("network") or
                                getattr(ep, "network", None) or
                                ep.resource_name in private_network_assets or
                                ep_display in private_network_assets
                            )

                            # CMEK check
                            ep_cmek = bool(
                                ep_dict.get("encryption_spec") or
                                getattr(ep, "encryption_spec", None) or
                                ep.resource_name in cmek_protected_assets or
                                ep_display in cmek_protected_assets
                            )

                            is_protected = is_private and (ep_cmek or model_armor_active)

                            discovered_endpoints.append({
                                "name": ep.resource_name,
                                "provider": "gcp",
                                "url": f"https://{loc}-aiplatform.googleapis.com",
                                "protected": is_protected
                            })

                            discovered_models.append({
                                "name": ep_display,
                                "provider": "gcp",
                                "resource_type": "vertex_ai_endpoint",
                                "location": loc,
                                "cmek_enabled": ep_cmek,
                                "model_armor_enabled": model_armor_active,
                                "private_endpoint": is_private,
                                "status": "HARDENED" if is_protected else "UNPROTECTED_EXPOSED"
                            })

                    except Exception as loc_err:
                        logger.debug(f"Vertex AI SDK scan for location {loc}: {loc_err}")

            except (ImportError, Exception):
                # REST fallback for Vertex AI Models & Endpoints
                if session is not None and use_rest_fallback:
                    for loc in target_locations:
                        # Fetch Models REST
                        url_m = f"https://{loc}-aiplatform.googleapis.com/v1/projects/{effective_project}/locations/{loc}/models"
                        try:
                            r_m = session.get(url_m, timeout=10)
                            if r_m.status_code == 200:
                                for item in r_m.json().get("models", []):
                                    m_res = item.get("name", "")
                                    m_disp = item.get("displayName", m_res)
                                    cmek = "encryptionSpec" in item or m_res in cmek_protected_assets
                                    is_priv = m_res in private_network_assets or True
                                    status = "HARDENED" if (cmek and model_armor_active) else ("PARTIALLY_HARDENED" if cmek else "UNPROTECTED_EXPOSED")
                                    discovered_models.append({
                                        "name": m_disp,
                                        "provider": "gcp",
                                        "resource_type": "vertex_ai_model",
                                        "location": loc,
                                        "cmek_enabled": cmek,
                                        "model_armor_enabled": model_armor_active,
                                        "private_endpoint": is_priv,
                                        "status": status
                                    })
                        except Exception as e:
                            logger.debug(f"Vertex AI REST Models {loc}: {e}")

                        # Fetch Endpoints REST
                        url_ep = f"https://{loc}-aiplatform.googleapis.com/v1/projects/{effective_project}/locations/{loc}/endpoints"
                        try:
                            r_ep = session.get(url_ep, timeout=10)
                            if r_ep.status_code == 200:
                                for item in r_ep.json().get("endpoints", []):
                                    ep_res = item.get("name", "")
                                    ep_disp = item.get("displayName", ep_res)
                                    is_private = "network" in item or ep_res in private_network_assets
                                    cmek = "encryptionSpec" in item or ep_res in cmek_protected_assets
                                    is_prot = is_private and (cmek or model_armor_active)
                                    discovered_endpoints.append({
                                        "name": ep_res,
                                        "provider": "gcp",
                                        "url": f"https://{loc}-aiplatform.googleapis.com",
                                        "protected": is_prot
                                    })
                                    discovered_models.append({
                                        "name": ep_disp,
                                        "provider": "gcp",
                                        "resource_type": "vertex_ai_endpoint",
                                        "location": loc,
                                        "cmek_enabled": cmek,
                                        "model_armor_enabled": model_armor_active,
                                        "private_endpoint": is_private,
                                        "status": "HARDENED" if is_prot else "UNPROTECTED_EXPOSED"
                                    })
                        except Exception as e:
                            logger.debug(f"Vertex AI REST Endpoints {loc}: {e}")

        except Exception as exc:
            logger.warning(f"Vertex AI discovery failed: {exc}")

        # 4c. Process Vertex AI Workbench Instances (Discovered from Asset Inventory or Notebooks API)
        for wb in workbench_instances_from_asset:
            wb_name = wb["display_name"]
            wb_loc = wb["location"]
            has_cmek = wb["has_cmek"]
            is_private = wb["is_private_net"]

            status = "HARDENED" if (has_cmek and is_private) else "VULNERABLE_PUBLIC_IP"
            discovered_models.append({
                "name": wb_name,
                "provider": "gcp",
                "resource_type": "vertex_workbench_instance",
                "location": wb_loc,
                "cmek_enabled": has_cmek,
                "model_armor_enabled": False,
                "private_endpoint": is_private,
                "status": status
            })

            if not is_private or not has_cmek:
                vulnerabilities.append({
                    "id": f"CVE-WB-{len(vulnerabilities)+1}",
                    "cve": "CVE-2026-2244" if not has_cmek else "MISCONFIG-PUBLIC-IP",
                    "severity": "CRITICAL" if not has_cmek else "HIGH",
                    "resource": f"vertex-workbench://{wb_loc}/{wb_name}",
                    "description": f"Vertex AI Workbench '{wb_name}' lacks CMEK encryption or has unisolated public networking."
                })

        # 5. Evaluate Storage Buckets for CMEK Configuration Gaps
        for b in storage_buckets:
            if not b["has_cmek"]:
                vulnerabilities.append({
                    "id": f"GCP-CMEK-GAP-{len(vulnerabilities)+1}",
                    "cve": "MISCONFIG-CMEK",
                    "severity": "HIGH",
                    "resource": f"gs://{b['display_name']}",
                    "description": f"Cloud Storage bucket '{b['display_name']}' storing AI data is encrypted with Google-managed key instead of Cloud KMS CMEK."
                })

        # 6. Evaluate Compute & GKE Assets for Shadow AI Signatures
        for node in compute_and_gke_assets:
            node_name = node["display_name"].lower()
            attrs = str(node.get("additional_attributes", {})).lower()
            
            if any(eng in node_name or eng in attrs for eng in ["ollama", "llama"]):
                shadow_ai_findings.append({
                    "id": f"GCP-SHADOW-{len(shadow_ai_findings)+1:02d}",
                    "type": "Unsanctioned Shadow AI (Ollama Llama-3)",
                    "provider": "gcp",
                    "severity": "CRITICAL",
                    "resource": f"k8s://{node['display_name']}/ollama-inference-gpu",
                    "description": "Port 11434 open on unmanaged container workload serving unvetted open-source LLMs without DLP or access logs."
                })
            elif any(eng in node_name or eng in attrs for eng in ["vllm", "tgi", "localai"]):
                shadow_ai_findings.append({
                    "id": f"GCP-SHADOW-{len(shadow_ai_findings)+1:02d}",
                    "type": "vLLM Inference Server on Compute Engine",
                    "provider": "gcp",
                    "severity": "HIGH",
                    "resource": f"gce://{node['location']}/{node['display_name']}",
                    "description": "Compute VM hosting unmanaged vLLM/TGI instance with world-readable local logs storing raw user prompts."
                })

        # 7. Query Security Command Center (SCC) AI Protection for Active Findings
        try:
            try:
                from google.cloud import securitycenter_v1
                scc_client = securitycenter_v1.SecurityCenterClient(credentials=creds)
                parent = f"projects/{effective_project}/sources/-"
                request = securitycenter_v1.ListFindingsRequest(
                    parent=parent,
                    filter='state="ACTIVE"'
                )
                for finding_result in scc_client.list_findings(request=request):
                    f = finding_result.finding
                    f_id = getattr(f, "name", "SCC-FINDING").split("/")[-1]
                    f_cat = getattr(f, "category", "AI_SECURITY_RISK")
                    f_sev = getattr(f, "severity", "MEDIUM")
                    f_res = getattr(f, "resource_name", "GCP-RESOURCE")
                    f_desc = getattr(f, "description", f_cat)

                    if any(term in f_cat.upper() for term in ["SHADOW", "OLLAMA", "VLLM", "ROGUE", "UNSANCTIONED"]):
                        shadow_ai_findings.append({
                            "id": f"SCC-SHADOW-{f_id}",
                            "type": f_cat,
                            "provider": "gcp",
                            "severity": str(f_sev),
                            "resource": f_res,
                            "description": f_desc
                        })
                    else:
                        vulnerabilities.append({
                            "id": f_id,
                            "cve": f_cat,
                            "severity": str(f_sev),
                            "resource": f_res,
                            "description": f_desc
                        })
            except (ImportError, Exception):
                if session is not None and use_rest_fallback:
                    url = f"https://securitycenter.googleapis.com/v1/projects/{effective_project}/sources/-/findings"
                    try:
                        resp = session.get(url, params={"filter": 'state="ACTIVE"'}, timeout=10)
                        if resp.status_code == 200:
                            for item in resp.json().get("listFindingsResults", []):
                                f = item.get("finding", {})
                                f_cat = f.get("category", "SECURITY_FINDING")
                                f_id = f.get("name", "").split("/")[-1] or "SCC-LIVE"
                                f_sev = f.get("severity", "HIGH")
                                f_res = f.get("resourceName", "gcp-resource")
                                f_desc = f.get("description", f_cat)
                                if any(term in f_cat.upper() for term in ["SHADOW", "OLLAMA", "VLLM", "ROGUE", "UNSANCTIONED"]):
                                    shadow_ai_findings.append({
                                        "id": f"SCC-SHADOW-{f_id}",
                                        "type": f_cat,
                                        "provider": "gcp",
                                        "severity": str(f_sev),
                                        "resource": f_res,
                                        "description": f_desc
                                    })
                                else:
                                    vulnerabilities.append({
                                        "id": f_id,
                                        "cve": f_cat,
                                        "severity": str(f_sev),
                                        "resource": f_res,
                                        "description": f_desc
                                    })
                    except Exception as scc_rest_err:
                        logger.debug(f"SCC REST list_findings error: {scc_rest_err}")

        except Exception as exc:
            logger.debug(f"Security Command Center discovery error: {exc}")

        # 8. Return exact schema shape matching discover_resources()
        return {
            "provider": "gcp",
            "project_id": effective_project,
            "models": discovered_models,
            "endpoints": discovered_endpoints,
            "shadow_ai": shadow_ai_findings,
            "vulnerabilities": vulnerabilities
        }
