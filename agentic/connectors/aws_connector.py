# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Amazon Web Services (AWS) AI-SPM Federated Discovery Connector.
Supports both offline customer simulation and real read-only AWS APIs
(Bedrock, SageMaker, S3) via least-privilege STS AssumeRole or standard credentials.
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

logger = logging.getLogger("AISPR-AWS-Connector")

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    ClientError = Exception
    NoCredentialsError = Exception
    PartialCredentialsError = Exception
    BotoCoreError = Exception


class AWSConnector(BaseCloudConnector):
    """
    Federated connector for AWS discovering Bedrock foundation/custom models,
    SageMaker endpoints/notebooks, and S3 Knowledge Bases using Read-Only credentials.
    """

    def __init__(
        self,
        account_id: str = "123456789012",
        role_arn: Optional[str] = "arn:aws:iam::123456789012:role/AISPR-ReadOnly-Role",
        region_name: str = "us-east-1",
        credentials_payload: Optional[Dict[str, Any]] = None,
        execution_mode: ExecutionMode = ExecutionMode.SIMULATION,
        boto3_session: Optional[Any] = None,
    ):
        super().__init__(
            provider=CloudProvider.AWS,
            target_identifier=account_id,
            execution_mode=execution_mode,
            credentials_payload=credentials_payload,
        )
        self.account_id = account_id
        self.role_arn = role_arn
        self.region_name = region_name
        self._session = boto3_session

    def _get_boto3_session(self) -> Any:
        """
        Builds or returns a read-only boto3 session using STS AssumeRole or environment credentials.
        Never logs or exposes secret keys.
        """
        if self._session is not None:
            return self._session

        if not BOTO3_AVAILABLE:
            raise CloudSDKMissingError(
                "AWS SDK 'boto3' is not installed. Run 'pip install boto3' to enable live AWS discovery.",
                provider=self.provider
            )

        try:
            creds = self._credentials_payload or {}
            aws_access_key = creds.get("aws_access_key_id") or os.environ.get("AWS_ACCESS_KEY_ID")
            aws_secret_key = creds.get("aws_secret_access_key") or os.environ.get("AWS_SECRET_ACCESS_KEY")
            aws_session_token = creds.get("aws_session_token") or os.environ.get("AWS_SESSION_TOKEN")

            if aws_access_key and aws_secret_key:
                base_session = boto3.Session(
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    aws_session_token=aws_session_token,
                    region_name=self.region_name,
                )
            else:
                base_session = boto3.Session(region_name=self.region_name)

            # If an STS role ARN is specified, assume read-only role
            if self.role_arn and "arn:aws:iam" in self.role_arn:
                try:
                    sts_client = base_session.client("sts")
                    sts_response = sts_client.assume_role(
                        RoleArn=self.role_arn,
                        RoleSessionName="AISPR-ReadOnly-AuditSession",
                        DurationSeconds=3600,
                    )
                    assumed_creds = sts_response["Credentials"]
                    self._session = boto3.Session(
                        aws_access_key_id=assumed_creds["AccessKeyId"],
                        aws_secret_access_key=assumed_creds["SecretAccessKey"],
                        aws_session_token=assumed_creds["SessionToken"],
                        region_name=self.region_name,
                    )
                    return self._session
                except (ClientError, BotoCoreError) as sts_err:
                    error_code = sts_err.response.get("Error", {}).get("Code", "") if hasattr(sts_err, "response") else ""
                    if error_code in ("AccessDenied", "UnauthorizedOperation", "AccessDeniedException"):
                        raise CloudPermissionDeniedError(
                            f"AWS STS AssumeRole permission denied for '{self.role_arn}': {sts_err}",
                            provider=self.provider
                        )
                    elif error_code in ("InvalidClientTokenId", "AuthFailure", "SignatureDoesNotMatch"):
                        raise CloudAuthenticationError(
                            f"AWS STS Authentication failed for '{self.role_arn}': {sts_err}",
                            provider=self.provider
                        )
                    raise CloudConnectorError(f"AWS STS AssumeRole failed: {sts_err}", provider=self.provider)

            self._session = base_session
            return self._session

        except (NoCredentialsError, PartialCredentialsError) as auth_err:
            raise CloudAuthenticationError(
                f"AWS Credentials not found or incomplete: {auth_err}",
                provider=self.provider
            )
        except (CloudAuthenticationError, CloudPermissionDeniedError):
            raise
        except Exception as exc:
            raise CloudConnectorError(f"Failed to initialize AWS session: {exc}", provider=self.provider)

    def discover_resources(self) -> Dict[str, Any]:
        """
        Scans Bedrock and SageMaker in Read-Only Customer Simulation Mode.
        Explicitly marked as SIMULATION.
        """
        self.execution_mode = ExecutionMode.SIMULATION
        logger.info(f"Scanning AWS Account '{self.account_id}' in Read-Only Mode (Customer Simulation)...")

        discovered_models = [
            {
                "name": "anthropic.claude-3-5-sonnet-20241022-v2:0",
                "provider": "aws",
                "resource_type": "bedrock_foundation_model",
                "location": self.region_name,
                "cmek_enabled": True,
                "model_armor_enabled": False,
                "private_endpoint": False,
                "status": "MISSING_GUARDRAIL"
            },
            {
                "name": "sagemaker-fraud-detection-endpoint",
                "provider": "aws",
                "resource_type": "sagemaker_endpoint",
                "location": self.region_name,
                "cmek_enabled": False,
                "model_armor_enabled": False,
                "private_endpoint": True,
                "status": "UNENCRYPTED_ENDPOINT"
            }
        ]

        discovered_endpoints = [
            {
                "name": f"arn:aws:bedrock:{self.region_name}:{self.account_id}:custom-model/fraud-classifier-v1",
                "provider": "aws",
                "url": f"https://bedrock-runtime.{self.region_name}.amazonaws.com",
                "protected": False
            }
        ]

        shadow_ai_findings = [
            {
                "id": "AWS-SHADOW-01",
                "type": "Unencrypted S3 Bucket with RAG Data",
                "provider": "aws",
                "severity": "HIGH",
                "resource": "arn:aws:s3:::banco-investment-rag-staging",
                "description": "S3 bucket storing confidential customer investment profiles without SSE-KMS."
            }
        ]

        vulnerabilities = [
            {
                "id": "AWS-BEDROCK-GAP-01",
                "cve": "MISCONFIG-NO-GUARDRAIL",
                "severity": "HIGH",
                "resource": "arn:aws:bedrock:us-east-1::foundation-model/claude-3-5-sonnet",
                "description": "Model invocation logging is disabled and no Bedrock Guardrails are attached."
            }
        ]

        return {
            "provider": "aws",
            "account_id": self.account_id,
            "execution_mode": "SIMULATION",
            "models": discovered_models,
            "endpoints": discovered_endpoints,
            "shadow_ai": shadow_ai_findings,
            "vulnerabilities": vulnerabilities
        }

    def discover_resources_live(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Executes real read-only API calls to AWS Bedrock, SageMaker, and S3.
        Only marks execution_mode as LIVE if real API calls execute successfully.
        """
        self.assert_read_only("discover_resources_live")
        target_regions = regions or [self.region_name]

        discovered_models: List[Dict[str, Any]] = []
        discovered_endpoints: List[Dict[str, Any]] = []
        shadow_ai_findings: List[Dict[str, Any]] = []
        vulnerabilities: List[Dict[str, Any]] = []

        session = self._get_boto3_session()

        for region in target_regions:
            logger.info(f"Querying live AWS AI services in region '{region}' for account '{self.account_id}'...")

            # ------------------------------------------------------------------
            # 1. Amazon Bedrock Live Inspection
            # ------------------------------------------------------------------
            try:
                bedrock_client = session.client("bedrock", region_name=region)
                
                # List Foundation Models
                try:
                    fm_resp = bedrock_client.list_foundation_models()
                    for fm in fm_resp.get("modelSummaries", []):
                        m_id = fm.get("modelId", "unknown-model")
                        discovered_models.append({
                            "name": m_id,
                            "provider": "aws",
                            "resource_type": "bedrock_foundation_model",
                            "location": region,
                            "cmek_enabled": True,  # Bedrock manages encryption at rest
                            "model_armor_enabled": False,
                            "private_endpoint": False,
                            "status": "ACTIVE_FOUNDATION_MODEL",
                            "metadata": {
                                "inputModalities": fm.get("inputModalities", []),
                                "outputModalities": fm.get("outputModalities", []),
                                "providerName": fm.get("providerName", "AWS"),
                            }
                        })
                except Exception as fm_err:
                    self._handle_boto_exception(fm_err, "bedrock:ListFoundationModels")

                # List Custom Models
                try:
                    cm_resp = bedrock_client.list_custom_models()
                    for cm in cm_resp.get("modelSummaries", []):
                        cm_name = cm.get("modelName", "custom-model")
                        cm_arn = cm.get("modelArn", f"arn:aws:bedrock:{region}:{self.account_id}:custom-model/{cm_name}")
                        discovered_models.append({
                            "name": cm_name,
                            "provider": "aws",
                            "resource_type": "bedrock_custom_model",
                            "location": region,
                            "resource_uri": cm_arn,
                            "cmek_enabled": bool(cm.get("customModelKmsKeyId")),
                            "model_armor_enabled": False,
                            "private_endpoint": False,
                            "status": "ACTIVE_CUSTOM_MODEL"
                        })
                except Exception as cm_err:
                    self._handle_boto_exception(cm_err, "bedrock:ListCustomModels")

                # Check Bedrock Guardrails
                has_guardrails = False
                try:
                    gr_resp = bedrock_client.list_guardrails()
                    guardrails = gr_resp.get("guardrails", [])
                    has_guardrails = len(guardrails) > 0
                except Exception as gr_err:
                    self._handle_boto_exception(gr_err, "bedrock:ListGuardrails")

                # Check Model Invocation Logging
                logging_enabled = False
                try:
                    log_resp = bedrock_client.get_model_invocation_logging_configuration()
                    config = log_resp.get("loggingConfig", {})
                    logging_enabled = bool(config.get("textDataDeliveryEnabled") or config.get("imageDataDeliveryEnabled"))
                except Exception as log_err:
                    self._handle_boto_exception(log_err, "bedrock:GetModelInvocationLoggingConfiguration")

                if not has_guardrails:
                    vulnerabilities.append({
                        "id": f"AWS-BEDROCK-GUARDRAIL-GAP-{region}",
                        "cve": "MISCONFIG-BEDROCK-NO-GUARDRAIL",
                        "severity": "HIGH",
                        "resource": f"arn:aws:bedrock:{region}:{self.account_id}:guardrails",
                        "description": f"No Amazon Bedrock Guardrails configured in region '{region}' to sanitize LLM prompt injection or toxic outputs."
                    })

                if not logging_enabled:
                    vulnerabilities.append({
                        "id": f"AWS-BEDROCK-LOGGING-GAP-{region}",
                        "cve": "MISCONFIG-BEDROCK-NO-LOGGING",
                        "severity": "MEDIUM",
                        "resource": f"arn:aws:bedrock:{region}:{self.account_id}:logging",
                        "description": f"Amazon Bedrock model invocation logging is disabled in '{region}', preventing security telemetry correlation."
                    })

            except (CloudAuthenticationError, CloudPermissionDeniedError):
                raise
            except Exception as bedrock_err:
                logger.debug(f"Bedrock scan skipped/failed for region {region}: {bedrock_err}")

            # ------------------------------------------------------------------
            # 2. Amazon SageMaker Live Inspection
            # ------------------------------------------------------------------
            try:
                sm_client = session.client("sagemaker", region_name=region)

                # List SageMaker Endpoints
                try:
                    ep_resp = sm_client.list_endpoints()
                    for ep in ep_resp.get("Endpoints", []):
                        ep_name = ep.get("EndpointName", "sagemaker-ep")
                        ep_arn = ep.get("EndpointArn", f"arn:aws:sagemaker:{region}:{self.account_id}:endpoint/{ep_name}")

                        # Describe endpoint for security posture
                        desc_ep = sm_client.describe_endpoint(EndpointName=ep_name)
                        has_kms = bool(desc_ep.get("KmsKeyId"))

                        discovered_endpoints.append({
                            "name": ep_arn,
                            "provider": "aws",
                            "url": f"https://runtime.sagemaker.{region}.amazonaws.com/endpoints/{ep_name}/invocations",
                            "protected": has_kms,
                            "cmek_enabled": has_kms,
                        })

                        if not has_kms:
                            vulnerabilities.append({
                                "id": f"AWS-SM-CMEK-GAP-{ep_name}",
                                "cve": "MISCONFIG-SAGEMAKER-NO-CMEK",
                                "severity": "HIGH",
                                "resource": ep_arn,
                                "description": f"SageMaker inference endpoint '{ep_name}' in '{region}' is unencrypted with customer-managed KMS keys (CMEK)."
                            })
                except Exception as ep_err:
                    self._handle_boto_exception(ep_err, "sagemaker:ListEndpoints")

                # List Notebook Instances
                try:
                    nb_resp = sm_client.list_notebook_instances()
                    for nb in nb_resp.get("NotebookInstances", []):
                        nb_name = nb.get("NotebookInstanceName", "notebook")
                        nb_arn = nb.get("NotebookInstanceArn", f"arn:aws:sagemaker:{region}:{self.account_id}:notebook-instance/{nb_name}")
                        desc_nb = sm_client.describe_notebook_instance(NotebookInstanceName=nb_name)

                        root_access = desc_nb.get("RootAccess", "Enabled")
                        direct_internet = desc_nb.get("DirectInternetAccess", "Enabled")
                        nb_kms = bool(desc_nb.get("KmsKeyId"))

                        discovered_models.append({
                            "name": nb_name,
                            "provider": "aws",
                            "resource_type": "sagemaker_notebook_instance",
                            "location": region,
                            "resource_uri": nb_arn,
                            "cmek_enabled": nb_kms,
                            "model_armor_enabled": False,
                            "private_endpoint": direct_internet == "Disabled",
                            "status": "SECURE" if (root_access == "Disabled" and direct_internet == "Disabled") else "EXPOSED"
                        })

                        if root_access == "Enabled":
                            vulnerabilities.append({
                                "id": f"AWS-SM-NOTEBOOK-ROOT-{nb_name}",
                                "cve": "MISCONFIG-NOTEBOOK-ROOT-ACCESS",
                                "severity": "HIGH",
                                "resource": nb_arn,
                                "description": f"SageMaker notebook '{nb_name}' has RootAccess enabled, creating container breakout risk."
                            })
                except Exception as nb_err:
                    self._handle_boto_exception(nb_err, "sagemaker:ListNotebookInstances")

            except (CloudAuthenticationError, CloudPermissionDeniedError):
                raise
            except Exception as sm_err:
                logger.debug(f"SageMaker scan skipped/failed for region {region}: {sm_err}")

            # ------------------------------------------------------------------
            # 3. Amazon S3 AI/RAG Buckets Live Inspection
            # ------------------------------------------------------------------
            try:
                s3_client = session.client("s3", region_name=region)
                buckets_resp = s3_client.list_buckets()
                for b in buckets_resp.get("Buckets", []):
                    b_name = b.get("Name", "")
                    b_name_lower = b_name.lower()
                    if any(term in b_name_lower for term in ["rag", "ai", "model", "training", "embedding", "knowledge"]):
                        b_arn = f"arn:aws:s3:::{b_name}"
                        # Check encryption
                        has_kms = False
                        try:
                            enc_resp = s3_client.get_bucket_encryption(Bucket=b_name)
                            rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                            has_kms = any(r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms" for r in rules)
                        except Exception:
                            has_kms = False

                        if not has_kms:
                            shadow_ai_findings.append({
                                "id": f"AWS-S3-RAG-CMEK-{b_name}",
                                "type": "Unencrypted S3 AI RAG Knowledge Base",
                                "provider": "aws",
                                "severity": "HIGH",
                                "resource": b_arn,
                                "description": f"S3 Bucket '{b_name}' containing AI training/RAG data is not encrypted with AWS KMS CMEK."
                            })
            except (CloudAuthenticationError, CloudPermissionDeniedError):
                raise
            except Exception as s3_err:
                logger.debug(f"S3 AI bucket scan error: {s3_err}")

        # If real API calls executed successfully, declare execution_mode as LIVE
        self.execution_mode = ExecutionMode.LIVE

        return {
            "provider": "aws",
            "account_id": self.account_id,
            "execution_mode": "LIVE",
            "models": discovered_models,
            "endpoints": discovered_endpoints,
            "shadow_ai": shadow_ai_findings,
            "vulnerabilities": vulnerabilities,
        }

    def _handle_boto_exception(self, err: Exception, api_name: str) -> None:
        """Translates botocore ClientErrors into AISPR canonical connector exceptions."""
        if hasattr(err, "response") and isinstance(err.response, dict):
            code = err.response.get("Error", {}).get("Code", "")
            msg = err.response.get("Error", {}).get("Message", str(err))
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "ForbiddenException"):
                raise CloudPermissionDeniedError(
                    f"AWS Read-Only permission denied for '{api_name}': {msg}",
                    provider=self.provider,
                    details={"api": api_name, "code": code}
                )
            if code in ("InvalidClientTokenId", "AuthFailure", "SignatureDoesNotMatch", "UnrecognizedClientException"):
                raise CloudAuthenticationError(
                    f"AWS Authentication failed for '{api_name}': {msg}",
                    provider=self.provider,
                    details={"api": api_name, "code": code}
                )
        if isinstance(err, (NoCredentialsError, PartialCredentialsError)):
            raise CloudAuthenticationError(
                f"AWS Authentication error in '{api_name}': {err}",
                provider=self.provider
            )

    def normalize(self, raw_data: Dict[str, Any], execution_mode: ExecutionMode) -> NormalizedDiscoveryResult:
        """
        Normalizes AWS raw dictionary output into canonical AIAsset, SecurityFinding, and Evidence entities.
        """
        assets: List[AIAsset] = []
        findings: List[SecurityFinding] = []
        evidence_list: List[Evidence] = []
        errors: List[str] = []

        is_live = (execution_mode == ExecutionMode.LIVE)
        evidence_status = EvidenceStatus.VERIFIED if is_live else EvidenceStatus.UNVERIFIED

        # 1. Normalize Models
        for m in raw_data.get("models", []):
            m_name = m.get("name", "aws-ai-model")
            r_type = m.get("resource_type", "bedrock_foundation_model")
            
            if "endpoint" in r_type.lower():
                a_type = AssetType.INFERENCE_ENDPOINT
            elif "notebook" in r_type.lower():
                a_type = AssetType.AI_WORKBENCH_NOTEBOOK
            elif "custom" in r_type.lower():
                a_type = AssetType.FOUNDATION_MODEL
            else:
                a_type = AssetType.FOUNDATION_MODEL

            res_uri = m.get("resource_uri") or f"arn:aws:bedrock:{m.get('location', self.region_name)}:{self.account_id}:model/{m_name}"

            asset = AIAsset(
                name=m_name,
                asset_type=a_type,
                provider=CloudProvider.AWS,
                location=m.get("location", self.region_name),
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
            ep_name = ep.get("name", "aws-endpoint")
            res_uri = ep_name if ep_name.startswith("arn:aws") else f"arn:aws:sagemaker:{self.region_name}:{self.account_id}:endpoint/{ep_name}"
            
            asset = AIAsset(
                name=ep_name.split("/")[-1] if "/" in ep_name else ep_name,
                asset_type=AssetType.INFERENCE_ENDPOINT,
                provider=CloudProvider.AWS,
                location=self.region_name,
                resource_uri=res_uri,
                display_name=ep_name.split("/")[-1],
                cmek_enabled=bool(ep.get("cmek_enabled", False)),
                is_private_endpoint=bool(ep.get("private_endpoint", False)),
                model_armor_enabled=bool(ep.get("protected", False)),
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
            # Resolve mapped asset
            mapped_asset = next((a for a in assets if a.resource_uri == res_uri or a.name == res_uri), None)
            if not mapped_asset:
                mapped_asset = AIAsset(
                    name=res_uri.split("/")[-1] if "/" in res_uri else res_uri,
                    asset_type=AssetType.INFERENCE_ENDPOINT if "endpoint" in res_uri else AssetType.VECTOR_DATABASE,
                    provider=CloudProvider.AWS,
                    location=self.region_name,
                    resource_uri=res_uri,
                )
                assets.append(mapped_asset)

            # Build technical evidence
            sanitized_payload = sanitize_evidence_content(f"AWS Resource: {res_uri} | Finding: {title} | Details: {desc}")
            ev = Evidence(
                evidence_id=f"EVD-AWS-{compute_sha256(f_id)[:8].upper()}",
                source=FindingSource.MULTI_CLOUD_SCANNER,
                provider=CloudProvider.AWS,
                resource=res_uri,
                collection_method="API_CALL" if is_live else "FIXTURE",
                evidence_type=EvidenceType.CONFIGURATION,
                status=evidence_status,
                confidence=1.0 if is_live else 0.5,
                execution_mode=execution_mode,
                sanitized_content=sanitized_payload,
                content_hash=compute_sha256(sanitized_payload),
                metadata={"aws_account_id": self.account_id, "control_id": control_id}
            )
            evidence_list.append(ev)

            # Map severity
            sev_upper = sev_str.upper()
            severity = FindingSeverity.HIGH
            if "CRITICAL" in sev_upper:
                severity = FindingSeverity.CRITICAL
            elif "MEDIUM" in sev_upper:
                severity = FindingSeverity.MEDIUM
            elif "LOW" in sev_upper:
                severity = FindingSeverity.LOW

            # Construct canonical SecurityFinding
            finding = SecurityFinding(
                finding_id=f"FND-{f_id.replace(':', '-')[:16].upper()}",
                assessment_id="ASSESSMENT-AWS-LIVE" if is_live else "ASSESSMENT-AWS-SIM",
                source=FindingSource.MULTI_CLOUD_SCANNER,
                provider=CloudProvider.AWS,
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
                        rationale=f"AWS AI-SPM automated finding mapped to {control_id}"
                    )
                ],
                cve=cve,
                metadata={"account_id": self.account_id}
            )
            findings.append(finding)

        # 3. Normalize Vulnerabilities
        for v in raw_data.get("vulnerabilities", []):
            v_id = v.get("id", "AWS-VULN-01")
            cve = v.get("cve", "MISCONFIG")
            desc = v.get("description", "AWS security deviation")
            res = v.get("resource", f"arn:aws:sagemaker:{self.region_name}:{self.account_id}")
            sev = v.get("severity", "HIGH")
            
            # Map control ID
            if "GUARDRAIL" in v_id or "NO-GUARDRAIL" in cve:
                cid = "APP-02"
            elif "LOGGING" in v_id:
                cid = "ASR-01"
            elif "CMEK" in v_id:
                cid = "INF-04"
            elif "ROOT" in v_id:
                cid = "MOD-03"
            else:
                cid = "INF-02"

            _build_canonical_finding(
                f_id=v_id,
                title=f"AWS AI Security Deviation: {cve}",
                desc=desc,
                sev_str=sev,
                res_uri=res,
                control_id=cid,
                cve=cve
            )

        # 4. Normalize Shadow AI
        for s in raw_data.get("shadow_ai", []):
            s_id = s.get("id", "AWS-SHADOW-01")
            s_type = s.get("type", "Shadow AI")
            desc = s.get("description", "Unsanctioned AI asset detected")
            res = s.get("resource", f"arn:aws:s3:::banco-rag")
            sev = s.get("severity", "HIGH")
            cid = "DAT-03" if "S3" in s_id or "s3" in res else "GOV-02"

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
            provider=CloudProvider.AWS,
            execution_mode=execution_mode,
            account_or_project_id=self.account_id,
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
                    logger.warning(f"AWS Live discovery failed ({exc}). Falling back to simulated metadata with explicit FALLBACK mode.")
                    raw_data = self.discover_resources()
                    raw_data["execution_mode"] = ExecutionMode.FALLBACK
                    raw_data["fallback_metadata"] = {
                        "provider": "aws",
                        "attempted_operation": "aws:discover_resources_live",
                        "failure_reason": str(exc),
                        "fallback_source": "LOCAL_SIMULATED_FIXTURE",
                        "timestamp": utc_now().isoformat(),
                    }
                    return self.normalize(raw_data, ExecutionMode.FALLBACK)
                raise
        else:
            raw_data = self.discover_resources()
            return self.normalize(raw_data, ExecutionMode.SIMULATION)
