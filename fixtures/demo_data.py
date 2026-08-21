# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR - AI Security Posture Review (AI-SPM) Platform
Demo & Simulation Fixtures (Fictional Reference Dataset)

===============================================================================
DISCLAIMER: FICTIONAL DEMONSTRATION DATA
===============================================================================
The entities, organization names, cloud project identifiers, account IDs,
service accounts, bucket names, and synthetic personas contained in this module
are strictly fictional mock data designed for offline demonstrations, UI testing,
simulated dry-run evaluations, and pre-flight architectural reviews.

They do NOT represent live production systems, real client infrastructure, or
actual Google Cloud / AWS / Azure credentials.
===============================================================================
"""

from typing import Dict, List, Any

# -----------------------------------------------------------------------------
# Fictional Client & Tenant Identity Constants
# -----------------------------------------------------------------------------
DEMO_CLIENT_NAME = "ApexFin Lab / Global Next Bank S.A."
DEMO_CLIENT_SHORT_NAME = "ApexFin"
DEMO_CLIENT_LEGAL_NAME = "Global Next Bank S.A."
DEMO_CLIENT_ORG = "ApexFin Global"
DEMO_CLIENT_FOLDER = "Finance AI"
DEMO_ORG_ID = "109283746501"

# -----------------------------------------------------------------------------
# Fictional Cloud Scope Identifiers
# -----------------------------------------------------------------------------
DEMO_PROJECT_ID = "fnlab-ai-data"
DEMO_GCP_PROJECT_ID = "fnlab-ai-data"
DEMO_GCP_APPS_PROJECT_ID = "fnlab-apps-98bf21"
DEMO_GCP_PROD_PROJECT_ID = "prod-fintech-ai-core"
DEMO_GCP_ENTERPRISE_PROJECT_ID = "enterprise-ai-prod"
DEMO_GCP_ENTERPRISE_AI_PROJECT_ID = "aispr-enterprise-ai"
DEMO_GCP_DEFAULT_PROJECT_ID = "enterprise-gcp-ai-prod"

DEMO_AWS_ACCOUNT_ID = "849201938491"
DEMO_AWS_ROLE_ARN = "arn:aws:iam::849201938491:role/AISPR-ReadOnly-Role"

DEMO_AZURE_SUBSCRIPTION_ID = "sub-000-111-222"
DEMO_AZURE_PROJECT = "azure-sub-001"

# -----------------------------------------------------------------------------
# Fictional Service Accounts & Principals
# -----------------------------------------------------------------------------
DEMO_SERVICE_ACCOUNT = "sa-ai-pipeline-dev"
DEMO_ANALYTICS_SA = "sa-analytics-ro"
DEMO_PAYMENT_SA = "sa-payment-app"
DEMO_ADMIN_EMAIL = "security-lead@apexfin.com"
DEMO_BEARER_USER_EMAIL = "bearer-authenticated-user@enterprise.com"

# -----------------------------------------------------------------------------
# Fictional Storage, Network & Encryption Resources
# -----------------------------------------------------------------------------
DEMO_STORAGE_BUCKET = "bkt-fnlab-fin-records-raw"
DEMO_BACKUP_BUCKET = "bkt-fnlab-app-backups"
DEMO_RAG_BUCKET = "banco-credit-rag"
DEMO_KMS_KEYRING = "banco-ai-keyring"
DEMO_VPC_NAME = "banco-ai-vpc"
DEMO_SUBNET_NAME = "banco-ai-subnet"

DEMO_SCOPE_DESCRIPTION = "Google Cloud (fnlab-ai-data, fnlab-apps), AWS Bedrock, Azure OpenAI"

# -----------------------------------------------------------------------------
# Fictional Findings Mapping (for UI & Demonstrations)
# -----------------------------------------------------------------------------
DEMO_FINDINGS_MAP: Dict[str, str] = {
    "INF-01": f"Scan Finding: Service Account '{DEMO_SERVICE_ACCOUNT}' holds 'roles/editor' role in project {DEMO_GCP_PROJECT_ID} (Least Privilege Violation).",
    "DAT-01": f"Scan Finding: Bucket '{DEMO_STORAGE_BUCKET}' does not use Customer-Managed Encryption Keys (Cloud KMS CMEK).",
    "DAT-05": "Scan Finding: SQL dump 'legacy_db_dump.sql' contains cleartext SSNs/CPFs and transactions without Cloud DLP masking.",
    "APP-01": "Scan Finding: Endpoint '/api/v1/customers/{id}' allows unauthorized customer record enumeration (BOLA/IDOR).",
    "APP-04": "Scan Finding: Endpoint '/api/v1/ai/chat' is vulnerable to direct Prompt Injection without active filtering layer.",
    "INF-04": "Scan Finding: Subnet 'sb-apps-uscentral1' has VPC Flow Logs disabled (Telemetry & visibility gap)."
}

# -----------------------------------------------------------------------------
# Fictional Discovered AI Assets (AI-BOM for UI & Demonstrations)
# -----------------------------------------------------------------------------
DEMO_DISCOVERED_AI_ASSETS: List[Dict[str, Any]] = [
    {
        "id": "asset-01",
        "name": "vertex-gemini-1.5-pro",
        "category": "Foundation Model",
        "provider": "Google Cloud",
        "product": "Gemini 1.5 Pro",
        "org": DEMO_CLIENT_ORG,
        "folder": DEMO_CLIENT_FOLDER,
        "project": DEMO_GCP_ENTERPRISE_AI_PROJECT_ID,
        "app": "Financial Chatbot (/api/v1/ai/chat)",
        "location": "us-central1",
        "version": "1.5-pro-002",
        "risk_tier": "HIGH",
        "status": "Warning: Guardrails Inactive",
        "encryption": "Google-Managed (CMEK Missing)",
        "data_classification": "Restricted (Financial Records)",
        "iam_principals": [f"{DEMO_SERVICE_ACCOUNT} (roles/editor)"],
        "guardrail_status": "Inactive (Vulnerable to Prompt Injection)",
        "score": 52.5,
        "domain": "MOD",
        "findings": [
            {"id": "APP-04", "title": "Inference endpoint vulnerable to Jailbreaking and Direct Prompt Injection without Model Armor", "severity": "HIGH"},
            {"id": "INF-01", "title": f"Service account attached with excessive roles/editor privilege in project", "severity": "CRITICAL"}
        ],
        "action": "Enable Model Armor Guardrail policy and restrict IAM binding to roles/aiplatform.user."
    },
    {
        "id": "asset-02",
        "name": DEMO_STORAGE_BUCKET,
        "category": "RAG Knowledge Base",
        "provider": "Google Cloud",
        "product": "Cloud Storage RAG",
        "org": DEMO_CLIENT_ORG,
        "folder": DEMO_CLIENT_FOLDER,
        "project": DEMO_GCP_ENTERPRISE_AI_PROJECT_ID,
        "app": "Analytical RAG Pipeline",
        "location": "us-central1",
        "version": "Dataset v3.2",
        "risk_tier": "HIGH",
        "status": "CMEK Missing / Google Key",
        "encryption": "Google-Managed (No Customer Key)",
        "data_classification": "Confidential / PII (Statements & Accounts)",
        "iam_principals": [DEMO_SERVICE_ACCOUNT, DEMO_ANALYTICS_SA],
        "guardrail_status": "N/A (Storage)",
        "score": 45.0,
        "domain": "DAT",
        "findings": [
            {"id": "DAT-01", "title": "RAG bucket lacking Customer-Managed Encryption Keys (Cloud KMS CMEK)", "severity": "HIGH"},
            {"id": "DAT-05", "title": "Cleartext PII and synthetic transactions detected without inline Cloud DLP masking", "severity": "HIGH"}
        ],
        "action": "Configure Cloud KMS CMEK and enable Cloud DLP automated inspection."
    },
    {
        "id": "asset-03",
        "name": "vm-payment-api (/api/v1/ai/chat)",
        "category": "AI Microservice",
        "provider": "Google Cloud",
        "product": "FastAPI Service",
        "org": DEMO_CLIENT_ORG,
        "folder": "Core Applications",
        "project": DEMO_GCP_APPS_PROJECT_ID,
        "app": "Payment API & AI Chat",
        "location": "10.20.10.3:8080 (VPC Apps)",
        "version": "FastAPI v2.4",
        "risk_tier": "HIGH",
        "status": "BOLA & Injection Active",
        "encryption": "TLS 1.3 in transit",
        "data_classification": "Transactional / Customer Records",
        "iam_principals": [DEMO_PAYMENT_SA],
        "guardrail_status": "Inactive",
        "score": 40.0,
        "domain": "APP",
        "findings": [
            {"id": "APP-01", "title": "Broken Object Level Authorization (BOLA/IDOR) on /api/v1/customers/{id}", "severity": "HIGH"},
            {"id": "APP-04", "title": "Direct Prompt Injection on /api/v1/ai/chat endpoint", "severity": "HIGH"}
        ],
        "action": "Implement strict JWT token validation and Model Armor input filtering."
    },
    {
        "id": "asset-04",
        "name": "claude-3-5-sonnet",
        "category": "Foundation Model",
        "provider": "AWS Bedrock",
        "product": "Claude 3.5 Sonnet",
        "org": DEMO_CLIENT_ORG,
        "folder": "Secondary AI",
        "project": f"acc-{DEMO_AWS_ACCOUNT_ID}",
        "app": "Enterprise Support",
        "location": "us-east-1 (Bedrock)",
        "version": "v1:0 (Bedrock)",
        "risk_tier": "LOW",
        "status": "Compliant / IAM Audited",
        "encryption": "AWS KMS (Customer Key)",
        "data_classification": "Internal",
        "iam_principals": ["AISPR-ReadOnly-Role"],
        "guardrail_status": "Bedrock Guardrails Active",
        "score": 92.0,
        "domain": "MOD",
        "findings": [],
        "action": "Monitor request quotas and CloudWatch telemetry."
    },
    {
        "id": "asset-05",
        "name": "gpt-4o-enterprise",
        "category": "Foundation Model",
        "provider": "Azure OpenAI",
        "product": "GPT-4o Enterprise",
        "org": DEMO_CLIENT_ORG,
        "folder": "Secondary AI",
        "project": DEMO_AZURE_PROJECT,
        "app": "Contract Analysis",
        "location": "eastus (Azure)",
        "version": "2024-05-13",
        "risk_tier": "LOW",
        "status": "Compliant / Private VNet",
        "encryption": "Azure Key Vault (CMEK)",
        "data_classification": "Confidential",
        "iam_principals": ["AISPR-Auditor-SPN"],
        "guardrail_status": "Azure Content Safety Active",
        "score": 95.0,
        "domain": "MOD",
        "findings": [],
        "action": "Audit telemetry logs monthly in Log Analytics."
    },
    {
        "id": "asset-06",
        "name": "sb-apps-uscentral1",
        "category": "Infrastructure / VPC",
        "provider": "Google Cloud",
        "product": "VPC Subnetwork",
        "org": DEMO_CLIENT_ORG,
        "folder": "Core Applications",
        "project": DEMO_GCP_APPS_PROJECT_ID,
        "app": "Application Network",
        "location": "us-central1 (10.20.10.0/24)",
        "version": "VPC v1",
        "risk_tier": "MED",
        "status": "VPC Flow Logs Disabled",
        "encryption": "N/A",
        "data_classification": "Internal Traffic",
        "iam_principals": ["Network Admin"],
        "guardrail_status": "N/A",
        "score": 60.0,
        "domain": "INF",
        "findings": [
            {"id": "INF-04", "title": "Subnet without VPC Flow Logs enabled for AI connection audit", "severity": "MED"}
        ],
        "action": "Enable VPC Flow Logs with 100% sampling rate in Google Cloud."
    },
    {
        "id": "asset-07",
        "name": "google-cloud-aiplatform",
        "category": "MLOps Library",
        "provider": "Google Cloud",
        "product": "Vertex AI SDK",
        "org": DEMO_CLIENT_ORG,
        "folder": DEMO_CLIENT_FOLDER,
        "project": DEMO_GCP_ENTERPRISE_AI_PROJECT_ID,
        "app": "Training & Inference Pipeline",
        "location": "Python 3.11 / SDK",
        "version": "1.74.0",
        "risk_tier": "LOW",
        "status": "Compliant / SLSA Level 3",
        "encryption": "N/A",
        "data_classification": "Code / Dependency",
        "iam_principals": ["DevOps Pipeline"],
        "guardrail_status": "N/A",
        "score": 90.0,
        "domain": "OPS",
        "findings": [],
        "action": "Maintain dependency up-to-date."
    }
]

# -----------------------------------------------------------------------------
# Fictional Topology Nodes & Edges (for Visual AI-BOM & Graph Explorer)
# -----------------------------------------------------------------------------
DEMO_TOPOLOGY_NODES: List[Dict[str, Any]] = [
    {
        "id": "node-gemini",
        "label": "Gemini 1.5 Pro (Core Agent)",
        "cloud": "GCP",
        "category": "Core Model",
        "environment": f"Vertex AI ({DEMO_GCP_PROD_PROJECT_ID})",
        "guardrail": "Missing Model Armor Filter",
        "encryption": "Cloud KMS CMEK",
        "risk_level": "MEDIUM",
        "status": "PARTIALLY_HARDENED"
    },
    {
        "id": "node-vertex-endpoint",
        "label": "Vertex Endpoint: Credit Scoring v2",
        "cloud": "GCP",
        "category": "Inference Endpoint",
        "environment": "Vertex AI Endpoint",
        "guardrail": "None (Direct HTTP)",
        "encryption": "Google Default Key",
        "risk_level": "HIGH",
        "status": "EXPOSED"
    },
    {
        "id": "node-rag-storage",
        "label": "RAG Vector Store (Credit Docs)",
        "cloud": "GCP",
        "category": "Vector Knowledge Base",
        "environment": f"Cloud Storage (gs://{DEMO_RAG_BUCKET})",
        "guardrail": "IAM Only",
        "encryption": "No CMEK",
        "risk_level": "HIGH",
        "status": "UNENCRYPTED_RAG"
    },
    {
        "id": "node-bedrock-claude",
        "label": "Claude 3.5 Sonnet (Fraud Fallback)",
        "cloud": "AWS",
        "category": "External Multi-Cloud AI",
        "environment": f"Amazon Bedrock (Account {DEMO_AWS_ACCOUNT_ID})",
        "guardrail": "Missing Bedrock Guardrail",
        "encryption": "AWS KMS",
        "risk_level": "MEDIUM",
        "status": "UNSHIELDED_EXTERNAL"
    },
    {
        "id": "node-azure-openai",
        "label": "Azure OpenAI GPT-4o (Chat Agent)",
        "cloud": "AZURE",
        "category": "External Multi-Cloud AI",
        "environment": f"Azure OpenAI Service ({DEMO_AZURE_SUBSCRIPTION_ID})",
        "guardrail": "Content Safety Basic",
        "encryption": "Azure Key Vault",
        "risk_level": "LOW",
        "status": "COMPLIANT"
    }
]

DEMO_TOPOLOGY_EDGES: List[Dict[str, Any]] = [
    {"source": "node-gemini", "target": "node-rag-storage", "label": "Embeddings Search", "encrypted": True},
    {"source": "node-gemini", "target": "node-vertex-endpoint", "label": "Model Invocation", "encrypted": True},
    {"source": "node-gemini", "target": "node-bedrock-claude", "label": "Cross-Cloud Fallback", "encrypted": True},
    {"source": "node-gemini", "target": "node-azure-openai", "label": "Contract Review Flow", "encrypted": True}
]
