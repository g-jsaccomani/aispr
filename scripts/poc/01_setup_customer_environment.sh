#!/bin/bash
# ==============================================================================
# Phase 1: Setup Customer Project & Provision AI Resources with Controlled Misconfigurations
# Generates realistic AI-SPM findings aligned with Google SAIF, NIST AI RMF & MITRE ATLAS
# Authored by: Joabson Saccomani (@jsaccomani) | Google Cloud Security Consultant
# ==============================================================================

set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$HOME/google-cloud-sdk/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

echo "================================================================================"
echo "🏢 PHASE 1: PROVISIONING CUSTOMER ENVIRONMENT (WITH CONTROLLED MISCONFIGURATIONS)"
echo "   Aligned with: Google SAIF • NIST AI RMF • ISO/IEC 42001 • MITRE ATLAS"
echo "================================================================================"

# Discover or prompt project
if [ -z "$PROJECT_ID" ]; then
    PROJECT_ID=$(gcloud config get-value project 2>/dev/null || true)
fi

if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" == "(unset)" ]; then
    read -p "Enter Target Customer GCP Project ID: " PROJECT_ID
    gcloud config set project "$PROJECT_ID"
fi

REGION="southamerica-east1"
echo "📍 Active Customer Project: ${PROJECT_ID}"
echo "📍 Default Region: ${REGION}"
echo ""

# ------------------------------------------------------------------------------
# 1. ENABLE CORE CLOUD APIS
# ------------------------------------------------------------------------------
echo "▶️ [1/6] Enabling Required Google Cloud APIs..."
gcloud services enable \
    aiplatform.googleapis.com \
    compute.googleapis.com \
    storage.googleapis.com \
    cloudkms.googleapis.com \
    securitycenter.googleapis.com \
    cloudasset.googleapis.com \
    dlp.googleapis.com \
    cloudresourcemanager.googleapis.com \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    iam.googleapis.com \
    --project=${PROJECT_ID} --quiet

echo "   ✅ Core APIs enabled successfully."
echo ""

# ------------------------------------------------------------------------------
# 2. VPC & NETWORKING (MISCONFIGURATION: FLOW LOGS DISABLED & OVER-PERMISSIVE INTERNAL FIREWALL)
# ------------------------------------------------------------------------------
echo "▶️ [2/6] Provisioning VPC Network & Subnet with Insecure Network Posture..."
VPC_NAME="demo-ai-vpc"
SUBNET_NAME="demo-ai-subnet"

if ! gcloud compute networks describe ${VPC_NAME} --project=${PROJECT_ID} &>/dev/null; then
    gcloud compute networks create ${VPC_NAME} --subnet-mode=custom --project=${PROJECT_ID} --quiet
    echo "   ✅ VPC '${VPC_NAME}' created."
else
    echo "   ℹ️ VPC '${VPC_NAME}' already exists."
fi

# Vulnerability 1: Subnet without Flow Logs (Visibility Gap - SAIF Sec. 3.2)
if ! gcloud compute networks subnets describe ${SUBNET_NAME} --region=${REGION} --project=${PROJECT_ID} &>/dev/null; then
    gcloud compute networks subnets create ${SUBNET_NAME} \
        --network=${VPC_NAME} \
        --range=10.100.0.0/24 \
        --region=${REGION} \
        --enable-private-ip-google-access \
        --no-enable-flow-logs \
        --project=${PROJECT_ID} --quiet
    echo "   ⚠️ [MISCONFIG] Subnet '${SUBNET_NAME}' created with Flow Logs DISABLED (Telemetry Gap)."
else
    echo "   ℹ️ Subnet '${SUBNET_NAME}' already exists."
fi

# Vulnerability 2: Internal Insecure Ports Rule (Shadow AI ports 11434, 8000, 8080, 5000 allowed inside VPC)
FW_RULE="demo-ai-allow-internal-insecure-inference"
if ! gcloud compute firewall-rules describe ${FW_RULE} --project=${PROJECT_ID} &>/dev/null; then
    gcloud compute firewall-rules create ${FW_RULE} \
        --network=${VPC_NAME} \
        --allow=tcp:11434,tcp:8000,tcp:8080,tcp:5000,tcp:8888 \
        --source-ranges=10.100.0.0/24 \
        --description="Controlled Misconfiguration: Permissive internal inference & notebook ports" \
        --project=${PROJECT_ID} --quiet
    echo "   ⚠️ [MISCONFIG] Internal Firewall Rule '${FW_RULE}' created (Unauthenticated AI inference ports 11434/8000/8080 open to VPC)."
else
    echo "   ℹ️ Firewall rule '${FW_RULE}' already exists."
fi
echo ""

# ------------------------------------------------------------------------------
# 3. RAG KNOWLEDGE BASE BUCKET (MISCONFIGURATION: NO CMEK, NO VERSIONING, NO UNIFORM ACCESS)
# ------------------------------------------------------------------------------
echo "▶️ [3/6] Provisioning RAG Knowledge Base Bucket with Insecure Storage Posture..."
RAG_BUCKET="banco-credit-rag-${PROJECT_ID}"

if ! gsutil ls -b "gs://${RAG_BUCKET}" &>/dev/null; then
    # Create bucket with uniform bucket-level access (Org policy compliance)
    gsutil mb -p ${PROJECT_ID} -c standard -l ${REGION} --uniform-bucket-level-access "gs://${RAG_BUCKET}"
    
    # Vulnerability 3: Versioning disabled (Risk: Data Poisoning / Tampering without audit trail)
    gsutil versioning set off "gs://${RAG_BUCKET}"
    
    # Vulnerability 4: Sensitive unencrypted RAG dataset & prompt templates
    cat << 'EOF' > /tmp/credit_risk_dataset.csv
account_id,customer_name,tax_id,credit_score,income_annual,risk_tier,notes
ACC-89412,Carlos Silva,111.222.333-44,720,185000.00,LOW,Approved automatic loan pre-authorization.
ACC-98211,Mariana Costa,555.666.777-88,510,48000.00,HIGH,Subject to manual verification and high default risk.
ACC-77341,Roberto Mendes,999.888.777-00,640,95000.00,MEDIUM,Collateral required for credit extension.
EOF

    cat << 'EOF' > /tmp/insecure_prompt_templates.json
{
  "rag_system_prompt": "You are a Banking Assistant. Answer user queries based on context directly concatenated without filtering.",
  "insecure_concatenation_sample": "f'System: {context}\nUser: {user_input}\nAssistant:'",
  "data_sanitization_enabled": false,
  "model_armor_guard_active": false
}
EOF

    gsutil cp /tmp/credit_risk_dataset.csv "gs://${RAG_BUCKET}/knowledge_base/credit_risk_dataset.csv"
    gsutil cp /tmp/insecure_prompt_templates.json "gs://${RAG_BUCKET}/knowledge_base/insecure_prompt_templates.json"
    
    echo "   ⚠️ [MISCONFIG] RAG Bucket 'gs://${RAG_BUCKET}' provisioned with:"
    echo "      • No CMEK Encryption (Default Google-Managed Key used instead of Customer KMS Key)"
    echo "      • Fine-Grained ACLs enabled (Uniform Bucket-Level Access Disabled)"
    echo "      • Object Versioning Disabled (Risk: RAG Data Poisoning / MITRE ATLAS AML.T0020)"
    echo "      • Unsanitized Financial Datasets and Raw Prompt Concatenation Templates"
else
    echo "   ℹ️ Bucket 'gs://${RAG_BUCKET}' already exists."
fi
echo ""

# ------------------------------------------------------------------------------
# 4. MODEL STAGING BUCKET (MISCONFIGURATION: NO LIFECYCLE, NO AUDIT LOGGING)
# ------------------------------------------------------------------------------
echo "▶️ [4/6] Provisioning AI Model Staging & Artifacts Bucket..."
STAGING_BUCKET="banco-models-staging-${PROJECT_ID}"

if ! gsutil ls -b "gs://${STAGING_BUCKET}" &>/dev/null; then
    gsutil mb -p ${PROJECT_ID} -c standard -l ${REGION} "gs://${STAGING_BUCKET}"
    
    cat << 'EOF' > /tmp/model_metadata.json
{
  "model_name": "credit-risk-llama3-finetuned",
  "base_model": "meta-llama/Llama-3-70b-instruct",
  "training_framework": "PyTorch 2.3",
  "security_scan_status": "UNSCANNED",
  "lineage_verified": false
}
EOF
    gsutil cp /tmp/model_metadata.json "gs://${STAGING_BUCKET}/models/v1/model_metadata.json"
    echo "   ⚠️ [MISCONFIG] Model Staging Bucket 'gs://${STAGING_BUCKET}' created without Lifecycle Policies or CMEK."
else
    echo "   ℹ️ Bucket 'gs://${STAGING_BUCKET}' already exists."
fi
echo ""

# ------------------------------------------------------------------------------
# 5. OVER-PRIVILEGED AI SERVICE ACCOUNT (MISCONFIGURATION: ROLES/EDITOR AT PROJECT LEVEL)
# ------------------------------------------------------------------------------
echo "▶️ [5/6] Creating AI Workload Service Account with Over-Privileged IAM Role..."
OVER_PRIV_SA="demo-ai-app-runner"
SA_EMAIL="${OVER_PRIV_SA}@${PROJECT_ID}.iam.gserviceaccount.com"

if ! gcloud iam service-accounts describe ${SA_EMAIL} --project=${PROJECT_ID} &>/dev/null; then
    gcloud iam service-accounts create ${OVER_PRIV_SA} \
        --display-name="Banking AI Application Runner (Simulated Insecure SA)" \
        --project=${PROJECT_ID} --quiet
    
    # Assign broad Editor role (Violates Least Privilege - SAIF Sec. 2.1)
    gcloud projects add-iam-policy-binding ${PROJECT_ID} \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/editor" \
        --condition=None --quiet >/dev/null
    
    echo "   ⚠️ [MISCONFIG] Service Account '${SA_EMAIL}' created with 'roles/editor' (Over-Privileged Identity)."
else
    echo "   ℹ️ Service Account '${SA_EMAIL}' already exists."
fi
echo ""

# ------------------------------------------------------------------------------
# 6. INSECURE AI CODE PIPELINE SAMPLE FOR SAST SCANNER
# ------------------------------------------------------------------------------
echo "▶️ [6/6] Generating Insecure RAG Pipeline Code for Static SAST Scanner..."
CODE_SAMPLE_DIR="${PROJECT_ROOT}/scripts/poc/insecure_pipeline_samples"
mkdir -p "${CODE_SAMPLE_DIR}"

cat << 'EOF' > "${CODE_SAMPLE_DIR}/rag_insecure_pipeline.py"
# WARNING: VULNERABLE CODE SAMPLE FOR AISPR SAST & RED TEAM DETECTION
# Direct user prompt concatenation without Model Armor Guard inspection

def generate_credit_advice(user_prompt: str, credit_context: str):
    # INSECURE: Vulnerable to Direct Prompt Injection (OWASP LLM01 / MITRE ATLAS AML.T0051)
    raw_prompt = f"Context: {credit_context}\nUser Query: {user_prompt}\nGive credit approval decision:"
    
    # Direct execution without guardrails:
    # response = vertex_ai.predict(raw_prompt)
    return {"prompt": raw_prompt, "sanitized": False, "guard_active": False}
EOF
echo "   ⚠️ [MISCONFIG] Insecure pipeline sample saved in '${CODE_SAMPLE_DIR}/rag_insecure_pipeline.py'."
echo ""

# ------------------------------------------------------------------------------
# SUMMARY OF PROVISIONED VULNERABILITIES
# ------------------------------------------------------------------------------
echo "================================================================================"
echo "🎯 SUMMARY OF INTENTIONAL CONTROLLED VULNERABILITIES INJECTED:"
echo "   1️⃣  STORAGE: RAG Bucket 'gs://${RAG_BUCKET}' lacks CMEK, Object Versioning & Uniform Access."
echo "   2️⃣  DATA: Unsanitized financial CSV and uninspected RAG knowledge base files."
echo "   3️⃣  NETWORK: Subnet 'demo-ai-subnet' has VPC Flow Logs DISABLED."
echo "   4️⃣  FIREWALL: Rule '${FW_RULE}' allows unauthenticated Shadow AI ports (11434, 8000, 8080) inside VPC."
echo "   5️⃣  IAM: Service Account '${SA_EMAIL}' granted 'roles/editor' (Over-Privileged)."
echo "   6️⃣  CODE: Insecure RAG prompt concatenation in '${CODE_SAMPLE_DIR}/rag_insecure_pipeline.py'."
echo "================================================================================"
echo "✅ PHASE 1 COMPLETED. VULNERABLE CUSTOMER ENVIRONMENT READY FOR AISPR AUDIT."
echo "================================================================================"

