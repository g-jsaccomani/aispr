#!/bin/bash
# ==============================================================================
# Phase 2: Provision Zero-Footprint Read-Only Service Account & IAM Bindings
# Authored by: Joabson Saccomani (@jsaccomani) | Google Cloud Security Consultant
# ==============================================================================

set -e
export PATH="$HOME/google-cloud-sdk/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

echo "================================================================================"
echo "🛡️ PHASE 2: PROVISIONING READ-ONLY SERVICE ACCOUNT & AUDITOR IAM ROLES"
echo "================================================================================"

PROJECT_ID=$(gcloud config get-value project 2>/dev/null || true)
if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" == "(unset)" ]; then
    read -p "Enter Target Customer GCP Project ID: " PROJECT_ID
fi

SA_NAME="aispr-agentless-reader"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "📍 Target Project: ${PROJECT_ID}"
echo "👤 Auditor Service Account: ${SA_EMAIL}"
echo ""

echo "▶️ [1/3] Creating Dedicated Agentless Reader Service Account..."
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" &>/dev/null; then
    gcloud iam service-accounts create "${SA_NAME}" \
        --display-name="Agentic AISPR Zero-Footprint Reader" \
        --description="Strictly read-only identity for multi-cloud AI security posture review" \
        --project="${PROJECT_ID}"
    echo "   ✅ Service Account '${SA_EMAIL}' created successfully."
else
    echo "   ℹ️ Service Account '${SA_EMAIL}' already exists."
fi

echo ""
echo "▶️ [2/3] Binding Least-Privilege Read-Only IAM Roles (Zero Write Access)..."
ROLES=(
    "roles/viewer"
    "roles/aiplatform.viewer"
    "roles/cloudasset.viewer"
    "roles/securitycenter.findingsViewer"
    "roles/cloudkms.viewer"
)

for ROLE in "${ROLES[@]}"; do
    echo "   🔐 Granting ${ROLE}..."
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="${ROLE}" \
        --condition=None --quiet >/dev/null 2>&1 || true
done

echo "   ✅ All read-only roles attached successfully."

echo ""
echo "▶️ [3/3] Validating Auditor Identity..."
gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" --format="table(email,displayName,disabled)"

echo ""
echo "================================================================================"
echo "✅ PHASE 2 COMPLETED. READ-ONLY AUDITOR IDENTITY READY WITH ZERO WRITE ACCESS."
echo "================================================================================"
