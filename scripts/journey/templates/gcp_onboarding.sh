#!/bin/bash
# ==============================================================================
# Google Cloud Platform (GCP) - Fast One-Liner Read-Only Onboarding Script
# ==============================================================================
set -e

PROJECT_ID=$(gcloud config get-value project 2>/dev/null || true)
if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" == "(unset)" ]; then
    read -p "Enter Target GCP Project ID: " PROJECT_ID
fi

SA_NAME="aispr-agentless-reader"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "🛡️ Creating AISPR Read-Only Auditor Service Account in ${PROJECT_ID}..."
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" &>/dev/null; then
    gcloud iam service-accounts create "${SA_NAME}" \
        --display-name="Agentic AISPR Zero-Footprint Reader" \
        --description="Strictly read-only identity for AI security review" \
        --project="${PROJECT_ID}"
fi

ROLES=(
    "roles/viewer"
    "roles/aiplatform.viewer"
    "roles/cloudasset.viewer"
    "roles/securitycenter.findingsViewer"
    "roles/cloudkms.viewer"
)

for ROLE in "${ROLES[@]}"; do
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="${ROLE}" \
        --condition=None --quiet >/dev/null 2>&1 || true
done

echo "✅ GCP Read-Only Auditor created successfully: ${SA_EMAIL}"
