#!/usr/bin/env bash
# ==============================================================================
# Agentic AISPR - Customer-Owned Node Provisioner (Bash 1-Liner Edition)
# Runs in Google Cloud Shell to deploy the private AISPR node and auditor identity
# ==============================================================================
set -euo pipefail

export PATH="${HOME}/.local/bin:${HOME}/google-cloud-sdk/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

PROJECT_ID=$(gcloud config get-value project 2>/dev/null || echo "")

if [[ -z "${PROJECT_ID}" || "${PROJECT_ID}" == "(unset)" ]]; then
  echo "[-] Please set the target project first: gcloud config set project <PROJECT_ID>"
  exit 1
fi

REGION="us-central1"
SA_NAME="sa-aispr-customer-node"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "================================================================================"
echo "🛡️  AGENTIC AISPR • CUSTOMER-OWNED ENVIRONMENT ONBOARDING"
echo "   Target Project: ${PROJECT_ID} | Region: ${REGION}"
echo "================================================================================"

echo "▶️ [1/4] Enabling required APIs..."
gcloud services enable \
  aiplatform.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com \
  iap.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  --project="${PROJECT_ID}" --quiet

echo "▶️ [2/4] Creating Read-Only Auditor Service Account: ${SA_NAME}..."
gcloud iam service-accounts create "${SA_NAME}" \
  --display-name="Agentic AISPR Customer Node SA" \
  --project="${PROJECT_ID}" --quiet || true

ROLES=(
  "roles/viewer"
  "roles/aiplatform.viewer"
  "roles/iam.securityReviewer"
)

for ROLE in "${ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" --quiet >/dev/null 2>&1 || true
done

echo "▶️ [3/4] Creating Private Storage Bucket for Reports..."
BKT_NAME="bkt-aispr-reports-${PROJECT_ID}"
gsutil mb -p "${PROJECT_ID}" -c standard -l "${REGION}" --uniform-bucket-level-access "gs://${BKT_NAME}" 2>/dev/null || true

echo "▶️ [4/4] Generating IAP Tunnel & Port-Forward Access Command..."
echo ""
echo "================================================================================"
echo "🎉 CUSTOMER-OWNED AISPR SETUP COMPLETED!"
echo "   • Auditor Service Account: ${SA_EMAIL}"
echo "   • Reports Bucket: gs://${BKT_NAME}"
echo "   • To connect the AISPR engine securely via IAP tunnel:"
echo "     👉 gcloud compute start-iap-tunnel <VM_NAME> 8501 --project=${PROJECT_ID} --zone=${REGION}-a --local-host-port=localhost:8501"
echo "================================================================================"
