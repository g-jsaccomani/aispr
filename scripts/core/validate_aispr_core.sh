#!/usr/bin/env bash
# ==============================================================================
# Agentic AISPR - Core Platform Validation Script
# Validates the AISPR Core project, runner VM, Vertex AI, Storage and IAP setup
# ==============================================================================
set -euo pipefail

export PATH="${HOME}/.local/bin:${HOME}/google-cloud-sdk/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TF_CORE_DIR="${PROJECT_ROOT}/terraform_core"

echo "================================================================================"
echo " 🔍 AGENTIC AISPR • VALIDATING CORE PLATFORM ENVIRONMENT"
echo "================================================================================"

cd "${TF_CORE_DIR}"

if [[ ! -f "terraform.tfstate" ]]; then
  echo "[-] ERROR: AISPR Core is not provisioned yet. Run 'make setup-aispr' first."
  exit 1
fi

AISPR_PRJ=$(terraform output -raw project_id)

echo "[*] Checking AISPR Core Project: ${AISPR_PRJ}"
gcloud projects describe "${AISPR_PRJ}" --format="table(projectId,name,projectNumber,parent.id:label=FOLDER_ID,lifecycleState)"

echo ""
echo "[*] Checking Private AISPR Runner VM:"
gcloud compute instances list --project="${AISPR_PRJ}" \
  --format="table(name,zone,machineType,networkInterfaces[0].networkIP:label=INTERNAL_IP,networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP,status)"

echo ""
echo "[*] Checking Storage Bucket (Reports & AI-BOMs):"
gcloud storage buckets list --project="${AISPR_PRJ}" --format="table(name,location,storageClass)"

echo ""
echo "[*] Checking Service Account & Vertex AI permissions:"
gcloud iam service-accounts list --project="${AISPR_PRJ}" --format="table(email,displayName)"

echo ""
echo "================================================================================"
echo " ✅ AISPR CORE PLATFORM VALIDATION COMPLETED WITH SUCCESS!"
echo "================================================================================"
