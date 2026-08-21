#!/usr/bin/env bash
# ==============================================================================
# Agentic AISPR - Dedicated Core Platform Provisioner
# Provisions the isolated AISPR Folder, Project, Private VPC, Runner VM & Storage
# Authored by: Joabson Saccomani (@jsaccomani) | Google Cloud Security Consultant
# ==============================================================================
set -euo pipefail

export PATH="${HOME}/.local/bin:${HOME}/google-cloud-sdk/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TF_CORE_DIR="${PROJECT_ROOT}/terraform_core"

echo "================================================================================"
echo "🛡️  AGENTIC AISPR • CORE PLATFORM ENVIRONMENT PROVISIONER"
echo "   Folder: fldr-aispr-platform | Isolated from Customer Workloads"
echo "================================================================================"

if ! command -v terraform &>/dev/null; then
  echo "[-] ERROR: Terraform CLI is required but not found in PATH."
  exit 1
fi

cd "${TF_CORE_DIR}"

echo "▶️ [1/3] Initializing Terraform for AISPR Core..."
terraform init -backend=false

echo ""
echo "▶️ [2/3] Applying AISPR Core Infrastructure (Folder, Project, VPC, Runner, GCS)..."
terraform apply -auto-approve

echo ""
echo "▶️ [3/3] Fetching AISPR Core Environment Outputs..."
AISPR_PRJ=$(terraform output -raw project_id 2>/dev/null || echo "")
AISPR_FOLDER=$(terraform output -raw folder_id 2>/dev/null || echo "")
AISPR_SA=$(terraform output -raw sa_engine_email 2>/dev/null || echo "")
AISPR_BKT=$(terraform output -raw reports_bucket 2>/dev/null || echo "")
AISPR_IP=$(terraform output -raw vm_runner_ip 2>/dev/null || echo "")

# Save state metadata for CLI and Journey orchestrator
mkdir -p "${PROJECT_ROOT}/config"
cat << EOF > "${PROJECT_ROOT}/config/aispr_core_config.json"
{
  "folder_id": "${AISPR_FOLDER}",
  "project_id": "${AISPR_PRJ}",
  "sa_engine": "${AISPR_SA}",
  "reports_bucket": "${AISPR_BKT}",
  "runner_ip": "${AISPR_IP}",
  "region": "us-central1"
}
EOF

echo ""
echo "================================================================================"
echo "🎉 AGENTIC AISPR CORE PLATFORM PROVISIONED SUCCESSFULLY!"
echo "   🏢 GCP Folder:          fldr-aispr-platform (${AISPR_FOLDER})"
echo "   📌 Dedicated Project:   ${AISPR_PRJ}"
echo "   👤 AISPR Engine SA:     ${AISPR_SA}"
echo "   🗄️ Reports Bucket:      gs://${AISPR_BKT}"
echo "   🖥️ Private Runner VM:   ${AISPR_IP} (us-central1-a)"
echo "   🔐 IAP Tunnel Command:  gcloud compute ssh vm-aispr-runner --project=${AISPR_PRJ} --zone=us-central1-a --tunnel-through-iap"
echo "================================================================================"
