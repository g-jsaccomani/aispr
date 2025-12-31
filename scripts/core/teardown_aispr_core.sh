#!/usr/bin/env bash
# ==============================================================================
# Agentic AISPR - Core Platform Teardown Script
# Safely destroys the AISPR Core project, runner VM, storage and folder
# ==============================================================================
set -euo pipefail

export PATH="${HOME}/.local/bin:${HOME}/google-cloud-sdk/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TF_CORE_DIR="${PROJECT_ROOT}/terraform_core"

echo "================================================================================"
echo " ⚠️  AGENTIC AISPR • CORE PLATFORM TEARDOWN"
echo "================================================================================"

cd "${TF_CORE_DIR}"

if [[ ! -f "terraform.tfstate" ]]; then
  echo "[-] No active AISPR Core state found. Nothing to destroy."
  exit 0
fi

echo "[*] Destroying AISPR Core resources and folder..."
terraform destroy -auto-approve

rm -f "${PROJECT_ROOT}/config/aispr_core_config.json"

echo ""
echo "================================================================================"
echo " ✅ AISPR CORE ENVIRONMENT TEARDOWN COMPLETED."
echo "================================================================================"
