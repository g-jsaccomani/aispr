#!/bin/bash
# ==============================================================================
# Microsoft Azure - CLI Fast Onboarding Script for AISPR
# ==============================================================================
set -e

SP_NAME="http://Agentic-AISPR-Security-Auditor"
echo "🛡️ Creating Azure Service Principal '${SP_NAME}' with Read-Only privileges..."

az ad sp create-for-rbac \
  --name "${SP_NAME}" \
  --role "Reader" \
  --scopes "/subscriptions/$(az account show --query id -o tsv)" \
  --years 1

echo "✅ Azure Service Principal created successfully."
