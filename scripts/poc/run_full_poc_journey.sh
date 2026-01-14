#!/bin/bash
# ==============================================================================
# Agentic AISPR - Master Enterprise Customer Onboarding & Audit Orchestrator
# Executes the entire 5-phase onboarding and audit journey in the exact sequence
# Authored by: Joabson Saccomani (@jsaccomani) | Google Cloud Security Consultant
# ==============================================================================

set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="${PROJECT_ROOT}/scripts/poc"

echo "================================================================================"
echo "🛡️  AGENTIC AISPR - MASTER CLIENT ONBOARDING & AUDIT ORCHESTRATOR"
echo "   Target Scope: Enterprise AI Security Posture Review (POC)"
echo "   Frameworks: Google SAIF • NIST AI RMF • ISO 42001 • MITRE ATLAS • EU AI Act"
echo "================================================================================"
echo ""

echo "📋 This orchestrator will execute all 6 phases in the exact sequence:"
echo "   [1] Provision Customer Environment & Base AI Resources"
echo "   [2] Create Zero-Footprint Read-Only Service Account & IAM Roles"
echo "   [3] Deploy & Launch Web Platform on Google Cloud Run & Local Mirror"
echo "   [4] Execute Agentless Scans (AI-BOM, Shadow AI Hunter, Prompt SAST)"
echo "   [5] Evaluate 104 Controls, Run Red Teaming & Generate Executive Deliverables"
echo "   [6] Implement Constructive, Consultive & Protective Google Cloud Model Armor"
echo ""

read -p "Start the automated customer onboarding journey now? (Y/n): " CONFIRM
if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
    echo "Operation aborted."
    exit 0
fi

echo ""
echo "▶️ [STEP 1/6] PROVISIONING CUSTOMER ENVIRONMENT..."
bash "${SCRIPT_DIR}/01_setup_customer_environment.sh"

echo ""
echo "▶️ [STEP 2/6] CREATING READ-ONLY AUDITOR IAM IDENTITY..."
bash "${SCRIPT_DIR}/02_create_readonly_auditor.sh"

echo ""
echo "▶️ [STEP 3/6] DEPLOYING AGENTIC AISPR PLATFORM TO CLOUD RUN..."
bash "${SCRIPT_DIR}/03_deploy_cloud_run_platform.sh"

echo ""
echo "▶️ [STEP 4/6] RUNNING AGENTLESS SCANS & THREAT HUNTING..."
bash "${SCRIPT_DIR}/04_execute_agentless_scans.sh"

echo ""
echo "▶️ [STEP 5/6] GENERATING 104-CONTROL AUDIT & EXECUTIVE REPORTS..."
bash "${SCRIPT_DIR}/05_generate_audit_and_reports.sh"

echo ""
echo "▶️ [STEP 6/6] IMPLEMENTING MODEL ARMOR CONSTRUCTIVE, CONSULTIVE & PROTECTIVE DEFENSE..."
bash "${SCRIPT_DIR}/06_implement_model_armor_defense.sh"

echo ""
echo "================================================================================"
echo "🎉 CLIENT ONBOARDING, AUDIT & MODEL ARMOR DEPLOYMENT COMPLETED WITH 100% SUCCESS!"
echo "   • Cloud Run HTTPS URL: https://aispr-platform-827541997890.southamerica-east1.run.app"
echo "   • Local Web Console: http://localhost:8501"
echo "   • Executive Report: ${PROJECT_ROOT}/reports/aispr_executive_report.md"
echo "   • Model Armor Blueprint: ${PROJECT_ROOT}/reports/model_armor_consulting_blueprint.md"
echo "   • Protection Certificate: ${PROJECT_ROOT}/reports/model_armor_verification_certificate.md"
echo "   • Terraform Suite: ${PROJECT_ROOT}/reports/model_armor_deployment/terraform/"
echo "   • CycloneDX AI-BOM: ${PROJECT_ROOT}/reports/ai_bom.json"
echo "================================================================================"
