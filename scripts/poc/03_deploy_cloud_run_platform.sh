#!/bin/bash
# ==============================================================================
# Phase 3: Deploy & Launch Agentic AISPR Web Console on Google Cloud Run
# Deploys serverless with native IAM authentication and local fallback mirror
# Authored by: Joabson Saccomani (@jsaccomani) | Google Cloud Security Consultant
# ==============================================================================

set -e
export PATH="$HOME/google-cloud-sdk/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${PROJECT_ROOT}"

PROJECT_ID=$(gcloud config get-value project 2>/dev/null || true)
if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" == "(unset)" ]; then
    read -p "Enter Target Customer GCP Project ID: " PROJECT_ID
fi

REGION="southamerica-east1"
SERVICE_NAME="aispr-platform"
SA_EMAIL="aispr-agentless-reader@${PROJECT_ID}.iam.gserviceaccount.com"

echo "================================================================================"
echo "🚀 PHASE 3: DEPLOYING AGENTIC AISPR WEB PLATFORM ON GOOGLE CLOUD RUN"
echo "================================================================================"
echo "📍 Target Project: ${PROJECT_ID}"
echo "📍 Cloud Run Service: ${SERVICE_NAME}"
echo "📍 Target Region: ${REGION}"
echo "👤 Execution Service Account: ${SA_EMAIL}"
echo ""

# Ensure Cloud Build & Compute service accounts have required permissions
PROJECT_NUMBER=$(gcloud projects describe ${PROJECT_ID} --format="value(projectNumber)")
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/storage.admin" --condition=None --quiet >/dev/null 2>&1 || true

gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/logging.logWriter" --condition=None --quiet >/dev/null 2>&1 || true

gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/artifactregistry.writer" --condition=None --quiet >/dev/null 2>&1 || true

OPERATOR_EMAIL=$(gcloud config get-value account 2>/dev/null || true)

echo "▶️ [1/2] Building container & deploying service to Google Cloud Run (IAM Protected)..."
gcloud run deploy ${SERVICE_NAME} \
    --source . \
    --region ${REGION} \
    --project ${PROJECT_ID} \
    --service-account "${SA_EMAIL}" \
    --no-allow-unauthenticated \
    --memory 1Gi \
    --cpu 1 \
    --port 8080 \
    --quiet

if [ -n "$OPERATOR_EMAIL" ] && [ "$OPERATOR_EMAIL" != "(unset)" ]; then
    echo "🔒 [IAM] Granting roles/run.invoker on ${SERVICE_NAME} to operator: ${OPERATOR_EMAIL}..."
    gcloud run services add-iam-policy-binding ${SERVICE_NAME} \
        --region ${REGION} \
        --project ${PROJECT_ID} \
        --member="user:${OPERATOR_EMAIL}" \
        --role="roles/run.invoker" \
        --quiet >/dev/null 2>&1 || true
fi

CLOUD_RUN_URL=$(gcloud run services describe ${SERVICE_NAME} --platform managed --region ${REGION} --project ${PROJECT_ID} --format="value(status.url)")

echo ""
echo "▶️ [2/2] Launching Local Mirrored Background Daemon (Port 8501)..."
lsof -ti:8501 | xargs kill -9 2>/dev/null || true
nohup python3 "${PROJECT_ROOT}/agentic/ui/server.py" 8501 > "${PROJECT_ROOT}/reports/aispr_server.log" 2>&1 &

echo ""
echo "================================================================================"
echo "🎉 AGENTIC AISPR PLATFORM DEPLOYED SUCCESSFULLY TO GOOGLE CLOUD RUN!"
echo "   🌐 Production HTTPS Cloud Run URL (IAM Invoker / IAP required):"
echo "      👉 ${CLOUD_RUN_URL}"
echo ""
echo "   🔐 To access the Cloud Run Console locally via authorized IAM proxy:"
echo "      👉 gcloud run services proxy ${SERVICE_NAME} --region ${REGION} --project ${PROJECT_ID} --port 8080"
echo ""
echo "   💻 Local Mirrored URL:"
echo "      👉 http://localhost:8501"
echo "================================================================================"
