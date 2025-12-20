#!/bin/bash
# ==============================================================================
# Teardown Script: Stop All AISPR Cloud Resources & Local Daemons (Zero Cost)
# Authored by: Joabson Saccomani (@jsaccomani) | Google Cloud Security Consultant
# ==============================================================================

set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$HOME/google-cloud-sdk/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

PROJECT_ID=$(gcloud config get-value project 2>/dev/null || true)
REGION="southamerica-east1"

echo "================================================================================"
echo "🛑 TEARING DOWN AISPR CLOUD & LOCAL RESOURCES TO PREVENT COSTS"
echo "================================================================================"
echo "📍 Target Project: ${PROJECT_ID}"
echo ""

echo "▶️ [1/6] Stopping local Python web servers on port 8501..."
lsof -ti:8501 | xargs kill -9 2>/dev/null || true
echo "   ✅ Local web server stopped."

echo ""
echo "▶️ [2/6] Deleting Cloud Run service 'aispr-platform'..."
if gcloud run services describe aispr-platform --region=${REGION} --project=${PROJECT_ID} &>/dev/null; then
    gcloud run services delete aispr-platform --region=${REGION} --project=${PROJECT_ID} --quiet
    echo "   ✅ Cloud Run service deleted."
else
    echo "   ℹ️ Cloud Run service not running or already deleted."
fi

echo ""
echo "▶️ [3/6] Deleting test Cloud Storage buckets..."
for BUCKET_NAME in "banco-credit-rag-${PROJECT_ID}" "banco-models-staging-${PROJECT_ID}"; do
    if gsutil ls -b "gs://${BUCKET_NAME}" &>/dev/null; then
        gsutil rm -r "gs://${BUCKET_NAME}" || true
        echo "   ✅ Bucket gs://${BUCKET_NAME} deleted."
    else
        echo "   ℹ️ Bucket gs://${BUCKET_NAME} not found or already removed."
    fi
done

echo ""
echo "▶️ [4/6] Deleting vulnerable firewall rules..."
FW_RULE="demo-ai-allow-internal-insecure-inference"
if gcloud compute firewall-rules describe ${FW_RULE} --project=${PROJECT_ID} &>/dev/null; then
    gcloud compute firewall-rules delete ${FW_RULE} --project=${PROJECT_ID} --quiet || true
    echo "   ✅ Firewall rule '${FW_RULE}' deleted."
else
    echo "   ℹ️ Firewall rule '${FW_RULE}' not found."
fi

echo ""
echo "▶️ [5/6] Deleting simulated over-privileged service account..."
OVER_PRIV_SA="demo-ai-app-runner@${PROJECT_ID}.iam.gserviceaccount.com"
if gcloud iam service-accounts describe ${OVER_PRIV_SA} --project=${PROJECT_ID} &>/dev/null; then
    gcloud iam service-accounts delete ${OVER_PRIV_SA} --project=${PROJECT_ID} --quiet || true
    echo "   ✅ Service account '${OVER_PRIV_SA}' deleted."
else
    echo "   ℹ️ Service account not found."
fi

echo ""
echo "▶️ [6/6] Cleaning up local code samples..."
rm -rf "${PROJECT_ROOT}/scripts/poc/insecure_pipeline_samples"
echo "   ✅ Local sample files cleaned."

echo ""
echo "================================================================================"
echo "✅ TEARDOWN COMPLETE. ZERO ACTIVE BILLING RESOURCES IN PROJECT ${PROJECT_ID}."
echo "================================================================================"
