#!/bin/bash
# Multi-Cloud AI-SPR GCP Bootstrap Script
# Authored by: @jsaccomani
# Purpose: Provision least-privilege IAM policies, custom roles, and service connections.

set -e

echo "=== @jsaccomani's AI-SPR Copilot IAM Setup ==="
echo "=============================================="

# Capture Target Environment Variables
read -p "Enter GCP Organization ID (numeric): " ORG_ID
read -p "Enter Target Project ID: " PROJECT_ID
read -p "Enter Administrator/Analyst Email: " USER_EMAIL

# 1. Create AIP Viewer Custom Role at Org Level
echo "[+] Creating custom role: AIP Viewer..."
gcloud iam roles create aip.viewer \
    --organization="$ORG_ID" \
    --title="AIP Viewer (@jsaccomani)" \
    --description="Least privilege read-only role for inspecting AI Protection metrics and SCC findings." \
    --permissions="cloudasset.assets.exportResource,cloudasset.assets.searchAllResources,securitycenter.findings.list,securitycenter.assets.list,securitycenter.attackpaths.list,securitycenter.complianceReports.aggregate,monitoring.timeSeries.list" \
    --quiet

# 2. Create AIP Essentials Custom Role at Org Level
echo "[+] Creating custom role: AIP Essentials..."
gcloud iam roles create aip.essentials \
    --organization="$ORG_ID" \
    --title="AIP Essentials (@jsaccomani)" \
    --description="Supporting role for metadata search and App Hub discovery in AI Security Posture." \
    --permissions="cloudasset.assets.searchEnrichmentResourceOwners,cloudasset.othercloudconnections.get,cloudasset.othercloudconnections.list,resourcemanager.organizations.get,resourcemanager.projects.get,securitycentermanagement.securityCommandCenter.get,securitycenter.simulations.get,securitycenter.valuedresources.list" \
    --quiet

# 3. Bind Admin and Compliance Roles to User
echo "[+] Binding security and admin roles to $USER_EMAIL..."
ADMIN_ROLES=(
    "roles/dspm.admin"
    "roles/modelarmor.admin"
    "roles/modelarmor.floorSettingsAdmin"
    "roles/cloudsecuritycompliance.admin"
    "roles/securityCenter.findingsViewer"
    "roles/monitoring.viewer"
    "roles/cloudasset.viewer"
    "organizations/$ORG_ID/roles/aip.essentials"
)

for ROLE in "${ADMIN_ROLES[@]}"; do
    gcloud organizations add-iam-policy-binding "$ORG_ID" \
        --member="user:$USER_EMAIL" \
        --role="$ROLE" \
        --quiet
done

echo "[SUCCESS] GCP Identity & Access Posture Bootstrapped by @jsaccomani!"
