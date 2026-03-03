# Enterprise Guide: How to Import & Run AISPR Scripts in Cloud Shell

This guide explains step-by-step how to import, upload, and execute the zero-footprint **Agentic AISPR** auditor packages across **Google Cloud (GCP)**, **AWS**, and **Azure**.

---

## 1.  Google Cloud Platform (GCP)

Google Cloud Shell is a free, pre-authenticated, browser-based terminal with `gcloud` and `terraform` pre-installed.

### Method A: Using Terraform in Google Cloud Shell (Recommended for DevOps & Production)
1. Open **Google Cloud Shell**: [https://shell.cloud.google.com](https://shell.cloud.google.com)
2. Ensure your target project is active:
   ```bash
   gcloud config set project <YOUR_TARGET_PROJECT_ID>
   ```
3. Click the **Three Dots menu (`⋮`)** in the upper-right corner of the Cloud Shell toolbar -> Click **Upload**.
4. Select the `gcp_onboarding.tf` file (located in `reports/onboarding_scripts/`).
5. In the Cloud Shell terminal, execute:
   ```bash
   terraform init
   terraform apply -auto-approve
   ```
6. **Expected Output:**
   * Creates Service Account: `aispr-agentless-reader@<YOUR_PROJECT_ID>.iam.gserviceaccount.com`
   * Binds strictly read-only roles: `roles/viewer`, `roles/aiplatform.viewer`, `roles/cloudkms.viewer`, and `roles/securitycenter.findingsViewer`.
   * **Zero write permissions, zero disruption to running workloads.**

---

### Method B: Using 1-Liner Bash in Google Cloud Shell (Fastest / 30 Seconds)
1. Open [Google Cloud Shell](https://shell.cloud.google.com).
2. Set your target project:
   ```bash
   gcloud config set project <YOUR_TARGET_PROJECT_ID>
   ```
3. Copy, paste, and run this complete block:
   ```bash
   cat << 'EOF' > gcp_onboarding.sh
   #!/usr/bin/env bash
   set -euo pipefail
   PROJECT_ID=$(gcloud config get-value project)
   SA_NAME="aispr-agentless-reader"
   SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

   echo "==> Creating Read-Only Service Account for AISPR Assessment..."
   gcloud iam service-accounts create "${SA_NAME}" \
     --display-name="AISPR Agentless Security Auditor" || true

   ROLES=(
     "roles/viewer"
     "roles/aiplatform.viewer"
     "roles/cloudkms.viewer"
     "roles/securitycenter.findingsViewer"
   )

   for ROLE in "${ROLES[@]}"; do
     gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
       --member="serviceAccount:${SA_EMAIL}" \
       --role="${ROLE}" \
       --condition=None --quiet
   done

   echo "================================================================"
   echo "Yes GCP AUDITOR SERVICE ACCOUNT READY: ${SA_EMAIL}"
   echo "================================================================"
   EOF
   chmod +x gcp_onboarding.sh && ./gcp_onboarding.sh
   ```

---

### Method C: Connecting the Auditor to AISPR Platform
1. On your machine, run:
   ```bash
   ./aispr-client-journey
   ```
2. Select **Option `[1]` (Access Granted • Direct Environment Connection)**.
3. Enter your Client Name and target GCP Project ID.
4. The system validates permissions and immediately launches the **Agentic AISPR Web Console** (`http://localhost:8501`).

---

## 2.  Amazon Web Services (AWS) CloudShell

1. Open the [AWS Management Console](https://console.aws.amazon.com).
2. Click the **CloudShell icon (`>_`)** in the top navigation bar.
3. Click **Actions** (top right) -> **Upload file** -> select `reports/onboarding_scripts/aws_onboarding.tf`.
4. Run:
   ```bash
   terraform init
   terraform apply -auto-approve
   ```
5. Note the output `role_arn` (e.g., `arn:aws:iam::123456789012:role/AISPR-ReadOnly-Role`) and paste it into Step 5 of the AISPR Web Console.

---

## 3.  Microsoft Azure Cloud Shell

1. Open the [Azure Portal](https://portal.azure.com).
2. Click the **Cloud Shell icon (`>_`)** in the top toolbar (select **Bash**).
3. Click the **Manage files (Upload)** icon -> select `reports/onboarding_scripts/azure_onboarding.sh`.
4. Make executable and run:
   ```bash
   chmod +x azure_onboarding.sh && ./azure_onboarding.sh
   ```
5. Copy the generated `appId` and `password` to connect in Step 5 of the AISPR Web Console.

---

*Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).*
*Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani*
*Licensed under the Apache License, Version 2.0.*

<!-- Checkpoint: 2026-03-03 - docs(delivery): finalize AI posture executive report for client security committee -->
