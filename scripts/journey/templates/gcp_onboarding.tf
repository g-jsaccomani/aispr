# ==============================================================================
# Google Cloud Platform (GCP) - Zero-Footprint AISPR Read-Only Auditor Setup
# Target Frameworks: Google SAIF • NIST AI RMF • ISO/IEC 42001 • MITRE ATLAS
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "Target GCP Project ID for AI Security Posture Review"
}

# 1. Create Dedicated Least-Privilege Read-Only Service Account
resource "google_service_account" "aispr_reader" {
  account_id   = "aispr-agentless-reader"
  display_name = "Agentic AISPR Zero-Footprint Reader"
  description  = "Strictly read-only auditor service account for automated AI security posture review"
  project      = var.project_id
}

# 2. Assign Granular Read-Only Roles (Zero Write / Zero Modify Privileges)
locals {
  readonly_roles = [
    "roles/viewer",
    "roles/aiplatform.viewer",
    "roles/cloudasset.viewer",
    "roles/securitycenter.findingsViewer",
    "roles/cloudkms.viewer"
  ]
}

resource "google_project_iam_member" "aispr_bindings" {
  for_each = toset(local.readonly_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.aispr_reader.email}"
}

output "auditor_service_account_email" {
  value       = google_service_account.aispr_reader.email
  description = "Share this Service Account email with the AISPR assessment team"
}
