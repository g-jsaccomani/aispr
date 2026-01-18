# ==============================================================================
# Agentic AISPR - Customer-Owned Remediation Blueprint (Terraform)
# Generated for: Enterprise Customer (your-gcp-project-id)
# ==============================================================================

# 1. Enforce Customer-Managed Encryption Key (Cloud KMS CMEK)
resource "google_kms_crypto_key" "ai_cmek_key" {
  name     = "demo-ai-cmek-key"
  key_ring = "projects/your-gcp-project-id/locations/southamerica-east1/keyRings/demo-ai-keyring"
  rotation_period = "7776000s" # 90 days
}

# 2. Disable Public IP on Vertex AI Workbench
resource "google_workbench_instance" "secure_analyst_workbench" {
  name     = "workbench-analyst-gpu-01"
  location = "southamerica-east1-a"

  gce_setup {
    machine_type = "n1-standard-8"
    disable_public_ip = true

    network_interfaces {
      network = "projects/your-gcp-project-id/global/networks/demo-ai-vpc"
      subnet  = "projects/your-gcp-project-id/regions/southamerica-east1/subnetworks/demo-ai-subnet"
    }
  }
}
