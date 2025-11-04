terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

variable "org_id" {
  type        = string
  default     = "31564119954"
  description = "GCP Organization ID"
}

variable "billing_account" {
  type        = string
  default     = "0180FF-1553BD-6B74BE"
  description = "GCP Billing Account ID"
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "Primary GCP Region for AISPR Core"
}

variable "folder_name" {
  type        = string
  default     = "fldr-aispr-platform"
  description = "Folder name for dedicated AISPR Core environment"
}

provider "google" {
  region = var.region
}

resource "random_id" "suffix" {
  byte_length = 3
}

# ==============================================================================
# 1. Dedicated AISPR Folder (Completely isolated from Customer Workloads)
# ==============================================================================
resource "google_folder" "aispr_folder" {
  display_name = var.folder_name
  parent       = "organizations/${var.org_id}"
}

# ==============================================================================
# 2. Dedicated AISPR Core Project
# ==============================================================================
resource "google_project" "aispr_project" {
  name            = "Agentic AISPR Core Platform"
  project_id      = "aispr-core-${random_id.suffix.hex}"
  folder_id       = google_folder.aispr_folder.folder_id
  billing_account = var.billing_account

  labels = {
    platform    = "agentic-aispr"
    environment = "core-security-engine"
    managed_by  = "terraform"
  }
}

# Enable Essential APIs for Agentic AISPR (Vertex AI, Storage, Compute, IAP, etc.)
resource "google_project_service" "aispr_apis" {
  for_each = toset([
    "aiplatform.googleapis.com",
    "compute.googleapis.com",
    "storage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iap.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com"
  ])

  project                    = google_project.aispr_project.project_id
  service                    = each.key
  disable_dependent_services = false
  disable_on_destroy         = false
}

# ==============================================================================
# 3. Private Isolated VPC for AISPR Core
# ==============================================================================
resource "google_compute_network" "vpc_aispr_core" {
  project                 = google_project.aispr_project.project_id
  name                    = "vpc-aispr-core"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Private VPC hosting the Agentic AISPR Engine and Web Console"
  depends_on              = [google_project_service.aispr_apis]
}

resource "google_compute_subnetwork" "sb_aispr_core" {
  project                  = google_project.aispr_project.project_id
  name                     = "sb-aispr-core-uscentral1"
  ip_cidr_range            = "10.50.10.0/24"
  region                   = var.region
  network                  = google_compute_network.vpc_aispr_core.id
  private_ip_google_access = true
}

# Cloud IAP Access to AISPR Console & SSH
resource "google_compute_firewall" "fw_allow_iap_aispr" {
  project     = google_project.aispr_project.project_id
  name        = "fw-allow-iap-aispr-core"
  network     = google_compute_network.vpc_aispr_core.name
  description = "Allows secure administration and Web Console tunneling via Google IAP (35.235.240.0/20)"

  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22", "8501", "8080"]
  }
}

# ==============================================================================
# 4. Service Account for Agentic AISPR Engine
# ==============================================================================
resource "google_service_account" "sa_aispr_engine" {
  project      = google_project.aispr_project.project_id
  account_id   = "sa-aispr-engine"
  display_name = "Agentic AISPR Engine Service Account"
  description  = "Dedicated identity for Vertex AI Gemini calls, threat analysis and report generation"
  depends_on   = [google_project_service.aispr_apis]
}

# Internal IAM roles in AISPR project
resource "google_project_iam_member" "engine_vertex_user" {
  project = google_project.aispr_project.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.sa_aispr_engine.email}"
}

resource "google_project_iam_member" "engine_storage_admin" {
  project = google_project.aispr_project.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.sa_aispr_engine.email}"
}

resource "google_project_iam_member" "engine_logging" {
  project = google_project.aispr_project.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.sa_aispr_engine.email}"
}

resource "google_project_iam_member" "engine_monitoring" {
  project = google_project.aispr_project.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.sa_aispr_engine.email}"
}

# ==============================================================================
# 5. Cloud Storage Bucket for AISPR Reports, AI-BOMs & Compliance Artifacts
# ==============================================================================
resource "google_storage_bucket" "bkt_aispr_reports" {
  project                     = google_project.aispr_project.project_id
  name                        = "bkt-aispr-reports-${random_id.suffix.hex}"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  force_destroy               = true

  versioning {
    enabled = true
  }

  labels = {
    platform   = "agentic-aispr"
    data_tier  = "compliance-reports"
    managed_by = "terraform"
  }
  depends_on = [google_project_service.aispr_apis]
}

# ==============================================================================
# 6. Compute Engine: AISPR Runner VM (100% Private, Shielded, OS Login)
# ==============================================================================
data "google_compute_image" "debian_image" {
  family  = "debian-12"
  project = "debian-cloud"
}

resource "google_compute_instance" "vm_aispr_runner" {
  project      = google_project.aispr_project.project_id
  name         = "vm-aispr-runner"
  machine_type = "e2-small"
  zone         = "${var.region}-a"

  tags = ["aispr-engine", "private-only"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.debian_image.self_link
      size  = 10
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.sb_aispr_core.id
    # STRICTLY PRIVATE: 0 Public IPs
  }

  service_account {
    email  = google_service_account.sa_aispr_engine.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
    startup-script = <<-EOF
      #!/usr/bin/env bash
      set -e

      cat << 'APPSCRIPT' > /opt/aispr_service.py
import http.server
import json
import os

class AISPRRunnerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            "platform": "Agentic AISPR Enterprise Runner",
            "version": "2.4.0",
            "status": "ONLINE",
            "capabilities": [
                "104-Control SAIF/NIST AI-SPM Audit",
                "Automated AI-BOM Generation (CycloneDX)",
                "Static Prompt SAST Threat Hunter",
                "Model Armor / Vertex AI Guardrails Verification",
                "Multi-Cloud Cross-Project Auditing"
            ],
            "project_id": "${google_project.aispr_project.project_id}",
            "sa_engine": "${google_service_account.sa_aispr_engine.email}",
            "reports_bucket": "${google_storage_bucket.bkt_aispr_reports.name}"
        }, indent=2).encode('utf-8'))

if __name__ == "__main__":
    server = http.server.HTTPServer(('0.0.0.0', 8501), AISPRRunnerHandler)
    server.serve_forever()
APPSCRIPT

      cat << 'SYSTEMD' > /etc/systemd/system/aispr-runner.service
      [Unit]
      Description=Agentic AISPR Core Runner Daemon
      After=network.target

      [Service]
      Type=simple
      User=root
      WorkingDirectory=/opt
      ExecStart=/usr/bin/python3 /opt/aispr_service.py
      Restart=always
      RestartSec=5

      [Install]
      WantedBy=multi-user.target
SYSTEMD

      systemctl daemon-reload
      systemctl enable aispr-runner
      systemctl restart aispr-runner
    EOF
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  labels = {
    platform    = "agentic-aispr"
    role        = "runner-node"
    environment = "core"
  }

  depends_on = [
    google_compute_subnetwork.sb_aispr_core,
    google_project_iam_member.engine_vertex_user
  ]
}

# ==============================================================================
# Outputs
# ==============================================================================
output "folder_id" {
  value       = google_folder.aispr_folder.folder_id
  description = "GCP Folder ID for AISPR Core Platform"
}

output "project_id" {
  value       = google_project.aispr_project.project_id
  description = "GCP Project ID for AISPR Core Platform"
}

output "vpc_name" {
  value       = google_compute_network.vpc_aispr_core.name
  description = "VPC Network name for AISPR Core"
}

output "sa_engine_email" {
  value       = google_service_account.sa_aispr_engine.email
  description = "Service Account email for AISPR Engine"
}

output "reports_bucket" {
  value       = google_storage_bucket.bkt_aispr_reports.name
  description = "Cloud Storage bucket for audit reports"
}

output "vm_runner_ip" {
  value       = google_compute_instance.vm_aispr_runner.network_interface[0].network_ip
  description = "Internal Private IP of the AISPR Runner VM"
}

output "iap_runner_tunnel_command" {
  value       = "gcloud compute ssh vm-aispr-runner --project=${google_project.aispr_project.project_id} --zone=${var.region}-a --tunnel-through-iap"
  description = "Command to connect to AISPR Runner VM via IAP"
}
