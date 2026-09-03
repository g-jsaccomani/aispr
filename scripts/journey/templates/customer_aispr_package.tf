/**
 * Copyright © 2026 Joabson Saccomani (@jsaccomani).
 * Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
 *
 * Agentic AISPR - Customer-Owned Deployment Package (Terraform)
 * Deploys an isolated, private AISPR Web Console & Scanner Node inside the customer's GCP environment.
 */

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

variable "project_id" {
  type        = string
  description = "Target Customer GCP Project ID where AISPR Node will be deployed"
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "Primary GCP Region"
}

variable "create_private_vpc" {
  type        = bool
  default     = true
  description = "Whether to create a dedicated private VPC for AISPR or use an existing subnet"
}

variable "existing_subnet_id" {
  type        = string
  default     = ""
  description = "Existing Subnetwork ID if create_private_vpc is false"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "random_id" "suffix" {
  byte_length = 2
}

# ==============================================================================
# 1. Enable Required Cloud APIs for AISPR Auditing
# ==============================================================================
resource "google_project_service" "aispr_apis" {
  for_each = toset([
    "aiplatform.googleapis.com",
    "compute.googleapis.com",
    "storage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iap.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com"
  ])

  project                    = var.project_id
  service                    = each.key
  disable_dependent_services = false
  disable_on_destroy         = false
}

# ==============================================================================
# 2. Private Isolated VPC for AISPR Node (Optional)
# ==============================================================================
resource "google_compute_network" "vpc_aispr_cust" {
  count                   = var.create_private_vpc ? 1 : 0
  name                    = "vpc-aispr-customer-node"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Private VPC hosting the Customer-Owned AISPR Node"
  depends_on              = [google_project_service.aispr_apis]
}

resource "google_compute_subnetwork" "sb_aispr_cust" {
  count                    = var.create_private_vpc ? 1 : 0
  name                     = "sb-aispr-cust-node"
  ip_cidr_range            = "10.60.10.0/24"
  region                   = var.region
  network                  = google_compute_network.vpc_aispr_cust[0].id
  private_ip_google_access = true
}

# IAP Firewall Rule
resource "google_compute_firewall" "fw_allow_iap_cust" {
  count       = var.create_private_vpc ? 1 : 0
  name        = "fw-allow-iap-aispr-cust"
  network     = google_compute_network.vpc_aispr_cust[0].name
  description = "Allows Google IAP secure tunneling for AISPR Console and SSH (35.235.240.0/20)"

  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22", "8501", "8080"]
  }
}

# ==============================================================================
# 3. Read-Only Auditor Service Account
# ==============================================================================
resource "google_service_account" "sa_aispr_auditor" {
  account_id   = "sa-aispr-customer-node"
  display_name = "Agentic AISPR Customer Node SA"
  description  = "Least-privilege read-only identity used by AISPR Node to audit AI & cloud posture"
  depends_on   = [google_project_service.aispr_apis]
}

# Least Privilege Auditor Roles
resource "google_project_iam_member" "auditor_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.sa_aispr_auditor.email}"
}

resource "google_project_iam_member" "auditor_ai_viewer" {
  project = var.project_id
  role    = "roles/aiplatform.viewer"
  member  = "serviceAccount:${google_service_account.sa_aispr_auditor.email}"
}

resource "google_project_iam_member" "auditor_sec_reviewer" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.sa_aispr_auditor.email}"
}

# ==============================================================================
# 4. Storage Bucket for Reports & Compliance Artifacts
# ==============================================================================
resource "google_storage_bucket" "bkt_aispr_reports" {
  name                        = "bkt-aispr-cust-reports-${var.project_id}-${random_id.suffix.hex}"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  force_destroy               = true

  versioning {
    enabled = true
  }

  labels = {
    platform  = "agentic-aispr"
    data_tier = "compliance-reports"
  }
  depends_on = [google_project_service.aispr_apis]
}

# ==============================================================================
# 5. Customer-Owned AISPR Node VM (100% Private, Shielded, OS Login)
# ==============================================================================
data "google_compute_image" "debian_image" {
  family  = "debian-12"
  project = "debian-cloud"
}

resource "google_compute_instance" "vm_aispr_node" {
  name         = "vm-aispr-node"
  machine_type = "e2-small"
  zone         = "${var.region}-a"

  tags = ["aispr-node", "private-only"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.debian_image.self_link
      size  = 10
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = var.create_private_vpc ? google_compute_subnetwork.sb_aispr_cust[0].id : var.existing_subnet_id
    # STRICTLY PRIVATE: 0 Public IPs
  }

  service_account {
    email  = google_service_account.sa_aispr_auditor.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
    startup-script = <<-EOF
      #!/usr/bin/env bash
      set -e

      cat << 'APPSCRIPT' > /opt/aispr_node.py
import http.server
import json
import os

class AISPRCustomerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            "platform": "Agentic AISPR Customer Node",
            "version": "2.4.0",
            "status": "ONLINE & READY",
            "project_id": "${var.project_id}",
            "auditor_sa": "${google_service_account.sa_aispr_auditor.email}",
            "reports_bucket": "${google_storage_bucket.bkt_aispr_reports.name}"
        }, indent=2).encode('utf-8'))

if __name__ == "__main__":
    server = http.server.HTTPServer(('0.0.0.0', 8501), AISPRCustomerHandler)
    server.serve_forever()
APPSCRIPT

      cat << 'SYSTEMD' > /etc/systemd/system/aispr-node.service
      [Unit]
      Description=Agentic AISPR Customer Node Runner
      After=network.target

      [Service]
      Type=simple
      User=root
      ExecStart=/usr/bin/python3 /opt/aispr_node.py
      Restart=always
      RestartSec=5

      [Install]
      WantedBy=multi-user.target
SYSTEMD

      systemctl daemon-reload
      systemctl enable aispr-node
      systemctl restart aispr-node
    EOF
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  labels = {
    platform    = "agentic-aispr"
    role        = "customer-auditor-node"
    environment = "client-owned"
  }

  depends_on = [
    google_project_service.aispr_apis,
    google_project_iam_member.auditor_viewer
  ]
}

# ==============================================================================
# Outputs
# ==============================================================================
output "aispr_node_ip" {
  value       = google_compute_instance.vm_aispr_node.network_interface[0].network_ip
  description = "Internal Private IP of the Customer-Owned AISPR Node"
}

output "auditor_sa_email" {
  value       = google_service_account.sa_aispr_auditor.email
  description = "Read-Only Auditor Service Account Email"
}

output "reports_bucket_name" {
  value       = google_storage_bucket.bkt_aispr_reports.name
  description = "Storage Bucket for Audit Reports and AI-BOMs"
}

output "iap_tunnel_command" {
  value       = "gcloud compute ssh vm-aispr-node --project=${var.project_id} --zone=${var.region}-a --tunnel-through-iap"
  description = "IAP SSH connection command"
}

output "web_console_iap_port_forward" {
  value       = "gcloud compute start-iap-tunnel vm-aispr-node 8501 --project=${var.project_id} --zone=${var.region}-a --local-host-port=localhost:8501"
  description = "IAP Port Forward command to access the AISPR Web Console locally"
}
