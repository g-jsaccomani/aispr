# ==============================================================================
# Microsoft Azure - Zero-Footprint AISPR Read-Only Service Principal Setup
# Target Services: Azure OpenAI • Azure AI Search • Key Vault • Storage Blobs
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.40"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
}

variable "subscription_id" {
  type        = string
  description = "Target Azure Subscription ID for AI Security Review"
}

# 1. Create Azure AD / Entra ID Application & Service Principal
resource "azuread_application" "aispr_app" {
  display_name = "Agentic-AISPR-Security-Auditor"
}

resource "azuread_service_principal" "aispr_sp" {
  client_id = azuread_application.aispr_app.client_id
}

resource "azuread_service_principal_password" "aispr_sp_pw" {
  service_principal_id = azuread_service_principal.aispr_sp.id
  end_date             = timeadd(timestamp(), "720h") # 30 days assessment window
}

# 2. Assign Granular Read-Only Roles at Subscription or Resource Group Scope
resource "azurerm_role_assignment" "reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.aispr_sp.object_id
}

resource "azurerm_role_assignment" "cognitive_reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Cognitive Services OpenAI Reader"
  principal_id         = azuread_service_principal.aispr_sp.object_id
}

output "azure_client_id" {
  value       = azuread_application.aispr_app.client_id
  description = "Azure Client ID (App ID)"
}

output "azure_client_secret" {
  value       = azuread_service_principal_password.aispr_sp_pw.value
  sensitive   = true
  description = "Azure Client Secret (Generated with 30-day assessment expiry)"
}
