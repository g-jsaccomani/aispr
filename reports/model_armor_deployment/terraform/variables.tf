variable "project_id" {
  description = "Target Google Cloud Project ID"
  type        = string
}

variable "location" {
  description = "Deployment region for Model Armor Templates"
  type        = string
  default     = "us-central1"
}

variable "template_id" {
  description = "Unique Identifier for the Model Armor Guardrail Template"
  type        = string
  default     = "secops-guardrail-prod"
}

variable "enable_floor_setting" {
  description = "Whether to enforce non-burlable project-wide FloorSetting"
  type        = bool
  default     = true
}

variable "enable_dlp_integration" {
  description = "Whether to provision Cloud DLP inspection and de-identification templates"
  type        = bool
  default     = true
}
