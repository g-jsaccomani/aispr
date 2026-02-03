output "model_armor_template_name" {
  description = "Full resource name of the deployed Model Armor Template"
  value       = "projects/${var.project_id}/locations/${var.location}/templates/${var.template_id}"
}

output "floor_setting_enforced" {
  description = "FloorSetting enforcement status"
  value       = var.enable_floor_setting
}

output "dlp_template_name" {
  description = "Cloud DLP Inspection Template resource name"
  value       = var.enable_dlp_integration ? google_data_loss_prevention_inspect_template.aispr_dlp_inspect[0].name : "DISABLED"
}
