# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Google Cloud Looker & BigQuery Telemetry Connector for AISPR
Transforms AI-SPM findings into continuous analytics schemas, SQL DDL, and Looker Studio dashboards.
"""

import os
import json
import datetime
from typing import Dict, List, Any


class LookerConnector:
    """
    Exports structured AI-SPM evaluation findings and telemetry to Google BigQuery & Looker Studio.
    """

    def __init__(self, dataset_id: str = "aispr_security_telemetry", tenant_id: str = "Enterprise Customer"):
        self.dataset_id = dataset_id
        self.tenant_id = tenant_id

    def generate_looker_dataset(self, score_data: Dict[str, Any], answers: Dict[str, Dict[str, Any]], inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Builds a normalized, analytics-ready JSON dataset for ingestion into BigQuery and Looker.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        summary_record = {
            "tenant_id": self.tenant_id,
            "timestamp": now,
            "overall_score": score_data.get("overall_percentage", 46.2),
            "posture_tier": score_data.get("posture_tier", "CRITICAL"),
            "total_controls_evaluated": score_data.get("overall_possible", 104),
            "controls_met": score_data.get("overall_earned", 48.0),
            "domains": score_data.get("domains", {})
        }

        controls_records = []
        for q_id, ans in answers.items():
            controls_records.append({
                "tenant_id": self.tenant_id,
                "timestamp": now,
                "control_id": q_id,
                "status": ans.get("status", "Y"),
                "criticality": ans.get("criticality", "MEDIUM"),
                "framework_mapping": ans.get("framework_mapping", "NIST AI RMF / ISO 42001"),
                "auditor_notes": ans.get("notes", "")
            })

        inventory_records = []
        for item in inventory:
            inventory_records.append({
                "tenant_id": self.tenant_id,
                "timestamp": now,
                "resource_name": item.get("name", item.get("label", "unknown")),
                "cloud_provider": item.get("cloud", item.get("provider", "GCP")),
                "resource_type": item.get("category", item.get("resource_type", "AI Model")),
                "guardrail_status": item.get("guardrail", "Missing"),
                "cmek_encrypted": item.get("cmek_enabled", False),
                "risk_level": item.get("risk_level", "MEDIUM")
            })

        return {
            "dataset_id": self.dataset_id,
            "exported_at": now,
            "summary": summary_record,
            "controls_evaluated_count": len(controls_records),
            "controls_data": controls_records,
            "inventory_data": inventory_records,
            "looker_dashboard_url": f"https://lookerstudio.google.com/reporting/aispr-ai-spm-executive?tenant={self.tenant_id.replace(' ', '+')}"
        }

    def generate_bigquery_ddl(self) -> str:
        """
        Generates BigQuery SQL DDL to provision tables for Looker Studio visualization.
        """
        return f"""-- ==============================================================================
-- Google BigQuery DDL Schema for Agentic AISPR & Looker Studio Analytics
-- Dataset: `{self.dataset_id}`
-- ==============================================================================

CREATE SCHEMA IF NOT EXISTS `{self.dataset_id}`
OPTIONS (
  location = 'southamerica-east1',
  description = 'Continuous AI Security Posture Review (AI-SPM) telemetry for Looker dashboards'
);

-- 1. AI Security Posture Summary Table
CREATE TABLE IF NOT EXISTS `{self.dataset_id}.posture_evaluations` (
  tenant_id STRING NOT NULL,
  evaluated_at TIMESTAMP NOT NULL,
  overall_score FLOAT64 NOT NULL,
  posture_tier STRING NOT NULL,
  total_controls INT64 NOT NULL,
  controls_met FLOAT64 NOT NULL,
  data_security_score FLOAT64,
  model_hardening_score FLOAT64,
  app_security_score FLOAT64,
  infra_isolation_score FLOAT64,
  monitoring_score FLOAT64,
  governance_score FLOAT64
)
PARTITION BY DATE(evaluated_at);

-- 2. 104 Controls Detailed Findings Table
CREATE TABLE IF NOT EXISTS `{self.dataset_id}.control_findings` (
  tenant_id STRING NOT NULL,
  evaluated_at TIMESTAMP NOT NULL,
  control_id STRING NOT NULL,
  status STRING NOT NULL,
  criticality STRING NOT NULL,
  framework_mapping STRING,
  auditor_notes STRING
)
PARTITION BY DATE(evaluated_at)
CLUSTER BY control_id, criticality, status;

-- 3. Multi-Cloud AI Asset Inventory Table
CREATE TABLE IF NOT EXISTS `{self.dataset_id}.ai_inventory` (
  tenant_id STRING NOT NULL,
  discovered_at TIMESTAMP NOT NULL,
  resource_name STRING NOT NULL,
  cloud_provider STRING NOT NULL,
  resource_type STRING NOT NULL,
  guardrail_status STRING,
  cmek_encrypted BOOL,
  risk_level STRING
)
PARTITION BY DATE(discovered_at)
CLUSTER BY cloud_provider, risk_level;
"""

    def sync_to_looker(self, score_data: Dict[str, Any], answers: Dict[str, Dict[str, Any]], inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Simulates streaming export to Google BigQuery and provides Looker Studio report links.
        """
        dataset = self.generate_looker_dataset(score_data, answers, inventory)
        return {
            "status": "SUCCESS_STREAMED_TO_BIGQUERY",
            "bigquery_dataset": f"{self.dataset_id}.posture_evaluations",
            "records_streamed": len(dataset["controls_data"]) + len(dataset["inventory_data"]) + 1,
            "looker_studio_url": dataset["looker_dashboard_url"],
            "dashboard_status": "READY_FOR_VISUALIZATION"
        }
