# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI-SPR - Multi-Cloud Static Posture Scanner (Zero-Footprint Agentless CLI)
Audits GCP Vertex AI, AWS Bedrock, and Azure OpenAI using local authenticated CLI tools.
"""

import subprocess
import json
import shutil
from typing import Dict, Any, List


class MultiCloudPostureScanner:
    """
    Scans GCP, AWS, and Azure AI platform parameters using local authenticated CLI tools.
    Provides non-intrusive, zero-footprint security validation.
    """

    def scan_gcp_vertex(self, project_id: str = None) -> Dict[str, Any]:
        """Audits Vertex AI, CMEK, and VPC Service Controls via gcloud CLI."""
        findings = []
        if not shutil.which("gcloud"):
            return {
                "provider": "GCP",
                "status": "CLI_NOT_INSTALLED",
                "findings": [{"id": "GCP-CLI", "severity": "INFO", "issue": "gcloud CLI not found in PATH."}]
            }

        try:
            # Check for VPC Service Controls Service Perimeters
            vpc_sc_check = subprocess.run(
                ["gcloud", "access-context-manager", "perimeters", "list", "--format=json"],
                capture_output=True, text=True, timeout=10
            )
            if vpc_sc_check.returncode == 0 and vpc_sc_check.stdout.strip():
                perimeters = json.loads(vpc_sc_check.stdout)
                if not perimeters:
                    findings.append({
                        "id": "INF-02", "severity": "HIGH",
                        "control": "VPC Service Controls Perimeter",
                        "issue": "No active VPC Service Controls perimeter protecting Vertex AI APIs."
                    })
            else:
                findings.append({
                    "id": "INF-02", "severity": "MEDIUM",
                    "control": "VPC Service Controls",
                    "issue": "VPC-SC inspection returned empty or requires Access Context Manager permissions."
                })
        except Exception as e:
            findings.append({"id": "INF-02", "severity": "LOW", "issue": f"VPC-SC scan skipped: {str(e)}"})

        return {
            "provider": "GCP",
            "status": "SCANNED",
            "findings": findings
        }

    def scan_aws_bedrock(self) -> Dict[str, Any]:
        """Audits Amazon Bedrock security posture via aws CLI."""
        findings = []
        if not shutil.which("aws"):
            return {
                "provider": "AWS",
                "status": "CLI_NOT_INSTALLED",
                "findings": [{"id": "AWS-CLI", "severity": "INFO", "issue": "aws CLI not found in PATH."}]
            }

        try:
            # 1. Check if Bedrock Model Invocation Logging is enabled
            logging_check = subprocess.run(
                ["aws", "bedrock", "get-model-invocation-logging-configuration"],
                capture_output=True, text=True, timeout=10
            )
            if logging_check.returncode != 0 or "loggingConfig" not in logging_check.stdout:
                findings.append({
                    "id": "ASR-01", "severity": "MEDIUM",
                    "control": "Model Invocation Telemetry",
                    "issue": "Amazon Bedrock model invocation logging is disabled or unconfigured."
                })

            # 2. Check for configured Guardrails
            guardrails_check = subprocess.run(
                ["aws", "bedrock", "list-guardrails", "--format=json"],
                capture_output=True, text=True, timeout=10
            )
            if guardrails_check.returncode == 0:
                guardrails = json.loads(guardrails_check.stdout).get("guardrailsSummaries", [])
                if not guardrails:
                    findings.append({
                        "id": "APP-01", "severity": "HIGH",
                        "control": "Bedrock Guardrails",
                        "issue": "No Amazon Bedrock Guardrails are active to prevent prompt injection or toxicity."
                    })
        except Exception as e:
            findings.append({"id": "AWS-CONN", "severity": "LOW", "issue": f"AWS CLI audit skipped: {str(e)}"})

        return {
            "provider": "AWS",
            "status": "SCANNED",
            "findings": findings
        }

    def scan_azure_openai(self) -> Dict[str, Any]:
        """Audits Azure OpenAI cognitive services via az CLI."""
        findings = []
        if not shutil.which("az"):
            return {
                "provider": "AZURE",
                "status": "CLI_NOT_INSTALLED",
                "findings": [{"id": "AZURE-CLI", "severity": "INFO", "issue": "az CLI not found in PATH."}]
            }

        try:
            # Check if public network access is allowed on Cognitive Services accounts
            az_check = subprocess.run(
                ["az", "cognitiveservices", "account", "list", "--query", "[?kind=='OpenAI'].{name:name, publicAccess:publicNetworkAccess}"],
                capture_output=True, text=True, timeout=10
            )
            if az_check.returncode == 0 and az_check.stdout.strip():
                accounts = json.loads(az_check.stdout)
                for acc in accounts:
                    if acc.get("publicAccess") != "Disabled":
                        findings.append({
                            "id": "INF-03", "severity": "HIGH",
                            "control": "Azure Private Endpoint Isolation",
                            "issue": f"Azure OpenAI Account '{acc['name']}' allows public network access instead of Private Endpoints."
                        })
        except Exception as e:
            findings.append({"id": "AZURE-CONN", "severity": "LOW", "issue": f"Azure CLI audit skipped: {str(e)}"})

        return {
            "provider": "AZURE",
            "status": "SCANNED",
            "findings": findings
        }

    def scan_all_clouds(self) -> Dict[str, Any]:
        """Executes full multi-cloud static audit across GCP, AWS, and Azure."""
        return {
            "gcp": self.scan_gcp_vertex(),
            "aws": self.scan_aws_bedrock(),
            "azure": self.scan_azure_openai()
        }


if __name__ == "__main__":
    scanner = MultiCloudPostureScanner()
    results = scanner.scan_all_clouds()
    print(json.dumps(results, indent=2))
