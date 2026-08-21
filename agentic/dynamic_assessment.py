# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Dynamic & Progressive Context-Aware Q&A Generator
Engineered by: @jsaccomani
"""

from typing import Dict, List, Any


class DynamicAssessmentEngine:
    """
    Generates intelligent, context-aware assessment questions based on real-time
    AI-BOM discovery findings across Google Cloud, AWS, and Azure.
    """

    @staticmethod
    def generate_questions(ai_bom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Synthesizes AI-BOM telemetry to create targeted GRC & technical questions.
        """
        questions = []

        # 1. Evaluate Models without Guardrails / Content Safety
        for model in ai_bom.get("discovered_models", []):
            provider = model.get("provider", "").upper()
            model_name = model.get("name", "")

            # AWS Bedrock without Guardrails
            if provider == "AWS" and not model.get("guardrails_enabled", False):
                questions.append({
                    "id": "DYN-AWS-BED-01",
                    "provider": "AWS",
                    "domain": "3. Application Security & Protection",
                    "severity": "HIGH",
                    "resource": model_name,
                    "question": f"Observed that AWS Bedrock model '{model_name}' has no active Amazon Bedrock Guardrail. How do you inspect and sanitize prompts against prompt injection or data leakage?",
                    "framework_mapping": "NIST AI RMF (MANAGE 2.4), OWASP LLM-01",
                    "suggested_mitigation": "Deploy an Amazon Bedrock Guardrail with Prompt Attack Content Filters (HIGH strength) and PII redaction."
                })

            # GCP Vertex Model without Model Armor
            if provider == "GCP" and not model.get("model_armor_enabled", False):
                questions.append({
                    "id": "DYN-GCP-ARM-01",
                    "provider": "GCP",
                    "domain": "3. Application Security & Protection",
                    "severity": "HIGH",
                    "resource": model_name,
                    "question": f"Vertex AI model '{model_name}' is deployed without inline Model Armor semantic inspection. What controls prevent semantic jailbreaks or system prompt exfiltration?",
                    "framework_mapping": "Google SAIF (Pillar 1), ISO 42001 (A.8.5)",
                    "suggested_mitigation": "Attach Google Cloud Model Armor floor settings with Sensitive Data Protection (DLP) de-identification templates."
                })

            # Azure OpenAI without Content Safety
            if provider == "AZURE" and not model.get("content_safety_enabled", False):
                questions.append({
                    "id": "DYN-AZ-SAFE-01",
                    "provider": "AZURE",
                    "domain": "3. Application Security & Protection",
                    "severity": "HIGH",
                    "resource": model_name,
                    "question": f"Azure OpenAI deployment '{model_name}' has Azure AI Content Safety disabled. How are toxic completions and adversarial prompt injections filtered?",
                    "framework_mapping": "ISO 42001 (A.8.3.2), OWASP LLM-01",
                    "suggested_mitigation": "Enable Azure AI Content Safety with severity threshold blocking for Hate, Violence, and Prompt Shield."
                })

        # 2. Evaluate Discovered Shadow AI Instances
        for shadow in ai_bom.get("shadow_ai_findings", []):
            provider = shadow.get("provider", "").upper()
            questions.append({
                "id": f"DYN-SHADOW-{shadow.get('id', '01')}",
                "provider": provider,
                "domain": "6. AI Governance & Compliance",
                "severity": shadow.get("severity", "CRITICAL"),
                "resource": shadow.get("resource", ""),
                "question": f"A shadow AI container '{shadow.get('type')}' was detected on {provider} at '{shadow.get('resource')}'. What is your governance approval and decommissioning policy for self-hosted local models?",
                "framework_mapping": "ISO 42001 (A.8.1), NIST AI RMF (GOVERN 1.2)",
                "suggested_mitigation": "Implement Organizational Policies / AWS SCPs restricting unmanaged LLM container ports (e.g., 11434, 8000, 8080) and centralize all inference via governed gateways."
            })

        # 3. Evaluate Discovered Infrastructure & CVE Vulnerabilities
        for vuln in ai_bom.get("vulnerabilities", []):
            questions.append({
                "id": f"DYN-VULN-{vuln.get('id', '01')}",
                "provider": vuln.get("provider", "GCP").upper(),
                "domain": "4. Infrastructure Security & Isolation",
                "severity": vuln.get("severity", "CRITICAL"),
                "resource": vuln.get("resource", ""),
                "question": f"Active vulnerability '{vuln.get('cve', 'CRITICAL MISCONFIGURATION')}' identified on '{vuln.get('resource')}': {vuln.get('description')}. What remediation timeline is committed for this endpoint?",
                "framework_mapping": "Google SAIF (Pillar 1), NIST AI RMF (MANAGE 2.1)",
                "suggested_mitigation": "Immediately isolate the instance, remediate unauthenticated startup scripts, and enforce Customer-Managed Encryption Keys (CMEK)."
            })

        return questions
