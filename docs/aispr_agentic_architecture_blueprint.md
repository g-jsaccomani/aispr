# AISPR Agentic: Enterprise-Grade Multi-Cloud AI-SPM & Governance Platform
**Chief Architect:** `@jsaccomani`
**Core Framework:** Agnostic AI-SPM (AI Security Posture Management) & DevSecOps
**Compliance targets:** NIST AI RMF 1.0, ISO/IEC 42001 (AIMS), and SAIF

This document defines the formal architecture blueprint for **AISPR Agentic**, a proprietary, agnostically designed multi-cloud agentic security platform. It detail how the platform discovers assets, evaluates governance, executes offensive simulation, and deploys inline active shielding across Google Cloud, AWS, and Azure.

---

## 1. Executive Summary & Design Philosophy
Traditional Cloud Security Posture Management (CSPM) operates purely at the infrastructure layer (such as checking open firewall ports and IAM roles). However, they are structurally blind to the unique vulnerabilities introduced by generative and agentic AI (e.g., prompt injection, model poisoning, and excessive agent agency).

**AISPR Agentic** merges **AI-SPM** (Active Scanning & Threat Operations) with **GRC** (Dynamic Governance Auditing) into a single, cohesive, and framework-agnostic platform. It operates as an autonomous security specialist that connects securely to any client's cloud, performs non-intrusive discovery, runs progressive context-aware assessment workshops, and generates automated mitigations (such as Model Armor policies, Bedrock Guardrails, and Terraform hardening files).

---

## 2. Multi-Cloud Connection & Trust Architecture
To prevent the storage or exposure of static credentials (which represent a critical attack vector), the platform implements **Federated Workload Identity** and ephemeral session roles to access client estates:

```text

     AISPR Agentic
   (Orchestrator Core)

             (Assumes Ephemeral Roles via OIDC / mTLS)



   Google Cloud Trust             AWS Security Hub                Azure Entra
   • Workload Identity           • AssumeRole STS              • Service Principal
   • roles/viewer (SCC)          • External ID token           • Reader (Defender)

```

### Identity and Access Mechanisms:
1. **Google Cloud (Vertex AI / GKE):** Leverages mTLS and Workload Identity Federation, granting the runner temporary permissions (`roles/monitoring.viewer` and `roles/securitycenter.viewer`) to query the native Security Command Center (SCC) AI Protection dashboard.
2. **Amazon Web Services (Bedrock / SageMaker):** Uses an AWS IAM Role with a cryptographically secure `External ID` managed by the orchestrator. The agent assumes this role via AWS STS (`AssumeRole`) to discover Bedrock workloads, read active GuardDuty AI Protection findings, and inspect CloudTrail events.
3. **Microsoft Azure (OpenAI / AI Foundry):** Integrates via Azure Entra ID using scoped Service Principals, allowing the agent to audit Cognitive Services configurations and retrieve real-time alerts from Microsoft Defender for Cloud's AI Threat Protection module.

---

## 3. Core Engine Workflow (4 Operational Phases)

### Phase 1: Continuous Autonomous Discovery (The AI-BOM)
When connected, the platform automatically scans the client's multicloud resources to compile an active AI Bill of Materials (AI-BOM). It discovers:
* **GCP:** Vertex AI Workbench notebooks, Vertex Agent Builder endpoints, Cloud Run hosting services, and GKE namespaces.
* **AWS:** Amazon Bedrock Agents, SageMaker endpoints, and EC2/ECS workloads.
* **Azure:** Azure OpenAI deployments and Azure AI Foundry projects.
* **Shadow AI:** Actively hunts for unmanaged, rogue local models (such as local Ollama, vLLM, or Triton instances) exposed on Compute instances or Kubernetes clusters.

### Phase 2: Dynamic & Progressive Assessment Loop (Dynamic Q&A)
Instead of walking the client's team through a static, exhausting spreadsheet of 104 questions, the orchestrator uses Gemini's reasoning engine to generate a **progressive, context-aware interview**:
1. **Pre-population:** The agent ingests the raw discovery output and automatically marks corresponding controls as compliant (e.g., verifying that CMEK encryption is active on Cloud Storage or AWS S3 buckets).
2. **Context-Aware Gating:** If a vulnerability or potential threat vector is surfaced (such as a public endpoint or missing input filters), the agent dynamically designs and generates interlocked questions:
   * *Example:* *"I discovered an active AWS Bedrock Agent calling your database but observed that no Amazon Bedrock Guardrail is configured on this endpoint. Let's discuss your input sanitization. How do you currently protect against prompt injection or cost-harvesting attacks?"*
3. **Qualitative Evidence Capture:** The agent records the client's feedback, system architecture details, and files them directly under the corresponding control in `controls.json`.

### Phase 3: Automated Attack Simulation (Red Teaming)
To validate that the controls described by the client's team in Phase 2 are actually operating as intended in production, the agent initiates controlled, automated adversarial tests:
* **Semantic Attack Vector:** Evaluates the API endpoint using a canonical database of **55 prompt injection, jailbreak, and system instructions override payloads**.
* **Exploit Verification:** Checks Vertex AI Workbench against startup script exfiltration vulnerabilities (CVE-2026-2244) and staging buckets against "Pickle-in-the-Middle" model poisoning.
* **Human-in-the-Loop (HITL) Gate:** When executing active payloads, the simulation uses structural approval gates. No command or call that might corrupt data is executed without explicit operator token confirmation.

### Phase 4: Self-Healing & Remediation (The Improvement Engine)
Upon completing the review, the agent calculates compliance scores, assigns a Posture Tier (Secure, Moderado, or Crítico), compiles the Executive CAPA Report, and generates the active fixes:
* **Terraform Blueprints:** Automatically outputs the necessary infrastructure code to create secure VPC Private Service Connect endpoints, disable VM public IPs, and restrict service account keys.
* **Active Security Policies:**
  * Generates Google Cloud **Model Armor templates** config JSON.
  * Generates AWS **Bedrock Guardrail** JSON policies.
  * Generates Azure **AI Content Safety** rules.
* **Direct Apply:** If authorized, the agent invokes the client's cloud APIs to update the safety templates inline, instantly sealing the detected vulnerabilities.

---

## 4. Software Design & Code Blueprint

The logical heart of the **AISPR Agentic Platform** is constructed in Python. Below is the architectural blueprint of how the core platform orchestrates connections and scans:

```python
# -*- coding: utf-8 -*-
"""
@jsaccomani's AISPR Agentic - Platform Core Engine
File: aispr_agentic/platform.py
Purpose: Modular, multi-cloud AI-SPM scanner and dynamic evaluation coordinator.
"""

import os
import json
import logging
from typing import Dict, List, Any

# Secure logger aligned with Central Security Operations (SecOps)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AISPR-Agentic-Core")

class AISPRAgenticCore:
    """
    Proprietary, framework-agnostic core engine that orchestrates multi-cloud
    AI-SPM discovery, dynamic GRC questioning, and inline remediations.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.scanners = {}
        logger.info(f"Initialized AISPR Agentic Core for tenant: {tenant_id}")

    def register_cloud_connector(self, cloud_provider: str, credentials_payload: Dict[str, Any]):
        """
        Registers federated credentials (such as AWS STS, Azure SP, or GCP mTLS keys)
        for non-intrusive discovery.
        """
        logger.info(f"Registering trusted connector for provider: {cloud_provider}")
        self.scanners[cloud_provider] = credentials_payload

    def run_multi_cloud_discovery(self) -> Dict[str, Any]:
        """
        Executes active scanning across GCP, AWS, and Azure, building the unified AI-BOM.
        """
        ai_bom = {
            "discovered_models": [],
            "discovered_endpoints": [],
            "shadow_ai_findings": [],
            "vulnerabilities": []
        }

        for provider, creds in self.scanners.items():
            logger.info(f"Invoking {provider.upper()} active scanning engine...")
            # Simulate or execute API calls to Cloud Asset Inventory, Security Hub, and Defender
            if provider == "gcp":
                # Scans GKE namespaces, Vertex AI Registry, and CVE-2026-2244 Workbench vulnerabilities
                ai_bom["discovered_endpoints"].append({"name": "vertex-gemini-endpoint-prod", "provider": "gcp", "protected": True})
            elif provider == "aws":
                # Scans Amazon Bedrock, SageMaker, and GuardDuty AI Protection
                ai_bom["discovered_models"].append({"name": "claude-3-5-sonnet", "provider": "aws", "guardrails_enabled": False})
                ai_bom["shadow_ai_findings"].append({"type": "Unsanctioned Ollama Container", "provider": "aws", "severity": "HIGH"})

        return ai_bom

    def generate_progressive_questions(self, ai_bom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Dynamically generates assessment questions based on scanned findings.
        """
        questions_to_ask = []

        # Scenario A: Detected an AWS Bedrock model without Guardrails
        for model in ai_bom.get("discovered_models", []):
            if model["provider"] == "aws" and not model["guardrails_enabled"]:
                questions_to_ask.append({
                    "id": "AWS-BED-01",
                    "domain": "Application Protection",
                    "severity": "HIGH",
                    "question": f"Observed that the AWS Bedrock model '{model['name']}' has no active Guardrail. How do you sanitize prompts and responses inline?",
                    "suggested_mitigation": "Deploy AWS Bedrock Guardrails with Prompt Attack Content Filters to block jailbreaks."
                })

        # Scenario B: Rogue/Shadow AI container detected
        for shadow_finding in ai_bom.get("shadow_ai_findings", []):
            questions_to_ask.append({
                "id": "SHADOW-AI-01",
                "domain": "Governance & Discovery",
                "severity": "CRITICAL",
                "question": f"A shadow model container '{shadow_finding['type']}' was discovered on {shadow_finding['provider'].upper()}. What is your approval and de-commissioning workflow for hosting local models?",
                "suggested_mitigation": "Configure AWS Security Hub / Google Cloud App Hub to catalog sanctioned models, and implement SCP/Organization policies to block unauthorized ports."
            })

        return questions_to_ask

    def generate_active_remediations(self, failed_controls: List[str]) -> Dict[str, Any]:
        """
        Generates the exact remediation configurations for the failed controls.
        """
        remediations = {}

        if "AWS-BED-01" in failed_controls:
            remediations["aws_bedrock_guardrail"] = {
                "name": "aispr-bedrock-guardrail-prod",
                "contentPolicyConfig": {
                    "filtersConfig": [{"type": "PROMPT_ATTACK", "inputStrength": "HIGH", "outputStrength": "NONE"}]
                }
            }

        if "SHADOW-AI-01" in failed_controls:
            remediations["terraform_organization_policy"] = """
resource "google_org_policy_policy" "restrict_vertex_workbench" {
  name   = "projects/PROJECT_ID/policies/vertexai.restrictWorkbench"
  parent = "projects/PROJECT_ID"
  spec {
    rules {
      deny_all = "true"
    }
  }
}
"""
        return remediations
```

---

## 5. Deployment & Integration Checklist (GitOps via Jetsky)
To deploy this proprietary product in a production-ready containerized service, leverage your **g-jsaccomani** Git organization:

1. **Host as a Standalone Cloud Run/ECS Service:** Deploy the orchestrator core inside a private network, communicating only via HTTPS regional endpoints to protect customer log data.
2. **Implement mTLS-based Trust Perimeters:** Enforce strict access control over the scanner engine. Use Workload Identity Federation so that the agent's active token is verified and short-lived.
3. **Continuous Updates via CI/CD:** Establish validation pipelines to test the scanner scripts against mock environments before promoting code changes, keeping the engine robust and error-free.

<!-- Checkpoint: 2026-03-09 - sec(governance): update AI security checklist for external financial client -->

<!-- Checkpoint: 2026-03-15 - sec(threat-intel): update adversarial attack taxonomy for client production models -->

<!-- Checkpoint: 2026-04-14 - sec(red-teaming): incorporate automated prompt fuzzing test suite for client staging model -->

<!-- Checkpoint: 2026-04-15 - sec(threat-intel): update adversarial attack taxonomy for client production models -->

<!-- Checkpoint: 2026-04-16 - docs(delivery): finalize AI posture executive report for client security committee -->
