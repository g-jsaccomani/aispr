# AI-SPR Governance & Posture Review Engine (`audit`)

---
**Author & Security Architect:** Joabson Saccomani ([@jsaccomani](https://github.com/g-jsaccomani))
**Role:** Cloud Security Consultant
**LinkedIn:** [linkedin.com/in/jsaccomani](https://www.linkedin.com/in/jsaccomani)
*Copyright © 2026 Google LLC / Joabson Saccomani. All rights reserved. Distributed under the Apache License 2.0.*

**Framework Alignments:** Google SAIF, NIST AI RMF 1.0 (Govern & Map), ISO/IEC 42001 (AIMS), MITRE ATLAS, OWASP Top 10 for LLM Applications

---

## Overview

The `audit/` module provides a comprehensive Governance, Risk, and Compliance (GRC) assessment framework for enterprise Generative AI workloads. It offers:
1. **Interactive & Automated CLI Assessment Engine**: Evaluates 6 core AI security domains.
2. **Quantitative Risk Scoring**: Computes domain-level compliance percentages and classifies organizational posture tiers (`SECURE`, `MODERATE`, `CRITICAL`).
3. **Automated Executive Deliverables**: Generates publication-ready Markdown reports with prioritized Corrective and Preventive Action (CAPA) roadmaps.
4. **Conversational Copilot**: ADK-compatible conversational review loop with Google Cloud Security Command Center (SCC) pre-flight telemetry.

---

## Module Structure

```text
audit/
 README.md                      # Module documentation & runbook
 cli.py                         # Interactive and automated assessment CLI
 engine/
    scorer.py                  # Quantitative scoring & posture tier classification engine
    reporter.py                # Executive Markdown deliverable & CAPA generator
 questionnaire/
    questions.json             # Canonical database of 6 core domains & controls
    handler.py                 # Progressive questionnaire gating and state tracker
 agent/
    main.py                    # Conversational Copilot entrypoint (ADK + Gemini)
    state.py                   # Isolated session state storage
    tools.py                   # Connectors for GCP Security Command Center (SCC) AI findings
 config/
    gcloud_setup.sh            # Least-privilege IAM roles setup (AIP Viewer & Essentials)
 templates/
    final_report_template.md   # Executive report template
 presentation/
     kickoff_agenda.md          # 2-Day workshop agenda & presentation deck outline
```

---

## Execution & Usage

### 1. Interactive Assessment Walkthrough (Consultant Mode)
Launch the interactive CLI to guide client workshops and document findings in real-time:
```bash
python audit/cli.py --client "Acme Global Bank" --project "Credit Underwriting Gemini Agent" --output "reports/acme_aispr_report.md"
```

### 2. Automated Demonstration / Mock Mode
Run in headless or automated CI/CD pipelines to verify scoring and report generation:
```bash
python audit/cli.py --demo --output "reports/demo_aispr_report.md"
```

### 3. Least-Privilege IAM Provisioning
Deploy the custom `AIP Viewer` and `AIP Essentials` organizational roles in Google Cloud:
```bash
chmod +x audit/config/gcloud_setup.sh
./audit/config/gcloud_setup.sh
```

---

## The 6 Core Assessment Domains

1. **Data Security & Integrity (`DAT`)**: Data lineage, classification schemas, unauthenticated dataset partitioning, and poisoning prevention.
2. **Model Hardening & Management (`MOD`)**: Foundation model selection, Model Registry versioning, serialization integrity (Pickle-in-the-Middle mitigation), and adversarial red-teaming.
3. **Application Security & Protection (`APP`)**: Input validation, Model Armor semantic firewalling, PII/Sensitive Data Protection (DLP), and plugin rate limits.
4. **Infrastructure Security & Isolation (`INF`)**: CSPR baselining, VPC Service Controls, Private Service Connect (PSC), Workload Identity, and CMEK encryption.
5. **Security Assurance & Monitoring (`ASR`)**: Prompt I/O streaming to SecOps SIEM, real-time jailbreak alerting, and AI incident response playbooks.
6. **AI Governance & Compliance (`GOV`)**: Organizational accountability, AI-BOM supply chain cataloging, and global privacy regulation mapping (GDPR, CCPA, LGPD).

---
*Developed and maintained by @jsaccomani.*

<!-- Checkpoint: 2026-02-23 - sec(threat-intel): update adversarial attack taxonomy for client production models -->
