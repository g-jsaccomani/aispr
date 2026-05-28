# AI-SPR Workshop: Technical Kickoff Agenda & Slide Deck

**Lead AI Security Architect:** `@jsaccomani`
**Engagement:** AI Security Posture Review (AI-SPR)
**Framework Alignment:** Google SAIF, NIST AI RMF 1.0, ISO/IEC 42001, MITRE ATLAS, OWASP Top 10 for LLM

---

## Executive Overview & Purpose

The **AI Security Posture Review (AI-SPR)** workshop is a structured, collaborative engagement designed to evaluate, baseline, and harden enterprise Generative AI and Large Language Model (LLM) architectures deployed across Google Cloud and hybrid environments.

---

## Workshop Agenda (2-Day Format)

### Day 1: Architecture Mapping & Governance Discovery
* **09:00 - 09:30** | **Session 1: Executive Alignment & Scope Definition**
  * Business objectives, regulatory constraints (EU AI Act, ISO 42001, LGPD/GDPR), and platform inventory.
* **09:30 - 11:00** | **Session 2: Data Security & Integrity (Domain 1)**
  * RAG data pipelines, fine-tuning dataset provenance, and data classification (SDP / Cloud DLP).
* **11:15 - 12:45** | **Session 3: Model Hardening & Management (Domain 2)**
  * Foundation model sourcing, Model Registry, serialization safeguards (Pickle-in-the-Middle), and SLSA for AI.
* **14:00 - 16:00** | **Session 4: Application Security & Semantic Gateways (Domain 3)**
  * Prompt injection defenses, Model Armor configuration, output sanitization, and agentic plugin constraints.

### Day 2: Infrastructure Hardening & Deliverable Review
* **09:00 - 10:30** | **Session 5: Infrastructure Isolation & IAM (Domain 4)**
  * VPC Service Controls (VPC-SC), Private Service Connect (PSC), Service Account Impersonation, and CMEK.
* **10:45 - 12:15** | **Session 6: Security Assurance & Monitoring (Domain 5)**
  * Prompt I/O telemetry export to Google SecOps (Chronicle SIEM), anomaly detection, and AI Incident Response.
* **13:30 - 15:00** | **Session 7: AI Governance & Compliance (Domain 6)**
  * AI-BOM supply chain tracking, role definitions, and risk management integration.
* **15:30 - 17:00** | **Session 8: Preliminary Findings & CAPA Roadmap Readout**
  * Presentation of initial posture scores, High-severity gaps, and next steps for the Executive Deliverable.

---

## Presentation Slides Outline

### Slide 1: Welcome & Context
* **Presenter:** @jsaccomani (Cloud Security Consultant)
* **Goal:** Establish a zero-trust security perimeter for enterprise AI systems.
* **Outcome:** Comprehensive Posture Scorecard + Actionable CAPA Hardening Roadmap.

### Slide 2: The Google Secure AI Framework (SAIF) Pillars
1. Expand strong security foundations to the AI ecosystem.
2. Extend detection and response to bring AI into the organization's threat universe.
3. Automate defenses to keep pace with existing and new threats.
4. Harmonize platform-level controls to provide consistent security.
5. Adapt controls to adjust mitigations and create faster feedback loops.
6. Contextualize AI system risks in business processes.

### Slide 3: The 6 AI-SPR Core Assessment Domains
1. **Data Security & Integrity:** Provenance, labeling, poisoning mitigation.
2. **Model Hardening:** Neural weight integrity, supply chain provenance, model registry.
3. **Application Security:** Semantic firewalls, Model Armor, prompt shielding, DLP masking.
4. **Infrastructure Security:** Private IP, VPC-SC, Workload Identity, CMEK encryption.
5. **Security Assurance:** SecOps telemetry, continuous red-teaming, SIEM detection rules.
6. **AI Governance:** AI-BOM inventory, policy compliance, accountability.

---
*Copyright © 2026 Google LLC / Joabson Saccomani. All rights reserved. Distributed under the Apache License 2.0.*

<!-- Checkpoint: 2026-03-30 - sec(governance): update AI security checklist for external financial client -->

<!-- Checkpoint: 2026-05-28 - sec(threat-intel): update adversarial attack taxonomy for client production models -->
