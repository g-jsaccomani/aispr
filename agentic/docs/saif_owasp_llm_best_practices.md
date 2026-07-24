# AI Security Posture Review (AI SPR) — SAIF & OWASP LLM Top 10 Baseline (2026)

This document defines the defense controls, architectures, and governance guidelines for applications with Generative Artificial Intelligence, Autonomous Agents, and LLMs, aligned with the **Google Secure AI Framework (SAIF)** and the **OWASP Top 10 for LLM Applications (2026)**.

---

## 1. Controls against Model Attacks (OWASP LLM Top 10)

| OWASP LLM Vulnerability | Main Risk | Recommended Control / Mitigation (SAIF) |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Injection of malicious instructions through user input or retrieved data (RAG) to subvert the agent. | Strictly separate system instructions from untrusted data; implement input filters (Model Armor / Guardrails). |
| **LLM02: Sensitive Information Disclosure** | Accidental exfiltration or leak of personal data (PII) or company secrets in LLM responses. | Mandatory integration of Sensitive Data Protection (formerly DLP) before sending prompts to models and in the output to the user. |
| **LLM03: Excessive Agency** | Granting high-privilege permissions to AI agents that make decisions or call tools autonomously. | Principle of Least Privilege for agent tools; mandatory human-in-the-loop for deletions, payments, or infrastructure mutations. |
| **LLM04: Supply Chain** | Compromise of open model weights (HuggingFace), Python dependencies, or tampered plugins. | Store certified models and packages in private Artifact Registry with vulnerability scanning and signature verification. |
| **LLM05: Data and Model Poisoning** | Manipulation of training or synthetic data to introduce backdoors and biases. | Validate data provenance with cryptographic signatures (SLSA for ML) and inspect RAG sources. |
| **LLM06: Unbounded Consumption** | Computational overload of the model via extensive prompts or recursive loops in autonomous agents. | Rate limits (Rate Limiting via Cloud Armor/Apigee), token window limitation, and strict timeouts per execution. |
| **LLM07: Misinformation** | The model generates incorrect, unsupported, or misleading information that is trusted by downstream processes. | Ground outputs in authoritative sources, require human-in-the-loop for high-impact actions, implement Claim-Check-Act patterns. |
| **LLM08: Hidden Context Exposure** | Unauthorized extraction of hidden system instructions or operational context placed in a model's context. | Do not embed secrets directly in the system prompt; enforce authorization and access control independently from the LLM. |
| **LLM09: Vector and Embedding Weaknesses** | Exploitation of the embedding layer and similarity search to extract data or bypass controls. | Apply access control at the chunk level, normalize content before embedding, and segregate data by trust tier. |
| **LLM10: Improper Output Handling** | Blind execution of LLM-generated output in shell commands, SQL, or browsers without sanitation. | Treat LLM outputs as untrusted external data; sanitize outputs before rendering or executing in APIs/databases. |

---

## 2. Implementation of Google Secure AI Framework (SAIF)

1. **Expand Strong Security Foundations**:
   - Apply strict IAM and CMEK encryption to GCS buckets and Vertex AI instances containing embedding data, vector stores (Vertex AI Vector Search), and model weights.
2. **Extend Access Controls to AI Agents**:
   - Service accounts used by agents must have specific read-only scopes or limited tools (`roles/aiplatform.user` in dedicated scopes).
3. **Automated Defenses in Runtime (Model Armor)**:
   - Application of toxicity filters, real-time Prompt Injection detection, and automatic obfuscation of banking/PII data.

<!-- Checkpoint: 2026-07-24 - docs(delivery): finalize AI posture executive report for client security committee -->
