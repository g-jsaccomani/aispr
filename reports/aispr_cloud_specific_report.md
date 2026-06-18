# AI-SPR Cloud-by-Cloud Tactical Engineering Report
**Client Organization:** Enterprise Customer
**Date:** 2026-08-17
**Audited Clouds:** Google Cloud Platform (GCP) • Amazon Web Services (AWS) • Microsoft Azure

---
## 1. Google Cloud Platform (GCP) AI Security Assessment
**Primary Scope:** `your-gcp-project-id` (Vertex AI, GKE, Cloud KMS, SCC AI Protection)

| Asset Name | Resource Type | CMEK Key | Guardrail | Threat / Vulnerability | Remediation |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `vertex-credit-scoring-v2` | Vertex Endpoint | No None | No None | Unshielded prompt injection target | Deploy Model Armor policy |
| `gemini-1.5-pro-financial-rag` | Foundation Model | Yes Cloud KMS | Warning Missing Filter | Jailbreak risk on financial queries | Attach Model Armor semantic floor |
| `workbench-analyst-gpu-01` | Vertex Workbench | No Default | N/A |  **CVE-2026-2244**: Public IP & Token Leak | Enforce `disable_public_ip = true` via Terraform |
| `k8s://credit-risk/ollama-pod` | GKE Shadow AI | No Default | No None |  **Port 11434 Rogue LLM Daemon** | Apply K8s NetworkPolicy to block Port 11434 |
| `gs://demo-credit-rag` | Cloud Storage RAG | No Default | IAM | Unencrypted vector store | Attach `demo-ai-cmek-key` |

### GCP Terraform Remediation Blueprint Snippet:
```hcl
# Enforce No Public IP on Vertex AI Workbench
resource "google_workbench_instance" "hardened_workbench" {
  name     = "workbench-analyst-gpu-01"
  location = "southamerica-east1-a"
  gce_setup {
    disable_public_ip = true
  }
}
```

## 2. Amazon Web Services (AWS) AI Security Assessment
**Primary Scope:** AWS Account `123456789012` (Amazon Bedrock, SageMaker, S3 RAG Buckets)

| Asset Name | Resource Type | KMS Encryption | Guardrail | Threat / Vulnerability | Remediation |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `anthropic.claude-3-5-sonnet` | Bedrock Foundation Model | Yes AWS KMS | No None | Missing Bedrock Guardrail filter | Attach Bedrock Guardrail with PII filters |
| `sagemaker-fraud-detection` | SageMaker Endpoint | No Unencrypted | N/A | Missing KMS CMEK encryption | Re-create endpoint with KMS key ARN |
| `s3://demo-bedrock-knowledge` | S3 Knowledge Base | No S3-Managed | IAM | Missing Customer Managed KMS | Enable `aws_kms_key` SSE-KMS |

### AWS Terraform Remediation Blueprint Snippet:
```hcl
resource "aws_bedrock_guardrail" "financial_guardrail" {
  name        = "demo-ai-bedrock-guardrail"
  description = "Blocks prompt injection and redacts financial PII"
}
```

## 3. Microsoft Azure AI Security Assessment
**Primary Scope:** Azure Subscription `sub-000-111-222` (Azure OpenAI, Azure AI Search)

| Asset Name | Resource Type | Key Vault CMEK | Private Endpoint | Threat / Vulnerability | Remediation |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `aoai-customer-service-gpt4o` | Azure OpenAI Service | Yes Key Vault | No Public Active | Public IP exposes API to brute-force | Disable `public_network_access_enabled` |
| `azure-search-credit-rag` | Azure AI Search | No Microsoft Key | No Public Active | Vector database missing private link | Provision Private Endpoint & Customer Key |

### Azure Terraform Remediation Blueprint Snippet:
```hcl
resource "azurerm_cognitive_account" "secure_openai" {
  name                          = "aoai-customer-service-gpt4o"
  public_network_access_enabled = false
}
```

<!-- Checkpoint: 2026-02-19 - docs(delivery): finalize AI posture executive report for client security committee -->

<!-- Checkpoint: 2026-03-17 - sec(red-teaming): incorporate automated prompt fuzzing test suite for client staging model -->

<!-- Checkpoint: 2026-04-09 - sec(red-teaming): incorporate automated prompt fuzzing test suite for client staging model -->

<!-- Checkpoint: 2026-05-15 - sec(red-teaming): incorporate automated prompt fuzzing test suite for client staging model -->

<!-- Checkpoint: 2026-06-18 - sec(threat-intel): update adversarial attack taxonomy for client production models -->
