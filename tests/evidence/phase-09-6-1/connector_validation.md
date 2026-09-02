# Validation: Cloud Connectors Read-Only & Fallback Propagation

## Date
2026-09-02T18:37:15.510419+00:00

## Git Commit Before Test
`9fc8b7490f8907a2843586121a340199e82bbfc8`

## Environment
macOS (Darwin 24.6.0), Python 3.14.5, AISPR Specification 2.0.0

## Connector Execution Matrix

| Provider & Path | Expected Result | Actual Observed Output | Result |
| :--- | :--- | :--- | :--- |
| **AWS Simulation Path** | `execution_mode == SIMULATION, evidence unverified` | `Mode: SIMULATION, Ev: UNVERIFIED` | PASS |
| **AWS Fallback Path** | `execution_mode == FALLBACK with failure metadata` | `Mode: FALLBACK, Reason: AWS SDK 'boto3' is not installed. Run 'pip install...` | PASS |
| **Azure Simulation Path** | `execution_mode == SIMULATION, evidence unverified` | `Mode: SIMULATION, Ev: UNVERIFIED` | PASS |
| **Azure Fallback Path** | `execution_mode == FALLBACK with failure metadata` | `Mode: FALLBACK, Reason: Azure Management SDK 'azure-mgmt-cognitiveservices...` | PASS |
| **GCP Simulation Path** | `execution_mode == SIMULATION, evidence unverified` | `Mode: SIMULATION, Ev: UNVERIFIED` | PASS |
| **GCP Fallback Path** | `execution_mode == FALLBACK with failure metadata` | `Mode: FALLBACK, Reason: GCP SDKs ('google-auth', 'google-cloud-asset') are...` | PASS |

---

## Fallback Metadata Contracts

### AWS Fallback Metadata
```json
{
  "provider": "aws",
  "attempted_operation": "aws:discover_resources_live",
  "failure_reason": "AWS SDK 'boto3' is not installed. Run 'pip install boto3' to enable live AWS discovery.",
  "fallback_source": "LOCAL_SIMULATED_FIXTURE",
  "timestamp": "2026-09-02T18:38:32.301234+00:00"
}
```

### Azure Fallback Metadata
```json
{
  "provider": "azure",
  "attempted_operation": "azure:discover_resources_live",
  "failure_reason": "Azure Management SDK 'azure-mgmt-cognitiveservices' is not installed.",
  "fallback_source": "LOCAL_SIMULATED_FIXTURE",
  "timestamp": "2026-09-02T18:38:32.301604+00:00"
}
```

### GCP Fallback Metadata
```json
{
  "provider": "gcp",
  "attempted_operation": "gcp:discover_resources_live",
  "failure_reason": "GCP SDKs ('google-auth', 'google-cloud-asset') are not installed. Run 'pip install google-auth google-cloud-asset' to enable live GCP discovery.",
  "fallback_source": "LOCAL_SIMULATED_FIXTURE",
  "timestamp": "2026-09-02T18:38:32.302165+00:00"
}
```
