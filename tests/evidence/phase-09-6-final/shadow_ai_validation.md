# Validation

## Timestamp
2026-09-02T18:59:14.931572+00:00

## Git SHA Before Validation
24119484fd57f2904d5520ec796ac75b45d0128d

## Command
Practical execution of `ShadowAIHunter.run_full_scan()` across:
1. `ExecutionMode.SIMULATION` (scenario fixtures)
2. `ExecutionMode.LIVE` (mocked provider boundary returning `projects/live-corp/clusters/us-central1-k8s/namespaces/ml-infra/pods/vllm-serving-7x`)
3. `ExecutionMode.LIVE` with provider API failure (`fallback_on_error=True`)

## Expected Result
1. In `SIMULATION`: Synthetic findings allowed, evidence is `SIMULATED`, confidence != `OBSERVED`, evidence != `VERIFIED`.
2. In `LIVE`: Resource originates exclusively from mocked provider discovery response (`projects/live-corp/clusters/us-central1-k8s/namespaces/ml-infra/pods/vllm-serving-7x`), execution mode is `LIVE`, evidence is `VERIFIED`, confidence is `OBSERVED`.
3. Hardcoded fixtures (`gke-credit-risk-prod`, `gce-sandbox`, `workbench-analyst-gpu-01`) MUST NOT be reported as VERIFIED LIVE.
4. On provider failure with fallback: Execution mode degrades to `FALLBACK`, zero fabricated live findings, failure metadata captured.

## Actual Result

### Test Matrix
| Scenario | Requested Mode | Provider Response | Result | Execution Mode | Evidence Status | Confidence | Resource Source | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Simulation Scan** | `SIMULATION` | N/A (offline fixtures) | 4 findings | `SIMULATION` | `SIMULATED` | `SUSPECTED` / `INFERRED` | Local simulation scenario | PASS |
| **Live Discovery Scan** | `LIVE` | 1 workload (`projects/live-corp/clusters/us-central1-k8s/namespaces/ml-infra/pods/vllm-serving-7x`) | 1 finding | `LIVE` | `VERIFIED` | `OBSERVED` | Mocked live GCP discovery API | PASS |
| **Live API Failure Fallback** | `LIVE` | `RuntimeError: 503` | 0 findings | `FALLBACK` | N/A (zero findings) | N/A | Explicit failure fallback metadata | PASS |
| **Fixture Quarantine Check** | `LIVE` | Custom live workload | 0 fixtures in live | `LIVE` | `VERIFIED` | `OBSERVED` | Confirmed: no simulation fixture promoted | PASS |

### Practical Execution Records

#### 1. Simulation Scan Output (Complete Record)
```json
{
  "project_id": "demo-enterprise",
  "execution_mode": "SIMULATION",
  "engine_classification": "OFFLINE_SIMULATION_HARNESS",
  "status": "COMPLETED",
  "total_findings": 4,
  "shadow_ai_detected": 2,
  "vulnerabilities_detected": 2,
  "summary": {
    "critical": 2,
    "high": 2,
    "medium": 0,
    "low": 0
  },
  "findings": {
    "shadow_ai": [
      {
        "finding_id": "SHADOW-GCP-K8S-01",
        "asset": "gke-credit-risk-prod/credit-risk-analytics/ollama-inference-daemon-7b89f",
        "provider": "gcp",
        "source": "cloud resources",
        "timestamp": "2026-09-02T19:00:27.661884+00:00",
        "confidence": "SUSPECTED",
        "execution_mode": "SIMULATION",
        "fixture_classification": "SIMULATION_SCENARIO",
        "severity": "CRITICAL",
        "category": "Unmanaged Local LLM Engine",
        "engine": "Ollama (Llama-3-70B)",
        "cluster": "gke-credit-risk-prod",
        "namespace": "credit-risk-analytics",
        "pod_name": "ollama-inference-daemon-7b89f",
        "port": 11434,
        "exposure": "INTERNAL_VPC_UNAUTHENTICATED",
        "risk": "Rogue LLM instance accepting uninspected internal prompts without Cloud DLP or Model Armor.",
        "mitigation": "Enforce admission controllers blocking unapproved container images and isolate port 11434 via NetworkPolicy.",
        "discovery_method": "SIMULATED_WORKLOAD_SPEC_INSPECTION",
        "provenance": "Simulation fixture scenario in namespace credit-risk-analytics.",
        "evidence": {
          "content_hash": "3105a4a2213d0e8630b4aeba92dff0bcfd001abc833053bf9093909a756654fa",
          "status": "SIMULATED"
        }
      },
      {
        "finding_id": "SHADOW-GCP-GCE-02",
        "asset": "gce-sandbox/default/ml-dev-sandbox-vm",
        "provider": "gcp",
        "source": "cloud resources",
        "timestamp": "2026-09-02T19:00:27.661884+00:00",
        "confidence": "SUSPECTED",
        "execution_mode": "SIMULATION",
        "fixture_classification": "SIMULATION_SCENARIO",
        "severity": "HIGH",
        "category": "Unmanaged Local LLM Engine",
        "engine": "vLLM Inference Server",
        "cluster": "gce-sandbox",
        "namespace": "default",
        "pod_name": "ml-dev-sandbox-vm",
        "port": 8000,
        "exposure": "VPC_PEERING_ACCESSIBLE",
        "risk": "Developer instance running vLLM with world-readable local logs logging raw financial prompts.",
        "mitigation": "Quarantine compute instance and migrate workload to managed Vertex AI Private Endpoints.",
        "discovery_method": "SIMULATED_COMPUTE_PROCESS_SCAN",
        "provenance": "Simulation fixture scenario in gce-sandbox.",
        "evidence": {
          "content_hash": "690f0b3d9f6e3e53a9d9835b84f387f75148990fa5807aa7c2c0265578301ff7",
          "status": "SIMULATED"
        }
      }
    ],
    "workbench_vulnerabilities": [
      {
        "finding_id": "VULN-GCP-WB-01",
        "asset": "projects/demo-enterprise/zones/southamerica-east1-a/instances/workbench-analyst-gpu-01",
        "provider": "gcp",
        "source": "infrastructure metadata",
        "timestamp": "2026-09-02T19:00:27.661917+00:00",
        "confidence": "INFERRED",
        "execution_mode": "SIMULATION",
        "fixture_classification": "SIMULATION_SCENARIO",
        "cve": "CVE-2026-2244",
        "severity": "CRITICAL",
        "resource_name": "workbench-analyst-gpu-01",
        "zone": "southamerica-east1-a",
        "vulnerability_type": "OAuth Token Exposure in World-Readable Logs",
        "risk": "Custom startup script writes Google Cloud access token to world-readable disk log (/var/log/startup.log).",
        "mitigation": "Update metadata to remove sensitive tokens and redeploy with Shielded VM and CMEK.",
        "discovery_method": "SIMULATED_WORKBENCH_METADATA_INSPECTION",
        "provenance": "Simulation fixture scenario in zone southamerica-east1-a.",
        "evidence": {
          "content_hash": "25a80a41b7a56ea0758cf717adcb4863e0252bb6e28ef4a23ea6eac2a4e4df44",
          "status": "SIMULATED"
        }
      },
      {
        "finding_id": "VULN-GCP-WB-02",
        "asset": "projects/demo-enterprise/zones/southamerica-east1-a/instances/workbench-analyst-gpu-01",
        "provider": "gcp",
        "source": "infrastructure metadata",
        "timestamp": "2026-09-02T19:00:27.661917+00:00",
        "confidence": "SUSPECTED",
        "execution_mode": "SIMULATION",
        "fixture_classification": "SIMULATION_SCENARIO",
        "cve": "MISCONFIG-PUBLIC-IP",
        "severity": "HIGH",
        "resource_name": "workbench-analyst-gpu-01",
        "zone": "southamerica-east1-a",
        "vulnerability_type": "Direct Internet Access (Public IP Enabled)",
        "risk": "Vertex AI Workbench instance is accessible directly via public IPv4 address without Cloud IAP.",
        "mitigation": "Disable public IP and enforce VPC-SC perimeter ingress rules.",
        "discovery_method": "SIMULATED_NETWORK_INTERFACE_INSPECTION",
        "provenance": "Simulation fixture scenario of networkInterfaces.",
        "evidence": {
          "content_hash": "a1ae2aab65e7c8b71936d45b1882b3534959f2cb5d8540f28416f282b91fd843",
          "status": "SIMULATED"
        }
      }
    ]
  }
}
```

#### 2. Live Scan with Mocked Provider Boundary (Complete Record)
```json
{
  "project_id": "live-corp",
  "execution_mode": "LIVE",
  "engine_classification": "LIVE_ENTERPRISE_DISCOVERY",
  "status": "COMPLETED",
  "total_findings": 1,
  "shadow_ai_detected": 1,
  "vulnerabilities_detected": 0,
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": {
    "shadow_ai": [
      {
        "finding_id": "SHADOW-LIVE-DISCOVERED-99",
        "asset": "projects/live-corp/clusters/us-central1-k8s/namespaces/ml-infra/pods/vllm-serving-7x",
        "provider": "gcp",
        "source": "cloud resources",
        "timestamp": "2026-09-02T19:00:27.662076+00:00",
        "confidence": "OBSERVED",
        "execution_mode": "LIVE",
        "status": "OBSERVED",
        "severity": "CRITICAL",
        "category": "Unmanaged Local LLM Engine",
        "engine": "vLLM-Production-Cluster",
        "cluster": "us-central1-k8s",
        "namespace": "ml-infra",
        "pod_name": "vllm-serving-7x",
        "port": 8000,
        "exposure": "VPC_INTERNAL",
        "risk": "Live discovered unmanaged AI workload.",
        "mitigation": "Enforce admission controllers and migrate to managed endpoints.",
        "discovery_method": "LIVE_GCP_API_DISCOVERY",
        "provenance": "Discovered via read-only live GCP API for project 'live-corp'.",
        "evidence": {
          "content_hash": "a6894eabdb39627eeef45ac9ca871087d6f8332cbad589a7fef310167ea1df69",
          "status": "VERIFIED",
          "collected_from": "projects/live-corp/clusters/us-central1-k8s/namespaces/ml-infra/pods/vllm-serving-7x"
        }
      }
    ],
    "workbench_vulnerabilities": []
  }
}
```

#### 3. Live Failure Fallback Output (Complete Record)
```json
{
  "project_id": "live-corp",
  "execution_mode": "FALLBACK",
  "engine_classification": "DEGRADED_FALLBACK_HARNESS",
  "status": "COMPLETED",
  "total_findings": 0,
  "shadow_ai_detected": 0,
  "vulnerabilities_detected": 0,
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": {
    "shadow_ai": [],
    "workbench_vulnerabilities": []
  },
  "fallback_metadata": {
    "provider": "gcp",
    "attempted_operation": "gcp:shadow_ai_live_discovery",
    "failure_reason": "GCP Cloud Asset Inventory API 503 Service Unavailable",
    "fallback_source": "DEGRADED_LOCAL_SCAN",
    "timestamp": "2026-09-02T19:00:27.662185+00:00"
  }
}
```

## Result
PASS
