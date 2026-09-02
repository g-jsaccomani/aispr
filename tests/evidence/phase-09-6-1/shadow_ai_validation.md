# Validation: Shadow AI Provider Discovery & Provenance

## Date
2026-09-02T18:37:15.510419+00:00

## Git Commit Before Test
`9fc8b7490f8907a2843586121a340199e82bbfc8`

## Environment
macOS (Darwin 24.6.0), Python 3.14.5, AISPR Specification 2.0.0

## Practical Validation Matrix

| Test Case | Command / Method | Expected Behavior | Actual Result | Result |
| :--- | :--- | :--- | :--- | :--- |
| **Test 1: Simulation Mode Fixtures** | `hunter = ShadowAIHunter(mode=SIMULATION)` | Synthetic assets allowed, evidence is SIMULATED, no VERIFIED evidence | `Mode: SIMULATION, All Evidence SIMULATED: True` | PASS |
| **Test 2: Live Mode Provider Discovery** | `hunter = ShadowAIHunter(mode=LIVE, connector=mock)` | Real asset from provider response, evidence VERIFIED, confidence OBSERVED | `Asset: projects/live-corp/clusters/k8s-prod-cluster/namespaces/ai-team/pods/custom-vllm-daemon-89ab, Mode: LIVE, Status: OBSERVED, Ev: VERIFIED` | PASS |
| **Test 3A: Live API Failure Degrades to Fallback** | `hunter = ShadowAIHunter(mode=LIVE, fallback_on_error=True)` | Mode FALLBACK, metadata recorded, NO fabricated LIVE assets | `Mode: FALLBACK, Findings: 0, Reason: GCP API 503 Service Unavailable` | PASS |
| **Test 3B: Live API Failure Fail Closed** | `hunter = ShadowAIHunter(mode=LIVE, fallback_on_error=False)` | Raise underlying discovery exception | `Raised RuntimeError: True` | PASS |
| **Test 4: Fixture Quarantine from Live** | Audit live findings for synthetic fixtures | Hardcoded fixtures (`gke-credit-risk-prod`, etc.) never appear as VERIFIED LIVE | `Fixtures appeared in LIVE: False` | PASS |

---

## Practical Execution Records

### 1. Simulation Scan Output (Complete Record)
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
        "timestamp": "2026-09-02T18:38:32.230566+00:00",
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
        "timestamp": "2026-09-02T18:38:32.230566+00:00",
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
        "timestamp": "2026-09-02T18:38:32.230595+00:00",
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
        "timestamp": "2026-09-02T18:38:32.230595+00:00",
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

### 2. Live Scan with Mocked Provider Discovery (Complete Record)
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
        "finding_id": "SHADOW-LIVE-DISCOVERED-01",
        "asset": "projects/live-corp/clusters/k8s-prod-cluster/namespaces/ai-team/pods/custom-vllm-daemon-89ab",
        "provider": "gcp",
        "source": "cloud resources",
        "timestamp": "2026-09-02T18:38:32.230720+00:00",
        "confidence": "OBSERVED",
        "execution_mode": "LIVE",
        "status": "OBSERVED",
        "severity": "CRITICAL",
        "category": "Unmanaged Local LLM Engine",
        "engine": "vLLM-Production",
        "cluster": "k8s-prod-cluster",
        "namespace": "ai-team",
        "pod_name": "custom-vllm-daemon-89ab",
        "port": 8000,
        "exposure": "INTERNAL_VPC",
        "risk": "Live discovered unmanaged AI workload.",
        "mitigation": "Enforce admission controllers and migrate to managed endpoints.",
        "discovery_method": "LIVE_GCP_API_DISCOVERY",
        "provenance": "Discovered via read-only live GCP API for project 'live-corp'.",
        "evidence": {
          "content_hash": "089879a8506f590d12ce843a0453cb865b97fdecf4e525c3da087260b0fa950f",
          "status": "VERIFIED",
          "collected_from": "projects/live-corp/clusters/k8s-prod-cluster/namespaces/ai-team/pods/custom-vllm-daemon-89ab"
        }
      }
    ],
    "workbench_vulnerabilities": []
  }
}
```

### 3. Live Failure Fallback Scan (Complete Record)
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
    "failure_reason": "GCP API 503 Service Unavailable",
    "fallback_source": "DEGRADED_LOCAL_SCAN",
    "timestamp": "2026-09-02T18:38:32.230964+00:00"
  }
}
```
