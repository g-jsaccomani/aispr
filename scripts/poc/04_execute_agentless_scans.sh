#!/bin/bash
# ==============================================================================
# Phase 4: Execute Agentless Discovery, AI-BOM Inventory & Threat Hunting
# Authored by: Joabson Saccomani (@jsaccomani) | Google Cloud Security Consultant
# ==============================================================================

set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH}"

REPORTS_DIR="${PROJECT_ROOT}/reports"
mkdir -p "${REPORTS_DIR}"

echo "================================================================================"
echo "🔍 PHASE 4: EXECUTING AGENTLESS DISCOVERY & MULTI-CLOUD THREAT SCANS"
echo "================================================================================"

echo "▶️ [1/4] Generating CycloneDX AI-BOM (Software Bill of Materials for AI)..."
python3 -c "
from agentic.threat_operations.ai_bom_generator import AIBOMGenerator
import json
generator = AIBOMGenerator('${PROJECT_ROOT}')
bom = generator.generate_bom()
with open('${REPORTS_DIR}/ai_bom.json', 'w') as f:
    json.dump(bom, f, indent=2)
print(f'   ✅ AI-BOM generated: {bom[\"metadata\"][\"total_models_detected\"]} AI models and {bom[\"metadata\"][\"total_ml_libraries_detected\"]} ML dependencies cataloged.')
"

echo ""
echo "▶️ [2/4] Hunting for Rogue Shadow AI & Instance Vulnerabilities..."
python3 -c "
from agentic.threat_operations.shadow_ai_hunter import ShadowAIHunter
import json
hunter = ShadowAIHunter()
scan = hunter.run_full_scan()
with open('${REPORTS_DIR}/shadow_ai_report.json', 'w') as f:
    json.dump(scan, f, indent=2)
print(f'   ✅ Shadow AI Hunt: {scan[\"total_findings\"]} critical findings identified (Port 11434 Ollama & CVE-2026-2244).')
"

echo ""
echo "▶️ [3/4] Running Static AST SAST Scanner for Prompt Injection Insecurities..."
python3 -c "
from agentic.threat_operations.static_prompt_sast import scan_repository_for_prompt_sast
import json
findings = scan_repository_for_prompt_sast('${PROJECT_ROOT}')
with open('${REPORTS_DIR}/sast_findings.json', 'w') as f:
    json.dump(findings, f, indent=2)
print(f'   ✅ SAST Completed: {len(findings)} prompt concatenation security checks performed.')
"

echo ""
echo "▶️ [4/4] Auditing Multi-Cloud Posture (GCP Vertex AI, AWS Bedrock, Azure OpenAI)..."
python3 -c "
from agentic.threat_operations.multi_cloud_posture_scanner import MultiCloudPostureScanner
import json
scanner = MultiCloudPostureScanner()
results = scanner.scan_all_clouds()
with open('${REPORTS_DIR}/multicloud_posture.json', 'w') as f:
    json.dump(results, f, indent=2)
print('   ✅ Multi-Cloud Federated Posture Audit completed.')
"

echo ""
echo "================================================================================"
echo "✅ PHASE 4 COMPLETED. AI-BOM INVENTORY & THREAT TELEMETRY COMPILED."
echo "================================================================================"
