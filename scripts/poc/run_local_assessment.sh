#!/bin/bash
# ==============================================================================
# Agentic AISPR - Unified Local & Offline Posture Assessment Runner
# Authored by: Joabson Saccomani (@jsaccomani) | Google Cloud Security Consultant
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

echo "================================================================================"
echo "🛡️  AGENTIC AISPR - UNIFIED LOCAL SECURITY POSTURE ASSESSMENT"
echo "   Google SAIF • NIST AI RMF • ISO 42001 • MITRE ATLAS • EU AI Act & LGPD"
echo "================================================================================"
echo ""

REPORTS_DIR="$PROJECT_ROOT/reports"
mkdir -p "$REPORTS_DIR"

echo "📦 [1/4] Generating AI-BOM (AI Software Bill of Materials)..."
python3 -c "
from agentic.threat_operations.ai_bom_generator import AIBOMGenerator
import json
generator = AIBOMGenerator('$PROJECT_ROOT')
bom = generator.generate_bom()
with open('$REPORTS_DIR/ai_bom.json', 'w') as f:
    json.dump(bom, f, indent=2)
print(f'   ✅ AI-BOM generated: {bom[\"metadata\"][\"total_models_detected\"]} models, {bom[\"metadata\"][\"total_ml_libraries_detected\"]} ML packages.')
"

echo "💻 [2/4] Executing Static Prompt SAST (Insecure Interpolations & Concat)..."
python3 -c "
from agentic.threat_operations.static_prompt_sast import scan_repository_for_prompt_sast
import json
findings = scan_repository_for_prompt_sast('$PROJECT_ROOT')
with open('$REPORTS_DIR/sast_findings.json', 'w') as f:
    json.dump(findings, f, indent=2)
print(f'   ✅ SAST scan completed: {len(findings)} prompt injection risks identified.')
"

echo "🌐 [3/4] Running Multi-Cloud Static CLI Posture Checks (GCP, AWS, Azure)..."
python3 -c "
from agentic.threat_operations.multi_cloud_posture_scanner import MultiCloudPostureScanner
import json
scanner = MultiCloudPostureScanner()
results = scanner.scan_all_clouds()
with open('$REPORTS_DIR/multicloud_posture.json', 'w') as f:
    json.dump(results, f, indent=2)
print('   ✅ Multi-Cloud audit completed.')
"

echo "⚔️ [4/4] Executing MITRE ATLAS Red Teaming Simulator & Model Armor Verification..."
python3 -c "
from agentic.threat_operations.ai_red_team_simulator import AIRedTeamSimulator
import json
sim = AIRedTeamSimulator()
report = sim.execute_campaign()
with open('$REPORTS_DIR/redteam_campaign.json', 'w') as f:
    json.dump(report, f, indent=2)
print(f'   ✅ Red Team Campaign: {report[\"metrics\"][\"defense_efficacy_percentage\"]}% defense efficacy against MITRE ATLAS.')
"

echo ""
echo "================================================================================"
echo "🎉 ALL LOCAL ASSESSMENTS COMPLETED SUCCESSFULLY!"
echo "   Artifacts saved to: $REPORTS_DIR/"
echo "================================================================================"
