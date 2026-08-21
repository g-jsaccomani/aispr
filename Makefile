export PATH := $(HOME)/google-cloud-sdk/bin:/opt/homebrew/bin:/usr/local/bin:$(PATH)

.PHONY: test test-audit test-agentic audit audit-demo scan redteam guard multicloud dashboard ai-bom sast scan-multicloud scan-all local-assessment aispr-client-journey client-journey journey poc poc-client-journey poc-step1 poc-step2 poc-step3 poc-step4 poc-step5 poc-step6 model-armor model-armor-blueprint model-armor-deploy model-armor-verify teardown setup-aispr aispr-core validate-aispr teardown-aispr help

help:
	@echo "================================================================================"
	@echo "🛡️  AGENTIC AISPR - Multi-Cloud AI Security Posture Review (AI-SPM) Automation"
	@echo "================================================================================"
	@echo "🚀 PRIMARY ROOT ENTRYPOINTS:"
	@echo "  make setup-aispr      - Provision dedicated AISPR Core folder & project in GCP"
	@echo "  make validate-aispr   - Validate dedicated AISPR Core platform infrastructure"
	@echo "  make teardown-aispr   - Destroy dedicated AISPR Core platform environment"
	@echo "  make journey          - Interactive Client Onboarding Journey (Option 1 to 4)"
	@echo "  make poc              - Execute FULL 6-phase automated customer POC journey"
	@echo "  make model-armor      - Execute Model Armor 3-Pillar Journey (Consultive, IaC, Verify)"
	@echo "  ./aispr-client-journey - 1-Click root launcher for Client Journey"
	@echo "  ./run-poc             - 1-Click root launcher for Full POC"
	@echo ""
	@echo "📋 AISPR CORE PLATFORM (scripts/core/):"
	@echo "  make setup-aispr      - Setup fldr-aispr-platform folder, core project & runner"
	@echo "  make validate-aispr   - Check AISPR Core runner VM, Vertex AI and Storage"
	@echo "  make teardown-aispr   - Teardown AISPR Core project and folder"
	@echo ""
	@echo "📋 GRANULAR POC STAGES (scripts/poc/):"
	@echo "  make poc-step1        - Setup customer GCP project & AI resources (VPC, RAG, etc)"
	@echo "  make poc-step2        - Create Read-Only Service Account & Custom Auditor Role"
	@echo "  make poc-step3        - Deploy Agentic AISPR Web Interface to Cloud Run"
	@echo "  make poc-step4        - Run Agentless Scans (AI-BOM, Shadow AI, SAST)"
	@echo "  make poc-step5        - Run Full 104-Control Audit, Red Teaming & Reports"
	@echo "  make poc-step6        - Implement Model Armor Constructive, Consultive & Protective Defense"
	@echo "  make teardown         - Stop & delete all cloud resources and local servers"
	@echo ""
	@echo "🛡️  MODEL ARMOR IMPLEMENTATION ENGINE:"
	@echo "  make model-armor           - Run complete 3-pillar Model Armor journey"
	@echo "  make model-armor-blueprint - Generate Consultive Architecture Blueprint & Matrix"
	@echo "  make model-armor-deploy    - Generate Production Terraform IaC & App Middleware"
	@echo "  make model-armor-verify    - Execute Adversarial Evals & Issue Protection Certificate"
	@echo ""
	@echo "🧪 TESTING & VERIFICATION:"
	@echo "  make test             - Run full unit test suite (audit + agentic)"
	@echo "  make test-audit       - Run audit module tests (Phase 1)"
	@echo "  make test-agentic     - Run agentic SecOps & Multi-Cloud tests (Phase 2)"
	@echo ""
	@echo "📊 CONSULTING & AUDIT TOOLS (scripts/cli/):"
	@echo "  make audit            - Run interactive AI-SPR GRC assessment (104 controls)"
	@echo "  make audit-demo       - Run automated demonstration audit"
	@echo "  make scan-all         - Execute AI-BOM, SAST, and Multi-Cloud scans in batch"
	@echo "  make dashboard        - Launch Executive Web Dashboard & Copilot locally"

setup-aispr:
	bash scripts/core/00_setup_aispr_core_platform.sh

aispr-core: setup-aispr

validate-aispr:
	bash scripts/core/validate_aispr_core.sh

teardown-aispr:
	bash scripts/core/teardown_aispr_core.sh

journey:
	python3 scripts/journey/aispr_client_journey.py

aispr-client-journey: journey

apispr-client-journey: journey

client-journey: journey

poc:
	bash scripts/poc/run_full_poc_journey.sh

poc-client-journey: poc

poc-step1:
	bash scripts/poc/01_setup_customer_environment.sh

poc-step2:
	bash scripts/poc/02_create_readonly_auditor.sh

poc-step3:
	bash scripts/poc/03_deploy_cloud_run_platform.sh

poc-step4:
	bash scripts/poc/04_execute_agentless_scans.sh

poc-step5:
	bash scripts/poc/05_generate_audit_and_reports.sh

poc-step6:
	bash scripts/poc/06_implement_model_armor_defense.sh

model-armor:
	python3 scripts/cli/aispr_cli.py model-armor --mode all

model-armor-blueprint:
	python3 scripts/cli/aispr_cli.py model-armor --mode consultive

model-armor-deploy:
	python3 scripts/cli/aispr_cli.py model-armor --mode constructive

model-armor-verify:
	python3 scripts/cli/aispr_cli.py model-armor --mode protective

teardown:
	bash scripts/poc/teardown_environment.sh

test: test-audit test-agentic

test-audit:
	python3 -m unittest discover -s audit/tests -p "test_*.py" -v

test-agentic:
	python3 -m unittest discover -s agentic/tests -p "test_*.py" -v

ai-bom:
	python3 -c "from agentic.threat_operations.ai_bom_generator import AIBOMGenerator; import json, os; b = AIBOMGenerator('.').generate_bom(); os.makedirs('reports', exist_ok=True); json.dump(b, open('reports/ai_bom.json', 'w'), indent=2); print('AI-BOM generated successfully in reports/ai_bom.json')"

sast:
	python3 -c "from agentic.threat_operations.static_prompt_sast import scan_repository_for_prompt_sast; import json, os; f = scan_repository_for_prompt_sast('.'); os.makedirs('reports', exist_ok=True); json.dump(f, open('reports/sast_findings.json', 'w'), indent=2); print(f'SAST scan completed: {len(f)} findings in reports/sast_findings.json')"

scan-multicloud:
	python3 -c "from agentic.threat_operations.multi_cloud_posture_scanner import MultiCloudPostureScanner; import json, os; r = MultiCloudPostureScanner().scan_all_clouds(); os.makedirs('reports', exist_ok=True); json.dump(r, open('reports/multicloud_posture.json', 'w'), indent=2); print('Multi-Cloud Posture Scan completed in reports/multicloud_posture.json')"

scan-all: ai-bom sast scan-multicloud
	@echo "All Zero-Footprint security scans executed successfully."

local-assessment:
	bash scripts/poc/run_local_assessment.sh

audit:
	python3 scripts/cli/aispr_consulting_tool.py

audit-demo:
	python3 scripts/cli/aispr_consulting_tool.py --demo

scan:
	python3 scripts/cli/aispr_cli.py scan

redteam:
	python3 scripts/cli/aispr_cli.py redteam

guard:
	python3 scripts/cli/aispr_cli.py guard

multicloud:
	python3 scripts/cli/aispr_cli.py multicloud

dashboard:
	python3 agentic/ui/server.py 8501
