# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI Red Team Adversarial Attack Simulator & Defense Verification Harness
Engineered by: @jsaccomani
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Any

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
agentic_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(agentic_dir)
for p in [root_dir, agentic_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agentic.runtime_defense.model_armor_guard import ModelArmorGuard


class AIRedTeamSimulator:
    """
    Automated red-teaming emulator that evaluates model endpoints and semantic gateways
    against MITRE ATLAS and OWASP GenAI adversarial attack categories.
    """

    def __init__(self, dataset_path: str = None, guard: ModelArmorGuard = None):
        if dataset_path is None:
            dataset_path = os.path.join(agentic_dir, "datasets", "prompt_adversarial_examples.json")
        self.dataset_path = dataset_path
        self.guard = guard or ModelArmorGuard()
        self.test_cases = self._load_dataset()

    def _load_dataset(self) -> List[Dict[str, Any]]:
        if os.path.exists(self.dataset_path):
            with open(self.dataset_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def execute_campaign(self) -> Dict[str, Any]:
        """
        Runs all adversarial test cases against the Model Armor defense layer and computes metrics.
        """
        results = []
        blocked_count = 0
        sanitized_count = 0
        allowed_count = 0
        bypassed_count = 0

        for tc in self.test_cases:
            prompt = tc.get("prompt", "")
            expected = tc.get("expected_verdict", "BLOCKED")
            
            verdict = self.guard.inspect_prompt(prompt)
            actual = verdict["verdict"]

            is_success = (actual == expected)
            if not is_success and expected == "BLOCKED" and actual == "ALLOWED":
                bypassed_count += 1

            if actual == "BLOCKED":
                blocked_count += 1
            elif actual == "SANITIZED":
                sanitized_count += 1
            elif actual == "ALLOWED":
                allowed_count += 1

            results.append({
                "id": tc.get("id"),
                "category": tc.get("category"),
                "mitre_atlas": tc.get("mitre_atlas_mapping"),
                "owasp": tc.get("owasp_mapping"),
                "expected": expected,
                "actual": actual,
                "risk_score": verdict["risk_score"],
                "matched_rules": verdict["matched_rules"],
                "passed_validation": is_success
            })

        total = len(self.test_cases)
        defense_efficacy = round(((blocked_count + sanitized_count) / max(total - allowed_count, 1)) * 100.0, 2)

        return {
            "total_adversarial_tests": total,
            "metrics": {
                "blocked": blocked_count,
                "sanitized": sanitized_count,
                "allowed": allowed_count,
                "bypasses": bypassed_count,
                "defense_efficacy_percentage": defense_efficacy
            },
            "test_results": results
        }


def main():
    parser = argparse.ArgumentParser(description="AI-SPR Red Team Adversarial Simulator")
    parser.add_argument("--dataset", default=None, help="Custom path to adversarial payload JSON")
    parser.add_argument("--output-json", default="reports/red_team_results.json", help="Path to write results JSON")

    args = parser.parse_args()

    print("=" * 80)
    print("      @jsaccomani's AI Red Team Adversarial Simulator (MITRE ATLAS)          ")
    print("=" * 80)

    simulator = AIRedTeamSimulator(dataset_path=args.dataset)
    report = simulator.execute_campaign()

    print(f"\n[+] Red Team Campaign Completed! Total Payloads Tested: {report['total_adversarial_tests']}")
    print(f"    • 🛡️  Blocked by Model Armor  : {report['metrics']['blocked']}")
    print(f"    • 🧼 Sanitized / PII Masked    : {report['metrics']['sanitized']}")
    print(f"    • 🟢 Allowed (Benign Benchmarks): {report['metrics']['allowed']}")
    print(f"    • 🚨 Bypasses / Failures       : {report['metrics']['bypasses']}")
    print(f"    • 📊 Defense Efficacy          : {report['metrics']['defense_efficacy_percentage']}%\n")

    print("--- Detailed Payload Results ---")
    for r in report["test_results"]:
        status_icon = "✅" if r["passed_validation"] else "❌"
        print(f"{status_icon} [{r['id']}] {r['category']}")
        print(f"   ATLAS : {r['mitre_atlas']} | OWASP: {r['owasp']}")
        print(f"   Result: Expected '{r['expected']}' -> Got '{r['actual']}' (Risk: {r['risk_score']})\n")

    os.makedirs(os.path.dirname(os.path.abspath(args.output_json)), exist_ok=True)
    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"✅ Full JSON Red Team Report exported to: {os.path.abspath(args.output_json)}")


if __name__ == "__main__":
    main()

# Audit checkpoint [2026-08-08]: fix(prompt-defense): adjust prompt injection heuristic thresholds for client customer-service bot
