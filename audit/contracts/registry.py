# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Control Contract Engine - Registry
Provides indexing, discovery, and query capabilities for the 104 versioned Security Control Contracts.
"""

import os
import json
from typing import Dict, List, Optional, Any

from domain.models import SecurityControlContract
from domain.enums import AutomationLevel, AssessmentType, CloudProvider


class ControlContractRegistry:
    """
    Central registry and catalog for the 104 AISPR Security Control Contracts.
    """

    CATALOG_FILE = os.path.join(os.path.dirname(__file__), "contracts_catalog_v2.json")

    def __init__(self, catalog_path: Optional[str] = None):
        self.catalog_path = catalog_path or self.CATALOG_FILE
        self._contracts: Dict[str, SecurityControlContract] = {}
        self._load_catalog()

    def _load_catalog(self):
        """Loads and parses the catalog JSON into strongly typed SecurityControlContract instances."""
        if not os.path.exists(self.catalog_path):
            raise FileNotFoundError(f"Control contracts catalog not found at: {self.catalog_path}")

        with open(self.catalog_path, "r", encoding="utf-8") as f:
            raw_list = json.load(f)

        self._contracts.clear()
        for item in raw_list:
            contract = SecurityControlContract.model_validate(item)
            self._contracts[contract.control_id] = contract

    def get_contract(self, control_id: str) -> Optional[SecurityControlContract]:
        """Returns the SecurityControlContract for a given control ID (e.g. 'APP-01')."""
        return self._contracts.get(control_id.strip().upper())

    def list_contracts(self) -> List[SecurityControlContract]:
        """Returns all registered control contracts in canonical order."""
        return list(self._contracts.values())

    def get_contracts_by_domain(self, domain_code: str) -> List[SecurityControlContract]:
        """Filters contracts by domain code (e.g., 'DAT', 'MOD', 'APP', 'INF', 'ASR', 'GOV')."""
        code = domain_code.strip().upper()
        return [c for c in self._contracts.values() if f"({code})" in c.domain or c.control_id.startswith(f"{code}-")]

    def get_contracts_by_framework(self, framework_name: str) -> List[SecurityControlContract]:
        """Returns all contracts with an active (non-NOT_MAPPED) mapping to a specific framework."""
        results = []
        for c in self._contracts.values():
            m = c.get_framework_mapping(framework_name)
            if m and m.reference != "NOT_MAPPED":
                results.append(c)
        return results

    def get_contracts_by_automation_level(self, level: AutomationLevel) -> List[SecurityControlContract]:
        """Filters contracts by automation level (FULL, PARTIAL, NONE)."""
        return [c for c in self._contracts.values() if c.automation_level == level]

    def get_coverage_matrix(self) -> List[Dict[str, Any]]:
        """
        Generates the comprehensive control coverage matrix across all 104 controls:
        Control | Automation | Evidence | Frameworks | Providers | Tests | Coverage
        """
        rows = []
        for c in self.list_contracts():
            mapped_fws = [m.framework for m in c.framework_mappings if m.reference != "NOT_MAPPED"]
            provs = [p.value if hasattr(p, "value") else str(p) for p in c.applicable_providers]
            tests = [t.test_id for t in c.test_definitions]
            evs = [e.evidence_type.value if hasattr(e.evidence_type, "value") else str(e.evidence_type) for e in c.evidence_requirements]
            
            # Compute coverage grade
            fw_coverage_pct = (len(mapped_fws) / 7.0) * 100
            if c.automation_level == AutomationLevel.FULL and len(mapped_fws) >= 4:
                coverage_grade = "HIGH"
            elif c.automation_level in (AutomationLevel.FULL, AutomationLevel.PARTIAL) and len(mapped_fws) >= 2:
                coverage_grade = "MEDIUM"
            else:
                coverage_grade = "STANDARD"

            ass_val = c.assessment_type.value if hasattr(c.assessment_type, "value") else str(c.assessment_type)
            auto_val = c.automation_level.value if hasattr(c.automation_level, "value") else str(c.automation_level)

            rows.append({
                "control_id": c.control_id,
                "title": c.title,
                "automation": f"{ass_val} ({auto_val})",
                "evidence": ", ".join(evs),
                "frameworks": f"{len(mapped_fws)}/7 ({', '.join(mapped_fws[:2])}...)",
                "providers": ", ".join(provs),
                "tests": f"{len(tests)} test(s)",
                "coverage": coverage_grade,
                "frameworks_count": len(mapped_fws)
            })
        return rows

    def generate_matrix_markdown(self) -> str:
        """Renders the coverage matrix as a GitHub-flavored Markdown table."""
        matrix = self.get_coverage_matrix()
        lines = [
            "# AI-SPR Security Control Contracts • Coverage Matrix",
            f"**Total Versioned Contracts:** {len(matrix)} | **Specification Version:** 2.0.0\n",
            "| Control | Automation | Evidence | Frameworks | Providers | Tests | Coverage |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :---: |"
        ]
        for row in matrix:
            lines.append(
                f"| `{row['control_id']}` {row['title'][:35]} | {row['automation']} | {row['evidence']} | {row['frameworks']} | {row['providers']} | {row['tests']} | **{row['coverage']}** |"
            )
        return "\n".join(lines)
