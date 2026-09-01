# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Findings Correlator - Step 2: Deduplicator
Deterministically deduplicates findings across multi-cloud scans without dropping evidence,
evaluating provider, resource, finding type, control, attack technique, and description.
"""

import re
import hashlib
from typing import List, Dict, Any

from domain.models import SecurityFinding
from domain.enums import FindingSeverity


class FindingDeduplicator:
    """
    Deduplicates findings deterministically using multi-dimensional fingerprinting,
    merging evidence and control links rather than dropping critical audit trails.
    """

    SEVERITY_ORDER = {
        FindingSeverity.CRITICAL: 4,
        FindingSeverity.HIGH: 3,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 1,
        FindingSeverity.INFO: 0
    }

    @staticmethod
    def normalize_text_tokens(text: str) -> str:
        """Strips punctuation, collapses whitespace, and normalizes text for token matching."""
        clean = re.sub(r"[^a-zA-Z0-9\s]", " ", text.lower())
        tokens = clean.split()
        return " ".join(sorted(set(tokens[:20])))

    def compute_fingerprint(self, finding: SecurityFinding) -> str:
        """
        Calculates a deterministic composite fingerprint.
        Considers: provider, resource, finding_type, control, attack_technique, normalized_description.
        Never relies solely on finding title.
        """
        prov = str(finding.provider).lower()
        res = finding.asset.resource_uri.strip().lower().rstrip("/")
        ftype = str(finding.metadata.get("category", "")).strip().lower()
        ctrl = finding.primary_control_id or "UNMAPPED"
        
        # Sort attack techniques
        atlas_ids = sorted(t.technique_id for t in finding.attack_techniques)
        attacks_str = ",".join(atlas_ids)
        
        desc_tokens = self.normalize_text_tokens(finding.description)

        raw_key = f"{prov}|{res}|{ftype}|{ctrl}|{attacks_str}|{desc_tokens}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def deduplicate(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """
        Deduplicates a list of findings, merging evidence and escalating severities.
        """
        unique_map: Dict[str, SecurityFinding] = {}

        for finding in findings:
            fp = self.compute_fingerprint(finding)

            if fp not in unique_map:
                finding.metadata["dedup_fingerprint"] = fp
                finding.metadata["duplicate_count"] = 1
                unique_map[fp] = finding
            else:
                existing = unique_map[fp]
                existing.metadata["duplicate_count"] = existing.metadata.get("duplicate_count", 1) + 1

                # 1. Merge evidence deterministically without duplicate hashes
                existing_hashes = {e.content_hash for e in existing.evidence if e.content_hash}
                for ev in finding.evidence:
                    if ev.content_hash not in existing_hashes:
                        existing.evidence.append(ev)
                        if ev.content_hash:
                            existing_hashes.add(ev.content_hash)

                # 2. Escalate severity if new duplicate is higher
                curr_weight = self.SEVERITY_ORDER.get(existing.severity, 1)
                new_weight = self.SEVERITY_ORDER.get(finding.severity, 1)
                if new_weight > curr_weight:
                    existing.severity = finding.severity

                # 3. Merge control links
                existing_ctrl_ids = {c.control_id for c in existing.control_links}
                for link in finding.control_links:
                    if link.control_id not in existing_ctrl_ids:
                        existing.control_links.append(link)
                        existing_ctrl_ids.add(link.control_id)

                # 4. Merge framework mappings
                existing_fws = {(m.framework, m.section_or_control) for m in existing.framework_mappings}
                for m in finding.framework_mappings:
                    if (m.framework, m.section_or_control) not in existing_fws:
                        existing.framework_mappings.append(m)
                        existing_fws.add((m.framework, m.section_or_control))

        return list(unique_map.values())
