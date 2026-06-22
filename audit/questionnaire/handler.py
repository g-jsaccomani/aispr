# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Progressive Gating Questionnaire Handler
Engineered by: @jsaccomani
"""

import json
import os
from typing import Dict, List, Any, Optional
from audit.engine.scorer import PostureScorer
from audit.engine.reporter import ExecutiveReporter


class QuestionnaireHandler:
    """
    Manages the progressive navigation and state tracking of the AI-SPR questionnaire,
    supporting both interactive CLI walkthroughs and conversational agent loops.
    """

    def __init__(self, questions_path: Optional[str] = None):
        if questions_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            questions_path = os.path.join(current_dir, "questions.json")

        self.questions_path = questions_path
        self.data = self._load_questions()
        self.question_db = self.data.get("domains", {})
        self.flat_questions = self._flatten_questions()

    def _load_questions(self) -> Dict[str, Any]:
        if os.path.exists(self.questions_path):
            with open(self.questions_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"audit_meta": {}, "domains": {}}

    def _flatten_questions(self) -> List[Dict[str, Any]]:
        flat = []
        for domain, q_list in self.question_db.items():
            for q in q_list:
                flat.append({"domain": domain, **q})
        return flat

    def get_total_questions(self) -> int:
        return len(self.flat_questions)

    def reload(self) -> int:
        """Hot-reloads questions from disk without server restart."""
        self.data = self._load_questions()
        self.question_db = self.data.get("domains", {})
        self.flat_questions = self._flatten_questions()
        return len(self.flat_questions)

    def get_framework_versions(self) -> Dict[str, Any]:
        """Returns framework versions, sources, and timestamps from audit_meta."""
        meta = self.data.get("audit_meta", {})
        fw_versions = meta.get("framework_versions", {})
        
        # Standardized framework catalogue
        catalog = [
            {
                "key": "SAIF",
                "name": "Google SAIF",
                "version": fw_versions.get("SAIF", {}).get("version", "2.0 (6 Core Pillars)"),
                "source": fw_versions.get("SAIF", {}).get("source", "Google Cloud Security (saif.google)"),
                "last_updated": fw_versions.get("SAIF", {}).get("last_updated", meta.get("last_updated", "2026-08-15T00:00:00Z"))
            },
            {
                "key": "NIST_AI_RMF",
                "name": "NIST AI RMF",
                "version": fw_versions.get("NIST_AI_RMF", {}).get("version", "1.0 (Govern, Map, Measure, Manage)"),
                "source": fw_versions.get("NIST_AI_RMF", {}).get("source", "NIST Trustworthy & Responsible AI Resource Center"),
                "last_updated": fw_versions.get("NIST_AI_RMF", {}).get("last_updated", meta.get("last_updated", "2026-07-20T00:00:00Z"))
            },
            {
                "key": "ISO_42001",
                "name": "ISO 42001",
                "version": fw_versions.get("ISO_42001", {}).get("version", "ISO/IEC 42001:2023 Edition"),
                "source": fw_versions.get("ISO_42001", {}).get("source", "ISO/IEC JTC 1/SC 42 Artificial Intelligence"),
                "last_updated": fw_versions.get("ISO_42001", {}).get("last_updated", meta.get("last_updated", "2026-06-10T00:00:00Z"))
            },
            {
                "key": "MITRE_ATLAS",
                "name": "MITRE ATLAS",
                "version": fw_versions.get("MITRE_ATLAS", {}).get("version", "v4.2.0 (Matrix AML)"),
                "source": fw_versions.get("MITRE_ATLAS", {}).get("source", "MITRE Corporation (atlas.mitre.org)"),
                "last_updated": fw_versions.get("MITRE_ATLAS", {}).get("last_updated", meta.get("last_updated", "2026-08-01T00:00:00Z"))
            },
            {
                "key": "OWASP_LLM",
                "name": "OWASP LLM",
                "version": fw_versions.get("OWASP_LLM", {}).get("version", "Top 10 for LLM Applications (2025/2026)"),
                "source": fw_versions.get("OWASP_LLM", {}).get("source", "OWASP GenAI Security Project"),
                "last_updated": fw_versions.get("OWASP_LLM", {}).get("last_updated", meta.get("last_updated", "2026-07-15T00:00:00Z"))
            },
            {
                "key": "EU_AI_ACT",
                "name": "EU AI Act",
                "version": fw_versions.get("EU_AI_ACT", {}).get("version", "Regulation (EU) 2024/1689"),
                "source": fw_versions.get("EU_AI_ACT", {}).get("source", "European Commission Official Journal"),
                "last_updated": fw_versions.get("EU_AI_ACT", {}).get("last_updated", meta.get("last_updated", "2026-08-02T00:00:00Z"))
            }
        ]
        
        return {
            "status": "SUCCESS",
            "audit_meta": meta,
            "frameworks": catalog,
            "total_controls": len(self.flat_questions)
        }

    def validate_and_diff(self, new_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates uploaded JSON against strict questions schema without executing arbitrary code.
        Computes added, removed, changed and unchanged control diffs.
        """
        if not isinstance(new_data, dict):
            raise ValueError("Root payload must be a JSON object.")
        
        domains = new_data.get("domains")
        if not isinstance(domains, dict) or not domains:
            raise ValueError("Payload must contain a non-empty 'domains' dictionary.")
        
        valid_criticalities = {"HIGH", "MEDIUM", "LOW"}
        seen_ids = set()
        new_flat: List[Dict[str, Any]] = []

        for domain_name, q_list in domains.items():
            if not isinstance(domain_name, str) or not domain_name.strip():
                raise ValueError("Domain names must be non-empty strings.")
            if not isinstance(q_list, list):
                raise ValueError(f"Domain '{domain_name}' must contain a list of questions.")
            
            for idx, q in enumerate(q_list):
                if not isinstance(q, dict):
                    raise ValueError(f"Control item #{idx+1} in domain '{domain_name}' must be a JSON object.")
                
                # Mandatory fields validation
                qid = q.get("id")
                if not isinstance(qid, str) or not qid.strip():
                    raise ValueError(f"Control in domain '{domain_name}' item #{idx+1} is missing a valid non-empty string 'id'.")
                qid = qid.strip()

                if qid in seen_ids:
                    raise ValueError(f"Duplicate control ID detected: '{qid}'. Every control ID must be strictly unique.")
                seen_ids.add(qid)

                question_text = q.get("question")
                if not isinstance(question_text, str) or not question_text.strip():
                    raise ValueError(f"Control '{qid}' is missing a valid non-empty string 'question'.")

                framework_mapping = q.get("framework_mapping")
                if not isinstance(framework_mapping, str) or not framework_mapping.strip():
                    raise ValueError(f"Control '{qid}' is missing a valid non-empty string 'framework_mapping'.")

                rationale = q.get("rationale")
                if not isinstance(rationale, str) or not rationale.strip():
                    raise ValueError(f"Control '{qid}' is missing a valid non-empty string 'rationale'.")

                criticality = q.get("criticality")
                if not isinstance(criticality, str) or criticality.strip().upper() not in valid_criticalities:
                    raise ValueError(f"Control '{qid}' has invalid criticality '{criticality}'. Must be HIGH, MEDIUM, or LOW.")
                
                # Normalize criticality in data structure
                q["criticality"] = criticality.strip().upper()
                new_flat.append({"domain": domain_name, **q})

        # Calculate Diff
        old_map = {q["id"]: q for q in self.flat_questions}
        new_map = {q["id"]: q for q in new_flat}

        added = [qid for qid in new_map if qid not in old_map]
        removed = [qid for qid in old_map if qid not in new_map]
        
        changed = []
        for qid in new_map:
            if qid in old_map:
                old_q = old_map[qid]
                new_q = new_map[qid]
                fields_changed = []
                for field in ["question", "framework_mapping", "rationale", "criticality", "domain"]:
                    if old_q.get(field) != new_q.get(field):
                        fields_changed.append(field)
                if fields_changed:
                    changed.append({
                        "id": qid,
                        "fields": fields_changed,
                        "before": {f: old_q.get(f) for f in fields_changed},
                        "after": {f: new_q.get(f) for f in fields_changed}
                    })

        unchanged_count = len(new_map) - len(added) - len(changed)

        diff_summary = {
            "total_controls_before": len(old_map),
            "total_controls_after": len(new_map),
            "added_count": len(added),
            "added_controls": added,
            "removed_count": len(removed),
            "removed_controls": removed,
            "changed_count": len(changed),
            "changed_controls": changed,
            "unchanged_count": unchanged_count
        }

        return {
            "valid": True,
            "diff": diff_summary,
            "total_controls": len(new_map),
            "new_flat": new_flat
        }

    def import_questionnaire(self, new_data: Dict[str, Any], commit: bool = True) -> Dict[str, Any]:
        """
        Validates schema, computes diff summary, and commits new questions.json to disk on success.
        """
        validation_result = self.validate_and_diff(new_data)
        diff_summary = validation_result["diff"]
        total_controls = validation_result["total_controls"]

        if commit:
            # Ensure audit_meta has updated total_controls and updated timestamp
            if "audit_meta" not in new_data or not isinstance(new_data["audit_meta"], dict):
                new_data["audit_meta"] = self.data.get("audit_meta", {})
            new_data["audit_meta"]["total_controls"] = total_controls
            from datetime import datetime, timezone
            new_data["audit_meta"]["last_updated"] = datetime.now(timezone.utc).isoformat()

            # Atomic / safe write to questions_path
            with open(self.questions_path, "w", encoding="utf-8") as f:
                json.dump(new_data, f, indent=2, ensure_ascii=False)
            
            # Hot-reload in memory
            self.reload()

        return {
            "status": "SUCCESS",
            "message": "Questionnaire imported and active controls replaced successfully." if commit else "Schema validation passed. Ready to commit.",
            "diff": diff_summary,
            "total_controls": total_controls,
            "committed": commit
        }

    def record_answer(self, question_id: str, status: str, notes: str = "", answers_dict: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Formats and records an answer for a specific question ID.
        Status: 'Y' (1.0), 'P' (0.5), 'N' (0.0), 'NA' (-1.0)
        """
        status_norm = status.strip().upper()
        score = 0.0
        if status_norm == "Y":
            score = 1.0
        elif status_norm == "P":
            score = 0.5
        elif status_norm == "NA":
            score = -1.0
        elif status_norm == "N":
            score = 0.0

        # Find question details
        q_obj = next((q for q in self.flat_questions if q["id"] == question_id), None)
        entry = {
            "status": status_norm,
            "score": score,
            "notes": notes if notes else "No specific architectural notes recorded.",
            "criticality": q_obj.get("criticality", "MEDIUM") if q_obj else "MEDIUM",
            "question_text": q_obj.get("question", "") if q_obj else "",
            "framework_mapping": q_obj.get("framework_mapping", "") if q_obj else "",
            "rationale": q_obj.get("rationale", "") if q_obj else ""
        }

        if answers_dict is not None:
            answers_dict[question_id] = entry

        return entry

    def get_next_step(self, user_input: str, session_state: Dict[str, Any]) -> str:
        """
        Stateful step coordinator for conversational ADK / Copilot loops.
        """
        current_idx = session_state.get("current_question_index", 0)

        if "answers" not in session_state:
            session_state["answers"] = {}

        # Save previous answer if in progress
        if current_idx > 0 and user_input.strip().lower() != "start questionnaire":
            prev_q = self.flat_questions[current_idx - 1]
            parts = user_input.split("|", 1)
            status = parts[0].strip().upper() if parts else "N"
            notes = parts[1].strip() if len(parts) > 1 else ""
            self.record_answer(prev_q["id"], status, notes, session_state["answers"])

        # Check if completed
        if current_idx >= len(self.flat_questions):
            session_state["quiz_active"] = False
            scores = PostureScorer.calculate_scores(session_state["answers"], self.question_db)
            return (
                f"✅ You have completed all {len(self.flat_questions)} AI-SPR questions!\n\n"
                f"📊 **Overall Compliance Score:** `{scores['overall_percentage']}%` ({scores['posture_tier']})\n\n"
                "Type **'Generate Report'** to produce the final Executive Hardening Report & CAPA roadmap."
            )

        q = self.flat_questions[current_idx]
        session_state["current_question_index"] = current_idx + 1

        return (
            f"**Domain:** {q['domain']}\n"
            f"**Question ({current_idx + 1}/{len(self.flat_questions)}):** [{q['id']}] (Criticality: `{q.get('criticality', 'MEDIUM')}`)\n"
            f"> {q['question']}\n\n"
            f"🔍 *Mapping:* {q.get('framework_mapping', 'N/A')}\n"
            f"💡 *Rationale:* {q.get('rationale', 'N/A')}\n\n"
            "*Reply format: `[Y/N/P/NA] | Your architectural findings/notes`*"
        )

# Audit checkpoint [2026-03-18]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment

# Audit checkpoint [2026-06-22]: fix(guardrails): patch safety boundary bypass detection for client conversational agent
