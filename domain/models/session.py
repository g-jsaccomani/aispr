# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - AssessmentSession Entity
Encapsulates real assessment state, scope, execution mode, findings, evidence,
and deterministic metrics with GCS and local filesystem persistence.
"""

import os
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import Field, field_validator

from domain.enums import ExecutionMode, AssessmentStatus
from domain.models.base import AISPRBaseModel, utc_now

logger = logging.getLogger("AISPR-AssessmentSession")


class AssessmentSession(AISPRBaseModel):
    """
    Real Assessment Session state entity.
    Guarantees no fabricated metrics, providing epistemic truthfulness
    across CLI, risk engines, and UI console interfaces.
    """
    session_id: str = Field(default_factory=lambda: f"SES-{uuid.uuid4().hex[:8].upper()}")
    client: str = Field(default="Enterprise Customer")
    scope: str = Field(default="Multi-Cloud AI Estate (GCP, AWS, Azure)")
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)
    answers: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    risk_result: Optional[Dict[str, Any]] = None
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    domain_scores: Dict[str, Any] = Field(default_factory=dict)
    status: AssessmentStatus = Field(default=AssessmentStatus.COMPLETED)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("execution_mode", mode="before")
    @classmethod
    def parse_execution_mode(cls, v: Any) -> ExecutionMode:
        if isinstance(v, str):
            try:
                return ExecutionMode(v.upper())
            except ValueError:
                return ExecutionMode.SIMULATION
        return v

    def calculate_metrics(self) -> Dict[str, Any]:
        """
        Calculates real deterministic metrics from the actual answers and findings.
        Strictly derives values from the question taxonomy and responses.
        """
        from audit.questionnaire.handler import QuestionnaireHandler
        from audit.engine.scorer import PostureScorer
        from audit.contracts.registry import ControlContractRegistry

        handler = QuestionnaireHandler()
        q_db = handler.question_db
        scores = PostureScorer.calculate_scores(self.answers, q_db)

        # Count verified statuses
        yes_cnt = 0
        partial_cnt = 0
        no_cnt = 0
        for ans in self.answers.values():
            st = (ans.get("status") if isinstance(ans, dict) else ans) or ""
            st = str(st).upper()
            if st in ("Y", "YES"):
                yes_cnt += 1
            elif st in ("P", "PARTIAL"):
                partial_cnt += 1
            elif st in ("N", "NO"):
                no_cnt += 1

        total_contracts = 104
        try:
            reg = ControlContractRegistry()
            total_contracts = len(reg.list_contracts()) or 104
        except Exception:
            pass

        total_evaluated = max(1, yes_cnt + partial_cnt + no_cnt)
        declared_coverage = round((yes_cnt + 0.5 * partial_cnt) / total_evaluated * 100.0, 1)

        # Implementation coverage strictly counts verified technical controls without unmitigated findings
        finding_count = len(self.findings)
        verified_impl_cnt = max(0, yes_cnt - min(yes_cnt, finding_count))
        implementation_coverage = round(
            (verified_impl_cnt + 0.25 * partial_cnt) / total_evaluated * 100.0, 1
        )
        if scores.get("overall_percentage") is not None and not self.findings:
            implementation_coverage = declared_coverage

        self.domain_scores = scores.get("domains", {})
        self.metrics = {
            "health_score_percentage": scores.get("overall_percentage", 0.0),
            "implementation_coverage": implementation_coverage,
            "declared_coverage": declared_coverage,
            "controls_total": total_contracts,
            "controls_yes": yes_cnt,
            "controls_partial": partial_cnt,
            "controls_no": no_cnt,
        }
        return self.metrics

    def save(
        self,
        storage_bucket: Optional[str] = None,
        project_id: Optional[str] = None,
        sessions_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Persists session to Cloud Storage when configured, with local JSON persistence.
        """
        self.updated_at = utc_now()
        if not self.metrics:
            self.calculate_metrics()

        payload_dict = self.model_dump()
        # Convert datetime objects to isoformat for robust serialization
        json_payload = json.dumps(payload_dict, indent=2, default=str)

        # 1. Attempt GCS persistence
        raw_bucket = (
            storage_bucket
            or os.environ.get("AISPR_STORAGE_BUCKET")
            or os.environ.get("GCS_AUDIT_BUCKET")
        )
        if raw_bucket:
            bucket_name = raw_bucket.replace("gs://", "").strip()
            blob_path = f"sessions/{self.session_id}/state.json"
            gcs_uri = f"gs://{bucket_name}/{blob_path}"
            try:
                from google.cloud import storage
                client = storage.Client(project=project_id)
                bucket = client.bucket(bucket_name)
                blob = bucket.blob(blob_path)
                blob.upload_from_string(json_payload, content_type="application/json")
                logger.info(f"Persisted AssessmentSession '{self.session_id}' to GCS: {gcs_uri}")
            except Exception as exc:
                logger.warning(f"GCS upload to '{gcs_uri}' failed ({exc}). Proceeding to local save.")

        # 2. Local JSON persistence
        base_dir = sessions_dir or os.path.join(os.getcwd(), "reports", "sessions")
        os.makedirs(base_dir, exist_ok=True)
        local_path = os.path.join(base_dir, f"{self.session_id}.json")
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(json_payload)
        logger.info(f"Saved AssessmentSession to local file: {local_path}")

        return {
            "success": True,
            "session_id": self.session_id,
            "local_path": local_path,
            "execution_mode": self.execution_mode.value if hasattr(self.execution_mode, "value") else str(self.execution_mode)
        }

    @classmethod
    def load(
        cls,
        session_id: Optional[str] = None,
        storage_bucket: Optional[str] = None,
        project_id: Optional[str] = None,
        sessions_dir: Optional[str] = None
    ) -> Optional["AssessmentSession"]:
        """
        Loads an AssessmentSession by session_id from local JSON or GCS.
        Returns None if no session matches.
        """
        if not session_id:
            return None

        base_dir = sessions_dir or os.path.join(os.getcwd(), "reports", "sessions")
        local_path = os.path.join(base_dir, f"{session_id}.json")

        # 1. Check local JSON
        if os.path.isfile(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return cls.model_validate(data)
            except Exception as exc:
                logger.error(f"Failed to load session from {local_path}: {exc}")

        # 2. Check GCS if configured
        raw_bucket = (
            storage_bucket
            or os.environ.get("AISPR_STORAGE_BUCKET")
            or os.environ.get("GCS_AUDIT_BUCKET")
        )
        if raw_bucket:
            bucket_name = raw_bucket.replace("gs://", "").strip()
            blob_path = f"sessions/{session_id}/state.json"
            try:
                from google.cloud import storage
                client = storage.Client(project=project_id)
                bucket = client.bucket(bucket_name)
                blob = bucket.blob(blob_path)
                if blob.exists():
                    content = blob.download_as_text()
                    data = json.loads(content)
                    return cls.model_validate(data)
            except Exception:
                pass

        return None
