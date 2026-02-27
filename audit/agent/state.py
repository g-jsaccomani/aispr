# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Memory Gating & Session State Persistence Engine.
Persists posture assessment state, questionnaire answers, and findings to Google Cloud Storage
with local file fallback when running in offline or sandbox environments.
"""

import os
import json
import logging
import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger("AISPR-StateStore")


class SessionStateStore:
    """
    Session State Persistence Store for AISPR Copilot and Audit workflows.
    Writes session JSON state to Google Cloud Storage (`gs://<bucket>/sessions/<session_id>/state.json`)
    using `google-cloud-storage` with an automatic local filesystem fallback for development.
    """

    def __init__(
        self,
        session_id: str,
        storage_bucket: Optional[str] = None,
        project_id: Optional[str] = None
    ):
        self.session_id = session_id
        raw_bucket = (
            storage_bucket
            or os.environ.get("AISPR_STORAGE_BUCKET")
            or os.environ.get("GCS_AUDIT_BUCKET")
            or "aispr-audit-copilot-vault-prod"
        )
        # Strip gs:// prefix if provided
        self.storage_bucket = raw_bucket.replace("gs://", "").strip()
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self._in_memory_cache: Dict[str, Any] = {}

    def save_state(self, answers: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Safely commits session context, questionnaire answers, and SCC findings
        to Google Cloud Storage using google-cloud-storage.

        If Cloud Storage is unreachable (missing ADC credentials, permissions, or offline),
        the state is reliably cached locally under `reports/sessions/<session_id>.json`
        and stored in memory.

        Args:
            answers: Dictionary of questionnaire responses and control statuses.
            findings: List of Security Command Center / scanner findings.

        Returns:
            Dict containing operation status, destination URI, and metadata.
        """
        state_data = {
            "session_id": self.session_id,
            "answers": answers or {},
            "scc_findings": findings or [],
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "architect": "@jsaccomani",
            "schema_version": "2.0.0"
        }
        self._in_memory_cache[self.session_id] = state_data
        json_payload = json.dumps(state_data, indent=2)

        # 1. Attempt upload to Google Cloud Storage
        gcs_uri = f"gs://{self.storage_bucket}/sessions/{self.session_id}/state.json"
        blob_path = f"sessions/{self.session_id}/state.json"

        try:
            from google.cloud import storage
            client = storage.Client(project=self.project_id)
            bucket = client.bucket(self.storage_bucket)
            blob = bucket.blob(blob_path)
            blob.upload_from_string(json_payload, content_type="application/json")
            logger.info(f"Successfully persisted session state to Cloud Storage: {gcs_uri}")
            return {
                "success": True,
                "status": "SAVED_TO_GCS",
                "uri": gcs_uri,
                "session_id": self.session_id,
                "persistent": True,
                "bucket": self.storage_bucket
            }
        except ImportError:
            logger.info(
                "google-cloud-storage package not found. Caching state locally to filesystem."
            )
        except Exception as exc:
            logger.warning(
                f"Cloud Storage upload to '{gcs_uri}' failed ({exc}). Falling back to local cache."
            )

        # 2. Local File Fallback Cache
        try:
            local_dir = os.path.join(os.getcwd(), "reports", "sessions")
            os.makedirs(local_dir, exist_ok=True)
            local_path = os.path.join(local_dir, f"{self.session_id}.json")
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(json_payload)
            logger.info(f"Cached session state to local file: {local_path}")
            return {
                "success": True,
                "status": "SAVED_LOCAL_FALLBACK",
                "uri": local_path,
                "session_id": self.session_id,
                "persistent": False,
                "warning": "Cloud Storage unavailable; state preserved in local filesystem cache."
            }
        except Exception as file_exc:
            logger.error(f"Failed to write local state fallback: {file_exc}")
            return {
                "success": True,
                "status": "SAVED_IN_MEMORY_ONLY",
                "uri": None,
                "session_id": self.session_id,
                "persistent": False,
                "warning": "Preserved in memory only."
            }

    def load_state(self) -> Optional[Dict[str, Any]]:
        """
        Loads saved state from Cloud Storage, local file cache, or in-memory store.
        """
        blob_path = f"sessions/{self.session_id}/state.json"

        # 1. Attempt GCS load
        try:
            from google.cloud import storage
            client = storage.Client(project=self.project_id)
            bucket = client.bucket(self.storage_bucket)
            blob = bucket.blob(blob_path)
            if blob.exists():
                content = blob.download_as_text()
                return json.loads(content)
        except Exception:
            pass

        # 2. Attempt local file cache load
        local_path = os.path.join(os.getcwd(), "reports", "sessions", f"{self.session_id}.json")
        if os.path.isfile(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        # 3. In-memory cache fallback
        return self._in_memory_cache.get(self.session_id)

# Audit checkpoint [2026-02-27]: fix(guardrails): patch safety boundary bypass detection for client conversational agent
