# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Centralized Secret Management Module for Multi-Cloud Credentials.
Uses Google Cloud Secret Manager to securely persist and retrieve AWS and Azure
onboarding credentials collected during the client journey.
NEVER writes sensitive cloud credentials, tokens, or private keys to local disk/files.
"""

import os
import re
import json
import logging
from typing import Dict, Any, Optional

try:
    from config.gcp_auth import get_default_project_id
except ImportError:
    def get_default_project_id(explicit_project: Optional[str] = None) -> Optional[str]:
        return explicit_project or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")

logger = logging.getLogger("AISPR-Secrets")

# Ephemeral in-memory vault fallback (STRICTLY VOLATILE - NEVER WRITTEN TO DISK)
_EPHEMERAL_VAULT: Dict[str, str] = {}


class SecretManagerStore:
    """
    Secure Secret Manager client for storing and retrieving Multi-Cloud
    (AWS Bedrock, Azure OpenAI) onboarding credentials via Google Cloud Secret Manager.
    Enforces zero-footprint security: credentials are never serialized to local disk files.
    """

    def __init__(self, project_id: Optional[str] = None):
        self.project_id = get_default_project_id(project_id) or "aispr-core-prod"
        self._client = None

    def _get_client(self) -> Any:
        """Initializes and returns the SecretManagerServiceClient."""
        if self._client is not None:
            return self._client
        try:
            from google.cloud import secretmanager
            self._client = secretmanager.SecretManagerServiceClient()
            return self._client
        except ImportError:
            logger.info("google-cloud-secret-manager not installed. Using secure ephemeral memory vault.")
            return None
        except Exception as exc:
            logger.warning(f"Failed to initialize SecretManagerServiceClient: {exc}")
            return None

    def _sanitize_secret_id(self, secret_id: str) -> str:
        """Converts strings into valid Secret Manager IDs (alphanumeric, dashes, underscores)."""
        clean = re.sub(r'[^a-zA-Z0-9_-]', '-', secret_id)
        return clean.strip('-')[:255]

    def store_secret(self, secret_id: str, secret_value: str) -> Dict[str, Any]:
        """
        Stores a secret string in Google Cloud Secret Manager.
        If Secret Manager is unreachable, retains in volatile memory only.
        NEVER writes secrets to local files.

        Args:
            secret_id: Unique secret identifier.
            secret_value: Secret payload string (e.g. JSON credentials, API tokens).

        Returns:
            Dict containing operation status and metadata.
        """
        clean_id = self._sanitize_secret_id(secret_id)
        client = self._get_client()

        if client is not None:
            parent = f"projects/{self.project_id}"
            secret_name = f"{parent}/secrets/{clean_id}"
            try:
                # 1. Check if secret exists or create it
                try:
                    client.get_secret(request={"name": secret_name})
                except Exception:
                    logger.info(f"Creating Secret Manager secret: {clean_id} in {parent}")
                    client.create_secret(
                        request={
                            "parent": parent,
                            "secret_id": clean_id,
                            "secret": {
                                "replication": {"automatic": {}},
                                "labels": {"managed-by": "aispr-copilot"}
                            }
                        }
                    )

                # 2. Add secret version
                payload = secret_value.encode("utf-8")
                version_resp = client.add_secret_version(
                    request={
                        "parent": secret_name,
                        "payload": {"data": payload}
                    }
                )
                logger.info(f"Successfully stored secret version in Secret Manager: {version_resp.name}")
                return {
                    "success": True,
                    "storage_backend": "GOOGLE_CLOUD_SECRET_MANAGER",
                    "secret_id": clean_id,
                    "version_name": version_resp.name,
                    "persistent": True
                }
            except Exception as exc:
                logger.warning(f"Secret Manager write failed for '{clean_id}': {exc}. Storing in memory.")

        # Fallback to volatile memory only (never write to disk)
        _EPHEMERAL_VAULT[clean_id] = secret_value
        return {
            "success": True,
            "storage_backend": "VOLATILE_MEMORY_VAULT",
            "secret_id": clean_id,
            "version_name": f"memory://{clean_id}/latest",
            "persistent": False,
            "warning": "Secret stored in volatile memory only; never committed to local disk."
        }

    def get_secret(self, secret_id: str, version: str = "latest") -> Optional[str]:
        """
        Retrieves a secret string from Google Cloud Secret Manager or memory vault.

        Args:
            secret_id: Unique secret identifier.
            version: Secret version (defaults to 'latest').

        Returns:
            Decoded secret payload string or None.
        """
        clean_id = self._sanitize_secret_id(secret_id)
        client = self._get_client()

        if client is not None:
            name = f"projects/{self.project_id}/secrets/{clean_id}/versions/{version}"
            try:
                response = client.access_secret_version(request={"name": name})
                return response.payload.data.decode("utf-8")
            except Exception as exc:
                logger.debug(f"Secret Manager retrieval failed for '{name}': {exc}")

        return _EPHEMERAL_VAULT.get(clean_id)

    def store_multicloud_credentials(
        self,
        provider: str,
        credentials_data: Dict[str, Any],
        tenant_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Stores AWS or Azure onboarding credentials in Secret Manager.
        Ensures credentials are encrypted in Google Cloud and NEVER written to local disk.
        """
        secret_id = f"aispr-{provider.lower()}-creds-{tenant_id.lower()}"
        payload_str = json.dumps(credentials_data, indent=2)
        return self.store_secret(secret_id=secret_id, secret_value=payload_str)

    def get_multicloud_credentials(
        self,
        provider: str,
        tenant_id: str = "default"
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves multi-cloud credentials dictionary for AWS or Azure.
        """
        secret_id = f"aispr-{provider.lower()}-creds-{tenant_id.lower()}"
        raw = self.get_secret(secret_id)
        if raw:
            try:
                return json.loads(raw)
            except Exception as exc:
                logger.error(f"Failed to parse credentials JSON for {secret_id}: {exc}")
        return None


# Module-level convenience functions
_default_store = None

def _get_store() -> SecretManagerStore:
    global _default_store
    if _default_store is None:
        _default_store = SecretManagerStore()
    return _default_store

def store_secret(secret_id: str, secret_value: str, project_id: Optional[str] = None) -> Dict[str, Any]:
    store = SecretManagerStore(project_id=project_id) if project_id else _get_store()
    return store.store_secret(secret_id, secret_value)

def get_secret(secret_id: str, version: str = "latest", project_id: Optional[str] = None) -> Optional[str]:
    store = SecretManagerStore(project_id=project_id) if project_id else _get_store()
    return store.get_secret(secret_id, version)

def store_multicloud_credentials(provider: str, credentials_data: Dict[str, Any], tenant_id: str = "default", project_id: Optional[str] = None) -> Dict[str, Any]:
    store = SecretManagerStore(project_id=project_id) if project_id else _get_store()
    return store.store_multicloud_credentials(provider, credentials_data, tenant_id)

def get_multicloud_credentials(provider: str, tenant_id: str = "default", project_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    store = SecretManagerStore(project_id=project_id) if project_id else _get_store()
    return store.get_multicloud_credentials(provider, tenant_id)
