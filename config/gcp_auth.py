# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Centralized Google Cloud Authentication & Authorization Module.
Provides Application Default Credentials (ADC) based authentication,
AuthorizedSession creation, and project resolution across both audit/ and agentic/ engines.
"""

import os
import logging
from typing import Tuple, Optional, List, Dict, Any

logger = logging.getLogger("AISPR-GCP-Auth")

# Default GCP API scopes required for security, asset, vertex, and model armor auditing
DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform"
]


def get_gcp_credentials(
    scopes: Optional[List[str]] = None,
    quota_project_id: Optional[str] = None,
    credentials_payload: Optional[Dict[str, Any]] = None
) -> Tuple[Any, Optional[str]]:
    """
    Acquires Google Cloud credentials using Application Default Credentials (ADC)
    or an explicit service account info dictionary.

    Args:
        scopes: List of OAuth 2.0 scopes (defaults to cloud-platform scope).
        quota_project_id: Optional GCP project ID used for quota and billing.
        credentials_payload: Optional service account key dictionary or info.

    Returns:
        Tuple of (credentials_object, resolved_project_id).
    """
    effective_scopes = scopes or DEFAULT_SCOPES

    # 1. If explicit credentials dictionary provided
    if credentials_payload and isinstance(credentials_payload, dict) and credentials_payload.get("type") == "service_account":
        try:
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_info(
                credentials_payload,
                scopes=effective_scopes
            )
            project_id = credentials_payload.get("project_id") or creds.project_id
            logger.info(f"Loaded credentials from explicit service account payload for project: {project_id}")
            return creds, project_id
        except ImportError:
            logger.warning("google-auth package not found. Install requirements to use service_account credentials.")
        except Exception as exc:
            logger.error(f"Failed to create service account credentials from payload: {exc}")

    # 2. Application Default Credentials (ADC) via google.auth.default()
    try:
        import google.auth
        from google.auth.exceptions import DefaultCredentialsError

        credentials, project_id = google.auth.default(
            scopes=effective_scopes,
            quota_project_id=quota_project_id
        )
        resolved_project = project_id or get_default_project_id()
        logger.info(f"Successfully obtained ADC credentials (Project: {resolved_project})")
        return credentials, resolved_project

    except ImportError:
        logger.warning(
            "google-auth package is not installed. Please run 'pip install -r requirements.txt' "
            "to enable live Google Cloud ADC authentication."
        )
        return None, get_default_project_id()
    except Exception as exc:
        logger.warning(f"Google Cloud ADC credentials discovery failed: {exc}")
        return None, get_default_project_id()


def get_default_project_id(explicit_project: Optional[str] = None) -> Optional[str]:
    """
    Resolves the target GCP Project ID in priority order:
    1. Explicit parameter
    2. GOOGLE_CLOUD_PROJECT environment variable
    3. GCP_PROJECT environment variable
    4. GCLOUD_PROJECT environment variable
    5. CLOUDSDK_CORE_PROJECT environment variable
    6. Default discovered from google.auth.default()
    """
    if explicit_project and explicit_project.strip():
        return explicit_project.strip()

    env_vars = [
        "GOOGLE_CLOUD_PROJECT",
        "GCP_PROJECT",
        "GCLOUD_PROJECT",
        "CLOUDSDK_CORE_PROJECT"
    ]
    for var in env_vars:
        val = os.environ.get(var)
        if val and val.strip():
            return val.strip()

    try:
        import google.auth
        _, proj = google.auth.default()
        if proj:
            return proj
    except Exception:
        pass

    return None


def get_authenticated_session(
    scopes: Optional[List[str]] = None,
    credentials: Optional[Any] = None
) -> Any:
    """
    Creates an AuthorizedSession for making direct REST API calls authenticated via ADC
    (e.g., for Model Armor REST API, Cloud Asset Inventory REST, or SCC REST).

    Args:
        scopes: OAuth scopes.
        credentials: Optional pre-loaded google.auth credentials.

    Returns:
        AuthorizedSession instance or standard requests.Session with warnings.
    """
    creds = credentials
    if creds is None:
        creds, _ = get_gcp_credentials(scopes=scopes)

    if creds is not None:
        try:
            from google.auth.transport.requests import AuthorizedSession
            return AuthorizedSession(creds)
        except ImportError:
            logger.warning("google.auth.transport.requests.AuthorizedSession not available.")

    # Fallback to requests.Session if available
    try:
        import requests
        session = requests.Session()
        return session
    except ImportError:
        logger.warning("requests library is not installed.")
        return None


def get_auth_headers(
    scopes: Optional[List[str]] = None,
    credentials: Optional[Any] = None
) -> Dict[str, str]:
    """
    Retrieves refreshed Bearer authorization headers for direct REST calls.
    """
    creds = credentials
    if creds is None:
        creds, _ = get_gcp_credentials(scopes=scopes)

    if creds is None:
        return {}

    try:
        import google.auth.transport.requests
        auth_req = google.auth.transport.requests.Request()
        creds.refresh(auth_req)
        if hasattr(creds, "token") and creds.token:
            return {
                "Authorization": f"Bearer {creds.token}",
                "Content-Type": "application/json"
            }
    except Exception as exc:
        logger.warning(f"Failed to refresh GCP authentication token: {exc}")

    return {}


def check_adc_status() -> Dict[str, Any]:
    """
    Inspects and validates the status of local Application Default Credentials (ADC).
    """
    try:
        import google.auth
        creds, project_id = google.auth.default()
        
        # Check credentials type
        creds_type = creds.__class__.__name__
        service_account_email = getattr(creds, "service_account_email", None)
        
        return {
            "adc_available": True,
            "credentials_type": creds_type,
            "project_id": project_id or get_default_project_id(),
            "service_account_email": service_account_email,
            "is_valid": creds.valid if hasattr(creds, "valid") else True,
            "error": None
        }
    except ImportError:
        return {
            "adc_available": False,
            "error": "google-auth package is not installed."
        }
    except Exception as exc:
        return {
            "adc_available": False,
            "error": str(exc),
            "project_id": get_default_project_id()
        }


def get_gemini_client(
    project_id: Optional[str] = None,
    location: str = "us-central1",
    vertexai: bool = True
) -> Any:
    """
    Initializes a Google GenAI Client (Gemini SDK) authenticated via ADC.
    """
    proj = get_default_project_id(project_id)
    try:
        from google import genai
        client = genai.Client(vertexai=vertexai, project=proj, location=location)
        logger.info(f"Initialized Google GenAI client for project '{proj}' (location: {location})")
        return client
    except ImportError:
        logger.warning("google-genai SDK not installed. Please install 'google-genai' to use the Gemini SDK.")
        return None
    except Exception as exc:
        logger.error(f"Failed to initialize google-genai Client: {exc}")
        return None


class GCPAuth:
    """
    Centralized GCP Authentication helper class for AISPR audit & agentic subsystems.
    """

    def __init__(self, project_id: Optional[str] = None, scopes: Optional[List[str]] = None):
        self.scopes = scopes or DEFAULT_SCOPES
        self.credentials, self.discovered_project = get_gcp_credentials(scopes=self.scopes)
        self.project_id = get_default_project_id(project_id) or self.discovered_project

    @property
    def is_authenticated(self) -> bool:
        return self.credentials is not None

    def get_session(self) -> Any:
        return get_authenticated_session(scopes=self.scopes, credentials=self.credentials)

    def get_headers(self) -> Dict[str, str]:
        return get_auth_headers(scopes=self.scopes, credentials=self.credentials)

    def get_genai(self, location: str = "us-central1", vertexai: bool = True) -> Any:
        return get_gemini_client(project_id=self.project_id, location=location, vertexai=vertexai)

# Audit checkpoint [2026-02-12]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout

# Audit checkpoint [2026-03-02]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment

# Audit checkpoint [2026-04-05]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment
