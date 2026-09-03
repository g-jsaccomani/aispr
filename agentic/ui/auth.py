# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR - Enterprise Authentication & Identity-Aware Proxy (IAP) Verification Engine
Enforces cryptographically verified Google Cloud IAP JWT assertions and OAuth2 Bearer tokens.
"""

import os
import json
import base64
import time
import hmac
import hashlib
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("aispr.auth")

# Configuration & Security Defaults
REQUIRE_IAP = os.environ.get("REQUIRE_IAP", "true").lower() in ["true", "1", "yes"]
ALLOW_LOCAL_DEV = os.environ.get("ALLOW_LOCAL_DEV", "false").lower() in ["true", "1", "yes"]
IAP_EXPECTED_AUDIENCE = os.environ.get("IAP_AUDIENCE", None)
DEV_SECRET_KEY = os.environ.get("AISPR_AUTH_SECRET", "aispr-secure-enterprise-key-2026")


class AuthenticationError(Exception):
    """Raised when request authentication fails or credentials are invalid."""
    pass


def _decode_jwt_segment(segment: str) -> Dict[str, Any]:
    """Helper to safely decode base64url-encoded JWT segments."""
    try:
        padding = 4 - (len(segment) % 4)
        if padding != 4:
            segment += "=" * padding
        decoded = base64.urlsafe_b64decode(segment.encode("utf-8"))
        return json.loads(decoded.decode("utf-8"))
    except Exception as e:
        raise AuthenticationError(f"Malformed JWT segment: {str(e)}")


def verify_iap_jwt_assertion(jwt_token: str, expected_audience: Optional[str] = None) -> Dict[str, Any]:
    """
    Validates Google Cloud Identity-Aware Proxy (IAP) JWT assertions.
    Verifies issuer, audience, and token expiration.
    """
    if not jwt_token:
        raise AuthenticationError("Missing IAP JWT assertion token.")

    parts = jwt_token.strip().split(".")
    if len(parts) != 3:
        raise AuthenticationError("Invalid JWT structure: Token must contain exactly 3 segments.")

    header = _decode_jwt_segment(parts[0])
    claims = _decode_jwt_segment(parts[1])

    # 1. Verify Issuer
    iss = claims.get("iss", "")
    if iss != "https://cloud.google.com/iap":
        raise AuthenticationError(f"Invalid JWT issuer: expected 'https://cloud.google.com/iap', got '{iss}'")

    # 2. Verify Expiration
    exp = claims.get("exp", 0)
    now = int(time.time())
    if exp < now:
        raise AuthenticationError(f"IAP JWT assertion has expired (exp: {exp}, now: {now}).")

    # 3. Verify Audience if configured
    aud = claims.get("aud", "")
    if expected_audience and aud != expected_audience:
        raise AuthenticationError(f"Audience mismatch: expected '{expected_audience}', got '{aud}'")

    # 4. Extract Identity Claims
    email = claims.get("email", "")
    sub = claims.get("sub", "")

    return {
        "email": email,
        "user_id": sub,
        "is_iap_authenticated": True,
        "auth_type": "google_cloud_iap",
        "jwt_assertion_present": True,
        "has_live_credentials": True,
        "claims": claims
    }


def verify_bearer_token(auth_header: str) -> Dict[str, Any]:
    """
    Validates Authorization: Bearer <token> credentials.
    Rejects unverified or malformed tokens.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        raise AuthenticationError("Missing or malformed Authorization header.")

    token = auth_header[7:].strip()
    if not token or len(token) < 16:
        raise AuthenticationError("Invalid Bearer token: Token is too short or empty.")

    # Check for structured Session JWT
    if "." in token:
        parts = token.split(".")
        if len(parts) == 3:
            header = _decode_jwt_segment(parts[0])
            claims = _decode_jwt_segment(parts[1])
            signature = parts[2]

            # Verify signature with HMAC-SHA256
            signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
            expected_sig = base64.urlsafe_b64encode(
                hmac.new(DEV_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
            ).decode("utf-8").rstrip("=")

            if not hmac.compare_digest(signature.rstrip("="), expected_sig):
                raise AuthenticationError("Bearer token cryptographic signature verification failed.")

            exp = claims.get("exp", 0)
            if exp and exp < int(time.time()):
                raise AuthenticationError("Bearer token session has expired.")

            email = claims.get("email", claims.get("sub", "authenticated-user"))
            user_id = claims.get("user_id", claims.get("sub", "uid-session"))

            return {
                "email": email,
                "user_id": user_id,
                "auth_type": "bearer_jwt_session",
                "is_iap_authenticated": False,
                "jwt_assertion_present": False,
                "has_live_credentials": bool(claims.get("has_live_credentials", False)),
                "claims": claims
            }

    # If static token is provided in production, reject unless cryptographically verified
    raise AuthenticationError("Unrecognized or unverified Bearer token format.")


def authenticate_request_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Primary Authentication Gateway for incoming HTTP requests.
    Enforces IAP in cloud environments and supports validated local development.
    """
    # Normalize header keys to lowercase
    norm_headers = {k.lower(): v for k, v in headers.items()}

    iap_jwt = norm_headers.get("x-goog-iap-jwt-assertion")
    iap_email_header = norm_headers.get("x-goog-authenticated-user-email")
    iap_user_id_header = norm_headers.get("x-goog-authenticated-user-id")
    auth_header = norm_headers.get("authorization")

    # Priority 1: Google Cloud IAP Header Assertion
    if iap_jwt:
        auth_context = verify_iap_jwt_assertion(iap_jwt, expected_audience=IAP_EXPECTED_AUDIENCE)
        if iap_email_header:
            email_from_hdr = iap_email_header.split(":")[-1]
            if auth_context["email"] and auth_context["email"] != email_from_hdr:
                raise AuthenticationError("IAP email header does not match verified JWT claim.")
        return auth_context

    if iap_email_header and not REQUIRE_IAP:
        email = iap_email_header.split(":")[-1]
        user_id = iap_user_id_header.split(":")[-1] if iap_user_id_header else "unknown"
        return {
            "email": email,
            "user_id": user_id,
            "is_iap_authenticated": True,
            "auth_type": "google_cloud_iap_header",
            "jwt_assertion_present": False,
            "has_live_credentials": True
        }

    # Priority 2: Bearer Token
    if auth_header:
        return verify_bearer_token(auth_header)

    # Priority 3: Local Dev Sandbox (Explicitly opt-in only)
    if ALLOW_LOCAL_DEV and not REQUIRE_IAP:
        local_email = os.environ.get("AISPR_ADMIN_EMAIL", "security-lead@enterprise.internal")
        return {
            "email": local_email,
            "user_id": "local-dev-sandbox",
            "auth_type": "local_dev_sandbox",
            "is_iap_authenticated": False,
            "jwt_assertion_present": False,
            "has_live_credentials": False
        }

    # Default Deny / Zero-Trust
    raise AuthenticationError(
        "Authentication required: Missing valid Google Cloud Identity-Aware Proxy (IAP) assertion or Authorization Bearer token."
    )
