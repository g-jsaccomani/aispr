# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - AI Asset Entity
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import Field, field_validator

from domain.enums import AssetType, CloudProvider
from domain.models.base import AISPRBaseModel, utc_now


class AIAsset(AISPRBaseModel):
    """
    Standardized entity representing an inventory item in the enterprise AI estate
    (e.g., Vertex AI Endpoint, Bedrock Foundation Model, Azure OpenAI Deployment,
    RAG Vector Store, or self-hosted Ollama container).
    """
    asset_id: str = Field(default_factory=lambda: f"AST-{uuid.uuid4().hex[:8].upper()}")
    name: str
    asset_type: AssetType = Field(default=AssetType.INFERENCE_ENDPOINT)
    provider: CloudProvider = Field(default=CloudProvider.GCP)
    location: str = Field(default="global")
    resource_uri: str = Field(default="")
    display_name: Optional[str] = None
    
    # Core AI Security Posture Attributes
    cmek_enabled: bool = False
    cmek_key_ref: Optional[str] = None
    is_private_endpoint: bool = False
    model_armor_enabled: bool = False
    
    # Governance & Metadata
    owner: Optional[str] = None
    classification: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    first_discovered: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)

    @field_validator("provider", mode="before")
    @classmethod
    def parse_provider(cls, v: Any) -> CloudProvider:
        if isinstance(v, str):
            val = v.lower()
            if val in ("gcp", "google", "google_cloud"):
                return CloudProvider.GCP
            if val in ("aws", "amazon"):
                return CloudProvider.AWS
            if val in ("azure", "microsoft"):
                return CloudProvider.AZURE
            try:
                return CloudProvider(val)
            except ValueError:
                raise ValueError(f"Invalid CloudProvider: '{v}'")
        return v

    @field_validator("asset_type", mode="before")
    @classmethod
    def parse_asset_type(cls, v: Any) -> AssetType:
        if isinstance(v, str):
            normalized = v.upper().replace(" ", "_").replace("-", "_")
            # Map legacy common strings
            if "NOTEBOOK" in normalized or "WORKBENCH" in normalized:
                return AssetType.AI_WORKBENCH_NOTEBOOK
            if "BUCKET" in normalized or "STORAGE" in normalized:
                return AssetType.STORAGE_BUCKET_RAG
            if "ENDPOINT" in normalized:
                return AssetType.INFERENCE_ENDPOINT
            if "MODEL" in normalized:
                return AssetType.FOUNDATION_MODEL
            try:
                return AssetType(normalized)
            except ValueError:
                raise ValueError(f"Invalid AssetType: '{v}'")
        return v
