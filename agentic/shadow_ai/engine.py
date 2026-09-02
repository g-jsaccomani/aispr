# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 9: Enterprise Shadow AI Discovery Engine.
Orchestrates:
  - Detection across all 7 sources (cloud resources, network indicators, endpoints,
    SaaS integrations, API usage, model endpoints, infrastructure metadata)
  - Epistemological confidence classification (OBSERVED, INFERRED, SUSPECTED)
  - Strict mandate: "Do not classify inference as fact."
  - Multi-vector risk scoring
  - Automatic deduplication and cross-sensor corroboration
  - Mandatory provenance and canonical Evidence with SHA-256
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from pydantic import Field
from domain.enums import ExecutionMode, FindingSeverity
from domain.models.base import AISPRBaseModel, utc_now
from .models import (
    ShadowAIDiscovery,
    ShadowConfidence,
    DetectionSource,
    ShadowAIRiskFactor,
)
from .detectors import ShadowAIDetectors
from .deduplicator import ShadowAIDeduplicator
from .risk_engine import ShadowAIRiskEngine

logger = logging.getLogger("AISPR-ShadowAIEngine")


class ShadowAIDiscoveryReport(AISPRBaseModel):
    """Aggregated enterprise Shadow AI discovery report."""
    scan_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)
    total_discovered: int = 0
    unique_assets_count: int = 0
    confidence_breakdown: Dict[str, int] = Field(default_factory=dict)
    source_breakdown: Dict[str, int] = Field(default_factory=dict)
    public_endpoints_count: int = 0
    discoveries: List[ShadowAIDiscovery] = Field(default_factory=list)


class EnterpriseShadowAIDiscoveryEngine:
    """
    Central orchestration engine for Enterprise Shadow AI discovery.
    """

    def __init__(self, default_mode: ExecutionMode = ExecutionMode.SIMULATION):
        self.default_mode = default_mode
        self.deduplicator = ShadowAIDeduplicator()

    def discover(
        self,
        cloud_resources: Optional[List[Dict[str, Any]]] = None,
        network_flows: Optional[List[Dict[str, Any]]] = None,
        host_processes: Optional[List[Dict[str, Any]]] = None,
        saas_records: Optional[List[Dict[str, Any]]] = None,
        api_logs: Optional[List[Dict[str, Any]]] = None,
        model_endpoints: Optional[List[Dict[str, Any]]] = None,
        infrastructure_metadata: Optional[List[Dict[str, Any]]] = None,
        execution_mode: Optional[ExecutionMode] = None,
    ) -> ShadowAIDiscoveryReport:
        """
        Executes multi-source Shadow AI discovery across all provided sensor streams.
        """
        mode = execution_mode or self.default_mode
        all_raw_discoveries: List[ShadowAIDiscovery] = []

        # 1. Cloud Resources
        if cloud_resources:
            all_raw_discoveries.extend(
                ShadowAIDetectors.detect_cloud_resources(cloud_resources, mode=mode)
            )

        # 2. Network Indicators
        if network_flows:
            all_raw_discoveries.extend(
                ShadowAIDetectors.detect_network_indicators(network_flows, mode=mode)
            )

        # 3. Endpoints (Host processes)
        if host_processes:
            all_raw_discoveries.extend(
                ShadowAIDetectors.detect_endpoints(host_processes, mode=mode)
            )

        # 4. SaaS Integrations
        if saas_records:
            all_raw_discoveries.extend(
                ShadowAIDetectors.detect_saas_integrations(saas_records, mode=mode)
            )

        # 5. API Usage
        if api_logs:
            all_raw_discoveries.extend(
                ShadowAIDetectors.detect_api_usage(api_logs, mode=mode)
            )

        # 6. Model Endpoints
        if model_endpoints:
            all_raw_discoveries.extend(
                ShadowAIDetectors.detect_model_endpoints(model_endpoints, mode=mode)
            )

        # 7. Infrastructure Metadata
        if infrastructure_metadata:
            all_raw_discoveries.extend(
                ShadowAIDetectors.detect_infrastructure_metadata(infrastructure_metadata, mode=mode)
            )

        # Ingest into deduplicator to corroborate and merge duplicates
        deduplicated = self.deduplicator.ingest_batch(all_raw_discoveries)

        # Compute summary metrics
        confidence_counts = {
            ShadowConfidence.OBSERVED.value: 0,
            ShadowConfidence.INFERRED.value: 0,
            ShadowConfidence.SUSPECTED.value: 0,
        }
        source_counts: Dict[str, int] = {}
        public_count = 0

        for disc in deduplicated:
            # Enforce FINAL invariant: Every finding MUST have provenance and confidence
            assert disc.provenance, f"Finding '{disc.discovery_id}' missing required provenance!"
            assert disc.confidence, f"Finding '{disc.discovery_id}' missing required confidence!"
            assert disc.evidence, f"Finding '{disc.discovery_id}' missing canonical evidence!"

            conf_str = str(disc.confidence.value if hasattr(disc.confidence, "value") else disc.confidence)
            src_str = str(disc.source.value if hasattr(disc.source, "value") else disc.source)
            confidence_counts[conf_str] = confidence_counts.get(conf_str, 0) + 1
            source_counts[src_str] = source_counts.get(src_str, 0) + 1
            if disc.is_public:
                public_count += 1

        scan_id = f"SCN-SHADOW-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        return ShadowAIDiscoveryReport(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc),
            execution_mode=mode,
            total_discovered=len(all_raw_discoveries),
            unique_assets_count=len(deduplicated),
            confidence_breakdown=confidence_counts,
            source_breakdown=source_counts,
            public_endpoints_count=public_count,
            discoveries=deduplicated,
        )
