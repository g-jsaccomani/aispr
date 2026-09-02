# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

Phase 9: Enterprise Shadow AI Discovery - Deduplication Engine.
Corroborates findings across multiple detection sensors and merges duplicate discoveries.
"""

from typing import Dict, List, Optional
from .models import ShadowAIDiscovery, ShadowConfidence


class ShadowAIDeduplicator:
    """
    Deduplicates discoveries across heterogeneous sensors and elevates confidence when
    multiple sensors corroborate the presence of an unmanaged AI asset.
    """

    def __init__(self):
        self._inventory: Dict[str, ShadowAIDiscovery] = {}

    def ingest(self, discovery: ShadowAIDiscovery) -> Tuple_Merged:
        """
        Ingests a discovery. If a duplicate exists, merges telemetry and updates confidence.
        Returns (discovery, is_new_boolean).
        """
        fp = discovery.fingerprint or discovery.compute_fingerprint()

        if fp in self._inventory:
            existing = self._inventory[fp]
            # Corroborate confidence: OBSERVED takes precedence over INFERRED / SUSPECTED
            if discovery.confidence == ShadowConfidence.OBSERVED and existing.confidence != ShadowConfidence.OBSERVED:
                existing.confidence = ShadowConfidence.OBSERVED
                existing.provenance = f"{existing.provenance} Corroborated with direct OBSERVED telemetry from {discovery.source}."
                if discovery.evidence:
                    existing.evidence = discovery.evidence

            # Merge unique risk factors
            for rf in discovery.risk_factors:
                if rf not in existing.risk_factors:
                    existing.risk_factors.append(rf)

            existing.risk_score = max(existing.risk_score, discovery.risk_score)
            return existing, False

        self._inventory[fp] = discovery
        return discovery, True

    def ingest_batch(self, discoveries: List[ShadowAIDiscovery]) -> List[ShadowAIDiscovery]:
        """Ingests a batch of discoveries and returns a deduplicated list."""
        for d in discoveries:
            self.ingest(d)
        return list(self._inventory.values())

    @property
    def total_unique(self) -> int:
        return len(self._inventory)


# Type helper
Tuple_Merged = tuple[ShadowAIDiscovery, bool]
