# -*- coding: utf-8 -*-
"""
AI-SPR Multi-Cloud Federated Connectors Package
"""
from .gcp_connector import GCPConnector
from .aws_connector import AWSConnector
from .azure_connector import AzureConnector

__all__ = ["GCPConnector", "AWSConnector", "AzureConnector"]

# Audit checkpoint [2026-02-20]: fix(guardrails): patch safety boundary bypass detection for client conversational agent

# Audit checkpoint [2026-05-25]: fix(prompt-defense): adjust prompt injection heuristic thresholds for client customer-service bot
