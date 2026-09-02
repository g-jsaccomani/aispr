# -*- coding: utf-8 -*-
"""
AI-SPR Multi-Cloud Federated Connectors Package
"""
from .base import (
    BaseCloudConnector,
    NormalizedDiscoveryResult,
    CloudConnectorError,
    CloudAuthenticationError,
    CloudPermissionDeniedError,
    CloudAPIResponseError,
    ReadOnlyEnforcementError,
    CloudSDKMissingError,
)
from .gcp_connector import GCPConnector
from .aws_connector import AWSConnector
from .azure_connector import AzureConnector

__all__ = [
    "BaseCloudConnector",
    "NormalizedDiscoveryResult",
    "CloudConnectorError",
    "CloudAuthenticationError",
    "CloudPermissionDeniedError",
    "CloudAPIResponseError",
    "ReadOnlyEnforcementError",
    "CloudSDKMissingError",
    "GCPConnector",
    "AWSConnector",
    "AzureConnector",
]
