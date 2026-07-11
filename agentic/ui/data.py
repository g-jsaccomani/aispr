# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR - UI Data Layer & Demonstration Fixtures Gateway
Imports sanitized, isolated mock fixtures from fixtures/demo_data.py.
"""

import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from fixtures.demo_data import (
    DEMO_CLIENT_NAME,
    DEMO_CLIENT_SHORT_NAME,
    DEMO_CLIENT_LEGAL_NAME,
    DEMO_CLIENT_ORG,
    DEMO_CLIENT_FOLDER,
    DEMO_ORG_ID,
    DEMO_PROJECT_ID,
    DEMO_GCP_PROJECT_ID,
    DEMO_GCP_APPS_PROJECT_ID,
    DEMO_GCP_PROD_PROJECT_ID,
    DEMO_GCP_ENTERPRISE_PROJECT_ID,
    DEMO_GCP_ENTERPRISE_AI_PROJECT_ID,
    DEMO_AWS_ACCOUNT_ID,
    DEMO_AWS_ROLE_ARN,
    DEMO_AZURE_SUBSCRIPTION_ID,
    DEMO_AZURE_PROJECT,
    DEMO_SERVICE_ACCOUNT,
    DEMO_ANALYTICS_SA,
    DEMO_PAYMENT_SA,
    DEMO_STORAGE_BUCKET,
    DEMO_BACKUP_BUCKET,
    DEMO_RAG_BUCKET,
    DEMO_KMS_KEYRING,
    DEMO_VPC_NAME,
    DEMO_SUBNET_NAME,
    DEMO_ADMIN_EMAIL,
    DEMO_BEARER_USER_EMAIL,
    DEMO_SCOPE_DESCRIPTION,
    DEMO_FINDINGS_MAP,
    DEMO_DISCOVERED_AI_ASSETS,
    DEMO_TOPOLOGY_NODES,
    DEMO_TOPOLOGY_EDGES,
)

FINDINGS_MAP = DEMO_FINDINGS_MAP
DISCOVERED_AI_ASSETS = DEMO_DISCOVERED_AI_ASSETS
TOPOLOGY_NODES = DEMO_TOPOLOGY_NODES
TOPOLOGY_EDGES = DEMO_TOPOLOGY_EDGES

# Audit checkpoint [2026-07-11]: feat(rag-security): implement vector database access control validation for client
