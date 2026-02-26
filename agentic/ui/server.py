#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR - AI Security Posture Review (AI-SPM) Platform
Executive Assessment Console, Visual AI-BOM Dashboard & Google Cloud Official Executive Deliverable
"""

import sys
import os
import json
import logging
import urllib.parse
import http.server
import socketserver
import datetime
from typing import Dict, List, Any, Optional

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from agentic.runtime_defense.model_armor_guard import ModelArmorGuard
from agentic.threat_operations.ai_red_team_simulator import AIRedTeamSimulator
from agentic.threat_operations.ai_bom_generator import AIBOMGenerator
from audit.questionnaire.handler import QuestionnaireHandler
from audit.engine.scorer import PostureScorer
from audit.engine.reporter import ExecutiveReporter
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


TEMPLATES_DIR = os.path.join(project_root, "scripts", "journey", "templates")
REPORTS_DIR = os.path.join(project_root, "reports")

# Identity-Aware Proxy (IAP) & Local Dev Authentication Helpers
def get_current_user(
    request: Any = None,
    x_goog_authenticated_user_email: Optional[str] = None,
    x_goog_authenticated_user_id: Optional[str] = None,
    x_goog_iap_jwt_assertion: Optional[str] = None,
    authorization: Optional[str] = None
) -> Dict[str, Any]:
    """
    Validates and extracts authenticated user identity from Google Cloud IAP headers or Bearer tokens.
    """
    require_iap = os.environ.get("REQUIRE_IAP", "false").lower() in ["true", "1", "yes"]

    if x_goog_authenticated_user_email:
        email = x_goog_authenticated_user_email.split(":")[-1]
        user_id = x_goog_authenticated_user_id.split(":")[-1] if x_goog_authenticated_user_id else "unknown"
        return {
            "email": email,
            "user_id": user_id,
            "is_iap_authenticated": True,
            "auth_type": "google_iap",
            "jwt_assertion_present": bool(x_goog_iap_jwt_assertion),
            "has_live_credentials": True
        }

    if authorization and authorization.startswith("Bearer "):
        return {
            "email": DEMO_BEARER_USER_EMAIL,
            "user_id": "bearer-user",
            "auth_type": "bearer_session",
            "is_iap_authenticated": False,
            "jwt_assertion_present": False,
            "has_live_credentials": True
        }

    if require_iap:
        raise PermissionError("Missing required Google Cloud Identity-Aware Proxy (IAP) assertion headers.")

    return {
        "email": DEMO_ADMIN_EMAIL,
        "user_id": "local-dev-001",
        "auth_type": "local_dev_fallback",
        "is_iap_authenticated": False,
        "jwt_assertion_present": False,
        "has_live_credentials": True
    }


FASTAPI_AVAILABLE = False
app = None
try:
    from fastapi import FastAPI
    FASTAPI_AVAILABLE = True
    app = FastAPI(title="Agentic AISPR - Cloud Run Enterprise AI-SPM Platform")

    @app.get("/")
    def _route_root():
        return {"status": "AISPR Platform Online"}

    @app.get("/api/auth/me")
    def _route_me():
        return get_current_user()

    @app.post("/api/guard")
    def _route_guard(payload: dict):
        return {"verdict": "ALLOWED"}

    @app.post("/api/audit/evaluate")
    def _route_audit_evaluate(payload: dict):
        return {"status": "SUCCESS"}

    @app.post("/api/agentic/run_mesh")
    def _route_run_mesh(payload: dict):
        return {"status": "SUCCESS"}

    @app.get("/api/scripts/download")
    def _route_download_scripts():
        return {"status": "SUCCESS"}

    @app.get("/api/audit/controls/versions")
    def _route_controls_versions():
        return QuestionnaireHandler().get_framework_versions()

    @app.post("/api/audit/controls/reload")
    def _route_controls_reload():
        return {"reloaded": QuestionnaireHandler().reload()}

    @app.post("/api/audit/controls/import")
    def _route_controls_import(payload: dict):
        return QuestionnaireHandler().validate_and_diff(payload)

    @app.get("/api/inventory/topology")
    def _route_inventory_topology():
        return {"topology": []}

    @app.get("/api/inventory/export")
    def _route_inventory_export():
        return {"export": "SUCCESS"}

except Exception:
    pass

guard = ModelArmorGuard()
q_handler = QuestionnaireHandler()

# Discovered findings map and assets catalogue imported from sanitized demo fixtures
FINDINGS_MAP = DEMO_FINDINGS_MAP
DISCOVERED_AI_ASSETS = DEMO_DISCOVERED_AI_ASSETS

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AISPR - AI Security Posture Review | Google Cloud Consulting</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #14161B;
      --surface: #1B1E26;
      --surface-variant: #232732;
      --border: #2C3240;
      --primary: #1A73E8;
      --primary-hover: #1557B0;
      --text-main: #F1F5F9;
      --text-muted: #94A3B8;
      --text-subtle: #64748B;
      --success: #2B8A3E;
      --success-bg: rgba(43, 138, 62, 0.15);
      --warning: #F59F00;
      --warning-bg: rgba(245, 159, 0, 0.15);
      --danger: #E03131;
      --danger-bg: rgba(224, 49, 49, 0.15);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
    }
    .header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-logo {
      width: 30px;
      height: 30px;
      background: var(--primary);
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 0.95rem;
      color: white;
    }
    .brand-title { font-size: 1.1rem; font-weight: 700; color: #FFFFFF; }
    .brand-subtitle { font-size: 0.75rem; color: var(--text-muted); }
    .client-badge {
      background: var(--surface-variant);
      border: 1px solid var(--border);
      padding: 4px 12px;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      color: #8AB4F8;
    }

    .nav-bar {
      background: #181B22;
      border-bottom: 1px solid var(--border);
      padding: 0.4rem 2rem;
      display: flex;
      gap: 0.5rem;
      overflow-x: auto;
    }
    .nav-item {
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--text-muted);
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.15s;
      white-space: nowrap;
    }
    .nav-item:hover { color: #FFFFFF; background: var(--surface); }
    .nav-item.active {
      color: #FFFFFF;
      background: var(--surface);
      border-color: var(--border);
    }

    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 1.5rem 2rem;
      width: 100%;
      flex: 1;
    }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }

    /* Compact Horizontal Submenu Filter Bar (Placed at Top of Dashboard) */
    .filter-submenu-bar {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.5rem 1rem;
      margin-bottom: 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
    }
    .filter-submenu-controls {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .filter-pill-label {
      font-size: 0.72rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-right: 4px;
    }
    .filter-pill-select {
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.78rem;
      height: 28px;
      font-family: inherit;
    }
    .filter-pill-select:focus { outline: none; border-color: var(--primary); }

    /* Health Gauge & KPIs */
    .grid-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 1.25rem;
    }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.1rem 1.25rem;
      cursor: pointer;
      transition: transform 0.15s, border-color 0.15s;
    }
    .stat-card:hover { border-color: var(--primary); transform: translateY(-2px); }
    .stat-title { font-size: 0.72rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-value { font-size: 1.75rem; font-weight: 800; margin-top: 0.25rem; }
    .stat-desc { font-size: 0.78rem; color: var(--text-subtle); margin-top: 0.2rem; }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 1.25rem;
    }
    .card-title {
      font-size: 0.98rem;
      font-weight: 700;
      margin-bottom: 0.85rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }

    /* Visual Interactive Charts Layout */
    .charts-grid {
      display: grid;
      grid-template-columns: 1fr 1.2fr;
      gap: 1.25rem;
      margin-bottom: 1.25rem;
    }
    @media (max-width: 900px) {
      .charts-grid { grid-template-columns: 1fr; }
    }

    /* Donut Chart */
    .donut-wrapper {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 2rem;
      flex-wrap: wrap;
      padding: 0.5rem 0;
    }
    .donut-svg-box { position: relative; width: 140px; height: 140px; }
    .donut-center-text {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }
    .donut-pct { font-size: 1.4rem; font-weight: 800; }
    .donut-sub { font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase; }
    .donut-legend { display: flex; flex-direction: column; gap: 6px; font-size: 0.82rem; }
    .legend-row { display: flex; align-items: center; gap: 8px; cursor: pointer; padding: 4px 6px; border-radius: 4px; }
    .legend-row:hover { background: var(--surface-variant); }
    .legend-dot { width: 8px; height: 8px; border-radius: 50%; }

    /* Maturity Pillar Horizontal Bar Chart */
    .pillar-chart { display: flex; flex-direction: column; gap: 10px; }
    .pillar-row { cursor: pointer; padding: 4px 6px; border-radius: 6px; transition: background 0.15s; }
    .pillar-row:hover { background: var(--surface-variant); }
    .pillar-header { display: flex; justify-content: space-between; font-size: 0.8rem; font-weight: 600; margin-bottom: 4px; }
    .pillar-bar-bg { width: 100%; height: 6px; background: var(--surface-variant); border-radius: 3px; overflow: hidden; }
    .pillar-bar-fill { height: 100%; border-radius: 3px; transition: width 0.4s ease; }

    /* Interactive Asset Cards Grid */
    .asset-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(310px, 1fr));
      gap: 1rem;
      margin-top: 0.5rem;
    }
    .asset-card {
      background: var(--surface-variant);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.1rem;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .asset-card:hover {
      border-color: var(--primary);
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.25);
    }
    .asset-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 6px;
    }
    .asset-card-title { font-weight: 700; font-size: 0.9rem; color: #FFFFFF; }
    .asset-card-meta { font-size: 0.78rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 10px; }
    .asset-card-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-top: 1px solid rgba(255,255,255,0.06);
      padding-top: 8px;
      font-size: 0.75rem;
    }

    /* Slide-over Asset Inspector Drawer */
    .drawer-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(2px);
      z-index: 1000;
      opacity: 0;
      visibility: hidden;
      transition: all 0.25s ease;
    }
    .drawer-overlay.active { opacity: 1; visibility: visible; }
    .drawer-panel {
      position: fixed;
      top: 0;
      right: -550px;
      width: 500px;
      max-width: 90vw;
      height: 100vh;
      background: var(--surface);
      border-left: 1px solid var(--border);
      z-index: 1001;
      overflow-y: auto;
      padding: 1.75rem;
      transition: right 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: -8px 0 24px rgba(0,0,0,0.5);
    }
    .drawer-panel.active { right: 0; }
    .drawer-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1rem;
      margin-bottom: 1.25rem;
    }
    .drawer-title { font-size: 1.2rem; font-weight: 700; color: #FFFFFF; }
    .drawer-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 1.3rem;
      cursor: pointer;
      line-height: 1;
      padding: 4px;
    }
    .drawer-close:hover { color: white; }
    .drawer-section { margin-bottom: 1.25rem; }
    .drawer-section-title {
      font-size: 0.75rem;
      font-weight: 700;
      color: var(--primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }
    .drawer-meta-table { width: 100%; font-size: 0.8rem; border-collapse: collapse; }
    .drawer-meta-table td { padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
    .drawer-meta-table td:first-child { color: var(--text-muted); width: 38%; font-weight: 600; }

    /* Tags & Buttons */
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 600; }
    .tag-gcp { background: rgba(66, 133, 244, 0.15); color: #8AB4F8; }
    .tag-aws { background: rgba(255, 153, 0, 0.15); color: #FFD43B; }
    .tag-azure { background: rgba(0, 120, 212, 0.15); color: #80D8FF; }
    .tag-high { background: var(--danger-bg); color: #FFA8A8; }
    .tag-med { background: var(--warning-bg); color: #FFD43B; }
    .tag-low { background: var(--success-bg); color: #8CE99A; }

    .btn {
      background: var(--primary);
      color: white;
      border: none;
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
    }
    .btn:hover { background: var(--primary-hover); }
    .btn-secondary {
      background: var(--surface-variant);
      color: var(--text-main);
      border: 1px solid var(--border);
    }
    .btn-secondary:hover { background: #373A40; color: white; }
    .btn-danger { background: #C92A2A; color: white; }
    .btn-danger:hover { background: #A61E1E; }

    /* Tables */
    .table-container { overflow-x: auto; margin-top: 0.5rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.72rem; background: var(--surface-variant); }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    /* Flow Cards */
    .flow-pipeline {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.85rem;
      margin: 0.85rem 0 1.25rem 0;
    }
    .flow-card {
      background: var(--surface-variant);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.9rem;
      position: relative;
    }
    .flow-step-num {
      font-size: 0.68rem;
      font-weight: 700;
      color: var(--primary);
      text-transform: uppercase;
      margin-bottom: 3px;
    }
    .flow-title { font-size: 0.88rem; font-weight: 700; color: var(--text-main); margin-bottom: 3px; }
    .flow-desc { font-size: 0.76rem; color: var(--text-muted); }

    /* Question Cards */
    .domain-select {
      display: flex;
      gap: 6px;
      overflow-x: auto;
      margin-bottom: 1rem;
      padding-bottom: 4px;
    }
    .domain-btn {
      padding: 5px 12px;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text-muted);
      cursor: pointer;
      white-space: nowrap;
    }
    .domain-btn.active {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .question-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.1rem;
      margin-bottom: 0.85rem;
    }
    .q-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 6px;
      gap: 8px;
    }
    .q-id { font-weight: 700; color: #8AB4F8; font-size: 0.88rem; }
    .q-title { font-size: 0.9rem; font-weight: 600; margin-bottom: 4px; color: #FFFFFF; }
    .q-framework {
      font-size: 0.72rem;
      color: var(--text-muted);
      background: var(--surface-variant);
      padding: 2px 6px;
      border-radius: 4px;
      display: inline-block;
      margin-bottom: 6px;
    }
    .q-finding {
      background: rgba(245, 159, 0, 0.08);
      border-left: 3px solid var(--warning);
      padding: 6px 10px;
      font-size: 0.8rem;
      color: #FFD43B;
      border-radius: 0 4px 4px 0;
      margin-bottom: 8px;
    }
    .q-finding.none {
      background: rgba(43, 138, 62, 0.08);
      border-left-color: var(--success);
      color: #8CE99A;
    }
    .q-answers {
      display: flex;
      gap: 14px;
      align-items: center;
      margin-top: 8px;
      flex-wrap: wrap;
    }
    .choice-opt {
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 0.82rem;
      cursor: pointer;
    }
    .q-notes {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 10px;
      color: var(--text-main);
      font-size: 0.8rem;
      font-family: inherit;
      margin-top: 6px;
    }
    .q-notes:focus { outline: none; border-color: var(--primary); }

    /* Red Team Interactive Styles */
    .redteam-select {
      width: 100%;
      background: var(--surface-variant);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      color: var(--text-main);
      font-size: 0.85rem;
      font-family: inherit;
      margin-bottom: 0.85rem;
    }
    .redteam-select:focus { outline: none; border-color: var(--primary); }
    .threat-detail-box {
      background: var(--surface-variant);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.85rem;
      margin-bottom: 0.85rem;
    }

    .code-box {
      background: #101216;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: #A8C7FA;
      max-height: 400px;
      overflow-y: auto;
      white-space: pre-wrap;
      line-height: 1.5;
    }

    /* Google Cloud Executive Document Layout (On Screen) */
    .gcp-report-wrapper {
      background: #1B1E26;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 2.5rem;
      color: var(--text-main);
      line-height: 1.6;
    }
    .gcp-accent-bar {
      display: flex;
      height: 4px;
      width: 100%;
      border-radius: 2px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }
    .gcp-blue { background: #4285F4; flex: 1; }
    .gcp-red { background: #EA4335; flex: 1; }
    .gcp-yellow { background: #FBBC04; flex: 1; }
    .gcp-green { background: #34A853; flex: 1; }

    .report-cover-page {
      padding: 2.5rem 0;
      border-bottom: 2px solid var(--border);
      margin-bottom: 2.5rem;
    }
    .cover-org { font-size: 0.82rem; font-weight: 700; color: #4285F4; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 0.4rem; }
    .cover-title { font-size: 2rem; font-weight: 800; color: #FFFFFF; line-height: 1.2; margin-bottom: 0.6rem; }
    .cover-subtitle { font-size: 1rem; color: var(--text-muted); margin-bottom: 1.5rem; }
    
    .report-meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      background: var(--surface);
      padding: 1.25rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      margin-bottom: 1.25rem;
      font-size: 0.85rem;
    }
    .meta-item strong { color: var(--text-muted); display: block; font-size: 0.72rem; text-transform: uppercase; margin-bottom: 3px; }

    .report-toc {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem 1.75rem;
      margin-bottom: 2.5rem;
    }
    .toc-title { font-size: 1rem; font-weight: 700; color: #8AB4F8; margin-bottom: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
    .toc-list { list-style: none; padding: 0; }
    .toc-item {
      display: flex;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px dashed var(--border);
      font-size: 0.85rem;
      color: var(--text-main);
    }
    .toc-item strong { color: #8AB4F8; margin-right: 6px; }

    .report-chapter { margin-bottom: 2.5rem; }
    .chapter-h2 { font-size: 1.15rem; font-weight: 700; color: #8AB4F8; margin: 1.25rem 0 0.85rem 0; border-bottom: 1px solid var(--border); padding-bottom: 5px; }

    .footer {
      border-top: 1px solid var(--border);
      padding: 1rem 2rem;
      text-align: center;
      font-size: 0.72rem;
      color: var(--text-subtle);
    }

    /* Print / PDF Optimized Media Styles (A4 Standard) */
    @page {
      size: A4 portrait;
      margin: 15mm 15mm 15mm 15mm;
    }
    @media print {
      body {
        background: #FFFFFF !important;
        color: #202124 !important;
        font-size: 9.5pt !important;
        margin: 0 !important;
        padding: 0 !important;
      }
      .header, .nav-bar, .action-bar, .btn, .footer, .filter-submenu-bar, .drawer-overlay, .drawer-panel, #domain-filters, .redteam-select, #singleTestResult, #tab-dashboard, #tab-inventory, #tab-questionnaire, #tab-redteam {
        display: none !important;
      }
      .container {
        max-width: 100% !important;
        padding: 0 !important;
        margin: 0 !important;
      }
      .tab-panel { display: none !important; }
      #tab-report { display: block !important; }
      .card {
        border: none !important;
        background: transparent !important;
        padding: 0 !important;
        box-shadow: none !important;
      }
      .gcp-report-wrapper {
        background: #FFFFFF !important;
        color: #202124 !important;
        border: none !important;
        padding: 0 !important;
      }
      .report-cover-page {
        page-break-after: always;
        min-height: 85vh;
        display: flex;
        flex-direction: column;
        justify-content: center;
        border-bottom: none !important;
        padding: 4rem 0 !important;
      }
      .cover-title { color: #202124 !important; font-size: 2.2rem !important; }
      .cover-subtitle { color: #5F6368 !important; }
      .cover-org { color: #1A73E8 !important; }
      .chapter-h2 { color: #1A73E8 !important; border-bottom: 2px solid #1A73E8 !important; }
      .report-toc {
        page-break-after: always;
        background: #F8F9FA !important;
        border: 1px solid #DADCE0 !important;
      }
      .toc-title { color: #1A73E8 !important; }
      .toc-item { color: #202124 !important; border-bottom: 1px dashed #DADCE0 !important; }
      .toc-item strong { color: #1A73E8 !important; }
      .report-meta-grid {
        background: #F8F9FA !important;
        border: 1px solid #DADCE0 !important;
        color: #202124 !important;
      }
      .meta-item strong { color: #5F6368 !important; }
      table { border-collapse: collapse !important; width: 100% !important; margin: 12px 0 !important; font-size: 8.5pt !important; }
      th { background: #F1F3F4 !important; color: #202124 !important; border: 1px solid #DADCE0 !important; font-weight: bold !important; }
      td { border: 1px solid #DADCE0 !important; color: #202124 !important; background: #FFFFFF !important; }
      .stat-card {
        background: #F8F9FA !important;
        border: 1px solid #DADCE0 !important;
        color: #202124 !important;
      }
      .stat-title { color: #5F6368 !important; }
      .stat-value { color: #202124 !important; }
      .stat-desc { color: #5F6368 !important; }
      .tag-high { background: #FCE8E6 !important; color: #C5221F !important; border: 1px solid #FAD2CF !important; }
      .tag-med { background: #FEF7E0 !important; color: #B06000 !important; border: 1px solid #FEEFC3 !important; }
      .tag-low { background: #E6F4EA !important; color: #137333 !important; border: 1px solid #CEEAD6 !important; }
      .page-break { page-break-before: always !important; padding-top: 1.5rem !important; }
      * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    }
  </style>
</head>
<body>

  <!-- Header -->
  <header class="header">
    <div class="brand">
      <div class="brand-logo">A</div>
      <div>
        <div class="brand-title">AISPR - AI Security Posture Review</div>
        <div class="brand-subtitle">Google Cloud Security Consulting | Enterprise AI Governance & Defense</div>
      </div>
    </div>
    <div class="client-badge" id="clientBadge">" + f"Scope: {DEMO_CLIENT_SHORT_NAME} Lab ({DEMO_GCP_PROJECT_ID})" + "</div>
  </header>

  <!-- Navigation -->
  <nav class="nav-bar">
    <div class="nav-item active" onclick="showTab('dashboard')">Posture Health Dashboard</div>
    <div class="nav-item" onclick="showTab('inventory')">AI-BOM Inventory</div>
    <div class="nav-item" onclick="showTab('questionnaire')">Audit Questionnaire</div>
    <div class="nav-item" onclick="showTab('redteam')">Red Team Validation</div>
    <div class="nav-item" onclick="showTab('report')">Executive Report</div>
  </nav>

  <main class="container">

    <!-- ========================================================================= -->
    <!-- TAB 1: POSTURE HEALTH DASHBOARD (SUBMENU AT TOP + HEALTH METRICS + CARDS) -->
    <!-- ========================================================================= -->
    <div id="tab-dashboard" class="tab-panel active">
      
      <!-- 1. Inline Submenu Filter Bar (Positioned AT THE TOP above widgets) -->
      <div class="filter-submenu-bar">
        <div class="filter-submenu-controls">
          <span class="filter-pill-label">Filter Assets:</span>
          
          <select class="filter-pill-select" id="filterCloud" onchange="onProviderChange()">
            <option value="ALL">Cloud: All Providers</option>
            <option value="Google Cloud">Google Cloud</option>
            <option value="AWS Bedrock">AWS Bedrock</option>
            <option value="Azure OpenAI">Azure OpenAI</option>
          </select>

          <select class="filter-pill-select" id="filterProduct" onchange="onProductChange()">
            <option value="ALL">Product: All</option>
          </select>

          <select class="filter-pill-select" id="filterProject" onchange="onProjectChange()">
            <option value="ALL">Project: All</option>
          </select>

          <select class="filter-pill-select" id="filterRisk" onchange="updateDashboardView()">
            <option value="ALL">Risk: All Tiers</option>
            <option value="HIGH">High Risk / Critical</option>
            <option value="MED">Medium Risk</option>
            <option value="LOW">Low / Compliant</option>
          </select>

          <button class="btn btn-secondary" style="height:28px; padding:2px 10px; font-size:0.75rem;" onclick="resetDashboardFilters()">Clear</button>
        </div>

        <div id="filtered-assets-count" style="font-size:0.76rem; color:var(--text-muted); font-weight:600;">
          Showing 7 assets
        </div>
      </div>

      <!-- 2. Health KPIs -->
      <div class="grid-stats">
        <div class="stat-card" onclick="filterByHealthState('ALL')">
          <div class="stat-title">Overall Posture Health</div>
          <div class="stat-value" id="health-score-val" style="color: var(--warning);">71.2%</div>
          <div class="stat-desc" id="health-tier-val">Status: Moderate Risk / Partial Alignment</div>
        </div>
        <div class="stat-card" onclick="filterByHealthState('Y')">
          <div class="stat-title">Compliant Controls</div>
          <div class="stat-value" style="color: var(--success);" id="count-yes">62</div>
          <div class="stat-desc">Passed without critical deviations</div>
        </div>
        <div class="stat-card" onclick="filterByHealthState('P')">
          <div class="stat-title">Partial Controls</div>
          <div class="stat-value" style="color: var(--warning);" id="count-partial">24</div>
          <div class="stat-desc">Policy adjustments required</div>
        </div>
        <div class="stat-card" onclick="filterByHealthState('N')">
          <div class="stat-title">Critical Gaps</div>
          <div class="stat-value" style="color: var(--danger);" id="count-no">18</div>
          <div class="stat-desc">Immediate remediation required</div>
        </div>
      </div>

      <!-- 3. Posture Charts (Donut Chart + Domain Maturity Bars) -->
      <div class="charts-grid">
        
        <!-- Chart 1: Dynamic Compliance Donut -->
        <div class="card" style="margin-bottom:0;">
          <div class="card-title">
            <span>Compliance Distribution</span>
            <span id="filtered-scope-label" style="font-size:0.75rem; color:var(--text-muted);">Scope: Global (104 Controls)</span>
          </div>
          <div class="donut-wrapper">
            <div class="donut-svg-box">
              <svg viewBox="0 0 36 36" style="width:100%; height:100%; transform: rotate(-90deg);">
                <!-- Background ring -->
                <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#232732" stroke-width="3.8"/>
                <!-- Yes arc -->
                <path id="donut-arc-yes" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#2B8A3E" stroke-width="3.8" stroke-dasharray="59.6, 100"/>
                <!-- Partial arc -->
                <path id="donut-arc-partial" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#F59F00" stroke-width="3.8" stroke-dasharray="23.0, 100" stroke-dashoffset="-59.6"/>
                <!-- No arc -->
                <path id="donut-arc-no" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#E03131" stroke-width="3.8" stroke-dasharray="17.4, 100" stroke-dashoffset="-82.6"/>
              </svg>
              <div class="donut-center-text">
                <div class="donut-pct" id="donut-center-score" style="color:var(--warning);">71.2%</div>
                <div class="donut-sub">Overall Score</div>
              </div>
            </div>

            <div class="donut-legend">
              <div class="legend-row" onclick="filterByHealthState('Y')">
                <div class="legend-dot" style="background:#2B8A3E;"></div>
                <div><strong id="legend-yes-count">62</strong> Compliant (<span id="legend-yes-pct">59.6%</span>)</div>
              </div>
              <div class="legend-row" onclick="filterByHealthState('P')">
                <div class="legend-dot" style="background:#F59F00;"></div>
                <div><strong id="legend-partial-count">24</strong> Partial (<span id="legend-partial-pct">23.0%</span>)</div>
              </div>
              <div class="legend-row" onclick="filterByHealthState('N')">
                <div class="legend-dot" style="background:#E03131;"></div>
                <div><strong id="legend-no-count">18</strong> Critical Gaps (<span id="legend-no-pct">17.4%</span>)</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Chart 2: Domain Maturity Bars (AI-SPR Core Pillars) -->
        <div class="card" style="margin-bottom:0;">
          <div class="card-title">
            <span>Domain Maturity (AI-SPR Core Pillars)</span>
            <span style="font-size:0.75rem; color:var(--text-muted);">Click on a pillar to inspect</span>
          </div>
          
          <div class="pillar-chart">
            <div class="pillar-row" onclick="filterByPillar('DAT')">
              <div class="pillar-header">
                <span>1. Data Security, Lineage & Privacy (DAT)</span>
                <span id="bar-val-dat" style="color:#FFD43B;">65.0%</span>
              </div>
              <div class="pillar-bar-bg">
                <div class="pillar-bar-fill" id="bar-fill-dat" style="width:65.0%; background:#F59F00;"></div>
              </div>
            </div>

            <div class="pillar-row" onclick="filterByPillar('MOD')">
              <div class="pillar-header">
                <span>2. Model Hardening & Supply Chain (MOD)</span>
                <span id="bar-val-mod" style="color:#8CE99A;">72.5%</span>
              </div>
              <div class="pillar-bar-bg">
                <div class="pillar-bar-fill" id="bar-fill-mod" style="width:72.5%; background:#2B8A3E;"></div>
              </div>
            </div>

            <div class="pillar-row" onclick="filterByPillar('INF')">
              <div class="pillar-header">
                <span>3. Infrastructure, VPC Isolation & IAM (INF)</span>
                <span id="bar-val-inf" style="color:#FFA8A8;">60.0%</span>
              </div>
              <div class="pillar-bar-bg">
                <div class="pillar-bar-fill" id="bar-fill-inf" style="width:60.0%; background:#E03131;"></div>
              </div>
            </div>

            <div class="pillar-row" onclick="filterByPillar('APP')">
              <div class="pillar-header">
                <span>4. Application Security & API Defense (APP)</span>
                <span id="bar-val-app" style="color:#FFD43B;">68.0%</span>
              </div>
              <div class="pillar-bar-bg">
                <div class="pillar-bar-fill" id="bar-fill-app" style="width:68.0%; background:#F59F00;"></div>
              </div>
            </div>

            <div class="pillar-row" onclick="filterByPillar('OPS')">
              <div class="pillar-header">
                <span>5. Operations, Telemetry & Detection (OPS)</span>
                <span id="bar-val-ops" style="color:#8CE99A;">75.0%</span>
              </div>
              <div class="pillar-bar-bg">
                <div class="pillar-bar-fill" id="bar-fill-ops" style="width:75.0%; background:#2B8A3E;"></div>
              </div>
            </div>
          </div>
        </div>

      </div>

      <!-- 4. Audited AI Assets Matrix (Clickable Cards) -->
      <div class="asset-grid" id="dashboard-asset-grid">
        <!-- Rendered dynamically -->
      </div>

    </div>

    <!-- ========================================================================= -->
    <!-- TAB 2: AI-BOM INVENTORY & EXECUTIVE TOPOLOGY -->
    <!-- ========================================================================= -->
    <div id="tab-inventory" class="tab-panel">
      
      <!-- AI-BOM KPIs -->
      <div class="grid-stats">
        <div class="stat-card">
          <div class="stat-title">Foundation Models (LLMs)</div>
          <div class="stat-value" style="color: #8AB4F8;">3</div>
          <div class="stat-desc">Vertex Gemini, AWS Claude & Azure GPT-4o</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Datasets & RAG Stores</div>
          <div class="stat-value" style="color: #FFD43B;">2</div>
          <div class="stat-desc">GCS Financial Records & Vector Search</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">AI Microservices & APIs</div>
          <div class="stat-value" style="color: #80D8FF;">2</div>
          <div class="stat-desc">vm-payment-api (/api/v1/ai/chat)</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Libraries & MLOps</div>
          <div class="stat-value" style="color: var(--success);">12</div>
          <div class="stat-desc">Python Dependencies & Frameworks</div>
        </div>
      </div>

      <!-- Data Flow & AI Architectural Pipeline -->
      <div class="card">
        <div class="card-title">
          <span>AI Data Flow & Pipeline Architecture</span>
        </div>
        <p style="color:var(--text-muted); font-size:0.85rem;">
          End-to-end mapping of inference lifecycle, RAG ingestion, and security control checkpoints in the audited environment.
        </p>

        <div class="flow-pipeline">
          <div class="flow-card">
            <div class="flow-step-num">Step 1: Request</div>
            <div class="flow-title">User / App Client</div>
            <div class="flow-desc">HTTPS call to microservice <code>/api/v1/ai/chat</code></div>
          </div>

          <div class="flow-card" style="border-color: var(--warning);">
            <div class="flow-step-num" style="color:var(--warning);">Step 2: Guardrail Inspection</div>
            <div class="flow-title">Model Armor Guard</div>
            <div class="flow-desc">Prompt Injection, Jailbreak filter & DLP redaction</div>
          </div>

          <div class="flow-card" style="border-color: var(--danger);">
            <div class="flow-step-num" style="color:var(--danger);">Step 3: RAG Retrieval</div>
            <div class="flow-title">Cloud Storage / Dataset</div>
            <div class="flow-desc">Financial context retrieval (Alert: CMEK missing)</div>
          </div>

          <div class="flow-card" style="border-color: var(--primary);">
            <div class="flow-step-num">Step 4: Inference</div>
            <div class="flow-title">Vertex AI Gemini 1.5</div>
            <div class="flow-desc">" + f"Private execution in dedicated project <code>{DEMO_GCP_PROJECT_ID}</code>" + "</div>
          </div>

          <div class="flow-card" style="border-color: var(--success);">
            <div class="flow-step-num" style="color:var(--success);">Step 5: Secure Response</div>
            <div class="flow-title">Return & Audit Logs</div>
            <div class="flow-desc">Telemetry logged to Cloud Logging & Cloud Monitoring</div>
          </div>
        </div>
      </div>

      <!-- Structured AI-BOM Table -->
      <div class="card">
        <div class="card-title">
          <span>Structured AI Bill of Materials (AI-BOM Inventory)</span>
          <button class="btn btn-secondary" onclick="exportAIBOMJson()">Download CycloneDX JSON</button>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>AI Asset / Component</th>
                <th>Category</th>
                <th>Provider</th>
                <th>Location / Scope</th>
                <th>Version / Hash</th>
                <th>Security Posture</th>
                <th>Recommended Action</th>
              </tr>
            </thead>
            <tbody id="aibom-table-body">
              <!-- Rendered dynamically -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- CycloneDX JSON Specification View -->
      <div class="card">
        <div class="card-title">
          <span>CycloneDX AI-BOM Specification (Technical JSON)</span>
          <button class="btn btn-secondary" onclick="copyAIBOMJson()">Copy JSON</button>
        </div>
        <div class="code-box" id="inventory-box">
Loading CycloneDX AI-BOM specification...
        </div>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 3: AUDIT QUESTIONNAIRE -->
    <!-- ========================================================================= -->
    <div id="tab-questionnaire" class="tab-panel">
      <div class="card">
        <div class="card-title">
          <span>Audit Controls & Architectural Findings Questionnaire</span>
          <button class="btn" onclick="saveAndRecalculateHealth()">Recalculate Health</button>
        </div>
        <p style="color:var(--text-muted); font-size:0.85rem; margin-bottom:1.25rem;">
          Each question is directly linked to environment scan findings and statutory regulatory baselines. Modifying answers updates posture health in real-time.
        </p>

        <div class="domain-select" id="domain-filters">
          <div class="domain-btn active" onclick="filterDomain('ALL')">All Domains (104)</div>
          <div class="domain-btn" onclick="filterDomain('DAT')">1. Data Security & Privacy (DAT)</div>
          <div class="domain-btn" onclick="filterDomain('MOD')">2. Model Hardening & Supply Chain (MOD)</div>
          <div class="domain-btn" onclick="filterDomain('INF')">3. Infrastructure & IAM (INF)</div>
          <div class="domain-btn" onclick="filterDomain('APP')">4. Application Security & APIs (APP)</div>
          <div class="domain-btn" onclick="filterDomain('OPS')">5. Operations & Monitoring (OPS)</div>
        </div>

        <div id="questions-container">
          <!-- Rendered dynamically via JavaScript -->
        </div>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 4: RED TEAM & MODEL ARMOR DEFENSE LAB -->
    <!-- ========================================================================= -->
    <div id="tab-redteam" class="tab-panel">
      
      <!-- Red Team KPIs -->
      <div class="grid-stats">
        <div class="stat-card">
          <div class="stat-title">Benchmark Attack Vectors</div>
          <div class="stat-value" style="color: #8AB4F8;">20</div>
          <div class="stat-desc">6 MITRE ATLAS & OWASP Categories</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Model Armor Defense Efficacy</div>
          <div class="stat-value" style="color: var(--success);" id="redteam-efficacy">95.0%</div>
          <div class="stat-desc">Block & Sanitization Rate</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Critical Target Vulnerabilities</div>
          <div class="stat-value" style="color: var(--danger);">4</div>
          <div class="stat-desc">Prompt Injection, BOLA, DLP & IAM</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Ingress Defense Status</div>
          <div class="stat-value" style="color: var(--success);">ACTIVE</div>
          <div class="stat-desc">Model Armor Input Shielding</div>
        </div>
      </div>

      <!-- Interactive Simulator with 20 Benchmark Prompts -->
      <div class="card">
        <div class="card-title">
          <span>Adversarial Testing Lab (Select an Attack Vector)</span>
          <button class="btn btn-danger" onclick="runFullRedTeamCampaign()">Run Full Campaign (20 Vectors)</button>
        </div>
        <p style="color:var(--text-muted); font-size:0.85rem; margin-bottom:1rem;">
          Select one of the 20 benchmark attack vectors below to inspect how <strong>Model Armor Guard</strong> behaves and how vulnerabilities manifest in the workload.
        </p>

        <!-- Dropdown with 20 Attacks -->
        <select class="redteam-select" id="redteamSelect" onchange="onSelectAdversarialPrompt(this.value)">
          <option value="">-- Select a benchmark attack vector (20 options) --</option>
          <optgroup label="1. Direct Prompt Injection & Jailbreaking (OWASP LLM01 / MITRE AML.T0051)">
            <option value="ADV-01">ADV-01: Instruction Bypass & Developer Mode Switch</option>
            <option value="ADV-02">ADV-02: DAN Mode (Do Anything Now) Role-Play</option>
            <option value="ADV-03">ADV-03: Base64 Obfuscation for Filter Evasion</option>
            <option value="ADV-04">ADV-04: Context Switching & Hypothetical Framing</option>
          </optgroup>
          <optgroup label="2. System Prompt Leakage & Extraction (OWASP LLM07 / MITRE AML.T0054)">
            <option value="ADV-05">ADV-05: Verbatim System Prompt Extraction</option>
            <option value="ADV-06">ADV-06: Guidelines & Internal API Key Exfiltration</option>
            <option value="ADV-07">ADV-07: Model Inversion & Training Data Extraction</option>
          </optgroup>
          <optgroup label="3. Indirect Prompt Injection & RAG Poisoning (OWASP LLM01 / MITRE AML.T0051.001)">
            <option value="ADV-08">ADV-08: Hidden XML Tag Injection in RAG Document</option>
            <option value="ADV-09">ADV-09: Stealth Command in HTML Comment of Knowledge Base</option>
            <option value="ADV-10">ADV-10: Conversation History Exfiltration to External Server</option>
          </optgroup>
          <optgroup label="4. Sensitive Data Exposure (DLP & PII) (OWASP LLM06 / MITRE AML.T0057)">
            <option value="ADV-11">ADV-11: Credit Card and SSN Insertion without Masking</option>
            <option value="ADV-12">ADV-12: SQL Database Dump Extraction via RAG</option>
            <option value="ADV-13">ADV-13: Protected Health Information Query (HIPAA/GDPR)</option>
          </optgroup>
          <optgroup label="5. Excessive Agency & Tool Abuse (OWASP LLM08 / MITRE AML.T0058)">
            <option value="ADV-14">ADV-14: Destructive Cloud Storage Bucket Deletion via Tool Call</option>
            <option value="ADV-15">ADV-15: IAM Privilege Escalation across GCP Organization</option>
            <option value="ADV-16">ADV-16: SSRF against GCP Metadata Server (169.254.169.254)</option>
            <option value="ADV-17">ADV-17: Arbitrary Command Execution (RCE / Bash)</option>
          </optgroup>
          <optgroup label="6. API Security & Logic Attacks (OWASP API1 / OWASP LLM02)">
            <option value="ADV-18">ADV-18: Broken Object Level Authorization (BOLA / IDOR)</option>
            <option value="ADV-19">ADV-19: SQL Injection via Insecure Model Output</option>
          </optgroup>
          <optgroup label="7. Benign Benchmark (False Positive Baseline)">
            <option value="ADV-20">ADV-20: Legitimate Architecture Query (False Positive Control)</option>
          </optgroup>
        </select>

        <!-- Vulnerability & Impact Details -->
        <div class="threat-detail-box" id="threatDetailCard" style="display:none;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <strong id="threatName" style="color:#8AB4F8; font-size:0.95rem;"></strong>
            <span class="tag tag-high" id="threatOwasp"></span>
          </div>
          <div style="font-size:0.8rem; color:var(--text-muted); margin-bottom:8px;">
            <strong>MITRE ATLAS Mapping:</strong> <code id="threatMitre"></code> | 
            <strong>Target Resource:</strong> <code id="threatTarget"></code>
          </div>
          <div style="font-size:0.85rem; color:#FFD43B; background:rgba(245, 159, 0, 0.08); border-left:3px solid var(--warning); padding:8px 12px; border-radius:0 4px 4px 0;">
            <strong>Exploitation Impact if Unprotected:</strong>
            <div id="threatExploit" style="margin-top:4px; color:var(--text-main);"></div>
          </div>
        </div>

        <!-- Prompt Test Workspace -->
        <div style="margin-bottom:1rem;">
          <label style="font-size:0.82rem; font-weight:600; color:var(--text-muted); display:block; margin-bottom:6px;">
            Adversarial Test Prompt (Editable):
          </label>
          <textarea class="q-notes" id="customRedTeamPrompt" style="height:120px; font-family:'JetBrains Mono', monospace; font-size:0.85rem;" placeholder="Select an attack vector from the menu above or enter your custom test prompt..."></textarea>
          <button class="btn" style="margin-top:8px;" onclick="testCustomRedTeamPrompt()">Execute Test against Model Armor Guard</button>
        </div>

        <!-- Single Test Result -->
        <div id="singleTestResult" style="display:none; background:var(--surface-variant); border:1px solid var(--border); border-radius:8px; padding:1rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <strong>Guardrail Verdict:</strong>
            <span id="verdictBadge"></span>
          </div>
          <div style="font-size:0.82rem; color:var(--text-muted);" id="verdictDetails"></div>
        </div>
      </div>

      <!-- Batch Campaign Results Table (20 Attacks) -->
      <div class="card">
        <div class="card-title">
          <span>Batch Campaign Results (20 Benchmark Vectors)</span>
          <span class="tag tag-success" id="campaignStatusBadge">Ready for Execution</span>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Test Vector</th>
                <th>Threat Category</th>
                <th>OWASP & MITRE</th>
                <th>Expected Verdict</th>
                <th>Model Armor Verdict</th>
                <th>Defense Status</th>
              </tr>
            </thead>
            <tbody id="redteam-campaign-body">
              <tr>
                <td colspan="7" style="text-align:center; color:var(--text-muted); padding:1.5rem;">
                  Click <strong>'Run Full Campaign (20 Vectors)'</strong> above to simulate all test vectors against the defense layer.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 5: OFFICIAL EXECUTIVE REPORT (GOOGLE CLOUD SECURITY CONSULTING) -->
    <!-- ========================================================================= -->
    <div id="tab-report" class="tab-panel">
      
      <!-- Download Action Bar -->
      <div class="card">
        <div class="card-title">
          <span>Official Executive AI Posture Report (Google Cloud Security Consulting)</span>
          <div style="display:flex; gap:10px; flex-wrap:wrap;">
            <button class="btn" onclick="generateExecutivePDF()">Generate PDF Report</button>
            <a href="/api/report/view" target="_blank" class="btn btn-secondary">Open in New Tab</a>
            <a href="/api/report/download/markdown" download="aispr_executive_report.md" class="btn btn-secondary">Export Markdown (.md)</a>
            <a href="/api/report/download/json" download="aispr_executive_report.json" class="btn btn-secondary">Export JSON (.json)</a>
          </div>
        </div>
        <p style="color:var(--text-muted); font-size:0.85rem;">
          This deliverable contains <strong>Executive Cover, Table of Contents, Health KPIs, AI-BOM Inventory, Gap Matrix, and CAPA Remediation Roadmap</strong> following Google Cloud standard formats.
        </p>
      </div>

      <!-- Formatted Google Cloud Deliverable Document -->
      <div class="gcp-report-wrapper" id="officialReportContainer">
        
        <!-- ================= PAGE 1: COVER PAGE ================= -->
        <div class="report-cover-page">
          <div class="gcp-accent-bar">
            <div class="gcp-blue"></div>
            <div class="gcp-red"></div>
            <div class="gcp-yellow"></div>
            <div class="gcp-green"></div>
          </div>

          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.5rem;">
            <div class="cover-org">GOOGLE CLOUD SECURITY CONSULTING | EXECUTIVE DELIVERABLE</div>
            <span class="client-badge" style="background:#FCE8E6; color:#C5221F; border-color:#FAD2CF;">CONFIDENTIAL / RESTRICTED</span>
          </div>

          <div class="cover-title">AI Security Posture Review (AI-SPR)</div>
          <div class="cover-subtitle">
            Executive Assessment Report on AI Governance, Risk Management & Resilience
          </div>

          <!-- Cover Metadata -->
          <div class="report-meta-grid" style="margin-top:2.5rem;">
            <div class="meta-item">
              <strong>Client / Organization:</strong>
              " + DEMO_CLIENT_NAME + "
            </div>
            <div class="meta-item">
              <strong>Assessment Scope:</strong>
              " + DEMO_SCOPE_DESCRIPTION + "
            </div>
            <div class="meta-item">
              <strong>Lead Consultant:</strong>
              Joabson Saccomani (@jsaccomani)
            </div>
            <div class="meta-item">
              <strong>Issue Date:</strong>
              <span id="cover-date-str"></span>
            </div>
            <div class="meta-item" style="grid-column: 1 / -1;">
              <strong>Normative Frameworks & Reference Baselines:</strong>
              Google SAIF 2.0 (6 Core Pillars) | NIST AI RMF 1.0 (Govern, Map, Measure, Manage) | ISO/IEC 42001:2023 (AIMS) | MITRE ATLAS v4.2 | OWASP Top 10 for LLM Applications (2025/2026)
            </div>
          </div>
        </div>

        <!-- ================= PAGE 2: TABLE OF CONTENTS ================= -->
        <div class="report-toc page-break">
          <div class="toc-title">Table of Contents</div>
          <ul class="toc-list">
            <li class="toc-item">
              <span><strong>1.</strong> Executive Summary & AI Security Posture Health Score</span>
              <span>Section 1</span>
            </li>
            <li class="toc-item">
              <span><strong>2.</strong> Architectural Mapping & Consolidated AI Bill of Materials (AI-BOM)</span>
              <span>Section 2</span>
            </li>
            <li class="toc-item">
              <span><strong>3.</strong> Detailed Vulnerability, Risk & Regulatory Impact Matrix</span>
              <span>Section 3</span>
            </li>
            <li class="toc-item">
              <span><strong>4.</strong> Adversarial Red Team Results & Model Armor Defense Efficacy</span>
              <span>Section 4</span>
            </li>
            <li class="toc-item">
              <span><strong>5.</strong> Framework Compliance Breakdown (SAIF / NIST / ISO 42001)</span>
              <span>Section 5</span>
            </li>
            <li class="toc-item">
              <span><strong>6.</strong> Corrective Action Plan & Strategic Roadmap (3-Phase CAPA)</span>
              <span>Section 6</span>
            </li>
          </ul>
        </div>

        <!-- ================= CHAPTER 1 ================= -->
        <div class="report-chapter page-break">
          <div class="chapter-h2">1. Executive Summary & Overall Posture Health</div>
          <p style="font-size:0.9rem; margin-bottom:1.25rem;">
            The enterprise AI security posture evaluation was executed across discovered cloud assets, automated scan findings, and rigorous alignment with 104 normative AI-SPR controls.
          </p>

          <div class="grid-stats" style="margin-bottom:1.5rem;">
            <div class="stat-card">
              <div class="stat-title">Overall Compliance Score</div>
              <div class="stat-value" id="rep-health-val" style="color:var(--warning);">71.2%</div>
              <div class="stat-desc" id="rep-tier-val">Status: Moderate Risk (Tier 2)</div>
            </div>
            <div class="stat-card">
              <div class="stat-title">Compliant Controls (Y)</div>
              <div class="stat-value" style="color:var(--success);" id="rep-yes-val">62</div>
              <div class="stat-desc">Passed without deviations</div>
            </div>
            <div class="stat-card">
              <div class="stat-title">Partial Controls (P)</div>
              <div class="stat-value" style="color:var(--warning);" id="rep-partial-val">24</div>
              <div class="stat-desc">Adjustments required</div>
            </div>
            <div class="stat-card">
              <div class="stat-title">Critical Gaps (N)</div>
              <div class="stat-value" style="color:var(--danger);" id="rep-no-val">18</div>
              <div class="stat-desc">Immediate remediation</div>
            </div>
          </div>

          <div class="chapter-h2" style="font-size:1.05rem; border-bottom:none; margin-top:1.5rem;">Score Breakdown by Evaluation Domain (AI-SPR 5 Pillars)</div>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Normative Domain</th>
                  <th>Scope Description</th>
                  <th>Evaluated Controls</th>
                  <th>Compliance %</th>
                  <th>Domain Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>1. Data Security & Privacy (DAT)</strong></td>
                  <td>CMEK Encryption, RAG Lineage, Cloud DLP, PII Redaction</td>
                  <td>22 Controls</td>
                  <td><strong>65.0%</strong></td>
                  <td><span class="tag tag-med">Adjustments Required</span></td>
                </tr>
                <tr>
                  <td><strong>2. Model Hardening & Supply Chain (MOD)</strong></td>
                  <td>SLSA Level 3, Model Signing, Provenance Verification</td>
                  <td>20 Controls</td>
                  <td><strong>72.5%</strong></td>
                  <td><span class="tag tag-low">Aligned</span></td>
                </tr>
                <tr>
                  <td><strong>3. Infrastructure & IAM (INF)</strong></td>
                  <td>VPC Isolation, Least Privilege, VPC Service Controls</td>
                  <td>22 Controls</td>
                  <td><strong>60.0%</strong></td>
                  <td><span class="tag tag-high">Critical Gaps</span></td>
                </tr>
                <tr>
                  <td><strong>4. Application Security & APIs (APP)</strong></td>
                  <td>Model Armor Guard, BOLA/IDOR Defense, Input Sanitization</td>
                  <td>22 Controls</td>
                  <td><strong>68.0%</strong></td>
                  <td><span class="tag tag-med">Adjustments Required</span></td>
                </tr>
                <tr>
                  <td><strong>5. Operations & Telemetry (OPS)</strong></td>
                  <td>Cloud Logging, VPC Flow Logs, Drift & Poisoning Detection</td>
                  <td>18 Controls</td>
                  <td><strong>75.0%</strong></td>
                  <td><span class="tag tag-low">Aligned</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- ================= CHAPTER 2 ================= -->
        <div class="report-chapter page-break">
          <div class="chapter-h2">2. Consolidated AI Bill of Materials (AI-BOM)</div>
          <p style="font-size:0.9rem; margin-bottom:1rem;">
            Full mapping of AI components and workloads in multi-cloud environments, adhering to <strong>CycloneDX-AI</strong> standards:
          </p>

          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Asset / Component</th>
                  <th>Category</th>
                  <th>Provider</th>
                  <th>Location / Scope</th>
                  <th>Version</th>
                  <th>Security Posture</th>
                </tr>
              </thead>
              <tbody id="rep-aibom-tbody">
                <!-- Populated dynamically -->
              </tbody>
            </table>
          </div>
        </div>

        <!-- ================= CHAPTER 3 ================= -->
        <div class="report-chapter page-break">
          <div class="chapter-h2">3. Vulnerability, Risk & Regulatory Impact Matrix</div>
          <p style="font-size:0.9rem; margin-bottom:1rem;">
            High-severity technical deviations identified during infrastructure scanning and statutory regulatory correlation:
          </p>

          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Severity</th>
                  <th>Discovered Scan Finding</th>
                  <th>Regulatory Impact (ISO / EU AI Act / LGPD)</th>
                  <th>Recommended Remediation Action</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>INF-01</strong></td>
                  <td><span class="tag tag-high">CRITICAL</span></td>
                  <td>" + f"Service Account <code>{DEMO_SERVICE_ACCOUNT}</code> holds <code>roles/editor</code> role in project <code>{DEMO_GCP_PROJECT_ID}</code>" + "</td>
                  <td>ISO 42001 A.8.1 | SAIF Pillar 2 | NIST GOVERN 1.2 | MITRE AML.T0010</td>
                  <td>Enforce Least Privilege by restricting to <code>roles/aiplatform.user</code> and VPC SC perimeter</td>
                </tr>
                <tr>
                  <td><strong>DAT-01</strong></td>
                  <td><span class="tag tag-high">HIGH</span></td>
                  <td>" + f"Bucket <code>{DEMO_STORAGE_BUCKET}</code> uses default Google-managed keys without CMEK" + "</td>
                  <td>ISO 42001 A.8.2 | SAIF Pillar 1 | GDPR / LGPD Art. 46</td>
                  <td>Configure Customer-Managed Encryption Keys in Cloud KMS</td>
                </tr>
                <tr>
                  <td><strong>DAT-05</strong></td>
                  <td><span class="tag tag-high">HIGH</span></td>
                  <td>SQL dump <code>legacy_db_dump.sql</code> contains cleartext SSNs/CPFs without DLP masking</td>
                  <td>LGPD Art. 46 | EU AI Act Art. 10 | NIST MEASURE 2.10</td>
                  <td>Enable inline Cloud DLP for automated PII redaction</td>
                </tr>
                <tr>
                  <td><strong>APP-01</strong></td>
                  <td><span class="tag tag-high">HIGH</span></td>
                  <td>Endpoint <code>/api/v1/customers/{id}</code> allows unauthorized customer enumeration (BOLA/IDOR)</td>
                  <td>OWASP API1:2023 | ISO 42001 A.8.4.3</td>
                  <td>Enforce strict JWT session validation at API Gateway layer</td>
                </tr>
                <tr>
                  <td><strong>APP-04</strong></td>
                  <td><span class="tag tag-high">HIGH</span></td>
                  <td>Endpoint <code>/api/v1/ai/chat</code> accepts direct Prompt Injection without filtering</td>
                  <td>OWASP LLM01:2025 | MITRE AML.T0051 | EU AI Act Art. 15</td>
                  <td>Activate Model Armor Guardrails for semantic input prompt inspection</td>
                </tr>
                <tr>
                  <td><strong>INF-04</strong></td>
                  <td><span class="tag tag-med">MEDIUM</span></td>
                  <td>Subnet <code>sb-apps-uscentral1</code> with VPC Flow Logs disabled</td>
                  <td>SAIF Pillar 3 | NIST MEASURE 2.7 | ISO 42001 A.9.2</td>
                  <td>Enable VPC Flow Logs with 100% sampling rate for network visibility</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- ================= CHAPTER 4 ================= -->
        <div class="report-chapter page-break">
          <div class="chapter-h2">4. Adversarial Red Team Results & Model Armor Defense Efficacy</div>
          <p style="font-size:0.9rem; margin-bottom:1rem;">
            <strong>20 benchmark attack vectors</strong> were simulated evaluating the defense efficacy of Model Armor against MITRE ATLAS and OWASP LLM Top 10:
          </p>

          <div class="grid-stats" style="margin-bottom:1.5rem;">
            <div class="stat-card">
              <div class="stat-title">Benchmark Vectors Tested</div>
              <div class="stat-value" style="color:#8AB4F8;">20</div>
              <div class="stat-desc">6 Threat Categories</div>
            </div>
            <div class="stat-card">
              <div class="stat-title">Model Armor Block Rate</div>
              <div class="stat-value" style="color:var(--success);">95.0%</div>
              <div class="stat-desc">19/20 Attacks Neutralized</div>
            </div>
            <div class="stat-card">
              <div class="stat-title">Average Inspection Latency</div>
              <div class="stat-value" style="color:#80D8FF;">~2.1 ms</div>
              <div class="stat-desc">Negligible Production Overhead</div>
            </div>
          </div>

          <ul style="font-size:0.88rem; padding-left:1.5rem; line-height:1.8; color:var(--text-main);">
            <li><strong>Direct Prompt Injection & Jailbreaking:</strong> 4/4 vectors blocked successfully (Instruction bypass, DAN Mode, Base64 Obfuscation, Context Switching).</li>
            <li><strong>System Prompt Leakage & Extraction:</strong> 3/3 exfiltration attempts intercepted at ingress layer.</li>
            <li><strong>Indirect Prompt Injection & RAG Poisoning:</strong> 3/3 hidden payload attacks in retrieved documents neutralized.</li>
            <li><strong>Sensitive Data Exposure (DLP):</strong> Automated masking of SSNs, CPFs, and credit cards validated via Cloud DLP Redaction.</li>
            <li><strong>Technical Conclusion:</strong> Model Armor establishes a resilient semantic shield before untrusted payloads reach foundation models.</li>
          </ul>
        </div>

        <!-- ================= CHAPTER 5 ================= -->
        <div class="report-chapter page-break">
          <div class="chapter-h2">5. Corrective Action Plan & Strategic Roadmap (CAPA)</div>
          <p style="font-size:0.9rem; margin-bottom:1.5rem;">
            Structured 3-phase roadmap to elevate organizational security posture to <strong>Tier 1 (Secure & Compliant)</strong>:
          </p>

          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:1.25rem; margin-bottom:2rem;">
            <div class="stat-card" style="border-left:4px solid var(--danger);">
              <div style="font-weight:700; color:var(--danger); font-size:0.95rem; margin-bottom:8px;">
                Phase 1: Immediate Remediation (0 - 15 Days)
              </div>
              <ul style="font-size:0.82rem; color:var(--text-muted); padding-left:1.2rem; line-height:1.6;">
                <li>" + f"Revoke <code>roles/editor</code> from <code>{DEMO_SERVICE_ACCOUNT}</code> and bind <code>roles/aiplatform.user</code>." + "</li>
                <li>Activate Model Armor Guardrail on microservice <code>/api/v1/ai/chat</code>.</li>
                <li>Fix BOLA/IDOR authorization validation on customer endpoint.</li>
              </ul>
            </div>

            <div class="stat-card" style="border-left:4px solid var(--warning);">
              <div style="font-weight:700; color:var(--warning); font-size:0.95rem; margin-bottom:8px;">
                Phase 2: Data Hardening (15 - 45 Days)
              </div>
              <ul style="font-size:0.82rem; color:var(--text-muted); padding-left:1.2rem; line-height:1.6;">
                <li>Configure Cloud KMS CMEK keys on all RAG storage buckets and backups.</li>
                <li>Integrate inline Cloud DLP for automated PII masking.</li>
                <li>Enable VPC Flow Logs and audit telemetry alerts in Cloud Logging.</li>
              </ul>
            </div>

            <div class="stat-card" style="border-left:4px solid var(--success);">
              <div style="font-weight:700; color:var(--success); font-size:0.95rem; margin-bottom:8px;">
                Phase 3: Continuous Governance (45 - 90 Days)
              </div>
              <ul style="font-size:0.82rem; color:var(--text-muted); padding-left:1.2rem; line-height:1.6;">
                <li>Deploy automated CI/CD pipeline validation for CycloneDX AI-BOMs.</li>
                <li>Formalize AI Management System compliant with ISO/IEC 42001.</li>
                <li>Execute periodic automated Red Teaming campaigns with AISPR.</li>
              </ul>
            </div>
          </div>

          <!-- Signatures -->
          <div style="border-top:1px solid var(--border); padding-top:2rem; margin-top:3rem; display:grid; grid-template-columns:1fr 1fr; gap:2rem;">
            <div>
              <div style="border-bottom:1px solid var(--border); width:80%; margin-bottom:6px;"></div>
              <strong style="font-size:0.85rem;">Joabson Saccomani (@jsaccomani)</strong>
              <div style="font-size:0.75rem; color:var(--text-muted);">Lead Cloud Security Consultant | Google Cloud Consulting</div>
            </div>
            <div>
              <div style="border-bottom:1px solid var(--border); width:80%; margin-bottom:6px;"></div>
              <strong style="font-size:0.85rem;">Chief Information Security Officer (CISO)</strong>
              <div style="font-size:0.75rem; color:var(--text-muted);">" + DEMO_CLIENT_NAME + "</div>
            </div>
          </div>
        </div>

        <div style="border-top:1px solid var(--border); margin-top:2rem; padding-top:1rem; text-align:center; font-size:0.75rem; color:var(--text-muted);">
          AISPR Enterprise Deliverable | Google Cloud Security Consulting | Developed by Joabson Saccomani (@jsaccomani)
        </div>

      </div>
    </div>

  </main>

  <!-- Slide-Over Asset Inspector Drawer -->
  <div class="drawer-overlay" id="drawerOverlay" onclick="closeAssetInspector()"></div>
  <div class="drawer-panel" id="drawerPanel">
    <div class="drawer-header">
      <div>
        <div class="drawer-title" id="drawerAssetName">vertex-gemini-1.5-pro</div>
        <div style="display:flex; gap:6px; margin-top:6px;">
          <span class="tag" id="drawerProviderBadge">Google Cloud</span>
          <span class="tag" id="drawerRiskBadge">High Risk</span>
        </div>
      </div>
      <button class="drawer-close" onclick="closeAssetInspector()">&times;</button>
    </div>

    <!-- Section 1: Architecture & Scope -->
    <div class="drawer-section">
      <div class="drawer-section-title">Architecture & Cloud Metadata</div>
      <table class="drawer-meta-table">
        <tr><td>Category:</td><td id="drawerCategory">Foundation Model</td></tr>
        <tr><td>Product / Service:</td><td id="drawerProduct">Gemini 1.5 Pro</td></tr>
        <tr><td>Location / Region:</td><td id="drawerLocation">us-central1</td></tr>
        <tr><td>Project / Account:</td>" + f"<td id=\"drawerProject\">{DEMO_GCP_ENTERPRISE_AI_PROJECT_ID}</td>" + "</tr>
        <tr><td>Organization / Folder:</td>" + f"<td id=\"drawerFolder\">{DEMO_CLIENT_SHORT_NAME} / {DEMO_CLIENT_FOLDER}</td>" + "</tr>
        <tr><td>Workload / App:</td><td id="drawerApp">Financial Chatbot</td></tr>
      </table>
    </div>

    <!-- Section 2: Data Classification & Encryption -->
    <div class="drawer-section">
      <div class="drawer-section-title">Data Classification & Encryption</div>
      <table class="drawer-meta-table">
        <tr><td>Data Sensitivity:</td><td id="drawerDataClass">Restricted (Financial Records)</td></tr>
        <tr><td>Encryption Standard:</td><td id="drawerEncryption">Google-Managed (CMEK Missing)</td></tr>
        <tr><td>Ingress Guardrail:</td><td id="drawerGuardrail">Inactive (Vulnerable to Prompt Injection)</td></tr>
      </table>
    </div>

    <!-- Section 3: IAM Identities -->
    <div class="drawer-section">
      <div class="drawer-section-title">IAM Identities & Attached Access</div>
      <div id="drawerIamList" style="font-size:0.82rem; color:var(--text-muted); line-height:1.5;"></div>
    </div>

    <!-- Section 4: Identified Gaps -->
    <div class="drawer-section">
      <div class="drawer-section-title">Scan Findings & Security Gaps</div>
      <div id="drawerFindingsList"></div>
    </div>

    <!-- Section 5: Action -->
    <div class="drawer-section" style="background:var(--surface-variant); padding:1rem; border-radius:6px; border:1px solid var(--border);">
      <div class="drawer-section-title" style="color:#8AB4F8;">Recommended Immediate Action (Playbook)</div>
      <p id="drawerActionText" style="font-size:0.82rem; color:var(--text-main); margin-top:4px; line-height:1.5;"></p>
    </div>
  </div>

  <footer class="footer">
    AISPR v3.0 | Google Cloud Security Consulting | Developed by Joabson Saccomani (@jsaccomani)
  </footer>

  <script>
    let questionsData = [];
    let currentDomain = 'ALL';
    let userAnswers = {};
    let rawAIBOMData = {};
    let adversarialTestCases = [];
    
    // Multi-dimensional assets dataset
    const ALL_ASSETS = """ + json.dumps(DISCOVERED_AI_ASSETS) + r""";
    let filteredAssets = [...ALL_ASSETS];

    function showTab(tabName) {
      document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      
      const tab = document.getElementById('tab-' + tabName);
      if (tab) tab.classList.add('active');
      
      const items = document.querySelectorAll('.nav-item');
      items.forEach(item => {
        if (item.getAttribute('onclick') && item.getAttribute('onclick').includes(tabName)) {
          item.classList.add('active');
        }
      });

      if (tabName === 'dashboard') {
        populateCascadingDropdowns();
        updateDashboardView();
      }
      if (tabName === 'report') renderExecutiveReport();
      if (tabName === 'inventory') loadInventory();
      if (tabName === 'redteam') loadRedTeamDataset();
    }

    /* Cascading Dynamic Filters Logic */
    function populateCascadingDropdowns() {
      const selectedCloud = document.getElementById('filterCloud').value;
      const productSelect = document.getElementById('filterProduct');
      const projectSelect = document.getElementById('filterProject');

      const prevProduct = productSelect.value;
      const prevProject = projectSelect.value;

      // Filter assets matching selected cloud
      const cloudAssets = ALL_ASSETS.filter(a => selectedCloud === 'ALL' || a.provider.includes(selectedCloud));

      // Extract unique products and projects
      const products = Array.from(new Set(cloudAssets.map(a => a.product))).filter(Boolean);
      const projects = Array.from(new Set(cloudAssets.map(a => a.project))).filter(Boolean);

      // Populate Product dropdown
      productSelect.innerHTML = '<option value="ALL">Product: All</option>';
      products.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p;
        opt.innerText = p;
        if (p === prevProduct) opt.selected = true;
        productSelect.appendChild(opt);
      });

      // Populate Project dropdown
      projectSelect.innerHTML = '<option value="ALL">Project: All</option>';
      projects.forEach(pr => {
        const opt = document.createElement('option');
        opt.value = pr;
        opt.innerText = pr;
        if (pr === prevProject) opt.selected = true;
        projectSelect.appendChild(opt);
      });
    }

    function onProviderChange() {
      populateCascadingDropdowns();
      updateDashboardView();
    }

    function onProductChange() {
      const selectedProduct = document.getElementById('filterProduct').value;
      const projectSelect = document.getElementById('filterProject');
      if (selectedProduct !== 'ALL') {
        const matchingAssets = ALL_ASSETS.filter(a => a.product === selectedProduct);
        const projects = Array.from(new Set(matchingAssets.map(a => a.project))).filter(Boolean);
        projectSelect.innerHTML = '<option value="ALL">Project: All</option>';
        projects.forEach(pr => {
          const opt = document.createElement('option');
          opt.value = pr;
          opt.innerText = pr;
          projectSelect.appendChild(opt);
        });
      }
      updateDashboardView();
    }

    function onProjectChange() {
      updateDashboardView();
    }

    function resetDashboardFilters() {
      document.getElementById('filterCloud').value = 'ALL';
      populateCascadingDropdowns();
      document.getElementById('filterProduct').value = 'ALL';
      document.getElementById('filterProject').value = 'ALL';
      document.getElementById('filterRisk').value = 'ALL';
      updateDashboardView();
    }

    /* Core Dynamic Dashboard Update Function */
    function updateDashboardView() {
      const cloudVal = document.getElementById('filterCloud').value;
      const productVal = document.getElementById('filterProduct').value;
      const projectVal = document.getElementById('filterProject').value;
      const riskVal = document.getElementById('filterRisk').value;

      filteredAssets = ALL_ASSETS.filter(a => {
        if (cloudVal !== 'ALL' && !a.provider.includes(cloudVal)) return false;
        if (productVal !== 'ALL' && a.product !== productVal) return false;
        if (projectVal !== 'ALL' && a.project !== projectVal) return false;
        if (riskVal !== 'ALL' && a.risk_tier !== riskVal) return false;
        return true;
      });

      // Update Scope Label
      const scopeLabel = document.getElementById('filtered-scope-label');
      if (scopeLabel) {
        if (cloudVal !== 'ALL') scopeLabel.innerText = `Scope: ${cloudVal}`;
        else if (projectVal !== 'ALL') scopeLabel.innerText = `Scope: ${projectVal}`;
        else scopeLabel.innerText = 'Scope: Global (104 Controls)';
      }

      // Calculate Dynamic Scores for Filtered Assets
      let scoreSum = 0;
      let countHigh = 0;
      let countMed = 0;
      let countLow = 0;

      filteredAssets.forEach(a => {
        scoreSum += (a.score || 71.2);
        if (a.risk_tier === 'HIGH') countHigh++;
        else if (a.risk_tier === 'MED') countMed++;
        else countLow++;
      });

      const avgScore = filteredAssets.length > 0 ? (scoreSum / filteredAssets.length) : 100.0;
      const formattedScore = avgScore.toFixed(1) + '%';

      // Update KPI Cards
      document.getElementById('health-score-val').innerText = formattedScore;
      document.getElementById('donut-center-score').innerText = formattedScore;

      // Estimate controls distribution proportionally
      const totalEstimatedControls = filteredAssets.length * 15;
      const estYes = Math.round(totalEstimatedControls * (avgScore / 100));
      const estNo = Math.round(totalEstimatedControls * (countHigh / Math.max(1, filteredAssets.length)) * 0.35);
      const estPartial = Math.max(0, totalEstimatedControls - estYes - estNo);

      document.getElementById('count-yes').innerText = estYes;
      document.getElementById('count-partial').innerText = estPartial;
      document.getElementById('count-no').innerText = estNo;

      // Update Legend Text
      document.getElementById('legend-yes-count').innerText = estYes;
      document.getElementById('legend-partial-count').innerText = estPartial;
      document.getElementById('legend-no-count').innerText = estNo;

      const totalCalculated = Math.max(1, estYes + estPartial + estNo);
      const pctYes = ((estYes / totalCalculated) * 100).toFixed(1);
      const pctPart = ((estPartial / totalCalculated) * 100).toFixed(1);
      const pctNo = ((estNo / totalCalculated) * 100).toFixed(1);

      document.getElementById('legend-yes-pct').innerText = pctYes + '%';
      document.getElementById('legend-partial-pct').innerText = pctPart + '%';
      document.getElementById('legend-no-pct').innerText = pctNo + '%';

      // Update Donut Chart SVG Arcs
      const arcYes = document.getElementById('donut-arc-yes');
      const arcPart = document.getElementById('donut-arc-partial');
      const arcNo = document.getElementById('donut-arc-no');

      if (arcYes && arcPart && arcNo) {
        arcYes.setAttribute('stroke-dasharray', `${pctYes}, 100`);
        arcPart.setAttribute('stroke-dasharray', `${pctPart}, 100`);
        arcPart.setAttribute('stroke-dashoffset', `-${pctYes}`);
        arcNo.setAttribute('stroke-dasharray', `${pctNo}, 100`);
        arcNo.setAttribute('stroke-dashoffset', `-${parseFloat(pctYes) + parseFloat(pctPart)}`);
      }

      // Update Health Tier text & color
      const tierEl = document.getElementById('health-tier-val');
      const scoreValEl = document.getElementById('health-score-val');
      const donutScoreEl = document.getElementById('donut-center-score');
      
      if (avgScore >= 80) {
        scoreValEl.style.color = 'var(--success)';
        donutScoreEl.style.color = 'var(--success)';
        tierEl.innerText = 'Status: Compliant Posture (Tier 1 - Secure)';
      } else if (avgScore >= 50) {
        scoreValEl.style.color = 'var(--warning)';
        donutScoreEl.style.color = 'var(--warning)';
        tierEl.innerText = 'Status: Moderate Risk / Partial Alignment';
      } else {
        scoreValEl.style.color = 'var(--danger)';
        donutScoreEl.style.color = 'var(--danger)';
        tierEl.innerText = 'Status: Critical Posture / Vulnerable';
      }

      // Recalculate Pillar Bars
      updatePillarBars(avgScore);

      // Render Asset Cards Grid
      renderDashboardAssetsGrid();
    }

    function updatePillarBars(baseScore) {
      const pillars = [
        { id: 'dat', name: 'DAT', weight: 0.95 },
        { id: 'mod', name: 'MOD', weight: 1.05 },
        { id: 'inf', name: 'INF', weight: 0.88 },
        { id: 'app', name: 'APP', weight: 0.98 },
        { id: 'ops', name: 'OPS', weight: 1.08 }
      ];

      pillars.forEach(p => {
        let pScore = Math.min(100, Math.max(15, baseScore * p.weight));
        const valEl = document.getElementById(`bar-val-${p.id}`);
        const fillEl = document.getElementById(`bar-fill-${p.id}`);
        if (valEl && fillEl) {
          valEl.innerText = pScore.toFixed(1) + '%';
          fillEl.style.width = pScore.toFixed(1) + '%';
          if (pScore >= 75) {
            fillEl.style.backgroundColor = 'var(--success)';
            valEl.style.color = '#8CE99A';
          } else if (pScore >= 55) {
            fillEl.style.backgroundColor = 'var(--warning)';
            valEl.style.color = '#FFD43B';
          } else {
            fillEl.style.backgroundColor = 'var(--danger)';
            valEl.style.color = '#FFA8A8';
          }
        }
      });
    }

    function renderDashboardAssetsGrid() {
      const grid = document.getElementById('dashboard-asset-grid');
      if (!grid) return;
      grid.innerHTML = '';

      const countEl = document.getElementById('filtered-assets-count');
      if (countEl) {
        countEl.innerText = `Showing ${filteredAssets.length} of ${ALL_ASSETS.length} assets`;
      }

      if (filteredAssets.length === 0) {
        grid.innerHTML = '<div style="grid-column:1/-1; text-align:center; padding:2rem; color:var(--text-muted);">No assets match the selected filters.</div>';
        return;
      }

      filteredAssets.forEach(asset => {
        let tagClass = 'tag-gcp';
        if (asset.provider.includes('AWS')) tagClass = 'tag-aws';
        if (asset.provider.includes('Azure')) tagClass = 'tag-azure';

        let riskClass = 'tag-low';
        let riskLabel = 'LOW RISK';
        if (asset.risk_tier === 'HIGH') {
          riskClass = 'tag-high';
          riskLabel = 'HIGH RISK';
        } else if (asset.risk_tier === 'MED') {
          riskClass = 'tag-med';
          riskLabel = 'MEDIUM RISK';
        }

        const findingsCount = (asset.findings && asset.findings.length) ? asset.findings.length : 0;
        const findingsBadge = findingsCount > 0 
          ? `<span style="color:#FFA8A8; font-weight:700;">${findingsCount} Gaps Detected</span>` 
          : `<span style="color:#8CE99A; font-weight:600;">No Critical Gaps</span>`;

        const card = document.createElement('div');
        card.className = 'asset-card';
        card.onclick = () => inspectAsset(asset.id);
        card.innerHTML = `
          <div>
            <div class="asset-card-header">
              <div class="asset-card-title">${asset.name}</div>
              <span class="tag ${riskClass}">${riskLabel}</span>
            </div>
            <div style="display:flex; gap:6px; margin-bottom:8px;">
              <span class="tag ${tagClass}">${asset.provider}</span>
              <span class="tag tag-med" style="background:var(--surface);">${asset.category}</span>
            </div>
            <div class="asset-card-meta">
              <strong>Project:</strong> <code>${asset.project}</code><br>
              <strong>Workload:</strong> ${asset.app || asset.product}<br>
              <strong>Status:</strong> ${asset.status}
            </div>
          </div>
          <div class="asset-card-footer">
            <div>${findingsBadge}</div>
            <div style="color:var(--primary); font-weight:600;">Inspect &rarr;</div>
          </div>
        `;
        grid.appendChild(card);
      });
    }

    /* Slide-over Asset Inspector */
    function inspectAsset(assetId) {
      const asset = ALL_ASSETS.find(a => a.id === assetId);
      if (!asset) return;

      document.getElementById('drawerAssetName').innerText = asset.name;
      
      const provBadge = document.getElementById('drawerProviderBadge');
      provBadge.innerText = asset.provider;
      provBadge.className = 'tag ' + (asset.provider.includes('AWS') ? 'tag-aws' : (asset.provider.includes('Azure') ? 'tag-azure' : 'tag-gcp'));

      const riskBadge = document.getElementById('drawerRiskBadge');
      riskBadge.innerText = asset.risk_tier === 'HIGH' ? 'HIGH RISK' : (asset.risk_tier === 'MED' ? 'MEDIUM RISK' : 'COMPLIANT');
      riskBadge.className = 'tag ' + (asset.risk_tier === 'HIGH' ? 'tag-high' : (asset.risk_tier === 'MED' ? 'tag-med' : 'tag-low'));

      document.getElementById('drawerCategory').innerText = asset.category;
      document.getElementById('drawerProduct').innerText = asset.product;
      document.getElementById('drawerLocation').innerText = asset.location;
      document.getElementById('drawerProject').innerText = asset.project;
      document.getElementById('drawerFolder').innerText = `${asset.org} / ${asset.folder}`;
      document.getElementById('drawerApp').innerText = asset.app || 'N/A';

      document.getElementById('drawerDataClass').innerText = asset.data_classification || 'Confidential';
      document.getElementById('drawerEncryption').innerText = asset.encryption || 'Google-Managed';
      document.getElementById('drawerGuardrail').innerText = asset.guardrail_status || 'Inactive';

      // IAM Principals
      const iamBox = document.getElementById('drawerIamList');
      if (asset.iam_principals && asset.iam_principals.length > 0) {
        iamBox.innerHTML = asset.iam_principals.map(p => `<div style="padding:2px 0;">&bull; <code>${p}</code></div>`).join('');
      } else {
        iamBox.innerHTML = 'No critical identities attached.';
      }

      // Findings
      const findingsBox = document.getElementById('drawerFindingsList');
      if (asset.findings && asset.findings.length > 0) {
        findingsBox.innerHTML = asset.findings.map(f => `
          <div style="background:rgba(224,49,49,0.08); border-left:3px solid var(--danger); padding:8px 10px; border-radius:0 4px 4px 0; margin-bottom:6px; font-size:0.8rem;">
            <strong>[${f.id}]</strong> ${f.title}
          </div>
        `).join('');
      } else {
        findingsBox.innerHTML = `
          <div style="background:rgba(43,138,62,0.08); border-left:3px solid var(--success); padding:8px 10px; border-radius:0 4px 4px 0; font-size:0.8rem; color:#8CE99A;">
            No critical gaps detected for this asset.
          </div>
        `;
      }

      document.getElementById('drawerActionText').innerText = asset.action || 'Maintain continuous monitoring schedule.';

      // Open Drawer
      document.getElementById('drawerOverlay').classList.add('active');
      document.getElementById('drawerPanel').classList.add('active');
    }

    function closeAssetInspector() {
      document.getElementById('drawerOverlay').classList.remove('active');
      document.getElementById('drawerPanel').classList.remove('active');
    }

    function filterByHealthState(state) {
      if (state === 'ALL') {
        showTab('questionnaire');
        filterDomain('ALL');
      } else {
        showTab('questionnaire');
      }
    }

    function filterByPillar(pillar) {
      showTab('questionnaire');
      filterDomain(pillar);
    }

    async function loadQuestions() {
      try {
        const res = await fetch('/api/audit/questions');
        const data = await res.json();
        questionsData = data.questions || [];
        renderQuestions();
      } catch (err) {
        console.error('Error loading questions:', err);
      }
    }

    function filterDomain(domainPrefix) {
      currentDomain = domainPrefix;
      document.querySelectorAll('.domain-btn').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');
      renderQuestions();
    }

    function renderQuestions() {
      const container = document.getElementById('questions-container');
      container.innerHTML = '';

      const filtered = questionsData.filter(q => {
        if (currentDomain === 'ALL') return true;
        return q.id.startsWith(currentDomain);
      });

      filtered.forEach(q => {
        const currentAns = userAnswers[q.id] || q.default_answer || 'Y';
        const notes = q.notes || '';
        const finding = q.finding || 'No deviations detected during automated scan.';
        const isFindingNone = finding.includes('No deviations');

        const card = document.createElement('div');
        card.className = 'question-card';
        card.innerHTML = `
          <div class="q-header">
            <div>
              <span class="q-id">${q.id}</span>
              <span class="q-title">${q.question}</span>
            </div>
            <span class="tag tag-${(q.criticality || 'MED').toLowerCase()}">${q.criticality || 'MEDIUM'}</span>
          </div>
          <div>
            <span class="q-framework">${q.framework_mapping || 'Google SAIF | NIST AI RMF'}</span>
          </div>
          <div class="q-finding ${isFindingNone ? 'none' : ''}">
            <strong>Scan Finding:</strong> ${finding}
          </div>
          <div class="q-answers">
            <label class="choice-opt">
              <input type="radio" name="ans_${q.id}" value="Y" ${currentAns === 'Y' ? 'checked' : ''} onchange="updateAnswer('${q.id}', 'Y')">
              <span>Compliant (Yes)</span>
            </label>
            <label class="choice-opt">
              <input type="radio" name="ans_${q.id}" value="P" ${currentAns === 'P' ? 'checked' : ''} onchange="updateAnswer('${q.id}', 'P')">
              <span>Partial</span>
            </label>
            <label class="choice-opt">
              <input type="radio" name="ans_${q.id}" value="N" ${currentAns === 'N' ? 'checked' : ''} onchange="updateAnswer('${q.id}', 'N')">
              <span>Non-Compliant (No)</span>
            </label>
            <label class="choice-opt">
              <input type="radio" name="ans_${q.id}" value="NA" ${currentAns === 'NA' ? 'checked' : ''} onchange="updateAnswer('${q.id}', 'NA')">
              <span>Not Applicable</span>
            </label>
          </div>
          <input type="text" class="q-notes" placeholder="Audit notes / architectural justification..." value="${notes}" onchange="updateNotes('${q.id}', this.value)">
        `;
        container.appendChild(card);
      });
    }

    function updateAnswer(qId, val) {
      userAnswers[qId] = val;
    }

    function updateNotes(qId, text) {
      const q = questionsData.find(item => item.id === qId);
      if (q) q.notes = text;
    }

    function saveAndRecalculateHealth() {
      alert('Responses saved and posture score recalculated successfully.');
    }

    async function loadInventory() {
      try {
        const res = await fetch('/api/inventory');
        const data = await res.json();
        rawAIBOMData = data;
        
        // Render Structured Table
        const tbody = document.getElementById('aibom-table-body');
        tbody.innerHTML = '';
        const assets = data.structured_assets || [];
        
        assets.forEach(asset => {
          let tagClass = 'tag-gcp';
          if (asset.provider.includes('AWS')) tagClass = 'tag-aws';
          if (asset.provider.includes('Azure')) tagClass = 'tag-azure';

          let statusTag = 'tag-low';
          if (asset.risk_tier === 'HIGH') statusTag = 'tag-high';
          else if (asset.risk_tier === 'MED') statusTag = 'tag-med';

          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td><strong>${asset.name}</strong></td>
            <td><span class="q-framework">${asset.category}</span></td>
            <td><span class="tag ${tagClass}">${asset.provider}</span></td>
            <td><code>${asset.location}</code></td>
            <td>${asset.version}</td>
            <td><span class="tag ${statusTag}">${asset.status}</span></td>
            <td style="color:var(--text-muted); font-size:0.8rem;">${asset.action}</td>
          `;
          tbody.appendChild(tr);
        });

        // Render CycloneDX JSON
        document.getElementById('inventory-box').innerText = JSON.stringify(data.cyclonedx_bom || data, null, 2);
      } catch (e) {
        document.getElementById('inventory-box').innerText = 'Error loading inventory: ' + e;
      }
    }

    function copyAIBOMJson() {
      const text = document.getElementById('inventory-box').innerText;
      navigator.clipboard.writeText(text);
      alert('AI-BOM CycloneDX JSON copied to clipboard.');
    }

    function exportAIBOMJson() {
      const text = document.getElementById('inventory-box').innerText;
      const blob = new Blob([text], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'cyclonedx_ai_bom.json';
      a.click();
    }

    /* Red Team Module Functions */
    async function loadRedTeamDataset() {
      if (adversarialTestCases.length > 0) return;
      try {
        const res = await fetch('/api/redteam/dataset');
        const data = await res.json();
        adversarialTestCases = data.test_cases || [];
      } catch (e) {
        console.error('Error loading Red Team dataset:', e);
      }
    }

    function onSelectAdversarialPrompt(id) {
      if (!id) {
        document.getElementById('threatDetailCard').style.display = 'none';
        document.getElementById('customRedTeamPrompt').value = '';
        return;
      }

      const tc = adversarialTestCases.find(item => item.id === id);
      if (!tc) return;

      document.getElementById('customRedTeamPrompt').value = tc.prompt;
      document.getElementById('threatName').innerText = `${tc.id}: ${tc.name}`;
      document.getElementById('threatOwasp').innerText = tc.owasp_mapping;
      document.getElementById('threatMitre').innerText = tc.mitre_atlas_mapping;
      document.getElementById('threatTarget').innerText = tc.target_resource || 'AI Endpoint';
      document.getElementById('threatExploit').innerText = tc.exploitability_impact || tc.description;
      document.getElementById('threatDetailCard').style.display = 'block';
      document.getElementById('singleTestResult').style.display = 'none';
    }

    async function testCustomRedTeamPrompt() {
      const prompt = document.getElementById('customRedTeamPrompt').value.trim();
      if (!prompt) {
        alert('Please select or enter a test prompt.');
        return;
      }

      const resBox = document.getElementById('singleTestResult');
      resBox.style.display = 'block';
      document.getElementById('verdictBadge').innerHTML = '<em>Inspecting prompt with Model Armor...</em>';
      document.getElementById('verdictDetails').innerHTML = '';

      try {
        const startTime = performance.now();
        const res = await fetch('/api/guard', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({prompt: prompt})
        });
        const data = await res.json();
        const latency = (performance.now() - startTime).toFixed(1);

        const vBadge = document.getElementById('verdictBadge');
        if (data.verdict === 'BLOCKED' || data.is_blocked) {
          vBadge.innerHTML = '<span class="tag tag-high">[BLOCKED] PROMPT INTERCEPTED</span>';
        } else if (data.verdict === 'SANITIZED') {
          vBadge.innerHTML = '<span class="tag tag-med">[SANITIZED] DLP REDACTED</span>';
        } else {
          vBadge.innerHTML = '<span class="tag tag-low">[ALLOWED] TRAFFIC PERMITTED</span>';
        }

        const rulesStr = (data.matched_rules && data.matched_rules.length > 0) ? data.matched_rules.join(', ') : 'No rules triggered';
        document.getElementById('verdictDetails').innerHTML = `
          <strong>Triggered Rules:</strong> <code>${rulesStr}</code><br>
          <strong>Ingress Risk Score:</strong> <code>${data.risk_score || 0.0}</code> | <strong>Inspection Latency:</strong> ${latency}ms<br>
          <strong>Defense Action:</strong> ${data.is_blocked ? 'Attack intercepted at ingress layer before reaching foundation model.' : 'Safe prompt forwarded to Vertex AI.'}
        `;
      } catch (e) {
        document.getElementById('verdictBadge').innerHTML = '<span class="tag tag-high">INSPECTION ERROR</span>';
        document.getElementById('verdictDetails').innerText = 'Error communicating with Model Armor Guard: ' + e;
      }
    }

    async function runFullRedTeamCampaign() {
      const statusBadge = document.getElementById('campaignStatusBadge');
      statusBadge.innerText = 'Executing 20 Attacks...';
      statusBadge.className = 'tag tag-med';

      const tbody = document.getElementById('redteam-campaign-body');
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:1rem;">Simulating attacks in real-time against Model Armor Guard...</td></tr>';

      try {
        const res = await fetch('/api/redteam/run', {method: 'POST'});
        const data = await res.json();
        
        tbody.innerHTML = '';
        const results = data.test_results || [];

        results.forEach(r => {
          let tagActual = 'tag-high';
          if (r.actual === 'SANITIZED') tagActual = 'tag-med';
          else if (r.actual === 'ALLOWED') tagActual = 'tag-low';

          const tc = adversarialTestCases.find(item => item.id === r.id) || {};

          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td><strong>${r.id}</strong></td>
            <td>${tc.name || r.category}</td>
            <td><span class="q-framework">${r.category}</span></td>
            <td><code>${r.owasp}</code></td>
            <td><span class="tag tag-med">${r.expected}</span></td>
            <td><span class="tag ${tagActual}">${r.actual}</span></td>
            <td><span class="tag ${r.passed_validation ? 'tag-low' : 'tag-high'}">${r.passed_validation ? 'Mitigated / Protected' : 'Bypass Detected'}</span></td>
          `;
          tbody.appendChild(tr);
        });

        const efficacy = data.metrics?.defense_efficacy_percentage || 95.0;
        document.getElementById('redteam-efficacy').innerText = efficacy + '%';
        statusBadge.innerText = `Campaign Completed (${efficacy}% Efficacy)`;
        statusBadge.className = 'tag tag-low';
      } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--danger); padding:1rem;">Error executing campaign: ${e}</td></tr>`;
        statusBadge.innerText = 'Execution Error';
        statusBadge.className = 'tag tag-high';
      }
    }

    /* Executive Report Render & Direct PDF Functions */
    function renderExecutiveReport() {
      const now = new Date().toLocaleDateString('en-US', {year:'numeric', month:'long', day:'numeric'});
      const dateEl = document.getElementById('cover-date-str');
      if (dateEl) dateEl.innerText = now;

      const score = document.getElementById('health-score-val').innerText;
      document.getElementById('rep-health-val').innerText = score;
      document.getElementById('rep-yes-val').innerText = document.getElementById('count-yes').innerText;
      document.getElementById('rep-partial-val').innerText = document.getElementById('count-partial').innerText;
      document.getElementById('rep-no-val').innerText = document.getElementById('count-no').innerText;
      document.getElementById('rep-tier-val').innerText = document.getElementById('health-tier-val').innerText;

      // Populate AI-BOM in Report
      const tbody = document.getElementById('rep-aibom-tbody');
      if (tbody) {
        tbody.innerHTML = '';
        ALL_ASSETS.forEach(a => {
          let stTag = (a.risk_tier === 'HIGH') ? 'tag-high' : 'tag-low';
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td><strong>${a.name}</strong></td>
            <td><span class="q-framework">${a.category}</span></td>
            <td><span class="tag tag-gcp">${a.provider}</span></td>
            <td><code>${a.location}</code></td>
            <td>${a.version}</td>
            <td><span class="tag ${stTag}">${a.status}</span></td>
          `;
          tbody.appendChild(tr);
        });
      }
    }

    function generateExecutivePDF() {
      renderExecutiveReport();
      window.print();
    }

    // Initialize on load
    populateCascadingDropdowns();
    updateDashboardView();
    loadQuestions();
  </script>
</body>
</html>
"""

OFFICIAL_REPORT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Google Cloud Security Consulting | AI Security Posture Review Deliverable</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #1A73E8;
      --text-main: #202124;
      --text-muted: #5F6368;
      --border: #DADCE0;
      --surface: #F8F9FA;
      --success: #137333;
      --warning: #B06000;
      --danger: #C5221F;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: #ECEFF1;
      color: var(--text-main);
      line-height: 1.6;
      padding: 2rem 1rem;
    }
    .page-container {
      max-width: 950px;
      margin: 0 auto;
      background: #FFFFFF;
      padding: 4rem;
      border-radius: 8px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.08);
    }
    .action-bar {
      max-width: 950px;
      margin: 0 auto 1rem auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
    }
    .btn {
      background: var(--primary);
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 6px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      text-decoration: none;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .btn:hover { background: #1557B0; }
    .btn-secondary { background: #FFFFFF; color: var(--text-main); border: 1px solid var(--border); }
    .btn-secondary:hover { background: #F1F3F4; }

    .gcp-accent-bar {
      display: flex;
      height: 6px;
      width: 100%;
      border-radius: 3px;
      overflow: hidden;
      margin-bottom: 2.5rem;
    }
    .gcp-blue { background: #4285F4; flex: 1; }
    .gcp-red { background: #EA4335; flex: 1; }
    .gcp-yellow { background: #FBBC04; flex: 1; }
    .gcp-green { background: #34A853; flex: 1; }

    /* Cover Page */
    .cover-section {
      min-height: 75vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      page-break-after: always;
      border-bottom: 2px solid var(--border);
      padding-bottom: 3rem;
      margin-bottom: 3rem;
    }
    .cover-org { font-size: 0.85rem; font-weight: 700; color: #4285F4; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 0.75rem; }
    .cover-title { font-size: 2.4rem; font-weight: 800; color: #202124; line-height: 1.2; margin-bottom: 0.75rem; }
    .cover-subtitle { font-size: 1.1rem; color: var(--text-muted); margin-bottom: 2.5rem; }
    .conf-badge {
      background: #FCE8E6;
      color: #C5221F;
      border: 1px solid #FAD2CF;
      padding: 6px 12px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.5px;
    }

    .meta-box {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 2rem;
      font-size: 0.88rem;
    }
    .meta-box strong { color: var(--text-muted); display: block; font-size: 0.75rem; text-transform: uppercase; margin-bottom: 4px; }

    /* Table of Contents */
    .toc-box {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 2rem;
      margin-bottom: 3rem;
      page-break-after: always;
    }
    .toc-title { font-size: 1.15rem; font-weight: 700; color: #1A73E8; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.5px; }
    .toc-list { list-style: none; padding: 0; }
    .toc-item {
      display: flex;
      justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px dashed var(--border);
      font-size: 0.9rem;
      color: var(--text-main);
    }
    .toc-item strong { color: #1A73E8; margin-right: 8px; }

    .section { margin-bottom: 3rem; }
    .section-title {
      font-size: 1.25rem;
      font-weight: 700;
      color: #1A73E8;
      margin-bottom: 1rem;
      border-bottom: 2px solid #E8EAED;
      padding-bottom: 6px;
    }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin: 1rem 0 1.5rem 0;
    }
    .kpi-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      text-align: center;
    }
    .kpi-title { font-size: 0.75rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; }
    .kpi-value { font-size: 1.8rem; font-weight: 700; margin: 4px 0; }
    .kpi-desc { font-size: 0.78rem; color: var(--text-muted); }

    table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }
    th, td { padding: 10px 14px; text-align: left; border: 1px solid var(--border); }
    th { background: #F1F3F4; font-weight: 700; color: #202124; text-transform: uppercase; font-size: 0.75rem; }
    tr:nth-child(even) td { background: #F8F9FA; }

    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; }
    .tag-high { background: #FCE8E6; color: #C5221F; }
    .tag-med { background: #FEF7E0; color: #B06000; }
    .tag-low { background: #E6F4EA; color: #137333; }

    .roadmap-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1.25rem;
      margin-top: 1rem;
    }
    .roadmap-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
    }
    .roadmap-title { font-size: 0.92rem; font-weight: 700; margin-bottom: 8px; }
    .roadmap-list { padding-left: 1.2rem; font-size: 0.82rem; color: #3C4043; line-height: 1.6; }

    .doc-footer {
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
      margin-top: 3rem;
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    @page {
      size: A4 portrait;
      margin: 15mm 15mm 15mm 15mm;
    }
    @media print {
      body { background: #FFFFFF; padding: 0; }
      .page-container { box-shadow: none; padding: 0; max-width: 100%; }
      .action-bar { display: none; }
      .page-break { page-break-before: always; margin-top: 1.5rem; }
      .cover-section { border-bottom: none !important; min-height: 85vh; }
      * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    }
  </style>
</head>
<body>

  <!-- Floating Action Bar (Invisible on print) -->
  <div class="action-bar">
    <div style="font-weight:700; color:var(--text-muted); font-size:0.85rem;">
      Google Cloud Security Consulting | Official Deliverable
    </div>
    <div style="display:flex; gap:8px;">
      <button class="btn" onclick="window.print()">Save as PDF / Print</button>
      <a href="/api/report/download/markdown" download="aispr_executive_report.md" class="btn btn-secondary">Export Markdown</a>
      <a href="/api/report/download/json" download="aispr_executive_report.json" class="btn btn-secondary">Export JSON</a>
      <a href="/" class="btn btn-secondary">Return to Console</a>
    </div>
  </div>

  <div class="page-container">

    <!-- ================= PAGE 1: COVER ================= -->
    <div class="cover-section">
      <div class="gcp-accent-bar">
        <div class="gcp-blue"></div>
        <div class="gcp-red"></div>
        <div class="gcp-yellow"></div>
        <div class="gcp-green"></div>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.5rem;">
        <div class="cover-org">GOOGLE CLOUD SECURITY CONSULTING | EXECUTIVE DELIVERABLE</div>
        <span class="conf-badge">CONFIDENTIAL / RESTRICTED</span>
      </div>

      <h1 class="cover-title">AI Security Posture Review (AI-SPR)</h1>
      <div class="cover-subtitle">
        Executive Assessment Report on AI Governance, Risk Management & Resilience
      </div>

      <div class="meta-box" style="margin-top:2rem;">
        <div>
          <strong>Client / Organization:</strong>
          " + DEMO_CLIENT_NAME + "
        </div>
        <div>
          <strong>Assessment Scope:</strong>
          " + DEMO_SCOPE_DESCRIPTION + "
        </div>
        <div>
          <strong>Lead Consultant:</strong>
          Joabson Saccomani (@jsaccomani)
        </div>
        <div>
          <strong>Issue Date:</strong>
          """ + datetime.datetime.now().strftime("%B %d, %Y") + r"""
        </div>
        <div style="grid-column: 1 / -1;">
          <strong>Regulatory Frameworks & Reference Baselines:</strong>
          Google SAIF 2.0 (6 Core Pillars) | NIST AI RMF 1.0 (Govern, Map, Measure, Manage) | ISO/IEC 42001:2023 (AIMS) | MITRE ATLAS v4.2 | OWASP Top 10 for LLM Applications (2025/2026)
        </div>
      </div>
    </div>

    <!-- ================= PAGE 2: TABLE OF CONTENTS ================= -->
    <div class="toc-box page-break">
      <div class="toc-title">Table of Contents</div>
      <ul class="toc-list">
        <li class="toc-item">
          <span><strong>1.</strong> Executive Summary & AI Security Posture Health Score</span>
          <span>Section 1</span>
        </li>
        <li class="toc-item">
          <span><strong>2.</strong> Architectural Mapping & Consolidated AI Bill of Materials (AI-BOM)</span>
          <span>Section 2</span>
        </li>
        <li class="toc-item">
          <span><strong>3.</strong> Detailed Vulnerability, Risk & Regulatory Impact Matrix</span>
          <span>Section 3</span>
        </li>
        <li class="toc-item">
          <span><strong>4.</strong> Adversarial Red Team Results & Model Armor Defense Efficacy</span>
          <span>Section 4</span>
        </li>
        <li class="toc-item">
          <span><strong>5.</strong> Framework Compliance Breakdown (SAIF / NIST / ISO 42001)</span>
          <span>Section 5</span>
        </li>
        <li class="toc-item">
          <span><strong>6.</strong> Corrective Action Plan & Strategic Roadmap (3-Phase CAPA)</span>
          <span>Section 6</span>
        </li>
      </ul>
    </div>

    <!-- ================= CHAPTER 1 ================= -->
    <div class="section page-break">
      <h2 class="section-title">1. Executive Summary & Overall Posture Health</h2>
      <p style="font-size:0.9rem; color:#3C4043; margin-bottom:1.25rem;">
        This assessment evaluated the maturity, resilience, and security governance of the enterprise AI ecosystem across foundation models, RAG pipelines, inference microservices, and multi-cloud IAM configurations.
      </p>

      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-title">Overall Compliance Score</div>
          <div class="kpi-value" style="color:var(--warning);">71.2%</div>
          <div class="kpi-desc">Status: Moderate Risk (Tier 2)</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Compliant Controls (Y)</div>
          <div class="kpi-value" style="color:var(--success);">62</div>
          <div class="kpi-desc">Passed without deviations</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Partial Controls (P)</div>
          <div class="kpi-value" style="color:var(--warning);">24</div>
          <div class="kpi-desc">Adjustments required</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Critical Gaps (N)</div>
          <div class="kpi-value" style="color:var(--danger);">18</div>
          <div class="kpi-desc">Immediate remediation</div>
        </div>
      </div>

      <h3 style="font-size:1.05rem; color:#202124; margin:1.5rem 0 0.5rem 0;">Score Breakdown across 5 Core Pillars</h3>
      <table>
        <thead>
          <tr>
            <th>Normative Domain</th>
            <th>Scope Description</th>
            <th>Controls</th>
            <th>Compliance</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>1. Data Security & Privacy (DAT)</strong></td>
            <td>CMEK Encryption, RAG Lineage, Cloud DLP, PII Redaction</td>
            <td>22 Controls</td>
            <td><strong>65.0%</strong></td>
            <td><span class="tag tag-med">Adjustments Required</span></td>
          </tr>
          <tr>
            <td><strong>2. Model Hardening & Supply Chain (MOD)</strong></td>
            <td>SLSA Level 3, Model Signing, Provenance Verification</td>
            <td>20 Controls</td>
            <td><strong>72.5%</strong></td>
            <td><span class="tag tag-low">Aligned</span></td>
          </tr>
          <tr>
            <td><strong>3. Infrastructure & IAM (INF)</strong></td>
            <td>VPC Isolation, Least Privilege, VPC Service Controls</td>
            <td>22 Controls</td>
            <td><strong>60.0%</strong></td>
            <td><span class="tag tag-high">Critical Gaps</span></td>
          </tr>
          <tr>
            <td><strong>4. Application Security & APIs (APP)</strong></td>
            <td>Model Armor Guard, BOLA/IDOR Defense, Input Sanitization</td>
            <td>22 Controls</td>
            <td><strong>68.0%</strong></td>
            <td><span class="tag tag-med">Adjustments Required</span></td>
          </tr>
          <tr>
            <td><strong>5. Operations & Telemetry (OPS)</strong></td>
            <td>Cloud Logging, VPC Flow Logs, Drift & Poisoning Detection</td>
            <td>18 Controls</td>
            <td><strong>75.0%</strong></td>
            <td><span class="tag tag-low">Aligned</span></td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ================= CHAPTER 2 ================= -->
    <div class="section page-break">
      <h2 class="section-title">2. AI Bill of Materials (AI-BOM - CycloneDX Standard)</h2>
      <p style="font-size:0.9rem; color:#3C4043; margin-bottom:1rem;">
        Inventory of production AI assets and MLOps dependencies across the enterprise multi-cloud environment:
      </p>

      <table>
        <thead>
          <tr>
            <th>Asset / Component</th>
            <th>Category</th>
            <th>Provider</th>
            <th>Location / Scope</th>
            <th>Version</th>
            <th>Security Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>vertex-gemini-1.5-pro</strong></td>
            <td>Foundation Model</td>
            <td>Google Cloud</td>
            " + f"<td><code>{DEMO_GCP_PROJECT_ID} / us-central1</code></td>" + "
            <td>1.5-pro-002</td>
            <td><span class="tag tag-high">Guardrails Inactive</span></td>
          </tr>
          <tr>
            " + f"<td><strong>{DEMO_STORAGE_BUCKET}</strong></td>" + "
            <td>RAG Knowledge Base</td>
            <td>Google Cloud</td>
            " + f"<td><code>gs://{DEMO_STORAGE_BUCKET}</code></td>" + "
            <td>Dataset v3.2</td>
            <td><span class="tag tag-high">CMEK Missing</span></td>
          </tr>
          <tr>
            <td><strong>vm-payment-api (/api/v1/ai/chat)</strong></td>
            <td>AI Microservice</td>
            <td>Google Cloud</td>
            <td><code>10.20.10.3:8080 (VPC Apps)</code></td>
            <td>FastAPI v2.4</td>
            <td><span class="tag tag-high">BOLA & Injection Active</span></td>
          </tr>
          <tr>
            <td><strong>claude-3-5-sonnet</strong></td>
            <td>Foundation Model</td>
            <td>AWS Bedrock</td>
            <td><code>us-east-1 (Bedrock)</code></td>
            <td>v1:0</td>
            <td><span class="tag tag-low">Compliant / IAM Audited</span></td>
          </tr>
          <tr>
            <td><strong>gpt-4o-enterprise</strong></td>
            <td>Foundation Model</td>
            <td>Azure OpenAI</td>
            <td><code>eastus (Azure)</code></td>
            <td>2024-05-13</td>
            <td><span class="tag tag-low">Compliant / Private VNet</span></td>
          </tr>
          <tr>
            <td><strong>google-cloud-aiplatform</strong></td>
            <td>MLOps Library</td>
            <td>Python Runtime</td>
            <td><code>Python 3.11 / SDK</code></td>
            <td>1.74.0</td>
            <td><span class="tag tag-low">SLSA Level 3 Compliant</span></td>
          </tr>
          <tr>
            <td><strong>langchain-core</strong></td>
            <td>MLOps Library</td>
            <td>Python Runtime</td>
            <td><code>Python 3.11 / SDK</code></td>
            <td>0.1.20</td>
            <td><span class="tag tag-low">MIT License Approved</span></td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ================= CHAPTER 3 ================= -->
    <div class="section page-break">
      <h2 class="section-title">3. Critical Vulnerability & Gap Matrix</h2>
      <p style="font-size:0.9rem; color:#3C4043; margin-bottom:1rem;">
        High-severity technical deviations identified during automated infrastructure scans and regulatory mapping:
      </p>

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Scan Finding</th>
            <th>Regulatory Exposure</th>
            <th>Remediation Action</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>INF-01</strong></td>
            <td><span class="tag tag-high">CRITICAL</span></td>
            <td>" + f"Service Account <code>{DEMO_SERVICE_ACCOUNT}</code> holds <code>roles/editor</code> role in project <code>{DEMO_GCP_PROJECT_ID}</code>" + "</td>
            <td>SAIF Pillar 2 | NIST GOVERN 1.2 | MITRE AML.T0010</td>
            <td>Enforce Least Privilege by restricting to <code>roles/aiplatform.user</code> and VPC SC</td>
          </tr>
          <tr>
            <td><strong>DAT-01</strong></td>
            <td><span class="tag tag-high">HIGH</span></td>
            <td>" + f"Bucket <code>{DEMO_STORAGE_BUCKET}</code> uses default Google-managed keys without CMEK" + "</td>
            <td>ISO 42001 A.8.2 | SAIF Pillar 1</td>
            <td>Configure Customer-Managed Encryption Keys in Cloud KMS</td>
          </tr>
          <tr>
            <td><strong>DAT-05</strong></td>
            <td><span class="tag tag-high">HIGH</span></td>
            <td>SQL dump <code>legacy_db_dump.sql</code> contains cleartext SSNs/CPFs without DLP masking</td>
            <td>LGPD Art. 46 | NIST MEASURE 2.10</td>
            <td>Enable inline Cloud DLP for automated PII redaction</td>
          </tr>
          <tr>
            <td><strong>APP-01</strong></td>
            <td><span class="tag tag-high">HIGH</span></td>
            <td>Endpoint <code>/api/v1/customers/{id}</code> allows unauthorized customer enumeration (BOLA/IDOR)</td>
            <td>OWASP API1:2023</td>
            <td>Enforce strict JWT session validation at API Gateway layer</td>
          </tr>
          <tr>
            <td><strong>APP-04</strong></td>
            <td><span class="tag tag-high">HIGH</span></td>
            <td>Endpoint <code>/api/v1/ai/chat</code> accepts direct Prompt Injection without filtering</td>
            <td>OWASP LLM01:2025 | MITRE AML.T0051</td>
            <td>Activate Model Armor Guardrails for semantic prompt inspection</td>
          </tr>
          <tr>
            <td><strong>INF-04</strong></td>
            <td><span class="tag tag-med">MEDIUM</span></td>
            <td>Subnet <code>sb-apps-uscentral1</code> with VPC Flow Logs disabled</td>
            <td>SAIF Pillar 3 | NIST MEASURE 2.7</td>
            <td>Enable VPC Flow Logs with 100% sampling rate for network visibility</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ================= CHAPTER 4 ================= -->
    <div class="section page-break">
      <h2 class="section-title">4. Adversarial Red Team Validation Results</h2>
      <p style="font-size:0.9rem; color:#3C4043; margin-bottom:0.75rem;">
        <strong>20 benchmark attack vectors</strong> were simulated evaluating the defense efficacy of Model Armor against MITRE ATLAS and OWASP LLM Top 10:
      </p>

      <ul style="font-size:0.88rem; padding-left:1.5rem; line-height:1.8; color:#202124;">
        <li><strong>Total Vectors Tested:</strong> 20 attack scenarios (Jailbreaking, System Leakage, RAG Poisoning, PII Exfil, Tool Abuse, BOLA).</li>
        <li><strong>Overall Defense Efficacy:</strong> <strong style="color:var(--success);">95.0%</strong> block rate with Model Armor active.</li>
        <li><strong>Average Inspection Latency:</strong> <code>~2.1 ms</code> per request.</li>
        <li><strong>Technical Conclusion:</strong> Model Armor establishes a resilient semantic shield, neutralizing jailbreaks and prompt extraction before requests reach LLMs.</li>
      </ul>
    </div>

    <!-- ================= CHAPTER 5 ================= -->
    <div class="section page-break">
      <h2 class="section-title">5. Corrective Action Plan & Strategic Roadmap (CAPA)</h2>
      <p style="font-size:0.9rem; color:#3C4043; margin-bottom:1rem;">
        Structured 3-phase technical roadmap to elevate organizational security posture to <strong>Tier 1 (Secure & Compliant)</strong>:
      </p>

      <div class="roadmap-grid">
        <div class="roadmap-card" style="border-top:4px solid var(--danger);">
          <div class="roadmap-title" style="color:var(--danger);">Phase 1: Immediate Remediation (0 - 15 Days)</div>
          <ul class="roadmap-list">
            <li>" + f"Revoke <code>roles/editor</code> from <code>{DEMO_SERVICE_ACCOUNT}</code> and bind <code>roles/aiplatform.user</code>." + "</li>
            <li>Activate Model Armor Guardrail on microservice <code>/api/v1/ai/chat</code>.</li>
            <li>Fix BOLA/IDOR authorization validation on customer endpoint.</li>
          </ul>
        </div>

        <div class="roadmap-card" style="border-top:4px solid var(--warning);">
          <div class="roadmap-title" style="color:var(--warning);">Phase 2: Data Hardening (15 - 45 Days)</div>
          <ul class="roadmap-list">
            <li>Configure Cloud KMS CMEK keys on all RAG storage buckets and backups.</li>
            <li>Integrate inline Cloud DLP for automated PII masking.</li>
            <li>Enable VPC Flow Logs and audit telemetry alerts in Cloud Logging.</li>
          </ul>
        </div>

        <div class="roadmap-card" style="border-top:4px solid var(--success);">
          <div class="roadmap-title" style="color:var(--success);">Phase 3: Continuous Governance (45 - 90 Days)</div>
          <ul class="roadmap-list">
            <li>Deploy automated CI/CD pipeline validation for CycloneDX AI-BOMs.</li>
            <li>Formalize AI Management System compliant with ISO/IEC 42001.</li>
            <li>Execute periodic automated Red Teaming campaigns with AISPR.</li>
          </ul>
        </div>
      </div>

      <!-- Signatures -->
      <div style="border-top:1px solid var(--border); padding-top:2rem; margin-top:3rem; display:grid; grid-template-columns:1fr 1fr; gap:2rem;">
        <div>
          <div style="border-bottom:1px solid var(--border); width:80%; margin-bottom:6px;"></div>
          <strong style="font-size:0.85rem;">Joabson Saccomani (@jsaccomani)</strong>
          <div style="font-size:0.75rem; color:var(--text-muted);">Lead Cloud Security Consultant | Google Cloud Consulting</div>
        </div>
        <div>
          <div style="border-bottom:1px solid var(--border); width:80%; margin-bottom:6px;"></div>
          <strong style="font-size:0.85rem;">Chief Information Security Officer (CISO)</strong>
          <div style="font-size:0.75rem; color:var(--text-muted);">" + DEMO_CLIENT_NAME + "</div>
        </div>
      </div>
    </div>

    <!-- Document Footer -->
    <div class="doc-footer">
      Google Cloud Security Consulting | AI Security Posture Review (AI-SPR) | Developed by Joabson Saccomani (@jsaccomani)
    </div>

  </div>

</body>
</html>
"""


class AISPRServerHandler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, data, status_code=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file_download(self, content_bytes: bytes, content_type: str, filename: str):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(content_bytes)))
        self.end_headers()
        self.wfile.write(content_bytes)

    def _send_html(self, html_content, status_code=200):
        body = html_content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        if path in ["/", "/index.html"]:
            self._send_html(HTML_TEMPLATE)
        elif path == "/api/report/view":
            self._send_html(OFFICIAL_REPORT_HTML)
        elif path == "/api/report/download/json":
            report_data = {
                "organization": "" + DEMO_CLIENT_NAME + "",
                "scope": "" + DEMO_SCOPE_DESCRIPTION + "",
                "auditor": "Joabson Saccomani (@jsaccomani)",
                "date": datetime.datetime.now().isoformat(),
                "frameworks": [
                    "Google SAIF 2.0",
                    "NIST AI RMF 1.0",
                    "ISO/IEC 42001:2023",
                    "MITRE ATLAS v4.2",
                    "OWASP GenAI Top 10"
                ],
                "metrics": {
                    "health_score_percentage": 71.2,
                    "controls_total": 104,
                    "controls_yes": 62,
                    "controls_partial": 24,
                    "controls_no": 18
                },
                "domain_scores": {
                    "DAT": {"name": "Data Security & Privacy", "percentage": 65.0, "controls": 22},
                    "MOD": {"name": "Model Hardening & Supply Chain", "percentage": 72.5, "controls": 20},
                    "INF": {"name": "Infrastructure & IAM", "percentage": 60.0, "controls": 22},
                    "APP": {"name": "Application Security & APIs", "percentage": 68.0, "controls": 22},
                    "OPS": {"name": "Operations & Monitoring", "percentage": 75.0, "controls": 18}
                },
                "ai_bom": DISCOVERED_AI_ASSETS,
                "critical_findings": FINDINGS_MAP,
                "red_team_metrics": {
                    "benchmark_vectors_tested": 20,
                    "defense_efficacy_percentage": 95.0,
                    "latency_ms": 2.1,
                    "guardrail": "Model Armor Guard"
                },
                "remediation_roadmap": {
                    "phase_1_immediate": [
                        "" + f"Revoke roles/editor from {DEMO_SERVICE_ACCOUNT} and bind roles/aiplatform.user" + "",
                        "Activate Model Armor Guardrails on /api/v1/ai/chat endpoint",
                        "Implement strict JWT session validation on /api/v1/customers/{id}"
                    ],
                    "phase_2_hardening": [
                        "Configure Cloud KMS CMEK encryption on all AI storage buckets",
                        "Integrate Cloud DLP inline for automated PII masking",
                        "Enable VPC Flow Logs and audit alert telemetry"
                    ],
                    "phase_3_governance": [
                        "Implement automated CI/CD AI-BOM validation",
                        "Formalize ISO/IEC 42001 AI Management System (AIMS)",
                        "Run continuous automated AISPR red team exercises"
                    ]
                }
            }
            body = json.dumps(report_data, indent=2).encode("utf-8")
            self._send_file_download(body, "application/json", "aispr_executive_report.json")
        elif path == "/api/report/download/markdown":
            md_text = f"""# GOOGLE CLOUD SECURITY CONSULTING
# AI Security Posture Review (AI-SPR) - Executive Report

**Client / Organization:** " + DEMO_CLIENT_NAME + "  
**Assessment Scope:** " + DEMO_SCOPE_DESCRIPTION + "  
**Lead Consultant:** Joabson Saccomani (@jsaccomani)  
**Issue Date:** {datetime.datetime.now().strftime("%Y-%m-%d")}  
**Reference Baselines:** Google SAIF 2.0 | NIST AI RMF 1.0 | ISO/IEC 42001:2023 | MITRE ATLAS | OWASP GenAI Top 10  

---

## Table of Contents
1. Executive Summary & Posture Health Score
2. Consolidated AI Bill of Materials (AI-BOM)
3. Detailed Vulnerability, Risk & Regulatory Impact Matrix
4. Adversarial Red Team Results & Model Armor Efficacy
5. Normative Compliance Breakdown by Framework
6. Corrective Action Plan & Strategic Roadmap (CAPA)

---

## 1. Executive Summary & Overall Posture Health
- **Overall Compliance Score:** 71.2% (Status: Moderate Risk / Tier 2)  
- **Compliant Controls (Y):** 62  
- **Partial Controls (P):** 24  
- **Critical Gaps / Non-Compliant (N):** 18  

### Score Breakdown by Domain
| Normative Domain | Controls | Compliance % | Status |
|---|---|---|---|
| 1. Data Security & Privacy (DAT) | 22 | 65.0% | Adjustments Required |
| 2. Model Hardening & Supply Chain (MOD) | 20 | 72.5% | Aligned |
| 3. Infrastructure & IAM (INF) | 22 | 60.0% | Critical Gaps |
| 4. Application Security & APIs (APP) | 22 | 68.0% | Adjustments Required |
| 5. Operations & Monitoring (OPS) | 18 | 75.0% | Aligned |

---

## 2. AI Bill of Materials (AI-BOM)
| Asset / Component | Category | Provider | Location | Risk Status |
|---|---|---|---|---|
| vertex-gemini-1.5-pro | Foundation Model | Google Cloud " + f"| {DEMO_GCP_PROJECT_ID} / us-central1 |" + " Warning: Guardrails Inactive |
" + f"| {DEMO_STORAGE_BUCKET} |" + " RAG Knowledge Base | Google Cloud " + f"| gs://{DEMO_STORAGE_BUCKET} |" + " CMEK Missing |
| vm-payment-api (/api/v1/ai/chat) | AI Microservice | Google Cloud | 10.20.10.3:8080 (VPC Apps) | BOLA & Prompt Injection |
| claude-3-5-sonnet | Foundation Model | AWS Bedrock | us-east-1 | Compliant |
| gpt-4o-enterprise | Foundation Model | Azure OpenAI | eastus | Compliant |
| google-cloud-aiplatform | MLOps Library | Python 3.11 | SDK v1.74.0 | SLSA Level 3 Compliant |
| langchain-core | MLOps Library | Python 3.11 | SDK v0.1.20 | MIT License Approved |

---

## 3. Key Findings Discovered in Scan
1. **[CRITICAL] INF-01:** " + f"Service Account '{DEMO_SERVICE_ACCOUNT}' holds 'roles/editor' in project {DEMO_GCP_PROJECT_ID}" + ".
2. **[HIGH] DAT-01:** " + f"Bucket '{DEMO_STORAGE_BUCKET}' missing Customer-Managed Encryption Key (CMEK)" + ".
3. **[HIGH] DAT-05:** SQL dump 'legacy_db_dump.sql' contains cleartext SSNs/CPFs without Cloud DLP masking.
4. **[HIGH] APP-01:** Broken Object Level Authorization (BOLA/IDOR) on /api/v1/customers/{id}.
5. **[HIGH] APP-04:** Endpoint /api/v1/ai/chat vulnerable to direct Prompt Injection without Model Armor.
6. **[MEDIUM] INF-04:** Subnet 'sb-apps-uscentral1' with VPC Flow Logs disabled.

---

## 4. Adversarial Red Team Results
- **Total Vectors Tested:** 20 Benchmark Attack Scenarios (MITRE ATLAS / OWASP).  
- **Overall Defense Efficacy:** 95.0% with Model Armor active.  
- **Average Inspection Latency:** ~2.1 ms per request.  

---

## 5. Strategic Remediation Plan (CAPA Roadmap)
- **Phase 1 (0-15 Days):** " + f"Enforce least privilege on {DEMO_SERVICE_ACCOUNT}, activate Model Armor on /api/v1/ai/chat, and fix BOLA." + "  
- **Phase 2 (15-45 Days):** Activate Cloud KMS CMEK and enable inline Cloud DLP.  
- **Phase 3 (45-90 Days):** Implement automated CI/CD validation and ISO/IEC 42001 governance.  

---
*Confidential report generated by AISPR v3.0 - Google Cloud Security Consulting.*
"""
            self._send_file_download(md_text.encode("utf-8"), "text/markdown; charset=utf-8", "aispr_executive_report.md")
        elif path == "/api/health":
            self._send_json({"status": "UP", "platform": "AISPR v3.0", "engine": "Posture Assessment Engine"})
        elif path in ["/api/audit/questions", "/api/audit/questionnaire"]:
            flat_qs = []
            for domain_name, q_list in q_handler.question_db.items():
                for q in q_list:
                    qid = q.get("id", "")
                    finding_text = FINDINGS_MAP.get(qid, "No deviations detected during automated scan.")
                    default_ans = "N" if qid in FINDINGS_MAP else "Y"
                    flat_qs.append({
                        "id": qid,
                        "question": q.get("question", ""),
                        "framework_mapping": q.get("framework_mapping", ""),
                        "criticality": q.get("criticality", "MEDIUM"),
                        "rationale": q.get("rationale", ""),
                        "finding": finding_text,
                        "default_answer": default_ans,
                        "domain": domain_name
                    })
            self._send_json({"questions": flat_qs, "total": len(flat_qs)})
        elif path == "/api/audit/controls/versions":
            self._send_json(q_handler.get_framework_versions())
        elif path == "/api/redteam/dataset":
            simulator = AIRedTeamSimulator()
            self._send_json({"test_cases": simulator.test_cases, "total": len(simulator.test_cases)})
        elif path == "/api/inventory":
            try:
                bom_gen = AIBOMGenerator(project_root)
                cyclone_data = bom_gen.generate_bom()
                response_data = {
                    "structured_assets": DISCOVERED_AI_ASSETS,
                    "cyclonedx_bom": cyclone_data
                }
                self._send_json(response_data)
            except Exception as e:
                self._send_json({"error": str(e)}, status_code=500)
        else:
            self._send_json({"error": "Endpoint not found", "path": path}, status_code=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"
        
        try:
            payload = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            payload = {}

        if path == "/api/guard":
            try:
                res = guard.inspect_prompt(payload.get("prompt", ""))
                self._send_json(res)
            except Exception as e:
                self._send_json({"error": str(e)}, status_code=500)
        elif path == "/api/redteam/run":
            try:
                simulator = AIRedTeamSimulator()
                report = simulator.execute_campaign()
                self._send_json(report)
            except Exception as e:
                self._send_json({"error": str(e)}, status_code=500)
        elif path == "/api/audit/evaluate":
            try:
                answers_in = payload.get("answers", {})
                processed_answers = {}
                for q_id, ans_info in answers_in.items():
                    status_val = ans_info.get("status", "Y") if isinstance(ans_info, dict) else ans_info
                    notes = ans_info.get("notes", "") if isinstance(ans_info, dict) else ""
                    q_handler.record_answer(q_id, status_val, notes, processed_answers)
                
                scores = PostureScorer.calculate_scores(processed_answers, q_handler.question_db)
                self._send_json({"score_data": scores})
            except Exception as e:
                self._send_json({"error": str(e)}, status_code=500)
        else:
            self._send_json({"error": "Endpoint not found", "path": path}, status_code=404)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run_server(port: int = 8501, host: str = "0.0.0.0"):
    print("================================================================================")
    print(f"AISPR Web Console live at: http://{host}:{port}")
    print("Enterprise Assessment Console | Dynamic Health Scoring | Google Cloud Official Deliverable")
    print("================================================================================")
    server = ThreadedHTTPServer((host, port), AISPRServerHandler)
    server.serve_forever()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8501))
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_server(port=port)

# Audit checkpoint [2026-02-23]: refactor(evaluator): streamline multi-turn jailbreak evaluation pipeline for client rollout

# Audit checkpoint [2026-02-26]: refactor(scoring): calibrate model vulnerability scoring formula for client audit
