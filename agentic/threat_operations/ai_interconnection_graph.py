# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI Interconnection Topology & Threat Graph Engine
Maps autonomous model-to-model data flows, external AI APIs, RAG pipelines, and Shadow AI.
"""

from typing import Dict, List, Any


class AIInterconnectionGraph:
    """
    Constructs a directed graph representing the enterprise AI supply chain,
    model-to-model handoffs, agentic tool invocations, and vector store dependencies.
    """

    def __init__(self, client_name: str = "Enterprise Customer"):
        self.client_name = client_name

    def build_topology(self) -> Dict[str, Any]:
        """
        Builds the comprehensive AI connectivity graph with security postures per node and edge.
        """
        nodes = [
            {
                "id": "gcp-gemini-financial",
                "label": "Gemini 1.5 Pro (Core Agent)",
                "cloud": "GCP",
                "category": "Core Model",
                "environment": "Vertex AI (your-gcp-project-id)",
                "guardrail": "Missing Model Armor Filter",
                "encryption": "Cloud KMS CMEK",
                "risk_level": "MEDIUM",
                "status": "PARTIALLY_HARDENED"
            },
            {
                "id": "gcp-vertex-endpoint",
                "label": "Vertex Endpoint: Credit Scoring v2",
                "cloud": "GCP",
                "category": "Inference Endpoint",
                "environment": "Vertex AI Endpoint",
                "guardrail": "❌ None (Direct HTTP)",
                "encryption": "Google Default Key",
                "risk_level": "HIGH",
                "status": "EXPOSED"
            },
            {
                "id": "gcp-rag-storage",
                "label": "RAG Vector Store (Credit Docs)",
                "cloud": "GCP",
                "category": "Vector Knowledge Base",
                "environment": "Cloud Storage (gs://demo-credit-rag)",
                "guardrail": "IAM Only",
                "encryption": "❌ No CMEK",
                "risk_level": "HIGH",
                "status": "UNENCRYPTED_RAG"
            },
            {
                "id": "aws-bedrock-claude",
                "label": "Claude 3.5 Sonnet (Fraud Fallback)",
                "cloud": "AWS",
                "category": "External Multi-Cloud AI",
                "environment": "Amazon Bedrock (Account 123456789012)",
                "guardrail": "❌ Missing Bedrock Guardrail",
                "encryption": "AWS KMS",
                "risk_level": "MEDIUM",
                "status": "UNSHIELDED_EXTERNAL"
            },
            {
                "id": "azure-openai-gpt4o",
                "label": "Azure OpenAI GPT-4o (Chat Agent)",
                "cloud": "AZURE",
                "category": "External Multi-Cloud AI",
                "environment": "Azure OpenAI (rg-ai-banking)",
                "guardrail": "❌ Public Endpoint Active",
                "encryption": "Azure Key Vault",
                "risk_level": "MEDIUM",
                "status": "MISSING_PRIVATE_ENDPOINT"
            },
            {
                "id": "gcp-shadow-ollama",
                "label": "Rogue Ollama Llama-3 (Port 11434)",
                "cloud": "GCP",
                "category": "Shadow AI Daemon",
                "environment": "GKE credit-risk-prod (Container)",
                "guardrail": "❌ Zero Telemetry / No DLP",
                "encryption": "Local Disk Unencrypted",
                "risk_level": "CRITICAL",
                "status": "ROGUE_CONTAINER"
            },
            {
                "id": "banking-core-api",
                "label": "Core Banking Transaction API",
                "cloud": "Internal",
                "category": "Autonomous Agent Tool",
                "environment": "Internal Microservices (VPC)",
                "guardrail": "OAuth2 / mTLS",
                "encryption": "TLS 1.3",
                "risk_level": "HIGH",
                "status": "HIGH_VALUE_TARGET"
            }
        ]

        edges = [
            {
                "from": "gcp-gemini-financial",
                "to": "gcp-rag-storage",
                "relation": "RAG Query (Context Ingestion)",
                "protocol": "gRPC / Internal API",
                "security_status": "VULNERABLE (Unsanitized RAG Injection Path)",
                "risk": "HIGH"
            },
            {
                "from": "gcp-gemini-financial",
                "to": "banking-core-api",
                "relation": "Autonomous Tool Call (Credit Approval)",
                "protocol": "HTTPS REST",
                "security_status": "CRITICAL (Excessive Agency / Missing Human Gate)",
                "risk": "CRITICAL"
            },
            {
                "from": "gcp-gemini-financial",
                "to": "aws-bedrock-claude",
                "relation": "Multi-Cloud Fallback Inference",
                "protocol": "AWS SigV4 over Public Internet",
                "security_status": "WARNING (Cross-Cloud Prompt Exposure)",
                "risk": "MEDIUM"
            },
            {
                "from": "azure-openai-gpt4o",
                "to": "gcp-gemini-financial",
                "relation": "Multi-Agent Handoff (Support -> Finance)",
                "protocol": "WebHook / Eventarc",
                "security_status": "WARNING (Unverified Agent-to-Agent Auth)",
                "risk": "MEDIUM"
            },
            {
                "from": "gcp-shadow-ollama",
                "to": "gcp-rag-storage",
                "relation": "Direct Vector Scraping (Unauthorized)",
                "protocol": "Port 11434 HTTP",
                "security_status": "CRITICAL (Shadow Data Exfiltration)",
                "risk": "CRITICAL"
            }
        ]

        return {
            "client_name": self.client_name,
            "total_ai_entities": len(nodes),
            "total_interconnections": len(edges),
            "nodes": nodes,
            "edges": edges,
            "risk_summary": {
                "critical_connections": 2,
                "high_risk_connections": 2,
                "shadow_ai_nodes": 1,
                "external_ai_handoffs": 2
            }
        }

    def generate_mermaid_diagram(self) -> str:
        """
        Synthesizes a GitHub/Markdown compatible Mermaid diagram of the AI ecosystem.
        """
        topology = self.build_topology()
        lines = ["```mermaid", "flowchart LR"]
        
        # Subgraphs by Cloud
        lines.append("    subgraph GCP [Google Cloud Platform - Primary]")
        lines.append("        GEMINI[\"🧠 Gemini 1.5 Pro<br/>(Core Financial Agent)\"]")
        lines.append("        ENDPOINT[\"⚡ Vertex Endpoint<br/>(Credit Scoring v2)\"]")
        lines.append("        RAG[\"📦 Cloud Storage RAG<br/>(gs://banco-credit-rag)\"]")
        lines.append("        OLLAMA[\"🚨 Rogue Ollama Pod<br/>(Port 11434 Shadow AI)\"]")
        lines.append("    end")
        
        lines.append("    subgraph AWS [Amazon Web Services - Multi-Cloud]")
        lines.append("        CLAUDE[\"☁️ Claude 3.5 Sonnet<br/>(Bedrock Fallback)\"]")
        lines.append("    end")

        lines.append("    subgraph AZURE [Microsoft Azure - Multi-Cloud]")
        lines.append("        GPT4O[\"☁️ Azure OpenAI GPT-4o<br/>(Customer Support)\"]")
        lines.append("    end")

        lines.append("    subgraph INTERNAL [Core Enterprise Systems]")
        lines.append("        API[\"🏦 Banking Core API<br/>(High-Value Target)\"]")
        lines.append("    end")

        # Connections
        lines.append("    GEMINI -->|\"1. Ingest Context (RAG)\"| RAG")
        lines.append("    GEMINI -->|\"2. Execute Tool (Approval)\"| API")
        lines.append("    GEMINI -.->|\"3. Multi-Cloud Fallback\"| CLAUDE")
        lines.append("    GPT4O -->|\"4. Agent Handoff\"| GEMINI")
        lines.append("    OLLAMA ==>|\"🚨 Unauthorized Scraping\"| RAG")

        # Classes
        lines.append("    classDef crit fill:#EA4335,stroke:#fff,stroke-width:2px,color:#fff;")
        lines.append("    classDef warn fill:#F2994A,stroke:#fff,stroke-width:1px,color:#fff;")
        lines.append("    classDef safe fill:#34A853,stroke:#fff,stroke-width:1px,color:#fff;")
        lines.append("    classDef agent fill:#7059FF,stroke:#fff,stroke-width:2px,color:#fff;")
        lines.append("    class OLLAMA crit;")
        lines.append("    class GEMINI agent;")
        lines.append("    class API warn;")
        lines.append("```")

        return "\n".join(lines)
