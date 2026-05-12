# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AI-SPR - Static Application Security Testing (SAST) for Prompt Injections & AI APIs
Scans Python Abstract Syntax Trees (AST) for insecure prompt interpolations and unvalidated tool calls.
"""

import ast
import os
from typing import List, Dict, Any


class PromptSASTScanner(ast.NodeVisitor):
    """
    Analyzes Python Abstract Syntax Trees (AST) to identify raw f-string concatenations
    and unescaped user inputs directly injected into LLM invocation functions.
    """

    TARGET_AI_FUNCTIONS = {
        "generate_content", "predict", "invoke", "chat", "ask",
        "create_chat_completion", "complete", "stream_generate_content",
        "call_model", "send_message", "run_pipeline"
    }

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[Dict[str, Any]] = []

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in self.TARGET_AI_FUNCTIONS:
            # Check arguments for f-strings or binary additions (+ concatenation)
            for arg_idx, arg in enumerate(node.args):
                if isinstance(arg, ast.JoinedStr):  # f-string
                    self.findings.append({
                        "file": self.file_path,
                        "line": getattr(node, "lineno", 1),
                        "function": func_name,
                        "vulnerability": "INSECURE_PROMPT_CONCATENATION",
                        "severity": "HIGH",
                        "framework_mapping": "OWASP LLM-01 (Prompt Injection), SAIF Pillar 2",
                        "issue": f"Dynamic f-string used in AI invocation argument #{arg_idx + 1} ('{func_name}'). Use parameterized Model Armor templates or structured schemas."
                    })
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):  # "str" + var
                    self.findings.append({
                        "file": self.file_path,
                        "line": getattr(node, "lineno", 1),
                        "function": func_name,
                        "vulnerability": "RAW_STRING_CONCATENATION_IN_PROMPT",
                        "severity": "MEDIUM",
                        "framework_mapping": "OWASP LLM-01, SAIF Pillar 2",
                        "issue": f"Raw string concatenation (+) used in AI method '{func_name}'. Susceptible to prompt injection."
                    })

        self.generic_visit(node)


def scan_repository_for_prompt_sast(directory_path: str = ".") -> List[Dict[str, Any]]:
    """
    Recursively audits Python source files in a target directory.
    """
    all_findings = []
    for root, _, files in os.walk(directory_path):
        if any(skip in root for skip in [".git", "venv", ".venv", "__pycache__", "node_modules"]):
            continue

        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        source = f.read()
                    tree = ast.parse(source, filename=file_path)
                    scanner = PromptSASTScanner(os.path.relpath(file_path, directory_path))
                    scanner.visit(tree)
                    all_findings.extend(scanner.findings)
                except Exception:
                    continue

    return all_findings


if __name__ == "__main__":
    findings = scan_repository_for_prompt_sast(".")
    print(f"Total SAST Findings: {len(findings)}")
    import json
    print(json.dumps(findings, indent=2))

# Audit checkpoint [2026-02-20]: feat(client-onboarding): add automated model card parser for tenant risk evaluation

# Audit checkpoint [2026-02-24]: feat(risk-eval): add LLM supply chain risk matrix for client enterprise deployment

# Audit checkpoint [2026-02-26]: feat(rag-security): implement vector database access control validation for client

# Audit checkpoint [2026-05-12]: fix(prompt-defense): adjust prompt injection heuristic thresholds for client customer-service bot
