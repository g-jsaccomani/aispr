# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

P0 Regression Guard: Import and Typing Integrity Test Suite
Enforces:
  1. Every .py file in the repository imports without error across all supported Python versions (3.11-3.14).
  2. No repository file shadows any standard library module in sys.stdlib_module_names.
  3. Programmatic pyflakes analysis reveals zero 'undefined name' defects.
"""

import ast
import os
import sys
import unittest
import importlib.util

from pyflakes.checker import Checker
from pyflakes.messages import UndefinedName

EXCLUDED_DIRS = {".git", "__pycache__", ".venv", "venv", "env", ".idea", ".vscode", "reports"}


class TestImportIntegrity(unittest.TestCase):
    """Guards against latent syntax/typing errors, stdlib shadowing, and undefined names."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if cls.repo_root not in sys.path:
            sys.path.insert(0, cls.repo_root)

    def _get_python_files(self):
        """Walks repository and returns all tracked Python source files."""
        py_files = []
        for root, dirs, files in os.walk(self.repo_root):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            for file in sorted(files):
                if file.endswith(".py"):
                    py_files.append(os.path.join(root, file))
        return py_files

    def test_all_modules_import_without_error(self):
        """Test A: Walks every .py file in the repo and asserts it imports without error."""
        failures = []
        py_files = self._get_python_files()
        self.assertGreater(len(py_files), 50, "Expected at least 50 Python source files")

        for file_path in py_files:
            rel_path = os.path.relpath(file_path, self.repo_root)
            mod_name = os.path.splitext(rel_path)[0].replace(os.path.sep, ".")

            # Avoid re-importing test_import_integrity in an infinite loop
            if rel_path.endswith("test_import_integrity.py"):
                continue

            try:
                spec = importlib.util.spec_from_file_location(mod_name, file_path)
                if spec is None or spec.loader is None:
                    failures.append(f"{rel_path}: Could not load spec")
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = module
                spec.loader.exec_module(module)
            except Exception as exc:
                failures.append(f"{rel_path}: {type(exc).__name__}: {exc}")

        self.assertEqual(
            failures,
            [],
            f"Failed to import {len(failures)} file(s):\n" + "\n".join(failures),
        )

    def test_no_stdlib_module_shadowing(self):
        """Test B: Asserts no module in the repo shadows a name in sys.stdlib_module_names."""
        # sys.stdlib_module_names is available in Python 3.10+
        std_names = getattr(sys, "stdlib_module_names", None)
        if std_names is None:
            # Fallback for Python < 3.10 if ever executed
            import sysconfig
            std_names = frozenset(sys.builtin_module_names)

        shadowed = []
        py_files = self._get_python_files()

        for file_path in py_files:
            file_name = os.path.basename(file_path)
            module_base = file_name[:-3]
            # Check if module_base is in standard library modules
            if module_base in std_names:
                rel_path = os.path.relpath(file_path, self.repo_root)
                shadowed.append(rel_path)

        self.assertEqual(
            shadowed,
            [],
            f"Repository shadows standard library module name(s): {shadowed}",
        )

    def test_zero_undefined_names(self):
        """Test C: Runs pyflakes programmatically and asserts zero 'undefined name' results."""
        undefined_errors = []
        py_files = self._get_python_files()

        for file_path in py_files:
            rel_path = os.path.relpath(file_path, self.repo_root)
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            try:
                tree = ast.parse(content, filename=file_path)
            except SyntaxError as syn_err:
                undefined_errors.append(f"{rel_path}:{syn_err.lineno}: SyntaxError: {syn_err.msg}")
                continue

            checker = Checker(tree, filename=file_path)
            for msg in checker.messages:
                if isinstance(msg, UndefinedName) or "undefined name" in str(msg).lower():
                    undefined_errors.append(f"{rel_path}:{msg.lineno}: {msg.message % msg.message_args}")

        self.assertEqual(
            undefined_errors,
            [],
            f"Found {len(undefined_errors)} undefined name error(s):\n" + "\n".join(undefined_errors),
        )


if __name__ == "__main__":
    unittest.main()
