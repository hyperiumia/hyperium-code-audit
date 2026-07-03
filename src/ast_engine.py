"""
AST Engine — Abstract Syntax Tree analysis for deeper code understanding.

Currently supports Python AST (stdlib) with regex-based analysis
for other languages. This provides higher-confidence findings
by understanding code structure, not just text patterns.

Future: tree-sitter integration for true multi-language AST parsing.
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import List, Optional

from src.models import Finding, FindingCategory, Language, Severity

logger = logging.getLogger(__name__)


class PythonASTVisitor(ast.NodeVisitor):
    """Walks Python AST to find security-relevant patterns."""

    def __init__(self, file_path: str, lines: List[str]):
        self.file_path = file_path
        self.lines = lines
        self.findings: List[Finding] = []

    def _snippet(self, line: int, context: int = 2) -> str:
        start = max(0, line - 1 - context)
        end = min(len(self.lines), line + context)
        return "\n".join(
            f"{'>>>' if i == line - 1 else '   '} {i+1:4d} | {self.lines[i].rstrip()}"
            for i in range(start, end)
        )

    def _add(self, node, title, category, severity, cwe, owasp, desc, remediation, confidence=0.85):
        self.findings.append(Finding(
            rule_id=f"AST-PY-{cwe[-3:]}",
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            file_path=self.file_path,
            line_number=getattr(node, "lineno", 0),
            code_snippet=self._snippet(getattr(node, "lineno", 0)),
            language=Language.PYTHON,
            cwe_id=cwe,
            owasp_id=owasp,
            description=desc,
            remediation=remediation,
        ))

    def visit_Call(self, node):
        """Analyze function calls for security issues."""
        func_name = self._get_func_name(node)

        # SQL Injection via execute()
        if func_name in ("execute", "raw", "mogrify"):
            if node.args and self._is_string_concat(node.args[0]):
                self._add(node,
                    "SQL Injection via string concatenation (AST verified)",
                    FindingCategory.INJECTION, Severity.CRITICAL,
                    "CWE-89", "A03",
                    "SQL execute() called with a concatenated or formatted string.",
                    "Use parameterized queries with ? or %s placeholders.",
                    confidence=0.95,
                )

        # Command injection
        if func_name in ("system", "popen"):
            self._add(node,
                "OS command execution (AST verified)",
                FindingCategory.COMMAND_INJECTION, Severity.CRITICAL,
                "CWE-78", "A03",
                f"os.{func_name}() is dangerous. Use subprocess with argument lists.",
                "Replace os.system() with subprocess.run([...], shell=False).",
                confidence=0.9,
            )

        # eval/exec
        if func_name in ("eval", "exec"):
            self._add(node,
                f"Dangerous {func_name}() usage (AST verified)",
                FindingCategory.COMMAND_INJECTION, Severity.HIGH,
                "CWE-95", "A03",
                f"{func_name}() can execute arbitrary code if input is user-controlled.",
                "Use ast.literal_eval() for safe evaluation, or JSON.parse() for data.",
                confidence=0.85,
            )

        # pickle
        if func_name in ("loads", "load") and self._get_module_name(node) in ("pickle", "cPickle", "shelve"):
            self._add(node,
                "Insecure deserialization via pickle (AST verified)",
                FindingCategory.INSECURE_DESERIALIZATION, Severity.CRITICAL,
                "CWE-502", "A08",
                "pickle deserialization can execute arbitrary code.",
                "Use JSON for data exchange. If pickle is required, use HMAC verification.",
                confidence=0.95,
            )

        # yaml.load without safe Loader
        if func_name == "load" and self._get_module_name(node) == "yaml":
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader" and self._get_func_name(kw.value) in ("SafeLoader", "safe_load"):
                    has_safe_loader = True
            if not has_safe_loader:
                self._add(node,
                    "Unsafe YAML loading (AST verified)",
                    FindingCategory.INSECURE_DESERIALIZATION, Severity.HIGH,
                    "CWE-502", "A08",
                    "yaml.load() without SafeLoader can execute arbitrary Python code.",
                    "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                    confidence=0.9,
                )

        # requests with verify=False
        if func_name in ("get", "post", "put", "delete", "patch", "head"):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self._add(node,
                        "SSL verification disabled (AST verified)",
                        FindingCategory.CRYPTO_FAILURE, Severity.MEDIUM,
                        "CWE-295", "A02",
                        "HTTP request with verify=False disables TLS certificate validation.",
                        "Always use verify=True in production. Use certifi for custom CAs.",
                        confidence=0.95,
                    )

        self.generic_visit(node)

    def _get_func_name(self, node) -> str:
        """Extract function name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _get_module_name(self, node) -> str:
        """Get module name for a method call."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return node.func.value.id
        return ""

    def _is_string_concat(self, node) -> bool:
        """Check if a node involves string concatenation or formatting."""
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("format", "join"):
                return True
            if node.func.attr == "encode" and isinstance(node.func.value, ast.JoinedStr):
                return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):  # % formatting
            return True
        return False


class ASTEngine:
    """AST-based code analysis engine."""

    def scan_file(self, file_path: Path, language: Optional[Language] = None) -> List[Finding]:
        """Scan a file using AST analysis."""
        if language is None:
            suffix = file_path.suffix.lower()
            language = {".py": Language.PYTHON}.get(suffix, Language.UNKNOWN)

        if language == Language.PYTHON:
            return self._scan_python(file_path)
        return []  # Future: other languages via tree-sitter

    def _scan_python(self, file_path: Path) -> List[Finding]:
        """Scan a Python file using the stdlib AST module."""
        try:
            content = file_path.read_text(errors="replace")
            tree = ast.parse(content, filename=str(file_path))
            lines = content.split("\n")
            visitor = PythonASTVisitor(str(file_path), lines)
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError as e:
            logger.debug(f"Syntax error in {file_path}: {e}")
            return []
        except Exception as e:
            logger.warning(f"AST analysis failed for {file_path}: {e}")
            return []
