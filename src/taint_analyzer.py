"""
Taint Analyzer — Data-flow analysis for Python source code.

Tracks tainted data from sources (user input) through assignments
to sinks (dangerous functions). Eliminates false positives by
detecting when data passes through sanitizers.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from src.models import Finding, FindingCategory, Language, Severity

logger = logging.getLogger(__name__)

# Sources: where user-controlled data enters
TAINT_SOURCES: Dict[str, dict] = {
    "request.args.get": {"framework": "flask", "description": "URL query parameter"},
    "request.args": {"framework": "flask", "description": "URL query parameters"},
    "request.form.get": {"framework": "flask", "description": "Form data"},
    "request.form": {"framework": "flask", "description": "Form data"},
    "request.json": {"framework": "flask", "description": "JSON body"},
    "request.data": {"framework": "flask", "description": "Raw request body"},
    "request.headers.get": {"framework": "flask", "description": "HTTP headers"},
    "request.cookies.get": {"framework": "flask", "description": "Cookies"},
    "request.POST.get": {"framework": "django", "description": "POST data"},
    "request.GET.get": {"framework": "django", "description": "GET parameters"},
    "request.body": {"framework": "django", "description": "Raw body"},
    "request.META.get": {"framework": "django", "description": "Request meta"},
    "Query": {"framework": "fastapi", "description": "Query parameter"},
    "Body": {"framework": "fastapi", "description": "Request body"},
    "Path": {"framework": "fastapi", "description": "Path parameter"},
    "Header": {"framework": "fastapi", "description": "Header parameter"},
    "input": {"framework": "builtin", "description": "stdin input"},
    "sys.argv": {"framework": "builtin", "description": "Command-line arguments"},
    "os.environ.get": {"framework": "builtin", "description": "Environment variable"},
}

# Sinks: dangerous functions (matched by tail of dotted name)
TAINT_SINKS: Dict[str, dict] = {
    "execute": {
        "category": FindingCategory.INJECTION, "cwe": "CWE-89", "owasp": "A03",
        "description": "SQL query execution with tainted data",
        "remediation": "Use parameterized queries with placeholders (?, %s)",
    },
    "raw": {
        "category": FindingCategory.INJECTION, "cwe": "CWE-89", "owasp": "A03",
        "description": "Raw SQL query with tainted data",
    },
    "mogrify": {
        "category": FindingCategory.INJECTION, "cwe": "CWE-89", "owasp": "A03",
        "description": "SQL query formatting with tainted data",
    },
    "system": {
        "category": FindingCategory.COMMAND_INJECTION, "cwe": "CWE-78", "owasp": "A03",
        "description": "OS command execution with tainted data",
        "remediation": "Use subprocess.run() with argument list, never shell=True",
    },
    "popen": {
        "category": FindingCategory.COMMAND_INJECTION, "cwe": "CWE-78", "owasp": "A03",
        "description": "OS command popen with tainted data",
    },
    "eval": {
        "category": FindingCategory.COMMAND_INJECTION, "cwe": "CWE-95", "owasp": "A03",
        "description": "eval() with tainted data",
    },
    "exec": {
        "category": FindingCategory.COMMAND_INJECTION, "cwe": "CWE-95", "owasp": "A03",
        "description": "exec() with tainted data",
    },
    "render_template_string": {
        "category": FindingCategory.TEMPLATE_INJECTION, "cwe": "CWE-1336", "owasp": "A03",
        "description": "Server-side template injection via tainted template string",
    },
    "pickle.loads": {
        "category": FindingCategory.INSECURE_DESERIALIZATION, "cwe": "CWE-502", "owasp": "A08",
        "description": "pickle deserialization with tainted data",
    },
    "pickle.load": {
        "category": FindingCategory.INSECURE_DESERIALIZATION, "cwe": "CWE-502", "owasp": "A08",
        "description": "pickle deserialization with tainted data",
    },
    "yaml.load": {
        "category": FindingCategory.INSECURE_DESERIALIZATION, "cwe": "CWE-502", "owasp": "A08",
        "description": "Unsafe YAML loading with tainted data",
    },
    "open": {
        "category": FindingCategory.PATH_TRAVERSAL, "cwe": "CWE-22", "owasp": "A01",
        "description": "File open with tainted path",
        "remediation": "Validate path against allowlist, use os.path.realpath()",
    },
    "requests.get": {
        "category": FindingCategory.SSRF, "cwe": "CWE-918", "owasp": "A10",
        "description": "HTTP request to tainted URL",
        "remediation": "Validate URL against allowlist of trusted domains",
    },
    "requests.post": {
        "category": FindingCategory.SSRF, "cwe": "CWE-918", "owasp": "A10",
        "description": "HTTP POST to tainted URL",
    },
}

# Sanitizers
TAINT_SANITIZERS: Set[str] = {
    "escape", "html.escape", "markupsafe.escape", "bleach.clean",
    "urllib.parse.quote", "urllib.parse.quote_plus",
    "int", "float", "bool",
    "os.path.realpath", "os.path.abspath",
    "secure_filename", "werkzeug.utils.secure_filename",
    "json.loads", "json.dumps",
    "yaml.safe_load",
    "jwt.decode", "hmac.compare_digest",
}

# Suppression pattern
SUPPRESS_PATTERN = re.compile(
    r"#\s*code-audit\s*:\s*ignore\[([^^\]]+)\](?:\s*--\s*(.*))?",
    re.IGNORECASE,
)


@dataclass
class SuppressedRule:
    rule_id: str
    reason: str = ""
    line_number: int = 0


def parse_suppressions(source: str) -> Dict[int, List[SuppressedRule]]:
    """Parse suppression comments from source code."""
    suppressions: Dict[int, List[SuppressedRule]] = {}
    lines = source.split("\n")
    for i, line in enumerate(lines, 1):
        for match in SUPPRESS_PATTERN.finditer(line):
            rules_str = match.group(1).strip()
            reason = (match.group(2) or "").strip()
            if rules_str.lower() == "all":
                suppressions.setdefault(i, []).append(
                    SuppressedRule(rule_id="ALL", reason=reason, line_number=i)
                )
            else:
                for rule_id in rules_str.split(","):
                    rule_id = rule_id.strip()
                    if rule_id:
                        suppressions.setdefault(i, []).append(
                            SuppressedRule(rule_id=rule_id, reason=reason, line_number=i)
                        )
    return suppressions


def is_suppressed(rule_id: str, line: int, suppressions: Dict[int, List[SuppressedRule]]) -> bool:
    """Check if a finding at a given line is suppressed."""
    line_suppressions = suppressions.get(line, [])
    return any(s.rule_id == rule_id or s.rule_id == "ALL" for s in line_suppressions)


@dataclass
class TaintState:
    tainted_vars: Dict[str, str] = field(default_factory=dict)
    sanitized_vars: Set[str] = field(default_factory=set)
    findings: List[Finding] = field(default_factory=list)
    file_path: str = ""
    lines: List[str] = field(default_factory=list)
    suppressions: Dict[int, List[SuppressedRule]] = field(default_factory=dict)


class TaintVisitor(ast.NodeVisitor):
    """AST visitor that tracks taint propagation."""

    def __init__(self, state: TaintState):
        self.state = state

    def _get_full_attr(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._get_full_attr(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            return self._get_full_attr(node.func)
        return ""

    def _is_tainted_source(self, node: ast.AST) -> Optional[str]:
        """Check if a node is a known taint source."""
        full_name = self._get_full_attr(node)
        # Exact match
        if full_name in TAINT_SOURCES:
            return TAINT_SOURCES[full_name]["description"]
        # Tail match (e.g. "args.get" from "request.args.get")
        parts = full_name.split(".")
        for length in range(2, len(parts) + 1):
            tail = ".".join(parts[-length:])
            if tail in TAINT_SOURCES:
                return TAINT_SOURCES[tail]["description"]
        return None

    def _get_sink_info(self, func_name: str) -> Optional[dict]:
        """Get sink info by matching tail of function name."""
        # Exact match first
        if func_name in TAINT_SINKS:
            return TAINT_SINKS[func_name]
        # Tail match: "conn.execute" -> "execute", "os.system" -> "system"
        parts = func_name.split(".")
        for length in range(1, min(len(parts) + 1, 4)):
            tail = ".".join(parts[-length:])
            if tail in TAINT_SINKS:
                return TAINT_SINKS[tail]
        return None

    def _is_sanitizer_call(self, node: ast.AST) -> bool:
        full_name = self._get_full_attr(node)
        if full_name in TAINT_SANITIZERS:
            return True
        parts = full_name.split(".")
        for length in range(1, min(len(parts) + 1, 3)):
            if ".".join(parts[-length:]) in TAINT_SANITIZERS:
                return True
        return False

    def _snippet(self, line: int, context: int = 2) -> str:
        start = max(0, line - 1 - context)
        end = min(len(self.state.lines), line + context)
        return "\n".join(
            f">>> {i+1:4d} | {self.state.lines[i].rstrip()}" if i == line - 1
            else f"    {i+1:4d} | {self.state.lines[i].rstrip()}"
            for i in range(start, end)
        )

    def _add_finding(self, line: int, sink_name: str, source_desc: str,
                     sink_info: dict) -> None:
        rule_id = f"TAINT-{sink_info['cwe'][-3:]}"
        if is_suppressed(rule_id, line, self.state.suppressions):
            return
        if is_suppressed("ALL", line, self.state.suppressions):
            return

        self.state.findings.append(Finding(
            rule_id=rule_id,
            title=f"Tainted data reaches {sink_name} (data-flow verified)",
            category=sink_info["category"],
            severity=Severity.CRITICAL,
            confidence=0.95,
            file_path=self.state.file_path,
            line_number=line,
            code_snippet=self._snippet(line),
            language=Language.PYTHON,
            cwe_id=sink_info["cwe"],
            owasp_id=sink_info["owasp"],
            description=(
                f"User-controlled data from '{source_desc}' flows into "
                f"'{sink_name}' without sanitization. {sink_info['description']}"
            ),
            remediation=sink_info.get("remediation", "Validate and sanitize all user input"),
            tags=["taint-analysis", "data-flow", sink_info["owasp"]],
        ))

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track taint through assignments."""
        rhs_tainted = False
        source_desc = ""

        if isinstance(node.value, ast.Call):
            source_desc = self._is_tainted_source(node.value) or ""
            if source_desc:
                rhs_tainted = True
                if self._is_sanitizer_call(node.value):
                    rhs_tainted = False

        elif isinstance(node.value, ast.Name):
            if node.value.id in self.state.tainted_vars:
                rhs_tainted = True
                source_desc = self.state.tainted_vars[node.value.id]
                if node.value.id in self.state.sanitized_vars:
                    rhs_tainted = False

        elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
            if self._has_tainted_binop(node.value):
                rhs_tainted = True
                source_desc = "string concatenation with tainted data"

        elif isinstance(node.value, ast.JoinedStr):
            if self._has_tainted_joinedstr(node.value):
                rhs_tainted = True
                source_desc = "f-string with tainted data"

        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
            if node.value.func.attr == "format" and node.value.args:
                if any(self._is_var_tainted(a) for a in node.value.args):
                    rhs_tainted = True
                    source_desc = "string format with tainted data"

        for target in node.targets:
            if isinstance(target, ast.Name):
                if rhs_tainted:
                    self.state.tainted_vars[target.id] = source_desc
                    self.state.sanitized_vars.discard(target.id)
                else:
                    self.state.tainted_vars.pop(target.id, None)
                    self.state.sanitized_vars.discard(target.id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check if tainted data reaches a sink."""
        func_name = self._get_full_attr(node.func)
        sink_info = self._get_sink_info(func_name)

        if sink_info and node.args:
            first_arg = node.args[0]
            if self._is_var_tainted(first_arg):
                self._add_finding(
                    getattr(node, "lineno", 0),
                    func_name,
                    self._get_taint_source(first_arg),
                    sink_info,
                )

        self.generic_visit(node)

    def _is_var_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return (node.id in self.state.tainted_vars
                    and node.id not in self.state.sanitized_vars)
        if isinstance(node, ast.JoinedStr):
            return self._has_tainted_joinedstr(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._has_tainted_binop(node)
        if isinstance(node, ast.Call):
            return bool(self._is_tainted_source(node))
        return False

    def _get_taint_source(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.state.tainted_vars.get(node.id, "unknown source")
        if isinstance(node, ast.Call):
            return self._is_tainted_source(node) or "function call"
        return "unknown"

    def _has_tainted_binop(self, node: ast.BinOp) -> bool:
        return self._is_var_tainted(node.left) or self._is_var_tainted(node.right)

    def _has_tainted_joinedstr(self, node: ast.JoinedStr) -> bool:
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if self._is_var_tainted(value.value):
                    return True
        return False


class TaintAnalyzer:
    """Performs taint analysis on Python source files."""

    def scan_file(self, file_path: Path) -> List[Finding]:
        try:
            source = file_path.read_text(errors="replace")
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, Exception) as e:
            logger.debug(f"Taint analysis skipped for {file_path}: {e}")
            return []

        lines = source.split("\n")
        suppressions = parse_suppressions(source)
        all_findings: List[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                state = TaintState(
                    file_path=str(file_path),
                    lines=lines,
                    suppressions=suppressions,
                )
                visitor = TaintVisitor(state)
                visitor.visit(node)
                all_findings.extend(state.findings)

        return all_findings

    def scan_files(self, file_paths: List[Path]) -> List[Finding]:
        all_findings: List[Finding] = []
        for fp in file_paths:
            if fp.suffix == ".py":
                all_findings.extend(self.scan_file(fp))
        return all_findings
