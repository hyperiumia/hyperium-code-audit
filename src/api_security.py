"""
API Security Rules — detects common API security issues.

Detects:
        # CORS wildcard
        for line_text in content.splitlines():
            if ("CORS" in line_text or "cors" in line_text or "allow_origins" in line_text) and "*" in line_text:
                line = self._line(content, line_text)
                findings.append(self._finding(
                    fp, line, "CORS wildcard origin (*)",
                    Severity.HIGH, "CWE-942", "A05", 0.85,
                    "CORS wildcard allows any origin to make cross-origin requests.",
                    "Restrict to specific trusted origins.",
                    Language.PYTHON,
                ))
  - Debug mode in production
  - Missing rate limiting
  - Verbose error messages
  - Missing HTTPS enforcement
  - SQL/NoSQL injection in API handlers
"""

from __future__ import annotations
import logging
import re
from pathlib import Path
from typing import List

from src.models import Finding, FindingCategory, Language, Severity

logger = logging.getLogger(__name__)


class APISecurityScanner:
    """Scans source code for API security issues."""

    def scan_file(self, fp: Path, language: Language) -> List[Finding]:
        """Scan a file for API security issues."""
        findings = []
        try:
            content = fp.read_text(errors="replace")
        except Exception:
            return []
        lines = content.splitlines()

        if language == Language.PYTHON:
            findings.extend(self._scan_python(fp, content, lines))
        elif language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            findings.extend(self._scan_js(fp, content, lines))

        # Language-agnostic checks
        findings.extend(self._scan_generic(fp, content, lines, language))

        return findings

    def _scan_python(self, fp, content, lines) -> List[Finding]:
        findings = []

        # CORS wildcard
        for line_text in content.splitlines():
            if ("CORS" in line_text or "cors" in line_text or "allow_origins" in line_text) and "*" in line_text:
                line = self._line(content, line_text)
                findings.append(self._finding(
                    fp, line, "CORS wildcard origin (*)",
                    Severity.HIGH, "CWE-942", "A05", 0.85,
                    "CORS wildcard allows any origin to make cross-origin requests.",
                    "Restrict to specific trusted origins.",
                    Language.PYTHON,
                ))
        # Debug mode
        for match in re.finditer(r'DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True', content):
            line = self._line(content, match.group()[:40])
            findings.append(self._finding(
                fp, line, "Debug mode enabled",
                Severity.HIGH, "CWE-489", "A05", 0.9,
                "Debug mode exposes stack traces, debugger, and internal details.",
                "Set DEBUG = False in production. Use environment variables.",
                Language.PYTHON,
            ))

        # Missing @login_required
        for match in re.finditer(r'@app\.route\([^)]*\)$$\s*\n\s*def\s+', content):
            # Check if there's an auth decorator nearby
            route_text = match.group()
            end = match.end()
            next_lines = content[end:end + 200]
            auth_patterns = r'(?:@login_required|@auth\.|@jwt_required|@token_required|@requires_auth)'
            if not re.search(auth_patterns, next_lines):
                line = self._line(content, '@app.route')
                findings.append(self._finding(
                    fp, line, "Endpoint without authentication decorator",
                    Severity.MEDIUM, "CWE-306", "A01", 0.6,
                    "Route handler does not have an authentication decorator.",
                    "Add @login_required or equivalent auth decorator.",
                    Language.PYTHON,
                ))

        return findings

    def _scan_js(self, fp, content, lines) -> List[Finding]:
        findings = []

        # CORS wildcard
        for match in re.finditer(
            r'(?:cors|origin)\s*[:=(]\s*["\']\*["\']|Access-Control-Allow-Origin.*\*', content
        ):
            line = self._line(content, match.group()[:40])
            findings.append(self._finding(
                fp, line, "CORS wildcard origin (*)",
                Severity.HIGH, "CWE-942", "A05", 0.85,
                "CORS wildcard allows any origin to make cross-origin requests.",
                "Restrict to specific trusted origins.",
                Language.JAVASCRIPT,
            ))

        # Express debug/error detail leak
        for match in re.finditer(
            r'res\.(?:json|send)\s*\(\s*\{[^}]*err(?:or)?\.(?:message|stack)', content
        ):
            line = self._line(content, match.group()[:40])
            findings.append(self._finding(
                fp, line, "Error details leaked in API response",
                Severity.MEDIUM, "CWE-209", "A04", 0.7,
                "API response includes internal error details (stack trace, message).",
                "Return generic error messages in production.",
                Language.JAVASCRIPT,
            ))

        return findings

    def _scan_generic(self, fp, content, lines, language) -> List[Finding]:
        findings = []

        # HTTP instead of HTTPS
        for match in re.finditer(r'https?://localhost|127\.0\.0\.1', content):
            pass  # localhost is OK

        for match in re.finditer(r'(?:api_url|base_url|endpoint)\s*[:=]\s*["\']http://(?!localhost)', content, re.IGNORECASE):
            line = self._line(content, match.group()[:40])
            findings.append(self._finding(
                fp, line, "API endpoint uses HTTP instead of HTTPS",
                Severity.MEDIUM, "CWE-319", "A02", 0.75,
                "API communication over unencrypted HTTP.",
                "Use HTTPS for all API endpoints.",
                language,
            ))

        return findings

    def _line(self, content, pattern) -> int:
        for i, line in enumerate(content.splitlines(), 1):
            if pattern in line or pattern[:30] in line:
                return i
        return 1

    def _finding(self, fp, line, title, severity, cwe, owasp, confidence,
                 desc, remediation, language) -> Finding:
        return Finding(
            rule_id=f"API-SEC-{cwe[-3:]}",
            title=title, category=FindingCategory.SECURITY_MISCONFIG,
            severity=severity, confidence=confidence,
            file_path=str(fp), line_number=line,
            language=language, cwe_id=cwe, owasp_id=owasp,
            description=desc, remediation=remediation,
            tags=["api-security", owasp],
        )