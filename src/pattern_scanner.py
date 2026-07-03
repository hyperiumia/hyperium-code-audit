"""
OWASP Top 10 Pattern Scanner.

Detects security vulnerabilities via regex pattern matching
across multiple programming languages. Each rule maps to:
  - OWASP Top 10 category
  - CWE identifier
  - CVSS-based severity
  - Specific remediation guidance

Rule format:
  RULES[language] = [
    {"id": "...", "pattern": r"...", "title": "...", ...},
  ]
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.models import (
    Finding, FindingCategory, Language, Severity,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# RULE DEFINITIONS
# ═══════════════════════════════════════════════════════════════

@dataclass
class ScanRule:
    """A single vulnerability detection rule."""
    id: str
    title: str
    category: FindingCategory
    severity: Severity
    cwe_id: str
    owasp_id: str
    languages: List[Language]
    pattern: str
    description: str
    remediation: str
    impact: str = ""
    confidence: float = 0.8
    references: List[str] = field(default_factory=list)
    false_positive_hints: List[str] = field(default_factory=list)
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        try:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            logger.warning(f"Invalid regex in rule {self.id}: {e}")
            self._compiled = None


# ─────────────────────────────────────────────────────────────
# INJECTION RULES (A03)
# ─────────────────────────────────────────────────────────────

SQL_INJECTION_RULES = [
    ScanRule(
        id="GEN-SEC-001",
        title="SQL Injection via string concatenation",
        category=FindingCategory.INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-89",
        owasp_id="A03",
        languages=[Language.PYTHON, Language.JAVA, Language.CSHARP, Language.RUBY],
        pattern=r"""(?:execute|query|raw|cursor\.execute)\s*\(\s*(?:f['""]|['""].*%s|['""].*\+|['""].*\.format)""",
        description="SQL query constructed via string concatenation, f-string, or format(). "
                    "An attacker can inject arbitrary SQL by manipulating the concatenated values.",
        remediation="Use parameterized queries or prepared statements. "
                    "Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        impact="Full database compromise: data exfiltration, modification, or deletion.",
        confidence=0.85,
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
    ),
    ScanRule(
        id="GEN-SEC-002",
        title="SQL Injection in JavaScript/Node.js",
        category=FindingCategory.INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-89",
        owasp_id="A03",
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        pattern=r"""(?:query|execute|raw)\s*\(\s*['""`].*(?:\$\{|['"]\s*\+|\.concat)""",
        description="SQL query built with template literal interpolation or string concatenation.",
        remediation="Use parameterized queries: connection.query('SELECT * FROM users WHERE id = ?', [userId])",
        impact="Full database compromise.",
        confidence=0.8,
    ),
    ScanRule(
        id="GEN-SEC-003",
        title="SQL Injection in PHP",
        category=FindingCategory.INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-89",
        owasp_id="A03",
        languages=[Language.PHP],
        pattern=r"""(?:mysql_query|mysqli_query|pg_query|->query)\s*\(\s*['""].*(?:\$_(?:GET|POST|REQUEST|COOKIE)|['"]\s*\.)""",
        description="SQL query built with user input from superglobals.",
        remediation="Use PDO with prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');",
        impact="Full database compromise.",
        confidence=0.85,
    ),
]

COMMAND_INJECTION_RULES = [
    ScanRule(
        id="GEN-SEC-010",
        title="OS Command Injection (Python)",
        category=FindingCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-78",
        owasp_id="A03",
        languages=[Language.PYTHON],
        pattern=r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(\s*(?:f['""]|['""].*\+|['""].*\.format|[^,)]*\b(?:input|request|param|argv|user))""",
        description="OS command constructed with user-controlled input.",
        remediation="Use subprocess with a list of arguments, never shell=True with user input. "
                    "Validate and sanitize all inputs before passing to subprocess.",
        impact="Remote Code Execution (RCE).",
        confidence=0.8,
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
    ),
    ScanRule(
        id="GEN-SEC-011",
        title="OS Command Injection (JavaScript/Node.js)",
        category=FindingCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-78",
        owasp_id="A03",
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        pattern=r"""(?:child_process\.exec|execSync|spawn)\s*\(\s*(?:`.*\$\{|['"]\s*\+)""",
        description="OS command constructed with template literal or string concatenation.",
        remediation="Use execFile with argument arrays. Never interpolate user input into shell commands.",
        impact="Remote Code Execution.",
        confidence=0.8,
    ),
    ScanRule(
        id="GEN-SEC-012",
        title="Dangerous eval() usage",
        category=FindingCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-95",
        owasp_id="A03",
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT, Language.PHP, Language.RUBY],
        pattern=r"""(?:eval|exec)\s*\([^)]*(?:request|input|param|args|user|variable|data|body|query)""",
        description="eval() or exec() called with potentially user-controlled input.",
        remediation="Never use eval/exec with untrusted input. Use ast.literal_eval() for Python, "
                    "or JSON.parse() for JavaScript.",
        impact="Arbitrary code execution.",
        confidence=0.75,
    ),
]

XSS_RULES = [
    ScanRule(
        id="GEN-SEC-020",
        title="DOM-based XSS via innerHTML",
        category=FindingCategory.XSS,
        severity=Severity.HIGH,
        cwe_id="CWE-79",
        owasp_id="A03",
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        pattern=r"""\.innerHTML\s*=\s*(?!['""][^'""]*['""])""",
        description="innerHTML assigned with dynamic content. If the content includes user input, "
                    "this enables Cross-Site Scripting (XSS).",
        remediation="Use textContent instead of innerHTML, or sanitize with DOMPurify. "
                    "For React, use dangerouslySetInnerHTML only with sanitized content.",
        impact="Session hijacking, credential theft, malware distribution.",
        confidence=0.7,
        references=["https://owasp.org/www-community/attacks/xss/"],
    ),
    ScanRule(
        id="GEN-SEC-021",
        title="document.write() XSS",
        category=FindingCategory.XSS,
        severity=Severity.HIGH,
        cwe_id="CWE-79",
        owasp_id="A03",
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        pattern=r"""document\.write\s*\(""",
        description="document.write() can introduce XSS if content includes user-controlled data.",
        remediation="Use DOM manipulation methods (createElement, textContent) instead of document.write().",
        impact="Cross-Site Scripting.",
        confidence=0.6,
    ),
    ScanRule(
        id="GEN-SEC-022",
        title="Server-Side Template Injection (SSTI)",
        category=FindingCategory.TEMPLATE_INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-1336",
        owasp_id="A03",
        languages=[Language.PYTHON, Language.JAVA, Language.RUBY],
        pattern=r"""(?:render_template_string|Template\(|render_string)\s*\(\s*(?:request\.|args|form|user|f['""])""",
        description="Template engine renders user-controlled input as a template string.",
        remediation="Never pass user input as a template string. Use template files and pass user data as context variables.",
        impact="Remote Code Execution via template injection.",
        confidence=0.8,
    ),
    ScanRule(
        id="GEN-SEC-023",
        title="Jinja2 autoescape disabled",
        category=FindingCategory.XSS,
        severity=Severity.HIGH,
        cwe_id="CWE-79",
        owasp_id="A03",
        languages=[Language.PYTHON],
        pattern=r"""Environment\s*\(.*autoescape\s*=\s*False""",
        description="Jinja2 environment with autoescape disabled. HTML entities are not escaped.",
        remediation="Enable autoescape: Environment(autoescape=True) or use Markup() for trusted HTML.",
        impact="Cross-Site Scripting.",
        confidence=0.9,
    ),
]

# ─────────────────────────────────────────────────────────────
# CRYPTO RULES (A02)
# ─────────────────────────────────────────────────────────────

CRYPTO_RULES = [
    ScanRule(
        id="GEN-SEC-030",
        title="Weak hash function (MD5/SHA1) for passwords",
        category=FindingCategory.CRYPTO_FAILURE,
        severity=Severity.HIGH,
        cwe_id="CWE-328",
        owasp_id="A02",
        languages=[Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.PHP, Language.CSHARP, Language.RUBY, Language.GO],
        pattern=r"""(?:hashlib\.(?:md5|sha1)|MD5\.|SHA1\.|createHash\(['""](?:md5|sha1)|MessageDigest\.getInstance\(['""](?:MD5|SHA1))""",
        description="Weak hash algorithm (MD5 or SHA1) used. These are cryptographically broken.",
        remediation="For passwords: use bcrypt, argon2, or scrypt. For integrity: use SHA-256 or SHA-3.",
        impact="Password hashes can be cracked in seconds with rainbow tables or GPU brute-force.",
        confidence=0.9,
    ),
    ScanRule(
        id="GEN-SEC-031",
        title="Hardcoded encryption key",
        category=FindingCategory.CRYPTO_FAILURE,
        severity=Severity.HIGH,
        cwe_id="CWE-321",
        owasp_id="A02",
        languages=[Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.PHP, Language.CSHARP, Language.GO],
        pattern=r"""(?:key|secret|iv|salt)\s*=\s*['""][A-Za-z0-9+/=]{16,}['""]""",
        description="Encryption key or IV hardcoded in source code.",
        remediation="Store keys in environment variables or a secrets manager (AWS KMS, HashiCorp Vault).",
        impact="Encryption can be trivially reversed if key is exposed.",
        confidence=0.7,
    ),
    ScanRule(
        id="GEN-SEC-032",
        title="Insecure SSL/TLS verification disabled",
        category=FindingCategory.CRYPTO_FAILURE,
        severity=Severity.MEDIUM,
        cwe_id="CWE-295",
        owasp_id="A02",
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.JAVA],
        pattern=r"""(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|SSLContext.*CERT_NONE|InsecureRequestWarning)""",
        description="SSL/TLS certificate verification is disabled.",
        remediation="Always verify SSL certificates. For testing, use a proper test CA, not verify=False.",
        impact="Man-in-the-Middle attacks can intercept encrypted communications.",
        confidence=0.9,
    ),
]

# ─────────────────────────────────────────────────────────────
# SSRF RULES (A10)
# ─────────────────────────────────────────────────────────────

SSRF_RULES = [
    ScanRule(
        id="GEN-SEC-040",
        title="Server-Side Request Forgery (SSRF)",
        category=FindingCategory.SSRF,
        severity=Severity.HIGH,
        cwe_id="CWE-918",
        owasp_id="A10",
        languages=[Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.PHP, Language.GO],
        pattern=r"""(?:requests\.(?:get|post|put|delete|patch|head)|fetch\(|urllib\.request\.urlopen|http\.get|httpClient)\s*\(\s*(?:request\.|args|params|user|input|variable|f['""])""",
        description="HTTP request made to a URL that includes user-controlled input.",
        remediation="Validate and allowlist URLs. Block requests to internal/private IP ranges. "
                    "Use a URL parser to validate scheme, host, and port.",
        impact="Access to internal services, cloud metadata endpoints (169.254.169.254), port scanning.",
        confidence=0.7,
        references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    ),
]

# ─────────────────────────────────────────────────────────────
# PATH TRAVERSAL RULES (A01)
# ─────────────────────────────────────────────────────────────

PATH_TRAVERSAL_RULES = [
    ScanRule(
        id="GEN-SEC-050",
        title="Path Traversal in file operations",
        category=FindingCategory.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        cwe_id="CWE-22",
        owasp_id="A01",
        languages=[Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.PHP, Language.GO],
        pattern=r"""(?:open\(|readFile|readFileSync|fs\.read|file_get_contents|fopen|File\.open)\s*\(.*(?:request\.|args|params|user|input|filename|path_var)""",
        description="File path constructed with user-controlled input without validation.",
        remediation="Validate paths against an allowlist of permitted directories. "
                    "Use os.path.realpath() and verify the resolved path starts with the allowed base directory.",
        impact="Read arbitrary files on the server (/etc/passwd, application source, credentials).",
        confidence=0.7,
    ),
]

# ─────────────────────────────────────────────────────────────
# AUTH RULES (A07)
# ─────────────────────────────────────────────────────────────

AUTH_RULES = [
    ScanRule(
        id="GEN-SEC-060",
        title="Plaintext password storage",
        category=FindingCategory.BROKEN_AUTH,
        severity=Severity.CRITICAL,
        cwe_id="CWE-256",
        owasp_id="A07",
        languages=[Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.PHP, Language.CSHARP, Language.GO],
        pattern=r"""(?:password|passwd|pwd)\s*=\s*['""][^'""]{3,}['""]""",
        description="Password stored as plaintext in source code.",
        remediation="Never store passwords in code. Use environment variables and hash with bcrypt/argon2.",
        impact="Credential compromise if source code is exposed.",
        confidence=0.6,
        false_positive_hints=["May match documentation, test fixtures, or password validation strings"],
    ),
    ScanRule(
        id="GEN-SEC-061",
        title="Default/debug credentials",
        category=FindingCategory.SECURITY_MISCONFIG,
        severity=Severity.HIGH,
        cwe_id="CWE-798",
        owasp_id="A05",
        languages=[Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.PHP, Language.PYTHON],
        pattern=r"""(?:admin|root|test|debug|default)\s*[:=]\s*['""](?:admin|root|test|password|123456|default)['""]""",
        description="Default or debug credentials found in code.",
        remediation="Remove all default credentials. Use unique, randomly generated credentials.",
        impact="Unauthorized access with well-known credentials.",
        confidence=0.7,
    ),
]

# ─────────────────────────────────────────────────────────────
# INSECURE DESERIALIZATION (A08)
# ─────────────────────────────────────────────────────────────

DESERIALIZATION_RULES = [
    ScanRule(
        id="GEN-SEC-070",
        title="Insecure deserialization (Python pickle)",
        category=FindingCategory.INSECURE_DESERIALIZATION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-502",
        owasp_id="A08",
        languages=[Language.PYTHON],
        pattern=r"""(?:pickle\.loads|pickle\.load|cPickle\.loads|shelve\.open|yaml\.load)\s*\((?!.*Loader)""",
        description="Insecure deserialization via pickle or unsafe YAML loading.",
        remediation="Never deserialize untrusted data with pickle. Use JSON for data exchange. "
                    "For YAML, use yaml.safe_load().",
        impact="Remote Code Execution — pickle deserialization can execute arbitrary code.",
        confidence=0.85,
    ),
    ScanRule(
        id="GEN-SEC-071",
        title="Insecure deserialization (Java ObjectInputStream)",
        category=FindingCategory.INSECURE_DESERIALIZATION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-502",
        owasp_id="A08",
        languages=[Language.JAVA],
        pattern=r"""ObjectInputStream\s*\(""",
        description="Java native deserialization from ObjectInputStream is vulnerable to RCE.",
        remediation="Use JSON or XML deserialization with strict type validation.",
        impact="Remote Code Execution via gadget chains.",
        confidence=0.8,
    ),
]

# ─────────────────────────────────────────────────────────────
# OPEN REDIRECT (A01)
# ─────────────────────────────────────────────────────────────

REDIRECT_RULES = [
    ScanRule(
        id="GEN-SEC-080",
        title="Open Redirect",
        category=FindingCategory.OPEN_REDIRECT,
        severity=Severity.MEDIUM,
        cwe_id="CWE-601",
        owasp_id="A01",
        languages=[Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.PHP],
        pattern=r"""(?:redirect|Redirect|window\.location|Response\.Redirect)\s*\(\s*(?:request\.|args|params|user|query)""",
        description="Redirect target controlled by user input.",
        remediation="Validate redirect targets against an allowlist of trusted domains.",
        impact="Phishing attacks via trusted domain redirect.",
        confidence=0.7,
    ),
]

# ─────────────────────────────────────────────────────────────
# INFO DISCLOSURE (A01)
# ─────────────────────────────────────────────────────────────

INFO_DISCLOSURE_RULES = [
    ScanRule(
        id="GEN-SEC-090",
        title="Debug mode enabled in production",
        category=FindingCategory.SECURITY_MISCONFIG,
        severity=Severity.MEDIUM,
        cwe_id="CWE-489",
        owasp_id="A05",
        languages=[Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.PHP],
        pattern=r"""(?:DEBUG\s*=\s*True|debug\s*:\s*true|app\.debug\s*=\s*True|NODE_ENV.*development)""",
        description="Debug mode is enabled, which may expose stack traces and sensitive info.",
        remediation="Ensure DEBUG=False in production. Use environment variables to control debug mode.",
        impact="Information disclosure: stack traces, database queries, internal paths.",
        confidence=0.8,
    ),
    ScanRule(
        id="GEN-SEC-091",
        title="Stack trace / exception exposure",
        category=FindingCategory.LOGGING_FAILURE,
        severity=Severity.LOW,
        cwe_id="CWE-209",
        owasp_id="A09",
        languages=[Language.PYTHON, Language.JAVA, Language.JAVASCRIPT],
        pattern=r"""(?:traceback\.print_exc|print\(.*exception|console\.log\(.*err|\.stack\b)""",
        description="Exception details logged or printed, may expose internal information.",
        remediation="Log errors to a secure logging system. Never expose stack traces to users.",
        impact="Information disclosure aiding further attacks.",
        confidence=0.5,
    ),
]


# ═══════════════════════════════════════════════════════════════
# ALL RULES COMBINED
# ═══════════════════════════════════════════════════════════════

ALL_RULES: List[ScanRule] = (
    SQL_INJECTION_RULES
    + COMMAND_INJECTION_RULES
    + XSS_RULES
    + CRYPTO_RULES
    + SSRF_RULES
    + PATH_TRAVERSAL_RULES
    + AUTH_RULES
    + DESERIALIZATION_RULES
    + REDIRECT_RULES
    + INFO_DISCLOSURE_RULES
)


# ═══════════════════════════════════════════════════════════════
# EXTENSION → LANGUAGE MAPPING
# ═══════════════════════════════════════════════════════════════

EXTENSION_MAP: Dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".php": Language.PHP,
    ".java": Language.JAVA,
    ".go": Language.GO,
    ".cs": Language.CSHARP,
    ".rb": Language.RUBY,
    ".html": Language.HTML,
    ".htm": Language.HTML,
    ".vue": Language.HTML,
    ".ejs": Language.HTML,
    ".hbs": Language.HTML,
}


def detect_language(file_path: Path) -> Language:
    """Detect programming language from file extension."""
    return EXTENSION_MAP.get(file_path.suffix.lower(), Language.UNKNOWN)


def get_code_snippet(lines: List[str], line_number: int, context: int = 2) -> str:
    """Extract a code snippet around the finding location."""
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    snippet_lines = []
    for i in range(start, end):
        marker = ">>>" if i == line_number - 1 else "   "
        snippet_lines.append(f"{marker} {i+1:4d} | {lines[i].rstrip()}")
    return "\n".join(snippet_lines)


class PatternScanner:
    """Scans source files for vulnerability patterns."""

    def __init__(
        self,
        rules: Optional[List[ScanRule]] = None,
        min_confidence: float = 0.5,
        exclude_rules: Optional[List[str]] = None,
    ):
        self.rules = rules or ALL_RULES
        self.min_confidence = min_confidence
        self.exclude_rules = set(exclude_rules or [])
        self._rules_by_lang: Dict[Language, List[ScanRule]] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Index rules by language for fast lookup."""
        for rule in self.rules:
            if rule.id in self.exclude_rules:
                continue
            if rule.confidence < self.min_confidence:
                continue
            for lang in rule.languages:
                if lang not in self._rules_by_lang:
                    self._rules_by_lang[lang] = []
                self._rules_by_lang[lang].append(rule)

    def scan_file(self, file_path: Path, language: Optional[Language] = None) -> List[Finding]:
        """Scan a single file for vulnerability patterns."""
        if language is None:
            language = detect_language(file_path)

        if language == Language.UNKNOWN:
            return []

        applicable_rules = self._rules_by_lang.get(language, [])
        if not applicable_rules:
            return []

        try:
            content = file_path.read_text(errors="replace")
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return []

        lines = content.split("\n")
        findings: List[Finding] = []
        seen: set = set()  # Deduplicate same rule at same line

        for rule in applicable_rules:
            if rule._compiled is None:
                continue
            try:
                for match in rule._compiled.finditer(content):
                    line_number = content[:match.start()].count("\n") + 1
                    dedup_key = (rule.id, file_path, line_number)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    snippet = get_code_snippet(lines, line_number)
                    finding = Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        file_path=str(file_path),
                        line_number=line_number,
                        code_snippet=snippet,
                        language=language,
                        cwe_id=rule.cwe_id,
                        owasp_id=rule.owasp_id,
                        description=rule.description,
                        remediation=rule.remediation,
                        impact=rule.impact,
                        references=rule.references,
                        tags=[rule.category.value, rule.owasp_id],
                    )
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Error applying rule {rule.id} to {file_path}: {e}")

        return findings

    def scan_files(self, file_paths: List[Path]) -> List[Finding]:
        """Scan multiple files."""
        all_findings: List[Finding] = []
        for fp in file_paths:
            all_findings.extend(self.scan_file(fp))
        return all_findings

    @property
    def rule_count(self) -> int:
        return len(self.rules)
