"""
Infrastructure as Code Scanner — detects misconfigurations in
Dockerfiles, Terraform, and Kubernetes manifests.

No external dependencies. Pure regex pattern matching on IaC files.
"""

from __future__ import annotations
import logging
import re
from pathlib import Path
from typing import Dict, List

from src.models import Finding, FindingCategory, Language, Severity

logger = logging.getLogger(__name__)


class IaCScanner:
    """Scans IaC files for security misconfigurations."""

    def scan_files(self, files: List[Path]) -> List[Finding]:
        """Scan a list of files for IaC issues."""
        findings: List[Finding] = []
        for fp in files:
            suffix = fp.suffix.lower()
            name = fp.name.lower()
            if name == "dockerfile" or name.endswith(".dockerfile") or suffix == ".dockerfile":
                findings.extend(self._scan_dockerfile(fp))
            elif suffix == ".tf":
                findings.extend(self._scan_terraform(fp))
            elif suffix in (".yaml", ".yml") and self._is_k8s_manifest(fp):
                findings.extend(self._scan_k8s(fp))
        return findings

    # ── Dockerfile Rules ──

    def _scan_dockerfile(self, fp: Path) -> List[Finding]:
        findings = []
        try:
            lines = fp.read_text(errors="replace").splitlines()
        except Exception:
            return []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Rule: root user
            if re.match(r"^USER\s+root\s*$", stripped, re.IGNORECASE):
                findings.append(self._finding(
                    fp, i, "Container runs as root",
                    Severity.HIGH, "CWE-250", "A05", 0.85,
                    "Container is configured to run as root user.",
                    "Use a non-root user: USER appuser",
                    Language.DOCKERFILE,
                ))

            # Rule: ADD instead of COPY
            if re.match(r"^ADD\s+", stripped, re.IGNORECASE):
                if not re.search(r"https?://", stripped) and not stripped.endswith(".tar"):
                    findings.append(self._finding(
                        fp, i, "Use COPY instead of ADD",
                        Severity.LOW, "CWE-16", "A05", 0.8,
                        "ADD has implicit behaviors (URL fetching, tar extraction) that may be unexpected.",
                        "Use COPY unless you specifically need ADD's features.",
                        Language.DOCKERFILE,
                    ))

            # Rule: latest tag
            if re.match(r"^FROM\s+\S+:latest\s*$", stripped, re.IGNORECASE) or \
               re.match(r"^FROM\s+\S+\s*$", stripped, re.IGNORECASE) and \
               not re.search(r":\S+", stripped.split()[1] if len(stripped.split()) > 1 else ""):
                if re.match(r"^FROM\s+", stripped, re.IGNORECASE):
                    findings.append(self._finding(
                        fp, i, "Docker image uses :latest or no tag",
                        Severity.MEDIUM, "CWE-1104", "A05", 0.75,
                        "Using :latest or no tag means builds are not reproducible.",
                        "Pin to a specific version: FROM node:20-alpine",
                        Language.DOCKERFILE,
                    ))

            # Rule: secrets in ENV
            if re.match(r"^ENV\s+", stripped, re.IGNORECASE):
                env_match = re.search(r"ENV\s+(\w+)", stripped, re.IGNORECASE)
                if env_match:
                    key = env_match.group(1).upper()
                    secret_keywords = ("PASSWORD", "SECRET", "TOKEN", "KEY", "APIKEY", "API_KEY", "CREDENTIALS", "PRIVATE")
                    if any(sk in key for sk in secret_keywords):
                        if not re.search(r"\$\{.*\}", stripped):
                            findings.append(self._finding(
                                fp, i, "Secret hardcoded in ENV",
                                Severity.CRITICAL, "CWE-798", "A07", 0.9,
                                "Secrets in ENV are visible via docker inspect and stored in image layers.",
                                "Use build secrets (--mount=type=secret) or runtime env vars.",
                                Language.DOCKERFILE,
                            ))

            # Rule: EXPOSE common insecure ports
            expose_match = re.match(r"^EXPOSE\s+(\d+)", stripped, re.IGNORECASE)
            if expose_match:
                port = int(expose_match.group(1))
                if port in (23, 21, 3389, 5900):
                    findings.append(self._finding(
                        fp, i, f"Insecure port exposed: {port}",
                        Severity.HIGH, "CWE-284", "A01", 0.8,
                        f"Port {port} is commonly associated with insecure protocols.",
                        f"Remove EXPOSE {port} or use a secure alternative.",
                        Language.DOCKERFILE,
                    ))

            # Rule: curl/wget piped to shell
            if re.search(r"curl\s.*\|\s*(?:bash|sh|zsh)", stripped, re.IGNORECASE) or \
               re.search(r"wget\s.*-O\s*-\s*\|\s*(?:bash|sh|zsh)", stripped, re.IGNORECASE):
                findings.append(self._finding(
                    fp, i, "Piping curl/wget to shell",
                    Severity.HIGH, "CWE-829", "A08", 0.85,
                    "Downloading and executing scripts in a single step prevents integrity verification.",
                    "Download, verify checksum, then execute in separate steps.",
                    Language.DOCKERFILE,
                ))

            # Rule: COPY . . (copies everything including .git)
            if re.match(r"^COPY\s+\.\s+\.", stripped, re.IGNORECASE):
                findings.append(self._finding(
                    fp, i, "COPY . . may include secrets and .git",
                    Severity.MEDIUM, "CWE-200", "A05", 0.7,
                    "COPY . . copies everything, potentially including .git, .env, secrets.",
                    "Use .dockerignore or explicit COPY with specific paths.",
                    Language.DOCKERFILE,
                ))

        return findings

    # ── Terraform Rules ──

    def _scan_terraform(self, fp: Path) -> List[Finding]:
        findings = []
        try:
            content = fp.read_text(errors="replace")
        except Exception:
            return []

        # Rule: public S3 bucket
        if re.search(r'public_read_access\s*=\s*"?true"?', content, re.IGNORECASE):
            line = self._find_line(content, r'public_read_access\s*=\s*"?true"?')
            findings.append(self._finding(
                fp, line, "S3 bucket with public read access",
                Severity.CRITICAL, "CWE-284", "A01", 0.9,
                "S3 bucket is publicly readable. Data exposure risk.",
                "Set public_read_access = false",
                Language.TERRAFORM,
            ))

        # Rule: 0.0.0.0/0 in security group
        for line_text in content.splitlines():
            if ("cidr_blocks" in line_text or "source_ranges" in line_text) and "0.0.0.0/0" in line_text:
                findings.append(self._finding(
                    fp, self._find_line(content, "0.0.0.0/0"), "Security group open to 0.0.0.0/0",
                    Severity.CRITICAL, "CWE-284", "A01", 0.95,
                    "Resource is accessible from the entire internet.",
                    "Restrict to specific IP ranges or use VPN/private subnets.",
                    Language.TERRAFORM,
            ))

        # Rule: unencrypted EBS
        if re.search(r'encrypted\s*=\s*"?false"?', content, re.IGNORECASE):
            line = self._find_line(content, r'encrypted\s*=\s*"?false"?')
            findings.append(self._finding(
                fp, line, "Unencrypted storage volume",
                Severity.HIGH, "CWE-311", "A02", 0.85,
                "Storage volume is not encrypted. Data at rest is unprotected.",
                "Set encrypted = true",
                Language.TERRAFORM,
            ))

        # Rule: public RDS instance
        if re.search(r'publicly_accessible\s*=\s*"?true"?', content, re.IGNORECASE):
            line = self._find_line(content, r'publicly_accessible\s*=\s*"?true"?')
            findings.append(self._finding(
                fp, line, "Database publicly accessible",
                Severity.CRITICAL, "CWE-284", "A01", 0.9,
                "Database instance is publicly accessible from the internet.",
                "Set publicly_accessible = false and use private subnets.",
                Language.TERRAFORM,
            ))

        # Rule: plaintext password in tfvars
        if re.search(r'password\s*=\s*"[^"]{8,}"', content, re.IGNORECASE):
            line = self._find_line(content, r'password\s*=\s*"[^"]{8,}"')
            findings.append(self._finding(
                fp, line, "Password in Terraform variable",
                Severity.CRITICAL, "CWE-798", "A07", 0.85,
                "Password is hardcoded in Terraform configuration.",
                "Use variables, AWS Secrets Manager, or Vault.",
                Language.TERRAFORM,
            ))

        # Rule: missing logging
        if re.search(r'enable_logging\s*=\s*"?false"?', content, re.IGNORECASE):
            line = self._find_line(content, r'enable_logging\s*=\s*"?false"?')
            findings.append(self._finding(
                fp, line, "Logging disabled",
                Severity.MEDIUM, "CWE-778", "A09", 0.7,
                "Resource logging is disabled.",
                "Enable logging for audit trail.",
                Language.TERRAFORM,
            ))

        return findings

    # ── Kubernetes Rules ──

    def _is_k8s_manifest(self, fp: Path) -> bool:
        """Check if a YAML file is a K8s manifest."""
        try:
            content = fp.read_text(errors="replace")
            return "apiVersion:" in content and "kind:" in content
        except Exception:
            return False

    def _scan_k8s(self, fp: Path) -> List[Finding]:
        findings = []
        try:
            content = fp.read_text(errors="replace")
        except Exception:
            return []

        # Rule: privileged container
        if re.search(r'privileged:\s*true', content):
            line = self._find_line(content, r'privileged:\s*true')
            findings.append(self._finding(
                fp, line, "Privileged container in K8s",
                Severity.CRITICAL, "CWE-250", "A05", 0.95,
                "Privileged containers have full host access. Container escape risk.",
                "Remove privileged: true, use specific capabilities.",
                Language.KUBERNETES,
            ))

        # Rule: runAsRoot
        if re.search(r'runAsNonRoot:\s*false', content):
            line = self._find_line(content, r'runAsNonRoot:\s*false')
            findings.append(self._finding(
                fp, line, "Container runs as root in K8s",
                Severity.HIGH, "CWE-250", "A05", 0.85,
                "Container is allowed to run as root.",
                "Set runAsNonRoot: true and runAsUser: 1000",
                Language.KUBERNETES,
            ))

        # Rule: hostNetwork
        if re.search(r'hostNetwork:\s*true', content):
            line = self._find_line(content, r'hostNetwork:\s*true')
            findings.append(self._finding(
                fp, line, "Pod uses host network",
                Severity.HIGH, "CWE-420", "A05", 0.8,
                "Pod shares the host network namespace. Network isolation bypass.",
                "Remove hostNetwork: true unless absolutely required.",
                Language.KUBERNETES,
            ))

        # Rule: hostPID
        if re.search(r'hostPID:\s*true', content):
            line = self._find_line(content, r'hostPID:\s*true')
            findings.append(self._finding(
                fp, line, "Pod uses host PID namespace",
                Severity.HIGH, "CWE-420", "A05", 0.8,
                "Pod shares host PID namespace. Can see and signal host processes.",
                "Remove hostPID: true.",
                Language.KUBERNETES,
            ))

        # Rule: allowPrivilegeEscalation
        if re.search(r'allowPrivilegeEscalation:\s*true', content):
            line = self._find_line(content, r'allowPrivilegeEscalation:\s*true')
            findings.append(self._finding(
                fp, line, "Privilege escalation allowed",
                Severity.HIGH, "CWE-250", "A05", 0.8,
                "Container can escalate privileges beyond parent.",
                "Set allowPrivilegeEscalation: false",
                Language.KUBERNETES,
            ))

        # Rule: missing resource limits
        if "kind: Pod" in content or "kind: Deployment" in content:
            if "resources:" not in content:
                line = self._find_line(content, r'kind:\s*(?:Pod|Deployment)')
                findings.append(self._finding(
                    fp, line, "Missing resource limits",
                    Severity.LOW, "CWE-770", "A05", 0.6,
                    "No resource limits defined. Container can consume all node resources.",
                    "Add resources.limits.cpu and resources.limits.memory.",
                    Language.KUBERNETES,
                ))

        # Rule: secrets in env
        secret_env = re.finditer(
            r'(?:value|password|secret|token|key):\s*["\']?[A-Za-z0-9+/=]{16,}',
            content, re.IGNORECASE,
        )
        for match in secret_env:
            line = self._find_line(content, re.escape(match.group()[:40]))
            findings.append(self._finding(
                fp, line, "Possible secret in K8s manifest",
                Severity.HIGH, "CWE-798", "A07", 0.7,
                "Possible hardcoded secret in manifest environment variable.",
                "Use Kubernetes Secrets or external secret manager.",
                Language.KUBERNETES,
            ))

        return findings

    def _find_line(self, content: str, pattern: str) -> int:
        for i, line in enumerate(content.splitlines(), 1):
            if re.search(pattern, line, re.IGNORECASE):
                return i
        return 1

    def _finding(self, fp, line, title, severity, cwe, owasp, confidence,
                 desc, remediation, language) -> Finding:
        return Finding(
            rule_id=f"IAC-{cwe[-3:]}",
            title=title, category=FindingCategory.SECURITY_MISCONFIG,
            severity=severity, confidence=confidence,
            file_path=str(fp), line_number=line,
            language=language, cwe_id=cwe, owasp_id=owasp,
            description=desc, remediation=remediation,
            tags=["iac", language.value, owasp],
        )