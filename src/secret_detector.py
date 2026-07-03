"""
Secret Detector — Finds hardcoded credentials, API keys, and sensitive data.

Detection methods:
  1. Regex patterns for known key formats (AWS, Stripe, etc.)
  2. Entropy analysis for generic high-entropy strings
  3. Context analysis (variable names like "password", "secret", "key")
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from src.models import Language, SecretFinding, Severity

logger = logging.getLogger(__name__)


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )


def redact_secret(value: str, visible: int = 4) -> str:
    """Partially mask a secret value for safe display."""
    if len(value) <= visible * 2:
        return "*" * len(value)
    return value[:visible] + "*" * (len(value) - visible * 2) + value[-visible:]


# ═══════════════════════════════════════════════════════════════
# SECRET PATTERNS
# ═══════════════════════════════════════════════════════════════

@dataclass
class SecretRule:
    """A detection rule for a specific type of secret."""
    id: str
    name: str
    pattern: str
    secret_type: str
    is_live_indicator: str = ""  # Pattern that indicates live/production key
    description: str = ""
    severity: Severity = Severity.CRITICAL
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern, re.IGNORECASE)


SECRET_RULES: List[SecretRule] = [
    # AWS
    SecretRule(
        id="SEC-001", name="AWS Access Key ID",
        pattern=r"AKIA[0-9A-Z]{16}",
        secret_type="AWS_ACCESS_KEY",
        is_live_indicator="AKIA",
        description="AWS Access Key ID. Can be used to access AWS services.",
    ),
    SecretRule(
        id="SEC-002", name="AWS Secret Access Key",
        pattern=r"""(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
        secret_type="AWS_SECRET_KEY",
        description="AWS Secret Access Key paired with an Access Key ID.",
    ),
    # Stripe
    SecretRule(
        id="SEC-003", name="Stripe Live Secret Key",
        pattern=r"sk_live_[A-Za-z0-9]{20,}",
        secret_type="STRIPE_SECRET_KEY",
        is_live_indicator="sk_live_",
        description="Stripe live secret key. Can process real payments.",
        severity=Severity.CRITICAL,
    ),
    SecretRule(
        id="SEC-004", name="Stripe Test Secret Key",
        pattern=r"sk_test_[A-Za-z0-9]{20,}",
        secret_type="STRIPE_TEST_KEY",
        description="Stripe test secret key. Not a production risk but should not be in code.",
        severity=Severity.MEDIUM,
    ),
    SecretRule(
        id="SEC-005", name="Stripe Publishable Key",
        pattern=r"pk_(?:live|test)_[A-Za-z0-9]{20,}",
        secret_type="STRIPE_PUBLISHABLE_KEY",
        description="Stripe publishable key. Low risk but indicates payment integration.",
        severity=Severity.LOW,
    ),
    # MercadoPago
    SecretRule(
        id="SEC-006", name="MercadoPago Access Token",
        pattern=r"APP_USR-[0-9]+-[0-9]+-[a-f0-9]+-[a-f0-9]+",
        secret_type="MERCADOPAGO_TOKEN",
        is_live_indicator="APP_USR-",
        description="MercadoPago production access token.",
        severity=Severity.CRITICAL,
    ),
    SecretRule(
        id="SEC-007", name="MercadoPago Test Token",
        pattern=r"TEST-[0-9]+-[0-9]+-[a-f0-9]+-[a-f0-9]+",
        secret_type="MERCADOPAGO_TEST_TOKEN",
        description="MercadoPago test token.",
        severity=Severity.MEDIUM,
    ),
    # Google
    SecretRule(
        id="SEC-008", name="Google API Key",
        pattern=r"AIza[0-9A-Za-z_-]{35}",
        secret_type="GOOGLE_API_KEY",
        description="Google API key for Maps, Firebase, etc.",
    ),
    SecretRule(
        id="SEC-009", name="Google Service Account",
        pattern=r'"type"\s*:\s*"service_account"',
        secret_type="GOOGLE_SERVICE_ACCOUNT",
        description="Google service account JSON credentials.",
    ),
    # GitHub
    SecretRule(
        id="SEC-010", name="GitHub Personal Access Token",
        pattern=r"ghp_[A-Za-z0-9]{36}",
        secret_type="GITHUB_TOKEN",
        is_live_indicator="ghp_",
        description="GitHub personal access token with repo access.",
    ),
    SecretRule(
        id="SEC-011", name="GitHub OAuth Token",
        pattern=r"gho_[A-Za-z0-9]{36}",
        secret_type="GITHUB_OAUTH",
        description="GitHub OAuth access token.",
    ),
    # Generic JWT
    SecretRule(
        id="SEC-012", name="JSON Web Token (JWT)",
        pattern=r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        secret_type="JWT_TOKEN",
        description="Hardcoded JWT token.",
        severity=Severity.HIGH,
    ),
    # Database URLs
    SecretRule(
        id="SEC-013", name="Database Connection String",
        pattern=r"""(?:postgres|mysql|mongodb|redis|amqp|mssql)(?:ql)?://[^\s'"<>]{10,}""",
        secret_type="DATABASE_URL",
        is_live_indicator="://",
        description="Database connection string with embedded credentials.",
        severity=Severity.CRITICAL,
    ),
    # Private Keys
    SecretRule(
        id="SEC-014", name="Private Key (PEM)",
        pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        secret_type="PRIVATE_KEY",
        description="Private cryptographic key in PEM format.",
        severity=Severity.CRITICAL,
    ),
    # Slack
    SecretRule(
        id="SEC-015", name="Slack Bot Token",
        pattern=r"xoxb-[0-9]+-[A-Za-z0-9]+",
        secret_type="SLACK_TOKEN",
        description="Slack bot access token.",
    ),
    # Twilio
    SecretRule(
        id="SEC-016", name="Twilio API Key",
        pattern=r"SK[0-9a-fA-F]{32}",
        secret_type="TWILIO_KEY",
        description="Twilio API secret key.",
    ),
    # SendGrid
    SecretRule(
        id="SEC-017", name="SendGrid API Key",
        pattern=r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        secret_type="SENDGRID_KEY",
        description="SendGrid API key for email sending.",
    ),
    # Conekta
    SecretRule(
        id="SEC-018", name="Conekta Private Key",
        pattern=r"key_(?:live|test)_[A-Za-z0-9]{20,}",
        secret_type="CONEKTA_KEY",
        is_live_indicator="key_live_",
        description="Conekta payment gateway private key.",
        severity=Severity.CRITICAL,
    ),
    # Culqi
    SecretRule(
        id="SEC-019", name="Culqi Secret Key",
        pattern=r"sk_(?:live|test)_[A-Za-z0-9]{20,}",
        secret_type="CULQI_KEY",
        is_live_indicator="sk_live_",
        description="Culqi payment gateway secret key.",
        severity=Severity.CRITICAL,
    ),
    # OpenAI
    SecretRule(
        id="SEC-020", name="OpenAI API Key",
        pattern=r"sk-[A-Za-z0-9]{48}",
        secret_type="OPENAI_KEY",
        description="OpenAI API key.",
    ),
    # Generic high-entropy assignment
    SecretRule(
        id="SEC-099", name="Generic High-Entropy Secret",
        pattern=r"""(?:secret|token|apikey|api_key|password|passwd|auth_token|access_token|private_key)\s*[=:]\s*['"]([A-Za-z0-9+/=_-]{20,})['"]""",
        secret_type="GENERIC_SECRET",
        description="Potential secret found by variable name context.",
        severity=Severity.HIGH,
    ),
]


class SecretDetector:
    """Detects hardcoded secrets and credentials in source code."""

    def __init__(
        self,
        entropy_threshold: float = 4.5,
        rules: Optional[List[SecretRule]] = None,
        scan_env_files: bool = True,
    ):
        self.entropy_threshold = entropy_threshold
        self.rules = rules or SECRET_RULES
        self.scan_env_files = scan_env_files
        self._compiled_rules = [(r, re.compile(r.pattern, re.IGNORECASE)) for r in self.rules]

    def scan_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan a single file for hardcoded secrets."""
        try:
            content = file_path.read_text(errors="replace")
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return []

        lines = content.split("\n")
        findings: List[SecretFinding] = []
        seen: set = set()

        for rule, compiled in self._compiled_rules:
            for match in compiled.finditer(content):
                value = match.group(0)
                line_number = content[:match.start()].count("\n") + 1

                dedup_key = (rule.id, str(file_path), line_number)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Entropy check for generic rules
                entropy = calculate_entropy(value)
                if rule.id == "SEC-099" and entropy < self.entropy_threshold:
                    continue

                # Check if it's a live key
                is_live = bool(rule.is_live_indicator and rule.is_live_indicator in value)

                finding = SecretFinding(
                    secret_type=rule.secret_type,
                    file_path=str(file_path),
                    line_number=line_number,
                    redacted_value=redact_secret(value),
                    confidence=0.9 if rule.id != "SEC-099" else 0.7,
                    is_live_key=is_live,
                    entropy=round(entropy, 2),
                    description=rule.description,
                    remediation=(
                        "Remove secret from code immediately. "
                        "Rotate the compromised credential. "
                        "Use environment variables or a secrets manager."
                    ),
                )
                findings.append(finding)

        return findings

    def scan_files(self, file_paths: List[Path]) -> List[SecretFinding]:
        """Scan multiple files for secrets."""
        all_findings: List[SecretFinding] = []
        for fp in file_paths:
            all_findings.extend(self.scan_file(fp))
        return all_findings
