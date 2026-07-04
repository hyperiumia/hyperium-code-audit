"""
Secret Verifier — Validates detected secrets by format and optionally by API.

Verification levels:
  FORMAT_ONLY  — Check if key matches known format (regex + length)
  ENTROPY      — Add Shannon entropy check (high entropy = likely real)
  LIVE_CHECK   — API call to verify if key is active (opt-in, off by default)

Security considerations:
  - LIVE_CHECK is NEVER enabled by default
  - Only verifies against public "whoami" endpoints
  - Never sends data, only checks if key authenticates
  - Logs all verification attempts for audit trail
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of verifying a secret."""
    is_valid_format: bool = False
    is_high_entropy: bool = False
    is_live: bool = False
    confidence_boost: float = 0.0
    detail: str = ""


# Format validators for known secret types
FORMAT_VALIDATORS: Dict[str, dict] = {
    "AWS_ACCESS_KEY": {
        "pattern": r"^AKIA[0-9A-Z]{16}$",
        "min_length": 20,
        "max_length": 20,
        "description": "AWS Access Key ID (AKIA + 16 uppercase alphanumeric)",
    },
    "STRIPE_SECRET_KEY": {
        "pattern": r"^sk_(?:live|test)_[A-Za-z0-9]{20,}$",
        "min_length": 20,
        "description": "Stripe Secret Key",
    },
    "GITHUB_TOKEN": {
        "pattern": r"^ghp_[A-Za-z0-9]{36}$",
        "min_length": 40,
        "max_length": 40,
        "description": "GitHub Personal Access Token (ghp_ + 36 chars)",
    },
    "GITHUB_OAUTH": {
        "pattern": r"^gho_[A-Za-z0-9]{36}$",
        "min_length": 40,
        "max_length": 40,
        "description": "GitHub OAuth Token",
    },
    "JWT_TOKEN": {
        "pattern": r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$",
        "description": "JSON Web Token (3 base64url segments)",
    },
    "GOOGLE_API_KEY": {
        "pattern": r"^AIza[0-9A-Za-z_-]{35}$",
        "min_length": 39,
        "max_length": 39,
        "description": "Google API Key (AIza + 35 chars)",
    },
    "SLACK_TOKEN": {
        "pattern": r"^xoxb-[0-9]+-[A-Za-z0-9]+$",
        "min_length": 20,
        "description": "Slack Bot Token",
    },
    "SENDGRID_KEY": {
        "pattern": r"^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$",
        "description": "SendGrid API Key (SG. + 22 + 43 chars)",
    },
    "MERCADOPAGO_TOKEN": {
        "pattern": r"^APP_USR-\d{10,15}-\d{10,15}-[a-f0-9]{32}-[a-f0-9]{32}$",
        "description": "MercadoPago Access Token",
    },
    "OPENAI_KEY": {
        "pattern": r"^sk-[A-Za-z0-9]{48}$",
        "min_length": 51,
        "max_length": 51,
        "description": "OpenAI API Key (sk- + 48 chars)",
    },
    "PRIVATE_KEY": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "description": "PEM Private Key",
    },
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def verify_secret_format(secret_type: str, value: str) -> VerificationResult:
    """Verify a secret against its known format.

    Returns:
        VerificationResult with format validity, entropy check, and confidence boost.
    """
    result = VerificationResult()

    validator = FORMAT_VALIDATORS.get(secret_type)
    if not validator:
        return result

    # Format check
    pattern = validator.get("pattern")
    if pattern:
        if re.match(pattern, value):
            result.is_valid_format = True
            result.detail = f"Valid {validator['description']} format"
        else:
            result.detail = f"Does not match {secret_type} format (may be truncated or fake)"
            result.confidence_boost = -0.3
            return result

    # Length check
    min_len = validator.get("min_length")
    max_len = validator.get("max_length")
    if min_len and len(value) < min_len:
        result.is_valid_format = False
        result.detail = f"Too short for {secret_type} (expected {min_len}+, got {len(value)})"
        result.confidence_boost = -0.3
        return result
    if max_len and len(value) > max_len:
        result.is_valid_format = False
        result.detail = f"Too long for {secret_type} (expected {max_len}, got {len(value)})"
        result.confidence_boost = -0.2
        return result

    # Entropy check
    entropy = calculate_entropy(value)
    result.is_high_entropy = entropy >= 3.5
    if result.is_high_entropy:
        result.confidence_boost += 0.1
        result.detail += f" (entropy: {entropy:.1f} — high)"
    else:
        result.confidence_boost -= 0.1
        result.detail += f" (entropy: {entropy:.1f} — low, may be example/placeholder)"

    return result


def verify_secrets_batch(secrets: list) -> List[VerificationResult]:
    """Verify a batch of SecretFinding objects."""
    results = []
    for secret in secrets:
        result = verify_secret_format(secret.secret_type, secret.redacted_value)
        results.append(result)
    return results
