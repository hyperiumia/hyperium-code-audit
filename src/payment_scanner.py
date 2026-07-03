"""
Payment Scanner — Detects exposed payment gateway credentials.

Scans for API keys, secrets, and webhook configurations from:
  - Stripe, MercadoPago, PayPal, Square, Conekta, Culqi, Wompi
  - PCI DSS violations (card numbers in source code)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from src.models import Language, PaymentFinding, Severity

logger = logging.getLogger(__name__)


@dataclass
class PaymentRule:
    """Detection rule for payment gateway exposure."""
    id: str
    gateway: str
    key_type: str
    pattern: str
    severity: Severity = Severity.CRITICAL
    description: str = ""
    pci_violation: bool = True
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern, re.IGNORECASE)


PAYMENT_RULES: List[PaymentRule] = [
    # Stripe
    PaymentRule(
        id="PAY-001", gateway="Stripe", key_type="LIVE_SECRET",
        pattern=r"sk_live_[A-Za-z0-9]{20,}",
        description="Stripe live secret key exposed. Can process real charges.",
    ),
    PaymentRule(
        id="PAY-002", gateway="Stripe", key_type="TEST_SECRET",
        pattern=r"sk_test_[A-Za-z0-9]{20,}",
        severity=Severity.MEDIUM,
        description="Stripe test key exposed.",
        pci_violation=False,
    ),
    PaymentRule(
        id="PAY-003", gateway="Stripe", key_type="LIVE_RESTRICTED",
        pattern=r"rk_live_[A-Za-z0-9]{20,}",
        description="Stripe restricted API key exposed.",
    ),
    PaymentRule(
        id="PAY-004", gateway="Stripe", key_type="WEBHOOK_SECRET",
        pattern=r"whsec_[A-Za-z0-9]{20,}",
        severity=Severity.HIGH,
        description="Stripe webhook signing secret. Attackers can forge webhook events.",
    ),
    # MercadoPago
    PaymentRule(
        id="PAY-010", gateway="MercadoPago", key_type="LIVE_TOKEN",
        pattern=r"APP_USR-\d{10,15}-\d{10,15}-[a-f0-9]{32}-[a-f0-9]{32}",
        description="MercadoPago production access token.",
    ),
    PaymentRule(
        id="PAY-011", gateway="MercadoPago", key_type="TEST_TOKEN",
        pattern=r"TEST-\d{10,15}-\d{10,15}-[a-f0-9]{32}-[a-f0-9]{32}",
        severity=Severity.MEDIUM,
        description="MercadoPago test token.",
        pci_violation=False,
    ),
    PaymentRule(
        id="PAY-012", gateway="MercadoPago", key_type="PUBLIC_KEY",
        pattern=r"APP_USR-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        severity=Severity.LOW,
        description="MercadoPago public key.",
        pci_violation=False,
    ),
    # PayPal
    PaymentRule(
        id="PAY-020", gateway="PayPal", key_type="CLIENT_SECRET",
        pattern=r"""(?:paypal.*secret|PAYPAL.*SECRET|client_secret)\s*[=:]\s*['"]?[A-Za-z0-9_-]{20,}['"]?""",
        description="PayPal client secret exposed.",
    ),
    PaymentRule(
        id="PAY-021", gateway="PayPal", key_type="WEBHOOK_ID",
        pattern=r"""(?:paypal.*webhook|PAYPAL.*WEBHOOK)\s*[=:]\s*['"]?[A-Za-z0-9]{20,}['"]?""",
        severity=Severity.HIGH,
        description="PayPal webhook ID exposed.",
    ),
    # Conekta (Mexico)
    PaymentRule(
        id="PAY-030", gateway="Conekta", key_type="LIVE_KEY",
        pattern=r"key_live_[A-Za-z0-9]{20,}",
        description="Conekta live private key exposed.",
    ),
    PaymentRule(
        id="PAY-031", gateway="Conekta", key_type="TEST_KEY",
        pattern=r"key_test_[A-Za-z0-9]{20,}",
        severity=Severity.MEDIUM,
        description="Conekta test key.",
        pci_violation=False,
    ),
    # Culqi (Peru)
    PaymentRule(
        id="PAY-040", gateway="Culqi", key_type="LIVE_KEY",
        pattern=r"sk_live_[A-Za-z0-9]{20,}",
        description="Culqi live secret key.",
    ),
    PaymentRule(
        id="PAY-041", gateway="Culqi", key_type="TEST_KEY",
        pattern=r"sk_test_[A-Za-z0-9]{20,}",
        severity=Severity.MEDIUM,
        pci_violation=False,
        description="Culqi test key.",
    ),
    # Wompi (Colombia)
    PaymentRule(
        id="PAY-050", gateway="Wompi", key_type="LIVE_PRIVATE",
        pattern=r"prv_[A-Za-z0-9]{20,}",
        description="Wompi live private key.",
    ),
    PaymentRule(
        id="PAY-051", gateway="Wompi", key_type="LIVE_PUBLIC",
        pattern=r"pub_prod_[A-Za-z0-9]{20,}",
        severity=Severity.LOW,
        pci_violation=False,
        description="Wompi public key (low risk).",
    ),
    PaymentRule(
        id="PAY-052", gateway="Wompi", key_type="INTEGRITY",
        pattern=r"wi_[A-Za-z0-9]{20,}",
        severity=Severity.HIGH,
        description="Wompi integrity key. Webhook verification can be bypassed.",
    ),
    # Square
    PaymentRule(
        id="PAY-060", gateway="Square", key_type="LIVE_SECRET",
        pattern=r"sq0csp-[A-Za-z0-9_-]{20,}",
        description="Square production secret.",
    ),
    # PCI DSS — Card numbers
    PaymentRule(
        id="PAY-090", gateway="PCI_DSS", key_type="CARD_NUMBER",
        pattern=r"""(?:4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5})""",
        severity=Severity.CRITICAL,
        description="Potential payment card number in source code. PCI DSS violation.",
    ),
]


def _luhn_check(number: str) -> bool:
    """Validate a card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class PaymentScanner:
    """Scans for payment gateway credential exposure."""

    def __init__(self, rules: Optional[List[PaymentRule]] = None):
        self.rules = rules or PAYMENT_RULES
        self._compiled = [(r, re.compile(r.pattern, re.IGNORECASE)) for r in self.rules]

    def scan_file(self, file_path: Path) -> List[PaymentFinding]:
        """Scan a single file for payment-related exposures."""
        try:
            content = file_path.read_text(errors="replace")
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return []

        lines = content.split("\n")
        findings: List[PaymentFinding] = []
        seen: set = set()

        for rule, compiled in self._compiled:
            for match in compiled.finditer(content):
                value = match.group(0)
                line_number = content[:match.start()].count("\n") + 1

                dedup_key = (rule.id, str(file_path), line_number)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # For card numbers, validate with Luhn
                if rule.key_type == "CARD_NUMBER":
                    digits_only = "".join(c for c in value if c.isdigit())
                    if not _luhn_check(digits_only):
                        continue

                redacted = value[:6] + "*" * max(0, len(value) - 10) + value[-4:] if len(value) > 10 else "***"

                findings.append(PaymentFinding(
                    gateway=rule.gateway,
                    key_type=rule.key_type,
                    file_path=str(file_path),
                    line_number=line_number,
                    redacted_value=redacted,
                    severity=rule.severity,
                    description=rule.description,
                    pci_violation=rule.pci_violation,
                    remediation=(
                        f"Remove {rule.gateway} credential from source code immediately. "
                        "Store in environment variables or a secrets manager. "
                        "Rotate the compromised key."
                    ),
                ))

        return findings

    def scan_files(self, file_paths: List[Path]) -> List[PaymentFinding]:
        """Scan multiple files."""
        all_findings: List[PaymentFinding] = []
        for fp in file_paths:
            all_findings.extend(self.scan_file(fp))
        return all_findings
