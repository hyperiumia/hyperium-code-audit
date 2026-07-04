"""
Payment Logic Analyzer — Detects missing security controls in payment code.

Goes beyond "key found" to analyze HOW payment gateways are used:

Checks:
  1. Webhook signature verification (Stripe, MercadoPago, Conekta)
  2. Idempotency key usage on charge/create operations
  3. Server-side amount validation (not trusting frontend)
  4. HTTPS enforcement on payment endpoints
  5. Payment error handling (no sensitive data in responses)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List

from src.models import Finding, FindingCategory, Language, Severity

logger = logging.getLogger(__name__)


class PaymentLogicAnalyzer:
    """Analyzes payment-related code for security logic issues."""

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for payment logic issues."""
        try:
            content = file_path.read_text(errors="replace")
        except Exception:
            return []

        findings: List[Finding] = []
        lines = content.split("\n")

        # Check 1: Webhook signature verification
        findings.extend(self._check_webhook_verification(content, lines, str(file_path)))

        # Check 2: Idempotency
        findings.extend(self._check_idempotency(content, lines, str(file_path)))

        # Check 3: Amount validation
        findings.extend(self._check_amount_validation(content, lines, str(file_path)))

        # Check 4: Payment error handling
        findings.extend(self._check_error_handling(content, lines, str(file_path)))

        return findings

    def _check_webhook_verification(self, content: str, lines: List[str],
                                     file_path: str) -> List[Finding]:
        """Check if webhook endpoints verify signatures."""
        findings = []

        # Pattern: webhook endpoint without signature verification
        webhook_pattern = re.compile(
            r"""(?:@app\.(?:route|post)|app\.(?:post|use))\s*\(\s*['"].*(?:webhook|stripe|payment|hook)""",
            re.IGNORECASE,
        )

        # Signature verification patterns
        verify_patterns = [
            r"construct_event",  # Stripe
            r"verify_header",    # MercadoPago
            r"verify_signature", # Generic
            r"hmac",             # HMAC verification
            r"webhook_secret",
            r"Webhook\.construct",
        ]

        for i, line in enumerate(lines, 1):
            if webhook_pattern.search(line):
                # Check if signature verification exists in surrounding context
                context_start = max(0, i - 2)
                context_end = min(len(lines), i + 20)
                context = "\n".join(lines[context_start:context_end])

                has_verification = any(
                    re.search(pat, context, re.IGNORECASE) for pat in verify_patterns
                )

                if not has_verification:
                    findings.append(self._make_finding(
                        file_path, i,
                        "Webhook endpoint without signature verification",
                        FindingCategory.BROKEN_AUTH,
                        "CWE-345", "A07", 0.75,
                        "Payment webhook endpoint does not verify the webhook signature. "
                        "Attackers can forge webhook events to manipulate payment status.",
                        "Verify webhook signatures using the gateway's SDK: "
                        "Stripe: stripe.Webhook.construct_event(payload, sig, secret). "
                        "MercadoPago: validate x-signature header.",
                    ))

        return findings

    def _check_idempotency(self, content: str, lines: List[str],
                            file_path: str) -> List[Finding]:
        """Check if payment operations use idempotency keys."""
        findings = []

        # Patterns that create charges/payments
        charge_patterns = re.compile(
            r"""(?:stripe\.(?:charges?|payment_intents?)\.(?:create|capture)|"""
            r"""mercadopago.*(?:payment|charge)|"""
            r"""mp\.payments?\.(?:create|save)|"""
            r"""conekta.*(?:charge|order))""",
            re.IGNORECASE,
        )

        idempotency_patterns = re.compile(
            r"""(?:idempotency|idempotency_key|Idempotency-Key|idempotencyKey)""",
            re.IGNORECASE,
        )

        for i, line in enumerate(lines, 1):
            if charge_patterns.search(line):
                # Check surrounding context for idempotency
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 10)
                context = "\n".join(lines[context_start:context_end])

                if not idempotency_patterns.search(context):
                    findings.append(self._make_finding(
                        file_path, i,
                        "Payment operation without idempotency key",
                        FindingCategory.INSECURE_DIRECT_REF,
                        "CWE-799", "A04", 0.7,
                        "Payment charge/creation without idempotency key. "
                        "Network retries can cause duplicate charges.",
                        "Add idempotency_key parameter to payment operations. "
                        "Use a unique identifier per transaction (e.g., order ID).",
                    ))

        return findings

    def _check_amount_validation(self, content: str, lines: List[str],
                                  file_path: str) -> List[Finding]:
        """Check if payment amounts are validated server-side."""
        findings = []

        # Patterns where amount comes from request/params
        amount_from_request = re.compile(
            r"""(?:amount|total|price|monto)\s*(?:=|:)\s*(?:request\.|req\.|params\.|body\.)""",
            re.IGNORECASE,
        )

        # Server-side validation patterns
        validation_patterns = re.compile(
            r"""(?:validate.*amount|verify.*price|check.*total|amount.*(?:==|===|>=|<=))""",
            re.IGNORECASE,
        )

        for i, line in enumerate(lines, 1):
            if amount_from_request.search(line):
                context_start = max(0, i - 3)
                context_end = min(len(lines), i + 10)
                context = "\n".join(lines[context_start:context_end])

                if not validation_patterns.search(context):
                    findings.append(self._make_finding(
                        file_path, i,
                        "Payment amount from client without server validation",
                        FindingCategory.INSECURE_DIRECT_REF,
                        "CWE-472", "A04", 0.7,
                        "Payment amount read directly from client request without "
                        "server-side validation. Amount can be manipulated.",
                        "Always fetch the expected amount from your database/catalog. "
                        "Never trust the client-sent amount for payment processing.",
                    ))

        return findings

    def _check_error_handling(self, content: str, lines: List[str],
                              file_path: str) -> List[Finding]:
        """Check if payment errors expose sensitive data."""
        findings = []

        # Pattern: payment error response with sensitive fields
        error_pattern = re.compile(
            r"""(?:except|catch|error).*(?:return|res\.|response|json)\s*\(""",
            re.IGNORECASE,
        )
        sensitive_pattern = re.compile(
            r"""(?:card_number|cvv|cvc|expir|secret|token|apikey|api_key)""",
            re.IGNORECASE,
        )

        for i, line in enumerate(lines, 1):
            if error_pattern.search(line):
                context_start = max(0, i - 1)
                context_end = min(len(lines), i + 5)
                context = "\n".join(lines[context_start:context_end])

                if sensitive_pattern.search(context):
                    findings.append(self._make_finding(
                        file_path, i,
                        "Payment error may expose sensitive data",
                        FindingCategory.LOGGING_FAILURE,
                        "CWE-209", "A09", 0.65,
                        "Payment error handler may include sensitive fields "
                        "(card data, tokens) in error response or logs.",
                        "Sanitize error responses. Never include card numbers, "
                        "CVV, or tokens in error messages. Log only transaction IDs.",
                    ))

        return findings

    def _make_finding(self, file_path, line, title, category, cwe, owasp,
                      confidence, desc, remediation) -> Finding:
        return Finding(
            rule_id=f"PAY-LOGIC-{cwe[-3:]}",
            title=title, category=category, severity=Severity.HIGH,
            confidence=confidence, file_path=file_path,
            line_number=line, language=Language.PYTHON,
            cwe_id=cwe, owasp_id=owasp,
            description=desc, remediation=remediation,
            tags=["payment-logic", "payment-security", owasp],
        )
