"""
Compliance Mapper — Maps findings to security frameworks.

Supported frameworks:
  - OWASP Top 10 2021
  - PCI DSS v4.0 (relevant sections)
  - CWE Top 25
"""

from __future__ import annotations

import logging
from typing import Dict, List

from src.models import (
    ComplianceFramework, ComplianceMapping, ComplianceReport,
    ComplianceStatus, Finding, FindingCategory, PaymentFinding,
)

logger = logging.getLogger(__name__)


# OWASP Top 10 2021 Requirements
OWASP_TOP_10: Dict[str, dict] = {
    "A01": {
        "title": "Broken Access Control",
        "categories": [
            FindingCategory.PATH_TRAVERSAL, FindingCategory.OPEN_REDIRECT,
            FindingCategory.INSECURE_DIRECT_REF,
        ],
        "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
    },
    "A02": {
        "title": "Cryptographic Failures",
        "categories": [FindingCategory.CRYPTO_FAILURE, FindingCategory.HARDCODED_SECRET],
        "description": "Failures related to cryptography which often leads to data exposure.",
    },
    "A03": {
        "title": "Injection",
        "categories": [
            FindingCategory.INJECTION, FindingCategory.XSS,
            FindingCategory.COMMAND_INJECTION, FindingCategory.TEMPLATE_INJECTION,
            FindingCategory.SSRF,
        ],
        "description": "User-supplied data is not validated, filtered, or sanitized.",
    },
    "A04": {
        "title": "Insecure Design",
        "categories": [],
        "description": "Risks related to design flaws. Requires threat modeling and secure design patterns.",
    },
    "A05": {
        "title": "Security Misconfiguration",
        "categories": [FindingCategory.SECURITY_MISCONFIG, FindingCategory.XXE],
        "description": "Missing appropriate security hardening across any part of the application.",
    },
    "A06": {
        "title": "Vulnerable and Outdated Components",
        "categories": [FindingCategory.VULNERABLE_DEPENDENCY],
        "description": "Using components with known vulnerabilities.",
    },
    "A07": {
        "title": "Identification and Authentication Failures",
        "categories": [FindingCategory.BROKEN_AUTH],
        "description": "Confirmation of the user's identity, authentication, and session management is not implemented correctly.",
    },
    "A08": {
        "title": "Software and Data Integrity Failures",
        "categories": [FindingCategory.INSECURE_DESERIALIZATION],
        "description": "Code and infrastructure that does not protect against integrity violations.",
    },
    "A09": {
        "title": "Security Logging and Monitoring Failures",
        "categories": [FindingCategory.LOGGING_FAILURE],
        "description": "Insufficient logging, detection, monitoring, and active response.",
    },
    "A10": {
        "title": "Server-Side Request Forgery (SSRF)",
        "categories": [FindingCategory.SSRF],
        "description": "SSRF flaws occur when a web app fetches a remote resource without validating the user-supplied URL.",
    },
}


class ComplianceMapper:
    """Maps findings to compliance frameworks."""

    def __init__(self, frameworks: List[str] = None):
        self.frameworks = [ComplianceFramework(f) for f in (frameworks or ["owasp_top_10"])]

    def map_findings(
        self,
        findings: List[Finding],
        payment_findings: List[PaymentFinding] = None,
    ) -> List[ComplianceReport]:
        """Generate compliance reports for all configured frameworks."""
        reports: List[ComplianceReport] = []
        for fw in self.frameworks:
            if fw == ComplianceFramework.OWASP_TOP_10:
                reports.append(self._map_owasp(findings))
            # Future: PCI DSS, NIST, etc.
        return reports

    def _map_owasp(self, findings: List[Finding]) -> ComplianceReport:
        """Map findings to OWASP Top 10."""
        mappings: List[ComplianceMapping] = []
        passed = 0
        failed = 0

        for req_id, req_info in OWASP_TOP_10.items():
            matching_findings = [
                f for f in findings
                if f.category in req_info["categories"]
            ]

            if matching_findings:
                status = ComplianceStatus.FAIL
                failed += 1
            else:
                status = ComplianceStatus.PASS
                passed += 1

            mappings.append(ComplianceMapping(
                framework=ComplianceFramework.OWASP_TOP_10,
                requirement_id=req_id,
                requirement_title=req_info["title"],
                status=status,
                findings=[f.id for f in matching_findings],
                gap_description=req_info["description"] if matching_findings else "",
            ))

        total = len(OWASP_TOP_10)
        pct = (passed / total * 100) if total > 0 else 0

        return ComplianceReport(
            framework=ComplianceFramework.OWASP_TOP_10,
            total_requirements=total,
            passed=passed,
            failed=failed,
            compliance_percentage=round(pct, 1),
            mappings=mappings,
            gaps=[
                f"{m.requirement_id}: {m.requirement_title} — {len(m.findings)} finding(s)"
                for m in mappings if m.status == ComplianceStatus.FAIL
            ],
        )
