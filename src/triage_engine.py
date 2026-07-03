"""
Triage Engine — Risk scoring, prioritization, and deduplication.

Scoring model:
  Base score = sum of (severity.weight × confidence) for all findings
  Adjustments:
    - Critical paths (/admin, /login, /api) get 1.5x weight
    - Findings in CISA KEV get 2.0x weight
    - Findings with EPSS > 0.7 get 1.5x weight
  Final score = min(100, adjusted_score)
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict, List

from src.models import (
    DepVulnerability, Finding, PaymentFinding, RiskScore,
    SecretFinding, Severity,
)

logger = logging.getLogger(__name__)


class TriageEngine:
    """Calculates risk scores and prioritizes findings."""

    def __init__(self, critical_paths: List[str] = None):
        self.critical_paths = critical_paths or [
            "/admin", "/login", "/api/auth", "/payment", "/checkout",
            "/api/users", "/dashboard", "/settings",
        ]

    def score(
        self,
        findings: List[Finding],
        secrets: List[SecretFinding] = None,
        payment_findings: List[PaymentFinding] = None,
        dep_vulns: List[DepVulnerability] = None,
    ) -> RiskScore:
        """Calculate overall risk score."""
        secrets = secrets or []
        payment_findings = payment_findings or []
        dep_vulns = dep_vulns or []

        # Count by severity
        severity_counts = Counter()
        weighted_score = 0.0

        for f in findings:
            w = f.severity.weight * f.confidence
            if self._is_critical_path(f.file_path):
                w *= 1.5
            if f.in_cisa_kev:
                w *= 2.0
            if f.epss_score and f.epss_score > 0.7:
                w *= 1.5
            weighted_score += w
            severity_counts[f.severity] += 1

        # Secrets add to score
        for s in secrets:
            sev = Severity.CRITICAL if s.is_live_key else Severity.HIGH
            w = sev.weight * s.confidence
            weighted_score += w
            severity_counts[sev] += 1

        # Payment findings
        for p in payment_findings:
            w = p.severity.weight * 0.9
            weighted_score += w
            severity_counts[p.severity] += 1

        # Dependency vulns
        for d in dep_vulns:
            w = d.severity.weight * 0.8
            if d.in_cisa_kev:
                w *= 2.0
            weighted_score += w
            severity_counts[d.severity] += 1

        # Normalize to 0-100
        total = len(findings) + len(secrets) + len(payment_findings) + len(dep_vulns)
        if total == 0:
            overall = 0.0
        else:
            # Each finding contributes up to 10 (critical weight), cap at 100
            overall = min(100.0, (weighted_score / total) * 10)

        # Determine risk level
        if overall >= 80:
            risk_level = Severity.CRITICAL
        elif overall >= 60:
            risk_level = Severity.HIGH
        elif overall >= 40:
            risk_level = Severity.MEDIUM
        elif overall >= 20:
            risk_level = Severity.LOW
        else:
            risk_level = Severity.INFO

        # Top categories
        category_counts: Counter = Counter()
        for f in findings:
            category_counts[f.category.value] += 1
        top_categories = [
            {"category": cat, "count": count}
            for cat, count in category_counts.most_common(5)
        ]

        # Top files
        file_counts: Counter = Counter()
        for f in findings:
            file_counts[f.file_path] += 1
        for s in secrets:
            file_counts[s.file_path] += 1
        top_files = [
            {"file": fp, "count": count}
            for fp, count in file_counts.most_common(10)
        ]

        return RiskScore(
            overall_score=round(overall, 1),
            risk_level=risk_level,
            critical_count=severity_counts.get(Severity.CRITICAL, 0),
            high_count=severity_counts.get(Severity.HIGH, 0),
            medium_count=severity_counts.get(Severity.MEDIUM, 0),
            low_count=severity_counts.get(Severity.LOW, 0),
            info_count=severity_counts.get(Severity.INFO, 0),
            total_findings=total,
            top_categories=top_categories,
            top_files=top_files,
        )

    def _is_critical_path(self, file_path: str) -> bool:
        """Check if a file is in a critical application path."""
        path_lower = file_path.lower()
        return any(cp in path_lower for cp in self.critical_paths)

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings (same rule, same file, same line)."""
        seen: set = set()
        unique: List[Finding] = []
        for f in findings:
            key = (f.rule_id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def prioritize(self, findings: List[Finding]) -> List[Finding]:
        """Sort findings by severity (critical first), then confidence."""
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
        }
        return sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 9), -f.confidence),
        )
