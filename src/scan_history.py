"""
Scan History — Tracks scan results over time for trending and delta analysis.

Persists scan summaries to a JSON-lines file. Each line is a complete
scan summary that can be compared with previous scans.

Output:
  Delta report showing:
    - Overall trend (improving / degrading / stable)
    - New findings since last scan
    - Fixed findings since last scan
    - Severity distribution changes
    - Risk score trajectory
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.models import ScanResult, Severity

logger = logging.getLogger(__name__)


class ScanHistory:
    """Manages scan history for trending and delta analysis."""

    def __init__(self, history_dir: str = ".code_audit_history"):
        self.history_dir = Path(history_dir)
        self.history_file = self.history_dir / "scans.jsonl"

    def save_scan(self, result: ScanResult) -> Path:
        """Save a scan summary to history."""
        self.history_dir.mkdir(parents=True, exist_ok=True)

        summary = self._summarize(result)

        with open(self.history_file, "a") as f:
            f.write(json.dumps(summary, default=str) + "\n")

        return self.history_file

    def get_history(self) -> List[Dict[str, Any]]:
        """Load all scan summaries."""
        if not self.history_file.exists():
            return []
        scans = []
        for line in self.history_file.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    scans.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return scans

    def get_latest(self) -> Optional[Dict[str, Any]]:
        """Get the most recent scan summary."""
        history = self.get_history()
        return history[-1] if history else None

    def compare(self, current: ScanResult, previous_id: Optional[str] = None) -> Dict[str, Any]:
        """Compare current scan with a previous scan.

        If previous_id is None, compares with the most recent scan.
        """
        history = self.get_history()
        if not history:
            return {"status": "first_scan", "message": "No previous scans to compare"}

        previous = history[-1] if previous_id is None else None
        if previous_id:
            for scan in history:
                if scan.get("scan_id") == previous_id:
                    previous = scan
                    break

        if previous is None:
            return {"status": "first_scan", "message": "No previous scans to compare"}

        return self._calculate_delta(previous, self._summarize(current))

    def _summarize(self, result: ScanResult) -> Dict[str, Any]:
        """Create a summary dict from a ScanResult."""
        risk = result.risk_score
        return {
            "scan_id": result.scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": result.target_path,
            "risk_score": risk.overall_score if risk else 0,
            "risk_level": risk.risk_level.value if risk else "info",
            "total_findings": result.total_findings,
            "critical": risk.critical_count if risk else 0,
            "high": risk.high_count if risk else 0,
            "medium": risk.medium_count if risk else 0,
            "low": risk.low_count if risk else 0,
            "secrets": len(result.secrets),
            "payment": len(result.payment_findings),
            "deps": len(result.dep_vulnerabilities),
            "files_scanned": result.stats.total_files_scanned,
            "duration": result.stats.scan_duration_seconds,
            "finding_ids": [f.rule_id + ":" + f.file_path + ":" + str(f.line_number)
                           for f in result.findings[:500]],
        }

    def _calculate_delta(self, previous: Dict, current: Dict) -> Dict[str, Any]:
        """Calculate delta between two scan summaries."""
        prev_score = previous.get("risk_score", 0)
        curr_score = current.get("risk_score", 0)
        score_delta = curr_score - prev_score

        prev_findings = set(previous.get("finding_ids", []))
        curr_findings = set(current.get("finding_ids", []))

        fixed = prev_findings - curr_findings
        new = curr_findings - prev_findings

        # Trend determination
        if score_delta < -10:
            trend = "improving"
        elif score_delta > 10:
            trend = "degrading"
        else:
            trend = "stable"

        return {
            "status": "compared",
            "trend": trend,
            "previous_scan_id": previous.get("scan_id", "unknown"),
            "previous_timestamp": previous.get("timestamp", ""),
            "score": {
                "previous": prev_score,
                "current": curr_score,
                "delta": round(score_delta, 1),
                "change_pct": round(score_delta / max(prev_score, 1) * 100, 1),
            },
            "findings": {
                "previous": previous.get("total_findings", 0),
                "current": current.get("total_findings", 0),
                "new": len(new),
                "fixed": len(fixed),
            },
            "severity": {
                "critical": {"prev": previous.get("critical", 0), "curr": current.get("critical", 0)},
                "high": {"prev": previous.get("high", 0), "curr": current.get("high", 0)},
                "medium": {"prev": previous.get("medium", 0), "curr": current.get("medium", 0)},
                "low": {"prev": previous.get("low", 0), "curr": current.get("low", 0)},
            },
        }


def format_trend_report(delta: Dict[str, Any]) -> str:
    """Format a delta report for CLI display."""
    if delta.get("status") == "first_scan":
        return "First scan — no previous data to compare."

    lines = []
    trend = delta.get("trend", "unknown")
    emoji = {"improving": "↓", "degrading": "↑", "stable": "→"}.get(trend, "?")
    lines.append(f"Trend: {emoji} {trend.upper()}")

    score = delta.get("score", {})
    lines.append(f"Risk Score: {score.get('previous', 0)} → {score.get('current', 0)} "
                 f"({score.get('delta', 0):+.1f}, {score.get('change_pct', 0):+.1f}%)")

    findings = delta.get("findings", {})
    lines.append(f"Findings: {findings.get('previous', 0)} → {findings.get('current', 0)} "
                 f"(+{findings.get('new', 0)} new, -{findings.get('fixed', 0)} fixed)")

    sev = delta.get("severity", {})
    for level in ("critical", "high", "medium", "low"):
        s = sev.get(level, {})
        prev = s.get("prev", 0)
        curr = s.get("curr", 0)
        diff = curr - prev
        if diff != 0:
            lines.append(f"  {level}: {prev} → {curr} ({diff:+d})")

    return "\n".join(lines)
