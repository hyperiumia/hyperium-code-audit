"""
Main scan engine — orchestrates the full security scan pipeline.

Pipeline phases:
  1. DISCOVER  — Find all source files
  2. SCAN      — Run all scanners (patterns, secrets, payments, AST, deps)
  3. TRIAGE    — Risk scoring and prioritization
  4. COMPLIANCE — Map to frameworks
  5. REPORT    — Generate output
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from src.models import (
    Finding, ScanResult, ScanStats,
)
from src.config import CodeAuditConfig
from src.pattern_scanner import PatternScanner, detect_language
from src.secret_detector import SecretDetector
from src.payment_scanner import PaymentScanner
from src.dep_analyzer import DepAnalyzer
from src.ast_engine import ASTEngine
from src.triage_engine import TriageEngine
from src.compliance_mapper import ComplianceMapper
from src.checkpoint_manager import CheckpointManager

logger = logging.getLogger(__name__)


# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php",
    ".java", ".go", ".cs", ".rb", ".html", ".htm",
    ".vue", ".ejs", ".hbs", ".env", ".yaml", ".yml",
    ".json", ".xml", ".toml", ".cfg", ".ini", ".conf",
}


class CodeAuditEngine:
    """Main scan engine — orchestrates all scanners."""

    def __init__(self, config: Optional[CodeAuditConfig] = None):
        self.config = config or CodeAuditConfig()
        self._progress_callback: Optional[Callable] = None

        # Initialize scanners
        self.pattern_scanner = PatternScanner(
            min_confidence=self.config.scanners.min_confidence,
            exclude_rules=self.config.scanners.exclude_rules,
        )
        self.secret_detector = SecretDetector(
            entropy_threshold=self.config.scanners.entropy_threshold,
            scan_env_files=self.config.scanners.scan_env_files,
        )
        self.payment_scanner = PaymentScanner()
        self.dep_analyzer = DepAnalyzer(
            check_epss=self.config.scanners.check_epss,
            check_cisa_kev=self.config.scanners.check_cisa_kev,
            timeout=self.config.scanners.dep_api_timeout,
        )
        self.ast_engine = ASTEngine()
        self.triage_engine = TriageEngine(
            critical_paths=self.config.analysis.asset_criticality.get("critical_paths", []),
        )
        self.compliance_mapper = ComplianceMapper(
            frameworks=self.config.analysis.frameworks,
        )
        self.checkpoint_mgr = CheckpointManager(
            checkpoint_dir=self.config.checkpoint.checkpoint_dir,
            auto_resume=self.config.checkpoint.auto_resume,
            cleanup_on_success=self.config.checkpoint.cleanup_on_success,
        )

    def set_progress_callback(self, callback: Callable) -> None:
        self._progress_callback = callback

    def _report(self, phase: str, message: str, progress: int = 0) -> None:
        if self._progress_callback:
            self._progress_callback(phase, message, progress)

    def scan(self, target_path: Optional[str] = None) -> ScanResult:
        """Execute a full security scan."""
        target = Path(target_path or self.config.scan.paths[0])
        started = time.monotonic()

        result = ScanResult(
            target_path=str(target),
            started_at=datetime.now(timezone.utc).isoformat(),
            tool_version="1.0.0",
        )

        # Config hash for checkpoint validation
        config_hash = hashlib.sha256(
            str(self.config.model_dump()).encode()
        ).hexdigest()[:16]

        self.checkpoint_mgr.start_scan(result.scan_id, config_hash, 0)

        try:
            # Phase 1: Discover files
            self._report("DISCOVER", "Finding source files...", 5)
            self.checkpoint_mgr.update_phase("discover")
            source_files = self._discover_files(target)
            result.stats.total_files_discovered = len(source_files)
            self.checkpoint_mgr._state["total_files"] = len(source_files)
            self._report("DISCOVER", f"Found {len(source_files)} source files", 10)

            # Phase 2: Pattern + AST scanning
            self._report("SCAN", "Running pattern scanner...", 15)
            self.checkpoint_mgr.update_phase("pattern_scan")
            for i, fp in enumerate(source_files):
                lang = detect_language(fp)
                if self.config.scanners.pattern_scanner:
                    result.findings.extend(self.pattern_scanner.scan_file(fp, lang))
                if self.config.scanners.ast_engine and lang.value == "python":
                    result.findings.extend(self.ast_engine.scan_file(fp, lang))
                self.checkpoint_mgr.record_progress(1)
                if (i + 1) % 100 == 0:
                    self._report("SCAN", f"Scanned {i+1}/{len(source_files)} files", 15 + int(30 * i / max(len(source_files), 1)))
            self.checkpoint_mgr.complete_phase("pattern_scan")

            # Phase 3: Secret detection
            self._report("SECRETS", "Scanning for hardcoded secrets...", 50)
            self.checkpoint_mgr.update_phase("secret_scan")
            if self.config.scanners.secret_detector:
                result.secrets = self.secret_detector.scan_files(source_files)
            self.checkpoint_mgr.complete_phase("secret_scan")

            # Phase 4: Payment scanning
            self._report("PAYMENT", "Scanning for payment exposures...", 60)
            self.checkpoint_mgr.update_phase("payment_scan")
            if self.config.scanners.payment_scanner:
                result.payment_findings = self.payment_scanner.scan_files(source_files)
            self.checkpoint_mgr.complete_phase("payment_scan")

            # Phase 5: Dependency analysis
            self._report("DEPS", "Analyzing dependencies...", 70)
            self.checkpoint_mgr.update_phase("dep_scan")
            if self.config.scanners.dep_analyzer:
                result.dep_vulnerabilities = self.dep_analyzer.scan_directory(target)
            self.checkpoint_mgr.complete_phase("dep_scan")

            # Phase 6: Triage
            self._report("TRIAGE", "Calculating risk score...", 80)
            self.checkpoint_mgr.update_phase("triage")
            result.risk_score = self.triage_engine.score(
                findings=result.findings,
                secrets=result.secrets,
                payment_findings=result.payment_findings,
                dep_vulns=result.dep_vulnerabilities,
            )
            # Prioritize findings
            result.findings = self.triage_engine.prioritize(result.findings)
            self.checkpoint_mgr.complete_phase("triage")

            # Phase 7: Compliance
            self._report("COMPLIANCE", "Mapping to compliance frameworks...", 90)
            self.checkpoint_mgr.update_phase("compliance")
            result.compliance_reports = self.compliance_mapper.map_findings(
                result.findings, result.payment_findings,
            )
            self.checkpoint_mgr.complete_phase("compliance")

        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            self.checkpoint_mgr.record_error(str(e))
        finally:
            # Finalize
            elapsed = time.monotonic() - started
            result.completed_at = datetime.now(timezone.utc).isoformat()
            result.stats.total_files_scanned = len(source_files) if 'source_files' in dir() else 0
            result.stats.scan_duration_seconds = round(elapsed, 2)
            result.stats.files_by_language = self._count_by_lang(source_files) if 'source_files' in dir() else {}

            self.checkpoint_mgr.complete_scan(result.scan_id)
            self._report("DONE", f"Scan complete in {elapsed:.1f}s — {result.total_findings} findings", 100)

        return result

    def _discover_files(self, target: Path) -> List[Path]:
        """Discover all scannable source files."""
        files: List[Path] = []
        exclude = set(self.config.scan.exclude_patterns)
        max_size = self.config.scan.max_file_size_kb * 1024

        if target.is_file():
            return [target]

        for path in target.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            if any(path.match(pat) for pat in exclude):
                continue
            try:
                if path.stat().st_size > max_size:
                    result.stats.skipped_files += 1
                    continue
            except Exception:
                continue
            files.append(path)

        return files

    def _count_by_lang(self, files: List[Path]) -> dict:
        counts: dict = {}
        for f in files:
            lang = detect_language(f).value
            counts[lang] = counts.get(lang, 0) + 1
        return counts
