"""
Checkpoint Manager — Persists scan progress for resume capability.

Based on the Q-Audit Pro checkpoint pattern.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CheckpointManager:
    """Manages scan checkpoint persistence and resume."""

    def __init__(
        self,
        checkpoint_dir: str = ".code_audit_checkpoints",
        interval_files: int = 50,
        auto_resume: bool = True,
        max_age_hours: int = 24,
        cleanup_on_success: bool = True,
    ):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.interval_files = interval_files
        self.auto_resume = auto_resume
        self.max_age_hours = max_age_hours
        self.cleanup_on_success = cleanup_on_success
        self._state: Dict[str, Any] = {}
        self._files_since_save: int = 0

    def start_scan(self, scan_id: str, config_hash: str, total_files: int) -> Dict[str, Any]:
        """Start a new scan or resume from checkpoint."""
        existing = self._load(scan_id)
        if self.auto_resume and existing and existing.get("config_hash") == config_hash:
            if existing.get("is_complete"):
                return {}
            logger.info(f"Resuming scan {scan_id} from checkpoint")
            self._state = existing
            return existing

        self._state = {
            "scan_id": scan_id,
            "config_hash": config_hash,
            "total_files": total_files,
            "files_scanned": 0,
            "current_phase": "discovering",
            "phases_completed": [],
            "findings_count": 0,
            "is_complete": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "errors": [],
        }
        self._save()
        return self._state

    def update_phase(self, phase: str) -> None:
        self._state["current_phase"] = phase
        self._save()

    def record_progress(self, files_processed: int = 1, findings_count: int = 0) -> bool:
        """Record scan progress. Returns True if checkpoint was saved."""
        self._state["files_scanned"] = self._state.get("files_scanned", 0) + files_processed
        self._state["findings_count"] = self._state.get("findings_count", 0) + findings_count
        self._files_since_save += files_processed

        if self._files_since_save >= self.interval_files:
            self._files_since_save = 0
            self._save()
            return True
        return False

    def complete_phase(self, phase: str) -> None:
        self._state.setdefault("phases_completed", []).append(phase)
        self._save()

    def record_error(self, error: str) -> None:
        self._state.setdefault("errors", []).append(error)

    def complete_scan(self, scan_id: str) -> None:
        self._state["is_complete"] = True
        self._save()
        if self.cleanup_on_success:
            self._cleanup(scan_id)

    def should_skip_file(self, file_path: str) -> bool:
        """Check if a file was already scanned in a previous checkpoint run."""
        scanned = self._state.get("scanned_files", set())
        if isinstance(scanned, list):
            scanned = set(scanned)
        return file_path in scanned

    def _save(self) -> None:
        self._state["updated_at"] = datetime.now(timezone.utc).isoformat()
        scan_id = self._state.get("scan_id", "unknown")
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        path = self.checkpoint_dir / f"{scan_id}.json"
        try:
            # Convert sets to lists for JSON
            state_copy = {}
            for k, v in self._state.items():
                state_copy[k] = list(v) if isinstance(v, set) else v
            path.write_text(json.dumps(state_copy, indent=2, default=str))
        except Exception as e:
            logger.debug(f"Checkpoint save failed: {e}")

    def _load(self, scan_id: str) -> Optional[Dict[str, Any]]:
        path = self.checkpoint_dir / f"{scan_id}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            created = datetime.fromisoformat(data["created_at"])
            if datetime.now(timezone.utc) - created > timedelta(hours=self.max_age_hours):
                path.unlink()
                return None
            return data
        except Exception:
            return None

    def _cleanup(self, scan_id: str) -> None:
        path = self.checkpoint_dir / f"{scan_id}.json"
        if path.exists():
            path.unlink()
