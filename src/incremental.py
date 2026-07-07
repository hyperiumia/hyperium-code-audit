"""
Incremental Scanning — only scan files changed since a given git ref.

Uses git diff to determine which files changed, then filters
the file list to only those files. Dramatically reduces scan
time for large projects on PR/Push workflows.

Usage:
  code-audit scan . --since HEAD~1
  code-audit scan . --since main
  code-audit scan . --since v3.0.0
"""

from __future__ import annotations
import logging
import subprocess
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


def get_changed_files(repo_path: str, since_ref: str) -> Optional[List[Path]]:
    """Get list of files changed since a git reference.

    Args:
        repo_path: Path to the git repository root.
        since_ref: Git ref to compare against (branch, tag, commit, HEAD~N).

    Returns:
        List of changed file paths, or None if not a git repo or git not available.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", since_ref, "HEAD"],
            capture_output=True, text=True, cwd=repo_path, timeout=30,
        )
        if result.returncode != 0:
            logger.warning(f"git diff failed: {result.stderr.strip()}")
            return None

        files = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                fp = Path(repo_path) / line
                if fp.exists():
                    files.append(fp)

        logger.info(f"Found {len(files)} changed files since {since_ref}")
        return files

    except FileNotFoundError:
        logger.info("git not found, falling back to full scan")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("git diff timed out, falling back to full scan")
        return None
    except Exception as e:
        logger.warning(f"Incremental scan failed: {e}")
        return None


def is_git_repo(path: str) -> bool:
    """Check if path is inside a git repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, cwd=path, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False
