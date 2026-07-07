"""Tests for incremental scanning."""

import pytest
from src.incremental import is_git_repo, get_changed_files


class TestIncremental:
    def test_detects_git_repo(self):
        assert is_git_repo(".") is True

    def test_not_git_repo(self, tmp_path):
        assert is_git_repo(str(tmp_path)) is False

    def test_get_changed_files_returns_list(self):
        result = get_changed_files(".", "HEAD~5")
        # Should return a list (possibly empty) or None
        assert result is None or isinstance(result, list)

    def test_invalid_ref_returns_none(self):
        result = get_changed_files(".", "nonexistent_ref_12345")
        assert result is None
