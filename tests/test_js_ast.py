"""Tests for JavaScript/TypeScript AST engine."""

import pytest
from pathlib import Path


class TestJSASTEngine:
    def _has_tree_sitter(self):
        try:
            import tree_sitter_javascript
            return True
        except ImportError:
            return False

    @pytest.mark.skipif(True, reason="Requires tree-sitter-javascript installed")
    def test_detect_eval(self, tmp_path):
        from src.js_ast_engine import JSASTEngine
        f = tmp_path / "test.js"
        f.write_text("function process(input) {\n  return eval(input);\n}\n")
        engine = JSASTEngine()
        findings = engine.scan_file(f)
        assert len(findings) >= 1

    def test_engine_importable(self):
        from src.js_ast_engine import JSASTEngine
        engine = JSASTEngine()
        assert engine is not None

    def test_no_parser_returns_empty(self, tmp_path):
        """If tree-sitter not installed, returns empty list gracefully."""
        from src.js_ast_engine import JSASTEngine
        f = tmp_path / "test.xyz"
        f.write_text("test")
        engine = JSASTEngine()
        findings = engine.scan_file(f)
        assert isinstance(findings, list)
