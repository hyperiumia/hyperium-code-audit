"""Tests for the taint analyzer."""

import pytest
from pathlib import Path
from src.taint_analyzer import TaintAnalyzer, parse_suppressions, is_suppressed


class TestTaintAnalyzer:
    def test_detects_tainted_sql(self, tmp_path):
        code = tmp_path / "tainted.py"
        code.write_text(
            "from flask import request\n"
            "import sqlite3\n\n"
            "def get_user():\n"
            "    uid = request.args.get('id')\n"
            "    conn = sqlite3.connect('db.sqlite')\n"
            "    conn.execute('SELECT * FROM users WHERE id = ' + uid)\n"
        )
        analyzer = TaintAnalyzer()
        findings = analyzer.scan_file(code)
        assert len(findings) >= 1
        assert any(f.confidence >= 0.9 for f in findings)

    def test_detects_tainted_eval(self, tmp_path):
        code = tmp_path / "tainted_eval.py"
        code.write_text(
            "from flask import request\n\n"
            "def process():\n"
            "    data = request.args.get('code')\n"
            "    result = eval(data)\n"
        )
        analyzer = TaintAnalyzer()
        findings = analyzer.scan_file(code)
        assert len(findings) >= 1

    def test_detects_tainted_os_system(self, tmp_path):
        code = tmp_path / "tainted_cmd.py"
        code.write_text(
            "from flask import request\n"
            "import os\n\n"
            "def ping():\n"
            "    host = request.args.get('host')\n"
            "    os.system('ping -c 1 ' + host)\n"
        )
        analyzer = TaintAnalyzer()
        findings = analyzer.scan_file(code)
        assert len(findings) >= 1

    def test_no_false_positive_constant(self, tmp_path):
        code = tmp_path / "safe.py"
        code.write_text(
            "import os\n\n"
            "def ping():\n"
            "    host = '8.8.8.8'\n"
            "    os.system('ping -c 1 ' + host)\n"
        )
        analyzer = TaintAnalyzer()
        findings = analyzer.scan_file(code)
        assert len(findings) == 0

    def test_fstring_taint(self, tmp_path):
        code = tmp_path / "fstring.py"
        code.write_text(
            "from flask import request\n"
            "import os\n\n"
            "def ping():\n"
            "    host = request.args.get('host')\n"
            "    os.system(f'ping -c 1 {host}')\n"
        )
        analyzer = TaintAnalyzer()
        findings = analyzer.scan_file(code)
        assert len(findings) >= 1

    def test_non_python_returns_empty(self, tmp_path):
        code = tmp_path / "app.js"
        code.write_text("console.log('hello')")
        analyzer = TaintAnalyzer()
        assert len(analyzer.scan_file(code)) == 0


class TestSuppression:
    def test_parse_single(self):
        src = "execute(q)  # code-audit: ignore[GEN-SEC-001] -- safe"
        s = parse_suppressions(src)
        assert 1 in s
        assert s[1][0].rule_id == "GEN-SEC-001"

    def test_parse_multiple(self):
        src = "foo()  # code-audit: ignore[GEN-SEC-001,GEN-SEC-002]"
        s = parse_suppressions(src)
        assert 1 in s
        assert len(s[1]) == 2

    def test_parse_ignore_all(self):
        src = "bar()  # code-audit: ignore[all] -- fixture"
        s = parse_suppressions(src)
        assert 1 in s
        assert s[1][0].rule_id == "ALL"

    def test_is_suppressed_exact(self):
        from src.taint_analyzer import SuppressedRule
        s = {5: [SuppressedRule(rule_id="GEN-SEC-001", reason="")]}
        assert is_suppressed("GEN-SEC-001", 5, s) is True
        assert is_suppressed("GEN-SEC-002", 5, s) is False

    def test_is_suppressed_all(self):
        from src.taint_analyzer import SuppressedRule
        s = {5: [SuppressedRule(rule_id="ALL", reason="")]}
        assert is_suppressed("ANYTHING", 5, s) is True

    def test_no_suppression(self):
        assert is_suppressed("GEN-SEC-001", 5, {}) is False
