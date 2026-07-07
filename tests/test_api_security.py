"""Tests for API security scanner."""

import pytest
from pathlib import Path
from src.api_security import APISecurityScanner
from src.models import Language


class TestAPISecurity:
    def test_detect_cors_wildcard_python(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("from flask import Flask\nfrom flask_cors import CORS\napp = Flask(__name__)\nCORS(app, origins='*')\n")
        scanner = APISecurityScanner()
        findings = scanner.scan_file(f, Language.PYTHON)
        titles = [x.title for x in findings]
        assert any("cors" in t.lower() for t in titles)

    def test_detect_debug_mode(self, tmp_path):
        f = tmp_path / "settings.py"
        f.write_text("DEBUG = True\nSECRET_KEY = 'test'\n")
        scanner = APISecurityScanner()
        findings = scanner.scan_file(f, Language.PYTHON)
        titles = [x.title for x in findings]
        assert any("debug" in t.lower() for t in titles)

    def test_detect_cors_wildcard_js(self, tmp_path):
        f = tmp_path / "server.js"
        f.write_text("const express = require('express');\nconst app = express();\napp.use(cors({ origin: '*' }));\n")
        scanner = APISecurityScanner()
        findings = scanner.scan_file(f, Language.JAVASCRIPT)
        titles = [x.title for x in findings]
        assert any("cors" in t.lower() for t in titles)

    def test_clean_code(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("from flask import Flask\napp = Flask(__name__)\nDEBUG = False\n")
        scanner = APISecurityScanner()
        findings = scanner.scan_file(f, Language.PYTHON)
        assert len(findings) == 0
