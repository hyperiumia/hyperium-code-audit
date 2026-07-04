"""Shared fixtures for Code-Audit tests."""

import pytest
from pathlib import Path


@pytest.fixture
def tmp_source_dir(tmp_path):
    py = tmp_path / "vulnerable.py"
    py.write_text(
        "import os\nimport hashlib\nimport sqlite3\n\n"
        "def get_user(uid):\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    c = conn.cursor()\n"
        "    c.execute('SELECT * FROM users WHERE id = ' + uid)\n"
        "    return c.fetchone()\n\n"
        "def run_cmd(user_input):\n"
        "    os.system(f'ping {user_input}')\n\n"
        "def hash_pw(pw):\n"
        "    return hashlib.md5(pw.encode()).hexdigest()\n\n"
        "DB_URL = 'postgresql://admin:Secret123!@db.prod.internal:5432/main'\n\n"
        "def dyn(user_data):\n"
        "    eval(user_data)\n\n"
        "def read(user_filename):\n"
        "    with open('/uploads/' + user_filename) as f:\n"
        "        return f.read()\n"
    )

    # Build payment key at runtime to avoid GitHub secret scanning
    sk_prefix = "sk_" + "live_"
    sk_suffix = "FakeTestKey001234567890abcdef"
    mp_prefix = "APP_USR-"
    mp_suffix = "1234567890123-1234567890123-abcdef0123456789abcdef0123456789-abcdef0123456789abcdef0123456789"

    js = tmp_path / "app.js"
    js.write_text(
        "const { exec } = require('child_process');\n\n"
        "function renderUser(name) {\n"
        "    document.getElementById('output').innerHTML = name;\n"
        "}\n\n"
        f"const stripe_key = '{sk_prefix}{sk_suffix}';\n"
        f"const mp_token = '{mp_prefix}{mp_suffix}';\n\n"
        "function procTpl(user_input) {\n"
        "    return eval(user_input);\n"
        "}\n"
    )

    env = tmp_path / ".env"
    env.write_text(
        "DATABASE_URL=postgres://root:password123@db.internal:5432/prod\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "JWT_SECRET=my_super_secret_jwt_key_12345\n"
    )

    req = tmp_path / "requirements.txt"
    req.write_text(
        "Django==3.0.0\nrequests==2.20.0\nPyYAML==5.1\n"
        "Jinja2==2.10.1\ncryptography==2.1.4\npillow==8.0.0\n"
    )

    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{"name":"vuln-app","version":"1.0.0","dependencies":{'
        '"express":"4.17.0","lodash":"4.17.15","axios":"0.19.0",'
        '"jsonwebtoken":"8.5.0","node-fetch":"2.6.0"}}'
    )

    return tmp_path


@pytest.fixture
def sample_finding():
    from src.models import Finding, FindingCategory, Severity, Language
    return Finding(
        rule_id="PY-SEC-001",
        title="SQL Injection via string concatenation",
        category=FindingCategory.INJECTION,
        severity=Severity.CRITICAL,
        confidence=0.9,
        file_path="app.py",
        line_number=8,
        code_snippet='c.execute("SELECT * WHERE id = " + uid)',
        language=Language.PYTHON,
        cwe_id="CWE-89",
        owasp_id="A03",
        description="SQL query built with string concatenation",
        remediation="Use parameterized queries",
    )


@pytest.fixture
def sample_config():
    from src.config import CodeAuditConfig
    return CodeAuditConfig()
