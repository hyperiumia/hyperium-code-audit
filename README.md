# Hyperium Code-Audit

### Production-Grade SAST Scanner — v4.0

![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-120%20passing-brightgreen)
![Version](https://img.shields.io/badge/version-4.0.0-purple)
![License](https://img.shields.io/badge/license-MIT-green)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-orange)

**Scan your source code for OWASP Top 10 vulnerabilities, hardcoded secrets, payment gateway exposures, vulnerable dependencies, and infrastructure misconfigurations — in seconds.**

[Quick Start](#quick-start) · [Features](#features) · [Comparison](#comparison) · [CLI](#cli-usage) · [CI/CD](#cicd-integration) · [Architecture](#architecture)

---

## Quick Start

```bash
# Install
pip install hyperium-code-audit

# Scan your project
code-audit scan ./my-project

# Scan with SARIF output for GitHub Security tab
code-audit scan ./my-project --format sarif --fail-on critical
What It Scans

Category	What It Finds
OWASP Top 10	SQL injection, XSS, SSRF, command injection, path traversal, insecure deserialization
Hardcoded Secrets	AWS keys, Stripe, GitHub tokens, JWT, database URLs, private keys — 20+ patterns
Payment Gateways	Stripe, MercadoPago, PayPal, Conekta, Culqi, Wompi, Square + payment logic
Dependencies	65 real CVEs across 30 popular Python and JavaScript packages
Infrastructure	Dockerfile, Terraform, Kubernetes misconfigurations
API Security	Missing auth, CORS wildcards, debug mode, error detail leaks
Taint Analysis	Data-flow tracking from user input to dangerous sinks (Python)


Features

Pattern Scanner — 22 OWASP Rules

Category	OWASP	Examples
SQL Injection	A03	String concat in queries, unsafe formatting
Command Injection	A03	os.system, child_process.exec with user input
XSS	A03	innerHTML, document.write, template injection
SSRF	A10	requests.get with user-controlled URLs
Path Traversal	A01	File operations with user-controlled paths
Insecure Deserialization	A08	pickle.loads, ObjectInputStream
Crypto Failures	A02	MD5/SHA1 passwords, verify=False
Broken Auth	A07	Plaintext passwords, default credentials
Debug Mode	A05	DEBUG=True in production

Languages: Python, JavaScript, TypeScript, PHP, Java, Go, C#, Ruby


Taint Analysis (Python)

Data-flow tracking from user input to dangerous sinks:


text
Source (request.args.get("id"))
  → sanitize check (int(), escape(), parameterized)
  → Sink (cursor.execute())
Source (request.args.get("id"))
  → sanitize check (int(), escape(), parameterized)
  → Sink (cursor.execute())

Sources: Flask, Django, FastAPI request data
Sinks: SQL, cmd, eval, file, SSRF, deserialization
Sanitizers: int(), escape(), parameterized queries, allowlists

AST Engine — Python + JS/TS

Python: Abstract Syntax Tree analysis for high-confidence findings beyond regex
JavaScript/TypeScript: Tree-sitter based analysis detecting eval(), XSS (innerHTML), command injection, SQL in template literals

Secret Detector — 20 Patterns + Verification

AWS · Stripe · MercadoPago · GitHub · JWT · Database URLs · Private Keys · Google · Slack · Twilio · SendGrid · Conekta · Culqi · OpenAI · Generic high-entropy secrets


Verification (opt-in --verify-secrets):

Format validation against known key patterns
Shannon entropy scoring (high entropy = likely real)
Confidence boost/penalty based on verification result

Payment Scanner — 7 Gateways + Logic Analysis

Gateway	Key Types	PCI Flag
Stripe	Live/Test/Restricted/Webhook	Yes
MercadoPago	Live/Test/Public	Yes
PayPal	Client Secret/Webhook	Yes
Conekta	Live/Test	Yes
Culqi	Live/Test	Yes
Wompi	Private/Public/Integrity	Yes
Square	Live Secret	Yes

Payment Logic Analysis checks for:

Missing webhook signature verification
Missing idempotency keys on charge operations
Client-trusted payment amounts (no server validation)
Sensitive data in payment error responses

Dependency Analyzer

Checks requirements.txt and package.json against an offline CVE database containing 65 real CVEs across 30 packages — no network required.


Packages tracked include: Django, Flask, Requests, PyYAML, Jinja2, Pillow, cryptography, urllib3, Werkzeug, aiohttp, lodash, express, axios, jsonwebtoken, node-fetch, and 15 more.


Infrastructure as Code (v4.0)

Scans IaC files for security misconfigurations:


Dockerfile:

Running as root, secrets in ENV, :latest tags, ADD vs COPY, curl piped to shell, insecure port exposure

Terraform:

Public S3 buckets, exposed RDS instances, 0.0.0.0/0 security groups, unencrypted storage, hardcoded passwords, disabled logging

Kubernetes:

Privileged containers, hostNetwork, hostPID, allowPrivilegeEscalation, missing resource limits, secrets in manifests

API Security (v4.0)

Detects common API security issues across Python and JavaScript:


CORS wildcard (*) origins
Debug mode enabled in production
Endpoints without authentication decorators
Error detail / stack trace leaks in responses
API endpoints using HTTP instead of HTTPS

Incremental Scanning (v4.0)

Scan only files changed since a git reference — ideal for PR/push workflows:


bash
code-audit scan . --since HEAD~1    # Files changed in last commit
code-audit scan . --since main      # Files changed since main branch
code-audit scan . --since v3.0.0    # Files changed since tag
code-audit scan . --since HEAD~1    # Files changed in last commit
code-audit scan . --since main      # Files changed since main branch
code-audit scan . --since v3.0.0    # Files changed since tag

Risk Scoring

Weighted model: Score = (severity x confidence x path_criticality x exploit_multiplier)


Compliance Mapping

Maps every finding to OWASP Top 10 2021 with gap scoring per category.


Custom Rules Engine

Define your own vulnerability rules in YAML — no Python needed:


yaml
rules:
  - id: CUSTOM-001
    title: "API endpoint without rate limiting"
    severity: medium
    category: security_misconfig
    cwe_id: CWE-770
    languages: [python]
    pattern: '@app\.route\([^)]+\)\ndef (?!.*limiter)'
    remediation: "Add rate limiting decorator"
    confidence: 0.6
rules:
  - id: CUSTOM-001
    title: "API endpoint without rate limiting"
    severity: medium
    category: security_misconfig
    cwe_id: CWE-770
    languages: [python]
    pattern: '@app\.route\([^)]+\)\ndef (?!.*limiter)'
    remediation: "Add rate limiting decorator"
    confidence: 0.6

bash
code-audit rules                             # Generate example rules file
code-audit scan . --custom-rules my-rules.yaml
code-audit rules                             # Generate example rules file
code-audit scan . --custom-rules my-rules.yaml

Export Formats

HTML — Self-contained single-file report with interactive dashboard
JSON — Machine-readable for CI integration
SARIF v2.1.0 — GitHub/GitLab/Azure Security tab integration
PDF — Executive report (requires reportlab)

Scan Trending

Track your security posture over time:


bash
code-audit scan .        # Auto-saves to history
code-audit trend         # View trend: improving / degrading / stable
code-audit scan .        # Auto-saves to history
code-audit trend         # View trend: improving / degrading / stable

Shows delta between scans: new findings, fixed findings, severity changes, risk score trajectory.


Suppression Comments

Suppress specific findings inline:


python
cursor.execute(query)  # code-audit: ignore[PY-SEC-001] -- parameterized above
cursor.execute(query)  # code-audit: ignore[PY-SEC-001] -- parameterized above


Comparison

Feature	Code-Audit	Semgrep	Bandit	Snyk Code
OWASP Top 10 patterns (22 rules)	Yes	Yes	Partial	Yes
Python AST analysis	Yes	Yes	Yes	Yes
JS/TS AST (tree-sitter)	Yes	Yes	No	Yes
Taint analysis (Python)	Yes	Yes	No	Partial
Secret detection (20 patterns)	Yes	No	No	Yes
Secret verification (entropy)	Yes	No	No	No
Payment gateway scan (7)	Yes	No	No	No
Payment logic analysis	Yes	No	No	No
Dependency CVE check (65 CVEs)	Yes	No	No	Yes
IaC scanning (Dockerfile/Terraform/K8s)	Yes	Partial	No	Yes
API security rules	Yes	No	No	No
Incremental scan (git diff)	Yes	No	No	No
Custom rules (YAML)	Yes	Yes	No	No
SARIF export	Yes	Yes	No	Yes
PDF reports	Yes	No	No	No
Scan trending	Yes	No	No	No
Granular CI exit codes	Yes	Yes	Yes	Yes
Offline operation	Yes	Yes	Yes	No


CLI Usage

bash
# Basic scan — generates HTML report
code-audit scan ./my-project

# JSON output for CI integration
code-audit scan ./my-project --format json

# SARIF for GitHub Security tab
code-audit scan ./my-project --format sarif

# All formats (HTML + JSON + SARIF + PDF)
code-audit scan ./my-project --format all

# Incremental scan — only changed files
code-audit scan . --since HEAD~1
code-audit scan . --since main

# CI mode: exit 1 if critical findings exist
code-audit scan . --fail-on critical

# Verify secret format + entropy scoring
code-audit scan . --verify-secrets

# Use custom rules
code-audit scan . --custom-rules my-rules.yaml

# Skip specific scanners
code-audit scan . --no-deps --no-payment --no-taint

# Minimum confidence threshold
code-audit scan . --min-confidence 0.8

# View security trend
code-audit trend

# Generate example custom rules file
code-audit rules
# Basic scan — generates HTML report
code-audit scan ./my-project

# JSON output for CI integration
code-audit scan ./my-project --format json

# SARIF for GitHub Security tab
code-audit scan ./my-project --format sarif

# All formats (HTML + JSON + SARIF + PDF)
code-audit scan ./my-project --format all

# Incremental scan — only changed files
code-audit scan . --since HEAD~1
code-audit scan . --since main

# CI mode: exit 1 if critical findings exist
code-audit scan . --fail-on critical

# Verify secret format + entropy scoring
code-audit scan . --verify-secrets

# Use custom rules
code-audit scan . --custom-rules my-rules.yaml

# Skip specific scanners
code-audit scan . --no-deps --no-payment --no-taint

# Minimum confidence threshold
code-audit scan . --min-confidence 0.8

# View security trend
code-audit trend

# Generate example custom rules file
code-audit rules

CI/CD Exit Codes

bash
code-audit scan . --fail-on critical   # Exit 1 if any critical findings
code-audit scan . --fail-on high       # Exit 1 if high or critical
code-audit scan . --fail-on medium     # Exit 1 if medium or above
code-audit scan . --fail-on never      # Always exit 0, just report
code-audit scan . --fail-on critical   # Exit 1 if any critical findings
code-audit scan . --fail-on high       # Exit 1 if high or critical
code-audit scan . --fail-on medium     # Exit 1 if medium or above
code-audit scan . --fail-on never      # Always exit 0, just report


CI/CD Integration

GitHub Actions

yaml
name: Security Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  code-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install hyperium-code-audit
      - run: code-audit scan . --format sarif --fail-on critical
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: reports/ }
name: Security Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  code-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install hyperium-code-audit
      - run: code-audit scan . --format sarif --fail-on critical
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: reports/ }

Or use the composite action:


yaml
name: Security Scan
on: [push, pull_request]
jobs:
  code-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: hyperiumia/hyperium-code-audit@v4
        with:
          path: "."
          format: "sarif"
          fail-on: "critical"
name: Security Scan
on: [push, pull_request]
jobs:
  code-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: hyperiumia/hyperium-code-audit@v4
        with:
          path: "."
          format: "sarif"
          fail-on: "critical"

GitLab CI

yaml
code-audit:
  image: python:3.12-slim
  script:
    - pip install hyperium-code-audit
    - code-audit scan . --format sarif --fail-on critical
  artifacts:
    reports:
      sast: reports/*.sarif
code-audit:
  image: python:3.12-slim
  script:
    - pip install hyperium-code-audit
    - code-audit scan . --format sarif --fail-on critical
  artifacts:
    reports:
      sast: reports/*.sarif

Bitbucket Pipelines

yaml
pipelines:
  default:
    - step:
        name: Security Scan
        image: python:3.12
        script:
          - pip install hyperium-code-audit
          - code-audit scan . --format json --fail-on high
        artifacts:
          - reports/**
pipelines:
  default:
    - step:
        name: Security Scan
        image: python:3.12
        script:
          - pip install hyperium-code-audit
          - code-audit scan . --format json --fail-on high
        artifacts:
          - reports/**

Templates available in templates/.



Architecture

text
src/
  cli.py                 # Rich CLI interface (click + rich)
  engine.py              # Multi-phase scan pipeline orchestrator
  models.py              # Pydantic data models (15 models)
  config.py              # Configuration management

  # ── Scanning Engines ──
  pattern_scanner.py     # 22 OWASP Top 10 regex rules (8 languages)
  secret_detector.py     # 20 secret patterns + Shannon entropy
  secret_verifier.py     # Format validation + entropy scoring
  payment_scanner.py     # 7 payment gateways + Luhn check
  payment_logic.py       # Webhook, idempotency, amount analysis
  dep_analyzer.py        # CVE dependency analysis (65 CVEs)
  cve_database.py        # Offline CVE database (30 packages)
  ast_engine.py          # Python AST analysis
  js_ast_engine.py       # JS/TS tree-sitter AST
  taint_analyzer.py      # Python taint/data-flow analysis
  iac_scanner.py         # Dockerfile, Terraform, Kubernetes (v4.0)
  api_security.py        # API security rules (v4.0)
  incremental.py         # Git diff based scanning (v4.0)

  # ── Analysis & Reporting ──
  triage_engine.py       # Risk scoring + prioritization
  compliance_mapper.py   # OWASP Top 10 mapping
  custom_rules.py        # YAML custom rules engine
  scan_history.py        # Trending + delta analysis
  checkpoint_manager.py  # Scan persistence + resume
  sarif_exporter.py      # SARIF v2.1.0 export
  report_generator.py    # HTML + JSON reports
  pdf_report.py          # PDF generation (reportlab)
src/
  cli.py                 # Rich CLI interface (click + rich)
  engine.py              # Multi-phase scan pipeline orchestrator
  models.py              # Pydantic data models (15 models)
  config.py              # Configuration management

  # ── Scanning Engines ──
  pattern_scanner.py     # 22 OWASP Top 10 regex rules (8 languages)
  secret_detector.py     # 20 secret patterns + Shannon entropy
  secret_verifier.py     # Format validation + entropy scoring
  payment_scanner.py     # 7 payment gateways + Luhn check
  payment_logic.py       # Webhook, idempotency, amount analysis
  dep_analyzer.py        # CVE dependency analysis (65 CVEs)
  cve_database.py        # Offline CVE database (30 packages)
  ast_engine.py          # Python AST analysis
  js_ast_engine.py       # JS/TS tree-sitter AST
  taint_analyzer.py      # Python taint/data-flow analysis
  iac_scanner.py         # Dockerfile, Terraform, Kubernetes (v4.0)
  api_security.py        # API security rules (v4.0)
  incremental.py         # Git diff based scanning (v4.0)

  # ── Analysis & Reporting ──
  triage_engine.py       # Risk scoring + prioritization
  compliance_mapper.py   # OWASP Top 10 mapping
  custom_rules.py        # YAML custom rules engine
  scan_history.py        # Trending + delta analysis
  checkpoint_manager.py  # Scan persistence + resume
  sarif_exporter.py      # SARIF v2.1.0 export
  report_generator.py    # HTML + JSON reports
  pdf_report.py          # PDF generation (reportlab)

Scan Pipeline

text
Phase 0: INCREMENTAL  → Filter to changed files (if --since)
Phase 1: DISCOVER     → Find all source files
Phase 2: SCAN         → Pattern scanner + AST engine + Taint analysis
Phase 3: IaC          → Dockerfile + Terraform + Kubernetes (v4.0)
Phase 4: API          → API security rules (v4.0)
Phase 5: SECRETS      → Secret detector + verification
Phase 6: PAYMENT      → Payment gateway + logic analysis
Phase 7: DEPS         → Dependency CVE analyzer
Phase 8: TRIAGE       → Risk scoring + prioritization
Phase 9: COMPLIANCE   → OWASP Top 10 mapping
Phase 10: HISTORY     → Save scan for trending
Phase 11: REPORT      → HTML + JSON + SARIF + PDF generation
Phase 0: INCREMENTAL  → Filter to changed files (if --since)
Phase 1: DISCOVER     → Find all source files
Phase 2: SCAN         → Pattern scanner + AST engine + Taint analysis
Phase 3: IaC          → Dockerfile + Terraform + Kubernetes (v4.0)
Phase 4: API          → API security rules (v4.0)
Phase 5: SECRETS      → Secret detector + verification
Phase 6: PAYMENT      → Payment gateway + logic analysis
Phase 7: DEPS         → Dependency CVE analyzer
Phase 8: TRIAGE       → Risk scoring + prioritization
Phase 9: COMPLIANCE   → OWASP Top 10 mapping
Phase 10: HISTORY     → Save scan for trending
Phase 11: REPORT      → HTML + JSON + SARIF + PDF generation


Version History

Version	Tests	Highlights
v4.0	120	pip install, 65 CVEs, IaC scanning, API security, incremental scan, GitHub Action
v3.0	102	JS/TS AST, secret verification, payment logic, scan trending
v2.1	80	Custom rules (YAML), PDF reports, granular CI exit codes
v2.0	65	SARIF export, taint analysis, CI templates, suppression comments
v1.0	41	Pattern scanner, secret detector, payment scanner, risk scoring


Related Projects

Tool	Purpose
Hyperium Q-Audit Pro
Post-quantum cryptographic compliance audit
Hyperium TAT-PRO
Web application security reconnaissance


License

MIT — see LICENSE.



Built by 
Hyperium IA

