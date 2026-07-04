# Hyperium Code-Audit

### Production-Grade Source Code Security Scanner (SAST)

**Scan your source code for OWASP Top 10 vulnerabilities, hardcoded secrets, payment gateway exposures, and vulnerable dependencies — in seconds.**

[Getting Started](#getting-started) · [Features](#features) · [Architecture](#architecture) · [CLI Usage](#cli-usage)

---

## Why Code-Audit?

| Feature | Code-Audit | Semgrep | Bandit | Snyk Code |
|---------|:---:|:---:|:---:|:---:|
| OWASP Top 10 patterns | ✅ 22 rules | ✅ | Partial | ✅ |
| AST analysis (Python) | ✅ | ✅ | ✅ | ✅ |
| AST analysis (JS/TS) | ✅ tree-sitter | ✅ | ❌ | ✅ |
| Taint analysis (Python) | ✅ | ✅ | ❌ | Partial |
| Secret detection | ✅ 20 patterns | ❌ | ❌ | ✅ |
| Secret verification | ✅ format+entropy | ❌ | ❌ | ❌ |
| Payment gateway scan | ✅ 7 gateways | ❌ | ❌ | ❌ |
| Payment logic analysis | ✅ | ❌ | ❌ | ❌ |
| Dependency CVE check | ✅ | ❌ | ❌ | ✅ |
| Compliance mapping | ✅ OWASP | ❌ | ❌ | Partial |
| Custom rules (YAML) | ✅ | ✅ | ❌ | ❌ |
| SARIF export | ✅ | ✅ | ❌ | ✅ |
| PDF reports | ✅ | ❌ | ❌ | ❌ |
| Scan trending | ✅ | ❌ | ❌ | ❌ |
| CI exit codes | ✅ granular | ✅ | ✅ | ✅ |
| GitHub Action | ✅ | ✅ | ❌ | ✅ |
| Self-contained HTML report | ✅ | ❌ | ❌ | ❌ |
| Offline operation | ✅ | ✅ | ✅ | ❌ |
| LATAM payment gateways | ✅ | ❌ | ❌ | ❌ |

---

## Features

### 🔍 Pattern Scanner — 22 OWASP Rules

| Category | OWASP | Examples |
|----------|-------|----------|
| SQL Injection | A03 | String concat in queries, unsafe formatting |
| Command Injection | A03 | os.system, child_process.exec with user input |
| XSS | A03 | innerHTML, document.write, template injection |
| SSRF | A10 | requests.get with user-controlled URLs |
| Path Traversal | A01 | File operations with user-controlled paths |
| Insecure Deserialization | A08 | pickle.loads, ObjectInputStream |
| Crypto Failures | A02 | MD5/SHA1 passwords, verify=False |
| Broken Auth | A07 | Plaintext passwords, default credentials |
| Debug Mode | A05 | DEBUG=True in production |

**Languages:** Python, JavaScript, TypeScript, PHP, Java, Go, C#, Ruby

### 🧠 Taint Analysis (Python)

Data-flow tracking from user input to dangerous sinks:

Source (request.args.get("id"))
→ sanitize check (int(), escape(), parameterized)
→ Sink (cursor.execute())

text

- **Sources:** Flask, Django, FastAPI request data
- **Sinks:** SQL, cmd, eval, file, SSRF, deserialization
- **Sanitizers:** int(), escape(), parameterized queries, allowlists

### 🌲 AST Engine — Python + JS/TS

- **Python:** Abstract Syntax Tree analysis for high-confidence findings beyond regex
- **JavaScript/TypeScript:** Tree-sitter based analysis detecting eval(), XSS (innerHTML), command injection, SQL in template literals

### 🔑 Secret Detector — 20 Patterns + Verification

AWS · Stripe · MercadoPago · GitHub · JWT · Database URLs · Private Keys · Google · Slack · Twilio · SendGrid · Conekta · Culqi · OpenAI · Generic high-entropy secrets

**Verification** (opt-in `--verify-secrets`):
- Format validation against known key patterns
- Shannon entropy scoring (high entropy = likely real)
- Confidence boost/penalty based on verification result

### 💳 Payment Scanner — 7 Gateways + Logic Analysis

| Gateway | Key Types | PCI Flag |
|---------|-----------|----------|
| Stripe | Live/Test/Restricted/Webhook | ✅ |
| MercadoPago | Live/Test/Public | ✅ |
| PayPal | Client Secret/Webhook | ✅ |
| Conekta | Live/Test | ✅ |
| Culqi | Live/Test | ✅ |
| Wompi | Private/Public/Integrity | ✅ |
| Square | Live Secret | ✅ |

**Payment Logic Analysis** checks for:
- Missing webhook signature verification
- Missing idempotency keys on charge operations
- Client-trusted payment amounts (no server validation)
- Sensitive data in payment error responses

### 📦 Dependency Analyzer

Checks `requirements.txt` and `package.json` against offline CVE database.

### 📊 Risk Scoring

Weighted model: `Score = Σ(severity × confidence × path_criticality × exploit_multiplier)`

### 🏛️ Compliance Mapping

Maps every finding to OWASP Top 10 2021 with gap scoring.

### 📝 Custom Rules Engine

Define your own vulnerability rules in YAML — no Python needed:

```yaml
rules:
  - id: CUSTOM-001
    title: "API endpoint without rate limiting"
    severity: medium
    category: security_misconfig
    languages: [python]
    pattern: '@app\.route$$[^)]+$$\ndef (?!.*limiter)'
    remediation: "Add rate limiting decorator"

- **Sources:** Flask, Django, FastAPI request data
- **Sinks:** SQL, cmd, eval, file, SSRF, deserialization
- **Sanitizers:** int(), escape(), parameterized queries, allowlists

### 🌲 AST Engine — Python + JS/TS

- **Python:** Abstract Syntax Tree analysis for high-confidence findings beyond regex
- **JavaScript/TypeScript:** Tree-sitter based analysis detecting eval(), XSS (innerHTML), command injection, SQL in template literals

### 🔑 Secret Detector — 20 Patterns + Verification

AWS · Stripe · MercadoPago · GitHub · JWT · Database URLs · Private Keys · Google · Slack · Twilio · SendGrid · Conekta · Culqi · OpenAI · Generic high-entropy secrets

**Verification** (opt-in `--verify-secrets`):
- Format validation against known key patterns
- Shannon entropy scoring (high entropy = likely real)
- Confidence boost/penalty based on verification result

### 💳 Payment Scanner — 7 Gateways + Logic Analysis

| Gateway | Key Types | PCI Flag |
|---------|-----------|----------|
| Stripe | Live/Test/Restricted/Webhook | ✅ |
| MercadoPago | Live/Test/Public | ✅ |
| PayPal | Client Secret/Webhook | ✅ |
| Conekta | Live/Test | ✅ |
| Culqi | Live/Test | ✅ |
| Wompi | Private/Public/Integrity | ✅ |
| Square | Live Secret | ✅ |

**Payment Logic Analysis** checks for:
- Missing webhook signature verification
- Missing idempotency keys on charge operations
- Client-trusted payment amounts (no server validation)
- Sensitive data in payment error responses

### 📦 Dependency Analyzer

Checks `requirements.txt` and `package.json` against offline CVE database.

### 📊 Risk Scoring

Weighted model: `Score = Σ(severity × confidence × path_criticality × exploit_multiplier)`

### 🏛️ Compliance Mapping

Maps every finding to OWASP Top 10 2021 with gap scoring.

### 📝 Custom Rules Engine

Define your own vulnerability rules in YAML — no Python needed:

```yaml
rules:
  - id: CUSTOM-001
    title: "API endpoint without rate limiting"
    severity: medium
    category: security_misconfig
    languages: [python]
    pattern: '@app\.route$$[^)]+$$\ndef (?!.*limiter)'
    remediation: "Add rate limiting decorator"

bash
code-audit rules                     # Generate example rules file
code-audit scan . --custom-rules my-rules.yaml
code-audit rules                     # Generate example rules file
code-audit scan . --custom-rules my-rules.yaml

📤 Export Formats

HTML — Self-contained single-file report with dashboard
JSON — Machine-readable for CI integration
SARIF v2.1.0 — GitHub/GitLab/Azure Security tab integration
PDF — Executive report (requires reportlab)

📈 Scan Trending

Track your security posture over time:


bash
code-audit scan .                    # Auto-saves to history
code-audit trend                     # View trend: improving/degrading/stable
code-audit scan .                    # Auto-saves to history
code-audit trend                     # View trend: improving/degrading/stable

Shows delta between scans: new findings, fixed findings, severity changes, risk score trajectory.


🚦 CI/CD Exit Codes

bash
code-audit scan . --fail-on critical   # Exit 1 if any critical findings
code-audit scan . --fail-on high       # Exit 1 if high or critical
code-audit scan . --fail-on medium     # Exit 1 if medium or above
code-audit scan . --fail-on never      # Always exit 0, just report
code-audit scan . --fail-on critical   # Exit 1 if any critical findings
code-audit scan . --fail-on high       # Exit 1 if high or critical
code-audit scan . --fail-on medium     # Exit 1 if medium or above
code-audit scan . --fail-on never      # Always exit 0, just report

🔇 Suppression Comments

Suppress specific findings inline:


python
cursor.execute(query)  # code-audit: ignore[PY-SEC-001] -- parameterized above
cursor.execute(query)  # code-audit: ignore[PY-SEC-001] -- parameterized above


Getting Started

bash
git clone https://github.com/hyperiumia/hyperium-code-audit.git
cd hyperium-code-audit
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m src.cli scan /path/to/your/project
git clone https://github.com/hyperiumia/hyperium-code-audit.git
cd hyperium-code-audit
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m src.cli scan /path/to/your/project

CLI Usage

bash
code-audit scan ./my-project                     # Basic scan (HTML)
code-audit scan ./my-project --format json       # JSON output
code-audit scan ./my-project --format sarif      # SARIF for GitHub Security tab
code-audit scan ./my-project --format all        # HTML + JSON + SARIF + PDF
code-audit scan ./my-project --no-deps           # Skip dependency analysis
code-audit scan ./my-project --no-secrets        # Skip secret detection
code-audit scan ./my-project --no-taint          # Skip taint analysis
code-audit scan ./my-project --verify-secrets    # Verify secret format + entropy
code-audit scan ./my-project --min-confidence 0.8
code-audit scan ./my-project --fail-on high      # CI: exit 1 on high+ findings
code-audit scan ./my-project --custom-rules rules.yaml
code-audit scan ./my-project --config audit.yaml
code-audit rules                                 # Generate example custom rules
code-audit trend                                 # View scan trend
code-audit scan ./my-project                     # Basic scan (HTML)
code-audit scan ./my-project --format json       # JSON output
code-audit scan ./my-project --format sarif      # SARIF for GitHub Security tab
code-audit scan ./my-project --format all        # HTML + JSON + SARIF + PDF
code-audit scan ./my-project --no-deps           # Skip dependency analysis
code-audit scan ./my-project --no-secrets        # Skip secret detection
code-audit scan ./my-project --no-taint          # Skip taint analysis
code-audit scan ./my-project --verify-secrets    # Verify secret format + entropy
code-audit scan ./my-project --min-confidence 0.8
code-audit scan ./my-project --fail-on high      # CI: exit 1 on high+ findings
code-audit scan ./my-project --custom-rules rules.yaml
code-audit scan ./my-project --config audit.yaml
code-audit rules                                 # Generate example custom rules
code-audit trend                                 # View scan trend

GitHub Actions

Copy templates/github-actions-security-scan.yml to your repo's .github/workflows/ directory:


yaml
name: "Security Scan"
on: [push, pull_request]
jobs:
  code-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/hyperiumia/hyperium-code-audit.git
      - run: code-audit scan . --format sarif --fail-on critical
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: reports/ }
name: "Security Scan"
on: [push, pull_request]
jobs:
  code-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/hyperiumia/hyperium-code-audit.git
      - run: code-audit scan . --format sarif --fail-on critical
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: reports/ }

Templates also available for GitLab CI (templates/gitlab-ci.yml) and Bitbucket Pipelines (templates/bitbucket-pipelines.yml).



Architecture

text
src/
├── models.py              # Pydantic data models (15 models)
├── config.py              # Configuration management
├── pattern_scanner.py     # 22 OWASP Top 10 regex rules
├── secret_detector.py     # 20 secret patterns + entropy
├── payment_scanner.py     # 7 payment gateways + Luhn
├── dep_analyzer.py        # Offline CVE database
├── ast_engine.py          # Python AST analysis
├── js_ast_engine.py       # JS/TS tree-sitter AST analysis
├── taint_analyzer.py      # Python taint/data-flow analysis
├── secret_verifier.py     # Secret format + entropy verification
├── payment_logic.py       # Payment security logic analysis
├── custom_rules.py        # YAML custom rules engine
├── scan_history.py        # Scan trending + delta analysis
├── triage_engine.py       # Risk scoring + prioritization
├── compliance_mapper.py   # OWASP Top 10 mapping
├── checkpoint_manager.py  # Scan persistence + resume
├── report_generator.py    # HTML + JSON reports
├── sarif_exporter.py      # SARIF v2.1.0 export
├── pdf_report.py          # PDF report generation
├── engine.py              # Multi-phase pipeline orchestrator
└── cli.py                 # Rich CLI interface
src/
├── models.py              # Pydantic data models (15 models)
├── config.py              # Configuration management
├── pattern_scanner.py     # 22 OWASP Top 10 regex rules
├── secret_detector.py     # 20 secret patterns + entropy
├── payment_scanner.py     # 7 payment gateways + Luhn
├── dep_analyzer.py        # Offline CVE database
├── ast_engine.py          # Python AST analysis
├── js_ast_engine.py       # JS/TS tree-sitter AST analysis
├── taint_analyzer.py      # Python taint/data-flow analysis
├── secret_verifier.py     # Secret format + entropy verification
├── payment_logic.py       # Payment security logic analysis
├── custom_rules.py        # YAML custom rules engine
├── scan_history.py        # Scan trending + delta analysis
├── triage_engine.py       # Risk scoring + prioritization
├── compliance_mapper.py   # OWASP Top 10 mapping
├── checkpoint_manager.py  # Scan persistence + resume
├── report_generator.py    # HTML + JSON reports
├── sarif_exporter.py      # SARIF v2.1.0 export
├── pdf_report.py          # PDF report generation
├── engine.py              # Multi-phase pipeline orchestrator
└── cli.py                 # Rich CLI interface

Scan Pipeline

text
Phase 1: DISCOVER    → Find all source files
Phase 2: SCAN        → Pattern scanner + AST engine + Taint analysis
Phase 3: SECRETS     → Secret detector + verification
Phase 4: PAYMENT     → Payment gateway + logic analysis
Phase 5: DEPS        → Dependency CVE analyzer
Phase 6: TRIAGE      → Risk scoring + prioritization
Phase 7: COMPLIANCE  → OWASP Top 10 mapping
Phase 8: HISTORY     → Save scan for trending
Phase 9: REPORT      → HTML + JSON + SARIF + PDF generation
Phase 1: DISCOVER    → Find all source files
Phase 2: SCAN        → Pattern scanner + AST engine + Taint analysis
Phase 3: SECRETS     → Secret detector + verification
Phase 4: PAYMENT     → Payment gateway + logic analysis
Phase 5: DEPS        → Dependency CVE analyzer
Phase 6: TRIAGE      → Risk scoring + prioritization
Phase 7: COMPLIANCE  → OWASP Top 10 mapping
Phase 8: HISTORY     → Save scan for trending
Phase 9: REPORT      → HTML + JSON + SARIF + PDF generation


Related Projects

Tool	Purpose
Hyperium Q-Audit Pro
Post-quantum cryptographic compliance audit
Hyperium TAT-PRO
Web application security reconnaissance


Built by 
Hyperium IA


Securing LATAM's codebase, one scan at a time.
