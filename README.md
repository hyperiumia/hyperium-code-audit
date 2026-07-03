<div align="center">

# Hyperium Code-Audit

### Production-Grade Source Code Security Scanner (SAST)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-41%20passed-brightgreen.svg)](#testing)

**Scan your source code for OWASP Top 10 vulnerabilities, hardcoded secrets, payment gateway exposures, and vulnerable dependencies — in seconds.**

[Getting Started](#getting-started) · [Features](#features) · [Architecture](#architecture) · [CLI Usage](#cli-usage)

</div>

---

## Why Code-Audit?

| Feature | Code-Audit | Semgrep | Bandit | Snyk Code |
|---------|:----------:|:-------:|:------:|:---------:|
| OWASP Top 10 patterns | ✅ 22 rules | ✅ | Partial | ✅ |
| AST analysis (Python) | ✅ | ✅ | ✅ | ✅ |
| Secret detection | ✅ 20 patterns | ❌ | ❌ | ✅ |
| Payment gateway scan | ✅ 16 rules | ❌ | ❌ | ❌ |
| Dependency CVE check | ✅ | ❌ | ❌ | ✅ |
| Compliance mapping | ✅ OWASP | ❌ | ❌ | Partial |
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

### 🔑 Secret Detector — 20 Patterns

AWS Access Keys · Stripe · MercadoPago · GitHub · JWT · Database URLs · Private Keys · Google · Slack · Twilio · SendGrid · Conekta · Culqi · OpenAI · Generic high-entropy secrets

### 💳 Payment Scanner — 7 Gateways

| Gateway | Key Types | PCI Flag |
|---------|-----------|----------|
| Stripe | Live/Test/Restricted/Webhook | ✅ |
| MercadoPago | Live/Test/Public | ✅ |
| PayPal | Client Secret/Webhook | ✅ |
| Conekta | Live/Test | ✅ |
| Culqi | Live/Test | ✅ |
| Wompi | Private/Public/Integrity | ✅ |
| Square | Live Secret | ✅ |
| PCI DSS | Card numbers (Luhn validated) | ✅ |

### 📦 Dependency Analyzer

Checks `requirements.txt` and `package.json` against offline CVE database.

### 🧠 AST Engine (Python)

Parses Abstract Syntax Trees for high-confidence findings — beyond regex.

### 📊 Risk Scoring

Weighted model: `Score = Σ(severity × confidence × path_criticality × exploit_multiplier)`

### 🏛️ Compliance Mapping

Maps every finding to OWASP Top 10 2021 with gap scoring.

### 📝 Self-Contained HTML Report

Single-file report with risk dashboard, findings table, code snippets, and compliance gaps.

---

## Getting Started

```bash
git clone https://github.com/hyperiumia/hyperium-code-audit.git
cd hyperium-code-audit
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m src.cli scan /path/to/your/project
CLI Usage

bash
code-audit scan ./my-project                    # Basic scan
code-audit scan ./my-project --format json      # JSON output
code-audit scan ./my-project --format both      # HTML + JSON
code-audit scan ./my-project --no-deps          # Skip dep analysis
code-audit scan ./my-project --min-confidence 0.8
code-audit scan ./my-project --config audit.yaml
code-audit scan ./my-project                    # Basic scan
code-audit scan ./my-project --format json      # JSON output
code-audit scan ./my-project --format both      # HTML + JSON
code-audit scan ./my-project --no-deps          # Skip dep analysis
code-audit scan ./my-project --min-confidence 0.8
code-audit scan ./my-project --config audit.yaml


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
├── triage_engine.py       # Risk scoring + prioritization
├── compliance_mapper.py   # OWASP Top 10 mapping
├── checkpoint_manager.py  # Scan persistence + resume
├── report_generator.py    # HTML + JSON reports
├── engine.py              # 7-phase pipeline orchestrator
└── cli.py                 # Rich CLI interface
src/
├── models.py              # Pydantic data models (15 models)
├── config.py              # Configuration management
├── pattern_scanner.py     # 22 OWASP Top 10 regex rules
├── secret_detector.py     # 20 secret patterns + entropy
├── payment_scanner.py     # 7 payment gateways + Luhn
├── dep_analyzer.py        # Offline CVE database
├── ast_engine.py          # Python AST analysis
├── triage_engine.py       # Risk scoring + prioritization
├── compliance_mapper.py   # OWASP Top 10 mapping
├── checkpoint_manager.py  # Scan persistence + resume
├── report_generator.py    # HTML + JSON reports
├── engine.py              # 7-phase pipeline orchestrator
└── cli.py                 # Rich CLI interface

Scan Pipeline

text
Phase 1: DISCOVER    → Find all source files
Phase 2: SCAN        → Pattern scanner + AST engine
Phase 3: SECRETS     → Secret detector + entropy
Phase 4: PAYMENT     → Payment gateway scanner
Phase 5: DEPS        → Dependency CVE analyzer
Phase 6: TRIAGE      → Risk scoring + prioritization
Phase 7: COMPLIANCE  → OWASP Top 10 mapping
Phase 8: REPORT      → HTML + JSON generation
Phase 1: DISCOVER    → Find all source files
Phase 2: SCAN        → Pattern scanner + AST engine
Phase 3: SECRETS     → Secret detector + entropy
Phase 4: PAYMENT     → Payment gateway scanner
Phase 5: DEPS        → Dependency CVE analyzer
Phase 6: TRIAGE      → Risk scoring + prioritization
Phase 7: COMPLIANCE  → OWASP Top 10 mapping
Phase 8: REPORT      → HTML + JSON generation


Related Projects

Tool	Purpose
Hyperium Q-Audit Pro
Post-quantum cryptographic compliance audit
Hyperium TAT-PRO
Web application security reconnaissance



Built by 
Hyperium IA


Securing LATAM's codebase, one scan at a time.



