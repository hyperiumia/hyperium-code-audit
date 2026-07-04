"""Custom Rules Engine — Load vulnerability rules from YAML."""

from __future__ import annotations
import logging
import re
from pathlib import Path
from typing import List
import yaml
from src.models import FindingCategory, Language, Severity
from src.pattern_scanner import ScanRule

logger = logging.getLogger(__name__)
CATEGORY_MAP = {v.value: v for v in FindingCategory}
SEVERITY_MAP = {v.value: v for v in Severity}
LANGUAGE_MAP = {v.value: v for v in Language}


def load_custom_rules(rules_path: str) -> List[ScanRule]:
    """Load custom rules from a YAML file."""
    path = Path(rules_path)
    if not path.exists():
        raise FileNotFoundError(f"Custom rules file not found: {rules_path}")
    data = yaml.safe_load(path.read_text())
    if not data or "rules" not in data:
        return []
    rules = []
    for rd in data["rules"]:
        try:
            rule_id = rd.get("id", "")
            title = rd.get("title", "")
            pattern = rd.get("pattern", "")
            if not all([rule_id, title, pattern]):
                continue
            sev = SEVERITY_MAP.get(rd.get("severity", "medium").lower())
            if not sev:
                continue
            cat = CATEGORY_MAP.get(rd.get("category", "security_misconfig").lower())
            if not cat:
                cat = FindingCategory.SECURITY_MISCONFIG
            langs = []
            for ls in rd.get("languages", ["python"]):
                lang = LANGUAGE_MAP.get(ls.lower())
                if lang:
                    langs.append(lang)
            if not langs:
                langs = [Language.UNKNOWN]
            try:
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            rules.append(ScanRule(
                id=rule_id, title=title, category=cat, severity=sev,
                cwe_id=rd.get("cwe_id", ""), owasp_id=rd.get("owasp_id", ""),
                languages=langs, pattern=pattern,
                description=rd.get("description", ""),
                remediation=rd.get("remediation", ""),
                impact=rd.get("impact", ""),
                confidence=float(rd.get("confidence", 0.7)),
                references=rd.get("references", []),
            ))
        except Exception as e:
            logger.warning(f"Skipping custom rule: {e}")
    return rules


def generate_example_rules(output_path: str) -> Path:
    """Generate an example custom rules YAML file."""
    example = """# Hyperium Code-Audit Custom Rules
# Patterns use single quotes to avoid YAML escape issues

rules:
  - id: CUSTOM-RATE-LIMIT
    title: API endpoint without rate limiting
    severity: medium
    category: security_misconfig
    cwe_id: CWE-770
    owasp_id: A04
    languages: [python]
    pattern: '@app\\.route\\([^)]+\\)\\ndef (?!.*limiter|.*throttle)'
    description: API endpoint may lack rate limiting protection
    remediation: Add rate limiting decorator
    confidence: 0.6

  - id: CUSTOM-PII-LOG
    title: Potential PII in log output
    severity: medium
    category: logging_failure
    cwe_id: CWE-532
    owasp_id: A09
    languages: [python, javascript]
    pattern: '(?:logger|console)\\.(?:info|debug|warn)\\([^)]*(?:password|token|secret)'
    description: Sensitive data may be logged in plain text
    remediation: Mask or redact sensitive fields before logging
    confidence: 0.7

  - id: CUSTOM-MATH-RANDOM
    title: Math.random used for security context
    severity: high
    category: crypto_failure
    cwe_id: CWE-338
    owasp_id: A02
    languages: [javascript, typescript]
    pattern: 'Math\\.random\\(\\).*(?:token|session|key|password)'
    description: Math.random() is not cryptographically secure
    remediation: Use crypto.randomBytes() instead
    confidence: 0.8
"""
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(example)
    return p
