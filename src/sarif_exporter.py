"""
SARIF (Static Analysis Results Interchange Format) Exporter.

Generates SARIF v2.1.0 compliant output for integration with:
  - GitHub Advanced Security (code scanning)
  - GitLab SAST
  - Azure DevOps
  - VS Code SARIF Viewer
  - SonarQube

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from src.models import (
    DepVulnerability, Finding, PaymentFinding,
    ScanResult, SecretFinding, Severity,
)

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _severity_to_level(severity: Severity) -> str:
    """Map our severity to SARIF result level."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    return mapping.get(severity, "warning")


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map severity to SARIF reporting configuration level."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }
    return mapping.get(severity, "warning")


def _make_rule(rule_id: str, title: str, severity: Severity,
               cwe_id: str = "", owasp_id: str = "",
               description: str = "", remediation: str = "") -> Dict[str, Any]:
    """Build a SARIF rule descriptor."""
    rule: Dict[str, Any] = {
        "id": rule_id,
        "name": title,
        "shortDescription": {"text": title},
        "defaultConfiguration": {"level": _severity_to_sarif_level(severity)},
    }

    if description:
        rule["fullDescription"] = {"text": description}

    if remediation:
        rule["help"] = {"text": remediation, "markdown": remediation}

    # Properties with taxonomies
    properties: Dict[str, Any] = {"tags": []}
    if cwe_id:
        cwe_num = cwe_id.replace("CWE-", "")
        properties["tags"].append(f"CWE-{cwe_num}")
        properties["cwe"] = cwe_id
    if owasp_id:
        properties["tags"].append(f"OWASP-{owasp_id}")
        properties["owasp"] = owasp_id
    if properties["tags"]:
        rule["properties"] = properties

    return rule


def _make_location(file_path: str, line_number: int,
                   column: int = 1, snippet: str = "") -> Dict[str, Any]:
    """Build a SARIF location object."""
    phys_loc: Dict[str, Any] = {
        "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": line_number, "startColumn": column},
    }
    if snippet:
        phys_loc["region"]["snippet"] = {"text": snippet[:500]}

    return {"physicalLocation": phys_loc}


def _finding_to_result(finding: Finding) -> Dict[str, Any]:
    """Convert a Finding to a SARIF result."""
    result: Dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _severity_to_level(finding.severity),
        "message": {"text": finding.description or finding.title},
        "locations": [_make_location(
            finding.file_path, finding.line_number,
            finding.column or 1, finding.code_snippet,
        )],
    }

    # Partial fingerprints for deduplication across runs
    result["partialFingerprints"] = {
        "primaryLocationLineHash": f"{finding.rule_id}:{finding.file_path}:{finding.line_number}",
    }

    # Properties
    props: Dict[str, Any] = {}
    if finding.cwe_id:
        props["cwe"] = finding.cwe_id
    if finding.owasp_id:
        props["owasp"] = finding.owasp_id
    if finding.confidence:
        props["confidence"] = finding.confidence
    if props:
        result["properties"] = props

    return result


def _secret_to_result(secret: SecretFinding) -> Dict[str, Any]:
    """Convert a SecretFinding to a SARIF result."""
    return {
        "ruleId": f"SECRET-{secret.secret_type}",
        "level": "error" if secret.is_live_key else "warning",
        "message": {
            "text": f"Hardcoded {secret.secret_type} detected: {secret.redacted_value}"
        },
        "locations": [_make_location(secret.file_path, secret.line_number)],
        "properties": {
            "secretType": secret.secret_type,
            "isLiveKey": secret.is_live_key,
            "confidence": secret.confidence,
        },
    }


def _payment_to_result(pf: PaymentFinding) -> Dict[str, Any]:
    """Convert a PaymentFinding to a SARIF result."""
    return {
        "ruleId": f"PAY-{pf.gateway.upper()}",
        "level": _severity_to_level(pf.severity),
        "message": {
            "text": f"{pf.gateway} {pf.key_type} key exposed: {pf.redacted_value}"
        },
        "locations": [_make_location(pf.file_path, pf.line_number)],
        "properties": {
            "gateway": pf.gateway,
            "keyType": pf.key_type,
            "pciViolation": pf.pci_violation,
        },
    }


def _dep_to_result(dv: DepVulnerability) -> Dict[str, Any]:
    """Convert a DepVulnerability to a SARIF result."""
    return {
        "ruleId": dv.cve_id or f"DEP-{dv.package_name}",
        "level": _severity_to_level(dv.severity),
        "message": {
            "text": f"{dv.package_name}=={dv.current_version}: {dv.title} "
                    f"(CVSS {dv.cvss_score}). "
                    f"Fix: upgrade to {dv.fixed_version or 'latest'}"
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f"package:{dv.ecosystem}/{dv.package_name}",
                },
                "region": {},
            },
        }],
        "properties": {
            "package": dv.package_name,
            "version": dv.current_version,
            "fixedVersion": dv.fixed_version,
            "ecosystem": dv.ecosystem,
            "cvss": dv.cvss_score,
            "cve": dv.cve_id,
        },
    }


def generate_sarif(result: ScanResult, output_path: Path) -> Path:
    """Generate a SARIF v2.1.0 file from a ScanResult."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Collect unique rules
    rules: Dict[str, Dict[str, Any]] = {}

    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = _make_rule(
                f.rule_id, f.title, f.severity,
                f.cwe_id, f.owasp_id, f.description, f.remediation,
            )

    for s in result.secrets:
        rid = f"SECRET-{s.secret_type}"
        if rid not in rules:
            rules[rid] = _make_rule(
                rid, f"Hardcoded {s.secret_type}",
                Severity.CRITICAL if s.is_live_key else Severity.HIGH,
                cwe_id="CWE-798",
                description=s.description,
            )

    for p in result.payment_findings:
        rid = f"PAY-{p.gateway.upper()}"
        if rid not in rules:
            rules[rid] = _make_rule(
                rid, f"{p.gateway} credential exposure",
                p.severity, cwe_id="CWE-798",
                description=p.description,
            )

    for d in result.dep_vulnerabilities:
        rid = d.cve_id or f"DEP-{d.package_name}"
        if rid not in rules:
            rules[rid] = _make_rule(
                rid, f"Vulnerable dependency: {d.package_name}",
                d.severity, cwe_id="CWE-1104" if not d.cve_id else "",
                description=d.description,
            )

    # Build results
    sarif_results: List[Dict[str, Any]] = []
    sarif_results.extend(_finding_to_result(f) for f in result.findings)
    sarif_results.extend(_secret_to_result(s) for s in result.secrets)
    sarif_results.extend(_payment_to_result(p) for p in result.payment_findings)
    sarif_results.extend(_dep_to_result(d) for d in result.dep_vulnerabilities)

    # Build run
    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "hyperium-code-audit",
                "version": result.tool_version,
                "semanticVersion": result.tool_version,
                "informationUri": "https://github.com/hyperiumia/hyperium-code-audit",
                "rules": list(rules.values()),
            },
        },
        "results": sarif_results,
        "properties": {
            "scanId": result.scan_id,
            "targetPath": result.target_path,
            "startedAt": result.started_at,
            "completedAt": result.completed_at,
            "totalFindings": result.total_findings,
            "filesScanned": result.stats.total_files_scanned,
            "scanDurationSeconds": result.stats.scan_duration_seconds,
        },
    }

    # Add risk score if available
    if result.risk_score:
        run["properties"]["riskScore"] = {
            "overall": result.risk_score.overall_score,
            "level": result.risk_score.risk_level.value,
            "critical": result.risk_score.critical_count,
            "high": result.risk_score.high_count,
            "medium": result.risk_score.medium_count,
            "low": result.risk_score.low_count,
        }

    # Build SARIF document
    sarif_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }

    output_path.write_text(json.dumps(sarif_doc, indent=2, default=str))
    return output_path
