"""
Report Generator — Produces HTML and JSON security reports.

The HTML report is a self-contained, single-file document with
embedded CSS. No external dependencies needed to view it.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.models import ScanResult

logger = logging.getLogger(__name__)


def generate_json(result: ScanResult, output_path: Path) -> Path:
    """Generate a machine-readable JSON report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result.model_dump(), indent=2, default=str))
    return output_path


def generate_html(result: ScanResult, output_path: Path) -> Path:
    """Generate a self-contained HTML security report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    risk = result.risk_score
    risk_color = {
        "critical": "#ef4444", "high": "#f97316",
        "medium": "#f59e0b", "low": "#10b981", "info": "#3b82f6",
    }.get(risk.risk_level.value if risk else "info", "#3b82f6")

    severity_emoji = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵",
    }

    # Build findings rows
    findings_rows = ""
    for f in sorted(result.findings, key=lambda x: x.severity.weight, reverse=True)[:200]:
        emoji = severity_emoji.get(f.severity.value, "⚪")
        snippet_html = ""
        if f.code_snippet:
            snippet_html = f'<pre style="background:#1a1a2e;padding:8px;border-radius:4px;font-size:11px;overflow-x:auto;max-height:120px">{_escape(f.code_snippet)}</pre>'
        findings_rows += f"""
        <tr>
          <td>{emoji} {f.severity.value.upper()}</td>
          <td><strong>{_escape(f.title)}</strong><br/><small style="color:#888">{f.rule_id} · {f.cwe_id} · {f.owasp_id}</small></td>
          <td><code>{_escape(f.file_path)}:{f.line_number}</code></td>
          <td>{round(f.confidence * 100)}%</td>
          <td>{snippet_html}</td>
        </tr>"""

    # Secrets rows
    secrets_rows = ""
    for s in result.secrets[:50]:
        live_tag = ' <span style="color:#ef4444;font-weight:bold">LIVE</span>' if s.is_live_key else ""
        secrets_rows += f"""
        <tr>
          <td>{s.secret_type}{live_tag}</td>
          <td><code>{_escape(s.file_path)}:{s.line_number}</code></td>
          <td><code>{_escape(s.redacted_value)}</code></td>
          <td>{round(s.confidence * 100)}%</td>
        </tr>"""

    # Payment rows
    payment_rows = ""
    for p in result.payment_findings[:50]:
        payment_rows += f"""
        <tr>
          <td>{p.gateway} · {p.key_type}</td>
          <td><code>{_escape(p.file_path)}:{p.line_number}</code></td>
          <td><code>{_escape(p.redacted_value)}</code></td>
          <td>{p.severity.value.upper()}</td>
        </tr>"""

    # Dep vuln rows
    dep_rows = ""
    for d in result.dep_vulnerabilities[:50]:
        dep_rows += f"""
        <tr>
          <td>{d.package_name}=={d.current_version}</td>
          <td>{d.cve_id or d.ghsa_id}</td>
          <td>{d.cvss_score}</td>
          <td>{d.severity.value.upper()}</td>
          <td>{d.fixed_version or "—"}</td>
        </tr>"""

    # Compliance section
    compliance_html = ""
    for cr in result.compliance_reports:
        bars = ""
        for m in cr.mappings:
            color = {"pass": "#10b981", "fail": "#ef4444", "warning": "#f59e0b"}.get(m.status.value, "#888")
            count = len(m.findings)
            bars += f"""
            <div style="display:flex;align-items:center;gap:8px;margin:4px 0">
              <span style="min-width:50px;font-weight:600">{m.requirement_id}</span>
              <span style="min-width:200px">{m.requirement_title}</span>
              <span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{m.status.value.upper()}</span>
              <span style="color:#888;font-size:12px">{count} finding(s)</span>
            </div>"""
        compliance_html += f"""
        <h3>{cr.framework.value.replace('_', ' ').title()} — {cr.compliance_percentage}% compliant</h3>
        {bars}"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Report — {result.scan_id}</title>
<style>
body{{font-family:Inter,-apple-system,sans-serif;background:#0a0a0f;color:#e8e8f0;padding:24px;max-width:1200px;margin:0 auto}}
h1{{font-size:24px;margin-bottom:4px}}
h2{{font-size:18px;margin-top:32px;border-bottom:1px solid #2a2a3a;padding-bottom:8px}}
h3{{font-size:15px;margin-top:20px}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}}
.card{{background:#12121a;border:1px solid #2a2a3a;border-radius:8px;padding:16px;text-align:center}}
.card .val{{font-size:28px;font-weight:700}}
.card .lbl{{font-size:11px;color:#6a6a80;text-transform:uppercase;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin:12px 0}}
th{{background:#1a1a25;padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase;color:#6a6a80}}
td{{padding:8px 12px;border-bottom:1px solid #1a1a25}}
tr:hover{{background:#12121a}}
code{{background:#1a1a25;padding:2px 6px;border-radius:3px;font-size:12px}}
.meta{{color:#6a6a80;font-size:12px;margin-bottom:24px}}
</style>
</head>
<body>
<h1>🔍 Hyperium Code-Audit — Security Report</h1>
<p class="meta">
  Scan ID: {result.scan_id} · Target: {_escape(result.target_path)} ·
  {result.started_at[:19]} → {result.completed_at[:19] if result.completed_at else "in progress"} ·
  v{result.tool_version}
</p>

<div class="grid">
  <div class="card" style="border-color:{risk_color}">
    <div class="val" style="color:{risk_color}">{risk.overall_score if risk else 0}</div>
    <div class="lbl">Risk Score</div>
  </div>
  <div class="card">
    <div class="val" style="color:{risk_color}">{risk.risk_level.value.upper() if risk else "N/A"}</div>
    <div class="lbl">Risk Level</div>
  </div>
  <div class="card">
    <div class="val">{result.total_findings}</div>
    <div class="lbl">Total Findings</div>
  </div>
  <div class="card">
    <div class="val">{result.stats.total_files_scanned}</div>
    <div class="lbl">Files Scanned</div>
  </div>
</div>

<div class="grid">
  <div class="card"><div class="val" style="color:#ef4444">{risk.critical_count if risk else 0}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="val" style="color:#f97316">{risk.high_count if risk else 0}</div><div class="lbl">High</div></div>
  <div class="card"><div class="val" style="color:#f59e0b">{risk.medium_count if risk else 0}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="val" style="color:#10b981">{risk.low_count if risk else 0}</div><div class="lbl">Low</div></div>
</div>

<h2>📋 Findings ({len(result.findings)})</h2>
<table>
  <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Confidence</th><th>Code</th></tr></thead>
  <tbody>{findings_rows if findings_rows else '<tr><td colspan="5" style="color:#6a6a80">No findings detected</td></tr>'}</tbody>
</table>

{"<h2>🔑 Hardcoded Secrets (" + str(len(result.secrets)) + ")</h2><table><thead><tr><th>Type</th><th>Location</th><th>Value</th><th>Confidence</th></tr></thead><tbody>" + secrets_rows + "</tbody></table>" if result.secrets else ""}

{"<h2>💳 Payment Gateway Exposures (" + str(len(result.payment_findings)) + ")</h2><table><thead><tr><th>Gateway</th><th>Location</th><th>Key</th><th>Severity</th></tr></thead><tbody>" + payment_rows + "</tbody></table>" if result.payment_findings else ""}

{"<h2>📦 Vulnerable Dependencies (" + str(len(result.dep_vulnerabilities)) + ")</h2><table><thead><tr><th>Package</th><th>CVE</th><th>CVSS</th><th>Severity</th><th>Fix</th></tr></thead><tbody>" + dep_rows + "</tbody></table>" if result.dep_vulnerabilities else ""}

<h2>📊 Compliance Assessment</h2>
{compliance_html if compliance_html else '<p style="color:#6a6a80">No compliance frameworks configured.</p>'}

<hr style="border-color:#2a2a3a;margin:32px 0">
<p class="meta">Generated by Hyperium Code-Audit v{result.tool_version} · {datetime.now(timezone.utc).isoformat()[:19]}Z</p>
</body></html>"""

    output_path.write_text(html)
    return output_path


def _escape(text: str) -> str:
    """HTML-escape a string."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
