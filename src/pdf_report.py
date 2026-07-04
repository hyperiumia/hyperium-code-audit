"""
PDF Report Generator — Produces professional PDF security reports.
"""

from __future__ import annotations
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from src.models import ScanResult

logger = logging.getLogger(__name__)


def generate_pdf(result: ScanResult, output_path: Path) -> Optional[Path]:
    """Generate a PDF report from a ScanResult."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        return _generate_with_reportlab(result, output_path)
    except ImportError:
        logger.warning("reportlab not installed. Install with: pip install reportlab")
        return None


def _generate_with_reportlab(result: ScanResult, output_path: Path) -> Path:
    """Generate PDF using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
    )

    doc = SimpleDocTemplate(str(output_path), pagesize=A4,
                            rightMargin=20*mm, leftMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle('RiskScore', parent=styles['Heading1'], fontSize=28, spaceAfter=6))
    styles.add(ParagraphStyle('Section', parent=styles['Heading2'], fontSize=14,
                              spaceBefore=16, spaceAfter=8))
    styles.add(ParagraphStyle('Sm', parent=styles['Normal'], fontSize=8, textColor=colors.grey))

    elements = []
    risk = result.risk_score

    # Title
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("Security Audit Report", styles['Title']))
    elements.append(Paragraph(f"Hyperium Code-Audit v{result.tool_version}", styles['Normal']))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(
        f"Target: {result.target_path}<br/>"
        f"Scan ID: {result.scan_id}<br/>"
        f"Date: {result.started_at[:19]}<br/>"
        f"Files: {result.stats.total_files_scanned} | "
        f"Duration: {result.stats.scan_duration_seconds}s", styles['Normal']))
    elements.append(HRFlowable(width="100%", thickness=2))

    # Risk
    if risk:
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(
            f"Risk Score: {risk.overall_score}/100 — {risk.risk_level.value.upper()}", styles['RiskScore']))
        elements.append(Paragraph(
            f"Critical: {risk.critical_count} | High: {risk.high_count} | "
            f"Medium: {risk.medium_count} | Low: {risk.low_count}", styles['Normal']))

    # Findings
    if result.findings:
        elements.append(Spacer(1, 16))
        elements.append(Paragraph("Findings Summary", styles['Section']))
        td = [["#", "Severity", "Finding", "Location", "CWE"]]
        for i, f in enumerate(result.findings[:50], 1):
            td.append([str(i), f.severity.value.upper(),
                       Paragraph(f.title[:60], styles['Sm']),
                       f"{f.file_path}:{f.line_number}", f.cwe_id])
        t = Table(td, colWidths=[20, 55, 180, 130, 55])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(t)

    # Secrets
    if result.secrets:
        elements.append(Spacer(1, 16))
        elements.append(Paragraph("Hardcoded Secrets", styles['Section']))
        for s in result.secrets[:20]:
            live = " [LIVE]" if s.is_live_key else ""
            elements.append(Paragraph(
                f"<b>{s.secret_type}{live}</b> — {s.file_path}:{s.line_number} — {s.redacted_value}",
                styles['Normal']))

    # Payment
    if result.payment_findings:
        elements.append(Spacer(1, 16))
        elements.append(Paragraph("Payment Exposures", styles['Section']))
        for p in result.payment_findings[:20]:
            elements.append(Paragraph(
                f"<b>{p.gateway} ({p.key_type})</b> — {p.file_path}:{p.line_number} — {p.severity.value.upper()}",
                styles['Normal']))

    # Deps
    if result.dep_vulnerabilities:
        elements.append(Spacer(1, 16))
        elements.append(Paragraph("Vulnerable Dependencies", styles['Section']))
        dd = [["Package", "Version", "CVE", "CVSS", "Fix"]]
        for d in result.dep_vulnerabilities[:30]:
            dd.append([d.package_name, d.current_version, d.cve_id or "-", str(d.cvss_score), d.fixed_version or "latest"])
        dt = Table(dd, colWidths=[80, 55, 100, 40, 60])
        dt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        elements.append(dt)

    # Compliance
    if result.compliance_reports:
        elements.append(Spacer(1, 16))
        elements.append(Paragraph("Compliance", styles['Section']))
        for cr in result.compliance_reports:
            elements.append(Paragraph(
                f"<b>{cr.framework.value.replace('_', ' ').title()}</b> — {cr.compliance_percentage}% compliant",
                styles['Normal']))

    # Footer
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1))
    elements.append(Paragraph(
        f"Generated by Hyperium Code-Audit v{result.tool_version} — {datetime.now(timezone.utc).isoformat()[:19]}Z",
        styles['Sm']))

    doc.build(elements)
    return output_path
