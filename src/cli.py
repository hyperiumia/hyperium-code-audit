"""
CLI — Rich command-line interface for Hyperium Code-Audit.

Commands:
  scan      Run a security scan on a directory
  version   Show version information
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text

from src.config import CodeAuditConfig
from src.engine import CodeAuditEngine
from src.report_generator import generate_html, generate_json

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="hyperium-code-audit")
def main():
    """Hyperium Code-Audit — Production-grade source code security scanner."""
    pass


@main.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--config", "-c", type=click.Path(), help="Config file (YAML)")
@click.option("--output", "-o", default="./reports", help="Report output directory")
@click.option("--format", "-f", "fmt", default="html", type=click.Choice(["html", "json", "both"]))
@click.option("--no-secrets", is_flag=True, help="Disable secret detection")
@click.option("--no-deps", is_flag=True, help="Disable dependency analysis")
@click.option("--no-payment", is_flag=True, help="Disable payment scanning")
@click.option("--min-confidence", default=0.5, type=float, help="Minimum confidence threshold")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan(target, config, output, fmt, no_secrets, no_deps, no_payment, min_confidence, verbose):
    """Scan a directory for security vulnerabilities."""
    import logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Load config
    if config:
        cfg = CodeAuditConfig.from_yaml(config)
    else:
        cfg = CodeAuditConfig()

    # Apply CLI overrides
    cfg.scanners.secret_detector = not no_secrets
    cfg.scanners.dep_analyzer = not no_deps
    cfg.scanners.payment_scanner = not no_payment
    cfg.scanners.min_confidence = min_confidence
    cfg.report.output_dir = output
    cfg.report.format = fmt

    # Banner
    console.print()
    console.print(Panel(
        "[bold]HYPERIUM CODE-AUDIT[/bold]\n"
        "[dim]Production-grade source code security scanner[/dim]",
        border_style="cyan",
    ))
    console.print(f"  [dim]Target:[/dim]    {target}")
    console.print(f"  [dim]Output:[/dim]    {output}")
    console.print(f"  [dim]Format:[/dim]    {fmt}")
    console.print()

    # Run scan with progress
    engine = CodeAuditEngine(cfg)
    result = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=100)

        def on_progress(phase, message, pct):
            progress.update(task, completed=pct, description=f"[cyan]{phase}[/cyan] {message}")

        engine.set_progress_callback(on_progress)
        result = engine.scan(target)

    # Results summary
    console.print()
    risk = result.risk_score
    risk_color = {
        "critical": "red", "high": "orange",
        "medium": "yellow", "low": "green", "info": "blue",
    }.get(risk.risk_level.value if risk else "info", "blue")

    console.print(Panel(
        f"[bold {risk_color}]Risk Score: {risk.overall_score if risk else 0}/100 — "
        f"{risk.risk_level.value.upper() if risk else 'N/A'}[/bold {risk_color}]\n\n"
        f"  Findings:  {result.total_findings}\n"
        f"  Critical:  {risk.critical_count if risk else 0}\n"
        f"  High:      {risk.high_count if risk else 0}\n"
        f"  Medium:    {risk.medium_count if risk else 0}\n"
        f"  Low:       {risk.low_count if risk else 0}\n"
        f"  Secrets:   {len(result.secrets)}\n"
        f"  Payment:   {len(result.payment_findings)}\n"
        f"  Deps:      {len(result.dep_vulnerabilities)}\n"
        f"  Files:     {result.stats.total_files_scanned}\n"
        f"  Time:      {result.stats.scan_duration_seconds}s",
        title="[bold]Scan Results[/bold]",
        border_style=risk_color,
    ))

    # Compliance summary
    for cr in result.compliance_reports:
        pct = cr.compliance_percentage
        color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
        console.print(f"  [{color}]{cr.framework.value}: {pct}% compliant "
                      f"({cr.passed}/{cr.total_requirements} passed)[/{color}]")

    # Top findings table
    if result.findings:
        console.print()
        table = Table(title="Top Findings", show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("Finding", min_width=30)
        table.add_column("Location", min_width=20)
        table.add_column("Confidence", width=10)

        for f in result.findings[:15]:
            sev_color = f.severity.color
            table.add_row(
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f"{f.title}\n[dim]{f.rule_id} · {f.cwe_id}[/dim]",
                f"{f.file_path}:{f.line_number}",
                f"{round(f.confidence * 100)}%",
            )
        console.print(table)

    # Generate reports
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if fmt in ("html", "both"):
        html_path = generate_html(result, output_dir / f"{result.scan_id}.html")
        console.print(f"\n  [green]✓[/green] HTML report: {html_path}")

    if fmt in ("json", "both"):
        json_path = generate_json(result, output_dir / f"{result.scan_id}.json")
        console.print(f"  [green]✓[/green] JSON report: {json_path}")

    console.print()

    # Exit code based on risk
    if risk and risk.critical_count > 0:
        sys.exit(1)
    sys.exit(0)


@main.command()
def version():
    """Show version information."""
    console.print("[bold]Hyperium Code-Audit[/bold] v1.0.0")
    console.print("Production-grade source code security scanner")


if __name__ == "__main__":
    main()
