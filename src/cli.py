"""
CLI for Hyperium Code-Audit v2.1.
"""

from __future__ import annotations
import sys
from pathlib import Path
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from src.config import CodeAuditConfig
from src.engine import CodeAuditEngine
from src.report_generator import generate_html, generate_json
from src.sarif_exporter import generate_sarif

console = Console()


@click.group()
@click.version_option(version="2.1.0", prog_name="hyperium-code-audit")
def main():
    """Hyperium Code-Audit — Production-grade source code security scanner."""
    pass


@main.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--config", "-c", type=click.Path(), help="Config file (YAML)")
@click.option("--output", "-o", default="./reports", help="Report output directory")
@click.option("--format", "-f", "fmt", default="html", type=click.Choice(["html", "json", "sarif", "both", "all"]))
@click.option("--no-secrets", is_flag=True, help="Disable secret detection")
@click.option("--no-deps", is_flag=True, help="Disable dependency analysis")
@click.option("--no-payment", is_flag=True, help="Disable payment scanning")
@click.option("--no-taint", is_flag=True, help="Disable taint analysis")
@click.option("--min-confidence", default=0.5, type=float, help="Minimum confidence threshold")
@click.option("--fail-on", default="critical", type=click.Choice(["critical", "high", "medium", "low", "never"]),
              help="Exit code 1 if findings at this severity exist")
@click.option("--custom-rules", type=click.Path(), help="Custom rules YAML file")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan(target, config, output, fmt, no_secrets, no_deps, no_payment, no_taint,
         min_confidence, fail_on, custom_rules, verbose):
    """Scan a directory for security vulnerabilities."""
    import logging
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)

    cfg = CodeAuditConfig.from_yaml(config) if config else CodeAuditConfig()
    cfg.scanners.secret_detector = not no_secrets
    cfg.scanners.dep_analyzer = not no_deps
    cfg.scanners.payment_scanner = not no_payment
    cfg.scanners.taint_analyzer = not no_taint
    cfg.scanners.min_confidence = min_confidence
    cfg.report.output_dir = output
    if custom_rules:
        cfg.scanners.custom_rules_path = custom_rules

    console.print()
    console.print(Panel("[bold]HYPERIUM CODE-AUDIT v2.1[/bold]\n[dim]Production-grade SAST scanner[/dim]", border_style="cyan"))
    console.print(f"  [dim]Target:[/dim]    {target}")
    console.print(f"  [dim]Format:[/dim]    {fmt}")
    console.print(f"  [dim]Fail on:[/dim]   {fail_on}")
    console.print()

    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

    engine = CodeAuditEngine(cfg)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), console=console) as progress:
        task = progress.add_task("Scanning...", total=100)
        def on_progress(phase, message, pct):
            progress.update(task, completed=pct, description=f"[cyan]{phase}[/cyan] {message}")
        engine.set_progress_callback(on_progress)
        result = engine.scan(target)

    console.print()
    risk = result.risk_score
    rc = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green", "info": "blue"}.get(
        risk.risk_level.value if risk else "info", "blue")

    console.print(Panel(
        f"[bold {rc}]Risk Score: {risk.overall_score if risk else 0}/100 — {risk.risk_level.value.upper() if risk else 'N/A'}[/bold {rc}]\n\n"
        f"  Findings:  {result.total_findings}\n"
        f"  Critical:  {risk.critical_count if risk else 0}  |  High: {risk.high_count if risk else 0}\n"
        f"  Medium:    {risk.medium_count if risk else 0}  |  Low:  {risk.low_count if risk else 0}\n"
        f"  Secrets:   {len(result.secrets)}  |  Payment: {len(result.payment_findings)}\n"
        f"  Deps:      {len(result.dep_vulnerabilities)}  |  Files: {result.stats.total_files_scanned}\n"
        f"  Time:      {result.stats.scan_duration_seconds}s",
        title="[bold]Scan Results[/bold]", border_style=rc))

    for cr in result.compliance_reports:
        pct = cr.compliance_percentage
        color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
        console.print(f"  [{color}]{cr.framework.value}: {pct}% compliant[/{color}]")

    if result.findings:
        table = Table(title="Top Findings", show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("Finding", min_width=30)
        table.add_column("Location", min_width=20)
        table.add_column("Conf", width=8)
        for f in result.findings[:15]:
            table.add_row(f"[{f.severity.color}]{f.severity.value.upper()}[/{f.severity.color}]",
                          f"{f.title}\n[dim]{f.rule_id}[/dim]", f"{f.file_path}:{f.line_number}",
                          f"{round(f.confidence * 100)}%")
        console.print(table)

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if fmt in ("html", "both", "all"):
        p = generate_html(result, output_dir / f"{result.scan_id}.html")
        console.print(f"\n  [green]✓[/green] HTML: {p}")
    if fmt in ("json", "both", "all"):
        p = generate_json(result, output_dir / f"{result.scan_id}.json")
        console.print(f"  [green]✓[/green] JSON: {p}")
    if fmt in ("sarif", "all"):
        p = generate_sarif(result, output_dir / f"{result.scan_id}.sarif")
        console.print(f"  [green]✓[/green] SARIF: {p}")
    if fmt == "all":
        try:
            from src.pdf_report import generate_pdf
            p = generate_pdf(result, output_dir / f"{result.scan_id}.pdf")
            if p:
                console.print(f"  [green]✓[/green] PDF: {p}")
        except Exception as e:
            console.print(f"  [dim]PDF skipped: {e}[/dim]")

    console.print()
    exit_code = _calculate_exit_code(risk, fail_on)
    if exit_code != 0:
        console.print(f"[bold red]✗ Exit {exit_code}: findings at {fail_on}+ detected[/bold red]")
    else:
        console.print(f"[bold green]✓ Exit 0: clean[/bold green]")
    sys.exit(exit_code)


def _calculate_exit_code(risk, fail_on: str) -> int:
    """Calculate exit code based on risk and fail-on threshold."""
    if not risk or fail_on == "never":
        return 0
    all_counts = risk.critical_count + risk.high_count + risk.medium_count + risk.low_count
    if fail_on == "critical" and risk.critical_count > 0:
        return 1
    if fail_on == "high" and (risk.critical_count + risk.high_count) > 0:
        return 1
    if fail_on == "medium" and (risk.critical_count + risk.high_count + risk.medium_count) > 0:
        return 1
    if fail_on == "low" and all_counts > 0:
        return 1
    return 0


@main.command()
@click.argument("output", default="custom-rules.yaml")
def rules(output):
    """Generate an example custom rules YAML file."""
    from src.custom_rules import generate_example_rules
    path = generate_example_rules(output)
    console.print(f"[green]✓[/green] Example rules: {path}")
    console.print("  Edit and pass to scan: --custom-rules <path>")


@main.command()
def version():
    """Show version information."""
    console.print("[bold]Hyperium Code-Audit[/bold] v2.1.0")


if __name__ == "__main__":
    main()
