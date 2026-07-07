"""
CLI for Hyperium Code-Audit v4.0.
"""

from __future__ import annotations
import sys
from pathlib import Path
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from src.config import CodeAuditConfig
from src.incremental import get_changed_files, is_git_repo
from src.engine import CodeAuditEngine
from src.report_generator import generate_html, generate_json
from src.sarif_exporter import generate_sarif

console = Console()


@click.group()
@click.version_option(version="4.0.0", prog_name="hyperium-code-audit")
def main():
    """Hyperium Code-Audit -- Production-grade source code security scanner."""
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
@click.option("--since", default=None, help="Git ref to diff against (e.g. HEAD~1, main). Only scans changed files.")
@click.option("--custom-rules", type=click.Path(), help="Custom rules YAML file")
@click.option("--verify-secrets", is_flag=True, help="Verify secret format + entropy (opt-in)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan(target, config, output, fmt, no_secrets, no_deps, no_payment, no_taint,
         min_confidence, fail_on, since, custom_rules, verify_secrets, verbose):
    """Scan a directory for security vulnerabilities."""
    import logging
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)

    cfg = CodeAuditConfig.from_yaml(config) if config else CodeAuditConfig()
    cfg.scanners.secret_detector = not no_secrets
    cfg.scanners.dep_analyzer = not no_deps
    cfg.scanners.payment_scanner = not no_payment
    cfg.scanners.taint_analyzer = not no_taint
    cfg.scanners.verify_secrets = verify_secrets
    cfg.scanners.incremental_since = since or ""
    cfg.scanners.min_confidence = min_confidence
    cfg.report.output_dir = output
    if custom_rules:
        cfg.scanners.custom_rules_path = custom_rules

    console.print()
    console.print(Panel("[bold]HYPERIUM CODE-AUDIT v4.0[/bold]\n[dim]Production-grade SAST scanner[/dim]", border_style="cyan"))
    console.print("  [dim]Target:[/dim]    " + target)
    console.print("  [dim]Format:[/dim]    " + fmt)
    console.print("  [dim]Fail on:[/dim]   " + fail_on)
    console.print()

    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

    engine = CodeAuditEngine(cfg)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), console=console) as progress:
        task = progress.add_task("Scanning...", total=100)
        def on_progress(phase, message, pct):
            desc = "[cyan]" + phase + "[/cyan] " + message
            progress.update(task, completed=pct, description=desc)
        engine.set_progress_callback(on_progress)
        result = engine.scan(target)

    console.print()
    risk = result.risk_score
    rc = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green", "info": "blue"}.get(
        risk.risk_level.value if risk else "info", "blue")

    risk_text = "Risk Score: " + str(risk.overall_score if risk else 0) + "/100"
    if risk:
        risk_text += " -- " + risk.risk_level.value.upper()

    stats_text = (
        "\n  Findings:  " + str(result.total_findings) +
        "\n  Critical:  " + str(risk.critical_count if risk else 0) + "  |  High: " + str(risk.high_count if risk else 0) +
        "\n  Medium:    " + str(risk.medium_count if risk else 0) + "  |  Low:  " + str(risk.low_count if risk else 0) +
        "\n  Secrets:   " + str(len(result.secrets)) + "  |  Payment: " + str(len(result.payment_findings)) +
        "\n  Deps:      " + str(len(result.dep_vulnerabilities)) + "  |  Files: " + str(result.stats.total_files_scanned) +
        "\n  Time:      " + str(result.stats.scan_duration_seconds) + "s"
    )
    console.print(Panel("[" + rc + "]" + risk_text + "[/" + rc + "]" + stats_text,
                        title="[bold]Scan Results[/bold]", border_style=rc))

    for cr in result.compliance_reports:
        pct = cr.compliance_percentage
        color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
        label = cr.framework.value.replace("_", " ").title()
        console.print("  [" + color + "]" + label + ": " + str(pct) + "% compliant[/" + color + "]")

    if result.findings:
        table = Table(title="Top Findings", show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("Finding", min_width=30)
        table.add_column("Location", min_width=20)
        table.add_column("Conf", width=8)
        for f in result.findings[:15]:
            table.add_row(
                "[" + f.severity.color + "]" + f.severity.value.upper() + "[/" + f.severity.color + "]",
                f.title + "\n[dim]" + f.rule_id + "[/dim]",
                f.file_path + ":" + str(f.line_number),
                str(round(f.confidence * 100)) + "%",
            )
        console.print(table)

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if fmt in ("html", "both", "all"):
        p = generate_html(result, output_dir / (result.scan_id + ".html"))
        console.print("\n  [green]✓[/green] HTML: " + str(p))
    if fmt in ("json", "both", "all"):
        p = generate_json(result, output_dir / (result.scan_id + ".json"))
        console.print("  [green]✓[/green] JSON: " + str(p))
    if fmt in ("sarif", "all"):
        p = generate_sarif(result, output_dir / (result.scan_id + ".sarif"))
        console.print("  [green]✓[/green] SARIF: " + str(p))
    if fmt == "all":
        try:
            from src.pdf_report import generate_pdf
            p = generate_pdf(result, output_dir / (result.scan_id + ".pdf"))
            if p:
                console.print("  [green]✓[/green] PDF: " + str(p))
        except Exception as e:
            console.print("  [dim]PDF skipped: " + str(e) + "[/dim]")

    console.print()
    exit_code = _calculate_exit_code(risk, fail_on)
    if exit_code != 0:
        console.print("[bold red]✗ Exit " + str(exit_code) + ": findings at " + fail_on + "+ detected[/bold red]")
    else:
        console.print("[bold green]✓ Exit 0: clean[/bold green]")
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
    console.print("[green]✓[/green] Example rules: " + str(path))
    console.print("  Edit and pass to scan: --custom-rules <path>")


@main.command()
def trend():
    """Show scan trend compared to previous scans."""
    from src.scan_history import ScanHistory, format_trend_report
    history = ScanHistory()
    latest = history.get_latest()
    if not latest:
        console.print("[dim]No scan history found. Run a scan first.[/dim]")
        return
    console.print("Latest scan: " + str(latest.get("scan_id", "?")))
    console.print("  Risk Score: " + str(latest.get("risk_score", 0)) + "/100")
    console.print("  Findings: " + str(latest.get("total_findings", 0)))
    console.print("  Date: " + str(latest.get("timestamp", "?"))[:19])

    all_scans = history.get_history()
    if len(all_scans) >= 2:
        prev = all_scans[-2]
        console.print("\nPrevious scan: " + str(prev.get("scan_id", "?")))
        delta = history._calculate_delta(prev, latest)
        console.print("\n" + format_trend_report(delta))


@main.command()
def version():
    """Show version information."""
    console.print("[bold]Hyperium Code-Audit[/bold] v4.0.0")


if __name__ == "__main__":
    main()