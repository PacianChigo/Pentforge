"""Command-line interface for pentforge."""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from pentforge import __version__
from pentforge.enrich.severity import enrich
from pentforge.parsers import nmap
from pentforge.report import generator

app = typer.Typer(
    name="pentforge",
    help="Pentest report generator — parse nmap XML, generate HTML reports.",
    no_args_is_help=True,
)
console = Console()

SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "white",
}


def _print_summary(report) -> None:
    counts = report.severity_counts()
    table = Table(title="Findings Summary", show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ("critical", "high", "medium", "low", "info"):
        table.add_row(
            f"[{SEV_STYLE[sev]}]{sev.upper()}[/]",
            str(counts[sev]),
        )
    console.print(table)

    detail = Table(title="Findings")
    detail.add_column("Host")
    detail.add_column("Port")
    detail.add_column("Service")
    detail.add_column("Severity")

    for f in report.findings:
        detail.add_row(
            f.host,
            f"{f.port}/{f.protocol}",
            f.service or "—",
            f"[{SEV_STYLE[f.severity]}]{f.severity.upper()}[/]",
        )
    console.print(detail)


@app.command()
def parse(
    scan_file: Path = typer.Argument(..., help="Path to nmap XML file (-oX output)"),
    output: Path = typer.Option(
        None, "--output", "-o", help="Output file (.html or .json)"
    ),
    json_only: bool = typer.Option(
        False, "--json", help="Print JSON only (no tables)"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress terminal output"
    ),
) -> None:
    """Parse an nmap XML scan and generate a report."""
    if not scan_file.exists():
        console.print(f"[red]Error:[/] file not found: {scan_file}")
        raise typer.Exit(code=1)

    if not quiet:
        console.print(f"[cyan]Parsing[/] {scan_file} ...")

    report = nmap.parse(scan_file)

    if not report.findings:
        if not quiet:
            console.print("[yellow]No open ports found in scan file.[/]")
        raise typer.Exit(code=0)

    report = enrich(report)

    if json_only:
        print(json.dumps(report.model_dump(), indent=2, default=str))
    elif not quiet:
        _print_summary(report)

    if output:
        suffix = output.suffix.lower()
        if suffix == ".json":
            generator.write_json(report, output)
        else:
            generator.write_html(report, output)
        if not quiet:
            console.print(f"[green]✓[/] Report saved to {output}")


@app.command()
def version() -> None:
    """Show the version."""
    console.print(f"pentforge [bold cyan]{__version__}[/]")


if __name__ == "__main__":
    app()
