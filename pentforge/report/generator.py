"""Render the HTML report using Jinja2."""

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pentforge.models import ScanReport

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(report: ScanReport) -> str:
    """Render the HTML report as a string."""
    env = _env()
    template = env.get_template("report.html.j2")
    return template.render(
        report=report,
        counts=report.severity_counts(),
    )


def write_html(report: ScanReport, output: str | Path) -> Path:
    """Render and write the HTML report to a file."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    html = render_html(report)
    output.write_text(html, encoding="utf-8")
    return output


def write_json(report: ScanReport, output: str | Path) -> Path:
    """Write the report as JSON."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report.model_dump(), indent=2, default=str),
        encoding="utf-8",
    )
    return output
