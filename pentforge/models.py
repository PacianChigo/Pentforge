"""Pydantic models for findings and scan metadata."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class Finding(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    severity: Severity = "info"
    reason: str = ""
    remediation: str = ""


class ScanMeta(BaseModel):
    target: str = ""
    scan_date: str = ""
    nmap_version: str = ""
    args: str = ""


class ScanReport(BaseModel):
    meta: ScanMeta = Field(default_factory=ScanMeta)
    findings: list[Finding] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts
