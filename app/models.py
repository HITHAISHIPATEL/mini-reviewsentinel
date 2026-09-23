from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, Enum):
    APPROVED = "APPROVED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REJECTED = "REJECTED"


@dataclass
class Finding:
    file: str
    line: int
    finding: str
    severity: Severity
    evidence: str
    recommendation: str
    source: str = "static"
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ReviewReport:
    decision: Decision
    findings: list[Finding] = field(default_factory=list)
    llm_status: str = "not_configured"
    analysis_errors: list[dict[str, str]] = field(default_factory=list)
    context_retries: int = 0

    def to_dict(self) -> dict[str, Any]:
        finding_rows = []
        for finding in self.findings:
            row = finding.to_dict()
            row["decision"] = self.decision.value
            finding_rows.append(row)
        return {
            "decision": self.decision.value,
            "findings": finding_rows,
            "llm_status": self.llm_status,
            "analysis_errors": self.analysis_errors,
            "context_retries": self.context_retries,
        }


def validate_llm_payload(payload: Any, known_files: set[str], line_counts: dict[str, int]) -> list[Finding]:
    """Strictly validate model data; invalid records are ignored, never trusted."""
    if not isinstance(payload, dict) or not isinstance(payload.get("findings", []), list):
        raise ValueError("LLM response must be an object with a findings array")
    findings: list[Finding] = []
    for item in payload.get("findings", []):
        if not isinstance(item, dict):
            continue
        file = item.get("file")
        line = item.get("line")
        title = item.get("finding")
        evidence = item.get("evidence")
        recommendation = item.get("recommendation")
        if not isinstance(file, str) or file not in known_files:
            continue
        if not isinstance(line, int) or isinstance(line, bool) or line < 1 or line > line_counts.get(file, 0):
            continue
        if not all(isinstance(v, str) and v.strip() for v in (title, evidence, recommendation)):
            continue
        if any(len(v) > 1200 for v in (title, evidence, recommendation)):
            continue
        try:
            severity = Severity(str(item.get("severity", "MEDIUM")).upper())
        except ValueError:
            continue
        try:
            confidence = float(item.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        if not 0 <= confidence <= 1:
            confidence = 0.5
        findings.append(Finding(file, line, title.strip(), severity, evidence.strip(),
                                recommendation.strip(), "llm", confidence))
    return findings
