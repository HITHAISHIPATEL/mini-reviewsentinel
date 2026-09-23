from __future__ import annotations

from .agent import run_bounded_review
from .analyzer import analyze_source, collect_python_files
from .decision import decide
from .models import Finding, ReviewReport


def review_path(path: str, reviewer=None) -> ReviewReport:
    files, errors = collect_python_files(path)
    static_findings: list[Finding] = []
    for name, source in files:
        findings, file_errors = analyze_source(source, name)
        static_findings.extend(findings)
        errors.extend(file_errors)
    llm_findings, llm_status, retries = run_bounded_review(reviewer, dict(files), static_findings)
    combined: dict[tuple[str, int, str], Finding] = {}
    for finding in static_findings + llm_findings:
        key = (finding.file, finding.line, finding.finding)
        if key not in combined or (finding.source == "static" and combined[key].source != "static"):
            combined[key] = finding
    ordered = sorted(combined.values(), key=lambda f: (f.file, f.line, f.finding, f.source))
    errors = sorted(errors, key=lambda e: (e.get("file", ""), e.get("error", "")))
    return ReviewReport(decide(ordered, errors), ordered, llm_status, errors, retries)
