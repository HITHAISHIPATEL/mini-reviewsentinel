from .models import Decision, Finding, Severity


def decide(findings: list[Finding], analysis_errors: list[dict[str, str]]) -> Decision:
    """Deterministic precedence: static high => reject; model high => human review."""
    if any(f.source == "static" and f.severity in {Severity.HIGH, Severity.CRITICAL} for f in findings):
        return Decision.REJECTED
    if findings or analysis_errors:
        return Decision.REVIEW_REQUIRED
    return Decision.APPROVED
