from __future__ import annotations

from .models import Finding, validate_llm_payload

MAX_CONTEXT_RETRIES = 1


def run_bounded_review(reviewer, files: dict[str, str], static_findings: list[Finding]) -> tuple[list[Finding], str, int]:
    """Run one broad review and at most one targeted revisit for ambiguity/conflict."""
    if reviewer is None:
        return [], "not_configured", 0
    counts = {name: len(source.splitlines()) for name, source in files.items()}
    try:
        payload = reviewer.review(files)
        findings = validate_llm_payload(payload, set(files), counts)
        status = "ok"
        static_locations = {(f.file, f.line) for f in static_findings}
        llm_locations = {(f.file, f.line) for f in findings}
        # An omitted static finding is also disagreement: request one contextual
        # look. The original deterministic evidence always remains authoritative.
        uncovered_static = [f for f in static_findings if (f.file, f.line) not in llm_locations]
        candidates = [f for f in findings if f.confidence < 0.75 or (f.file, f.line) in static_locations]
        candidates.extend(uncovered_static)
        retries = 0
        if candidates:
            excerpts: dict[str, str] = {}
            for finding in candidates:
                lines = files[finding.file].splitlines()
                lo, hi = max(0, finding.line - 4), min(len(lines), finding.line + 3)
                excerpts[finding.file] = "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))
            context = (
                "Re-evaluate these uncertain/conflicting findings using only the surrounding source excerpt. "
                "Do not remove or downgrade deterministic findings. Excerpts:\n"
                + "\n---\n".join(f"{name}:\n{text}" for name, text in sorted(excerpts.items()))
            )
            retries = 1
            try:
                payload2 = reviewer.review(files, context=context)
                findings.extend(validate_llm_payload(payload2, set(files), counts))
            except Exception as exc:
                # Keep the first valid pass if the bounded context revisit fails.
                status = f"error: {type(exc).__name__}: {exc}"
        unique: dict[tuple[str, int, str], Finding] = {}
        for finding in findings:
            key = (finding.file, finding.line, finding.finding)
            if key not in unique or finding.confidence > unique[key].confidence:
                unique[key] = finding
        return sorted(unique.values(), key=lambda f: (f.file, f.line, f.finding)), status, retries
    except Exception as exc:
        # LLM errors never erase static results or crash the overall review.
        return [], f"error: {type(exc).__name__}: {exc}", 0
