from __future__ import annotations

import argparse
import json
import os
import sys

from .llm import LLMError, OpenAICompatibleReviewer
from .review import review_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review Python code for security issues.")
    parser.add_argument("path", help="Python file or repository directory")
    parser.add_argument("--json", action="store_true", help="Print the complete JSON report")
    parser.add_argument("--static-only", action="store_true", help="Skip LLM review")
    args = parser.parse_args(argv)
    reviewer = None
    if not args.static_only and os.getenv("REVIEW_SENTINEL_API_KEY"):
        try:
            reviewer = OpenAICompatibleReviewer()
        except LLMError:
            reviewer = None
    report = review_path(args.path, reviewer)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Decision: {report.decision.value}")
        print(f"LLM: {report.llm_status}; context retries: {report.context_retries}")
        for finding in report.findings:
            print(f"\n{finding.file}:{finding.line} [{finding.severity.value}] {finding.finding} ({finding.source})")
            print(f"  Evidence: {finding.evidence}")
            print(f"  Recommendation: {finding.recommendation}")
            print(f"  Decision: {report.decision.value}")
        for error in report.analysis_errors:
            print(f"\nAnalysis error — {error['file']}: {error['error']}")
    if any(error.get("error", "").startswith(("Input path does not exist", "Input must be", "No Python files found")) for error in report.analysis_errors):
        return 3
    return {"APPROVED": 0, "REVIEW_REQUIRED": 1, "REJECTED": 2}[report.decision.value]


if __name__ == "__main__":
    sys.exit(main())
