# Mini ReviewSentinel

A small Python CLI that reviews Python source without executing it. It combines deterministic AST/heuristic checks with an optional LLM review and a conservative decision layer. The LLM is advisory: a deterministic high-severity finding cannot be overruled by a model response.

## Install and run

Requires Python 3.10 or newer. Runtime uses only the standard library. From a clone or extracted ZIP, install any declared dependencies (currently none):

```bash
cd mini-reviewsentinel
python -m pip install -r requirements.txt
```

Then run the tool and tests:

```bash
python -m app.cli examples/vulnerable.py --static-only
python -m app.cli examples/safe.py --static-only
python -m unittest discover -v
```

JSON output is available with `--json`. Exit codes: `0` approved, `1` review required, `2` rejected, and `3` for input/runtime analysis errors that prevent a useful decision (individual file errors remain in the JSON report and require review).

To enable an OpenAI-compatible LLM endpoint, set `REVIEW_SENTINEL_API_KEY`. Optional settings are `REVIEW_SENTINEL_MODEL` (default `gpt-4o-mini`) and `REVIEW_SENTINEL_ENDPOINT` (default OpenAI chat completions URL). No key is sent or required in static-only mode. LLM calls use a bounded timeout; no network is used by the test suite.

## Architecture

```text
 Python file / repository (UNTRUSTED; never executed)
                         |
           Input, file filtering, size/parse checks [deterministic]
                         |
         +---------------+------------------+
         |                                  |
 Static AST checks [deterministic]     LLM contextual review [probabilistic]
 SQL interpolation, likely secrets,    optional provider; source is quoted as
 eval/exec                              untrusted; strict JSON validation
         |                                  |
         +---------------+------------------+
                         |
 Bounded state/revisit [deterministic control, max 1 context retry]
                         |
 Decision policy + deduplication [deterministic]
                         |
 JSON/human-readable report + exit status
```

**Deterministic:** file collection, parsing, security rules, output validation, retry limit, finding merge/deduplication, final decision.
**Probabilistic:** only the LLM's contextual observations. It cannot change static findings or set the final decision.

## What it checks

- **SQL injection:** flags dynamically interpolated/concatenated SQL passed to common `execute`-style calls, including a simple variable assignment before the call. Bound parameters passed separately are not flagged in the standard safe pattern.
- **Hard-coded secrets:** looks for non-placeholder string literals assigned to credential-like variable names and applies length/composition heuristics. Environment lookups and common placeholders are excluded.
- **Dynamic execution:** flags direct `eval()`/`exec()` calls and common aliases imported from `builtins`.

The tool reads source as text and parses it with `ast`; it never imports or executes reviewed code. It ignores common virtualenv/cache/build directories, limits individual files to 1 MB, and records unreadable or unparsable files in `analysis_errors` rather than silently treating them as clean.

## Example output

Running the bundled deliberately vulnerable sample:

```text
$ python -m app.cli examples/vulnerable.py --static-only
Decision: REJECTED
LLM: not_configured; context retries: 0

vulnerable.py:2 [HIGH] Possible hard-coded secret (static)
  Evidence: Sensitive variable 'api_key' is assigned a non-placeholder string literal.
  Recommendation: Load the credential from a secret manager or environment variable; rotate it if real.
  Decision: REJECTED

vulnerable.py:4 [HIGH] Potential SQL injection (static)
  Evidence: SQL execution receives a dynamically assembled query: f"SELECT * FROM users WHERE id = {user_id}"
  Recommendation: Use a constant query with bound parameters (for example, execute(sql, (value,))).
  Decision: REJECTED

vulnerable.py:5 [HIGH] Dangerous dynamic code execution via eval() (static)
  Evidence: Call expression: eval(user_expression)
  Recommendation: Avoid evaluating source strings; use a safe parser or an explicit allowlisted operation.
  Decision: REJECTED
```

The safe parameterized example is approved in static-only mode:

```text
$ python -m app.cli examples/safe.py --static-only
Decision: APPROVED
LLM: not_configured; context retries: 0
```

## LLM use, conflicting evidence, and safety

If configured, the LLM looks for contextual issues that simple rules can miss. Its response must be valid JSON, reference an input file and valid line, use a recognized severity, and provide bounded text fields. Invalid entries are discarded; malformed responses or API failures are reported through `llm_status`, without discarding static results or crashing the review.

A model finding is not automatically a rejection: absent a deterministic HIGH/CRITICAL signal, findings (including model-reported HIGH risk) lead to `REVIEW_REQUIRED`. A deterministic HIGH/CRITICAL finding always leads to `REJECTED`, even if the LLM says the code is safe. `APPROVED` requires no findings and no analysis errors. Without an API key, deterministic review still runs and the report says `not_configured`; this is reduced coverage, not proof that the code is safe.

Source code is treated as untrusted data. It is sent only as user-provided review content, the system prompt tells the model to ignore instructions inside comments/strings/docstrings, and the application never lets source text or model output alter review policy. Static findings remain authoritative for rejection.

The state machine makes at most one targeted contextual revisit when model confidence is low, a model finding overlaps a deterministic finding, or the model omits a deterministic finding. The retry limit is a constant (`MAX_CONTEXT_RETRIES = 1`); the original static evidence is preserved and repeated ambiguity terminates in the deterministic decision policy.

## Tests

Run `python -m unittest discover -v`. Tests use a fake reviewer and local code samples; they make no API calls. Coverage includes SQL injection and safe parameters, likely secrets and placeholder suppression, eval/exec, both conflict directions, source prompt injection, malformed LLM data, offline fallback, retry termination, parse failures, repeatability, and JSON CLI output. Captured command/test outputs are in [`TEST_OUTPUTS.md`](TEST_OUTPUTS.md).

## Known limitations

- SQL detection is intentionally conservative and local: it is not full taint analysis, does not understand every database wrapper/alias, and may miss values flowing through helper functions or report trusted dynamic SQL expressions.
- Secret detection is heuristic; it can miss secrets under generic names and may still flag unusual test credentials. Rotate any real credential that is reported.
- `eval`/`exec` are flagged regardless of whether a particular input is currently trusted; this is intentional for a mini security reviewer.
- LLM review is optional, network/provider dependent, and not a guarantee of correctness. The tool does not edit code, execute tests in the target repository, or replace human review.
- The CLI reviews files/directories, not patch semantics; line numbers refer to the current source files.
