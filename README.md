# Mini ReviewSentinel

Mini ReviewSentinel is a Python CLI for reviewing Python files or repositories. It combines deterministic static security checks with an LLM's contextual review. The LLM is advisory: it cannot remove a deterministic finding or decide the final outcome by itself.

## Install and run

Requires Python 3.10 or newer. Runtime and tests use the Python standard library; no `pip` packages are required. From the project root:

```powershell
python -m app.cli .\examples\vulnerable.py --static-only
python -m app.cli .\examples\safe.py --static-only
python -m unittest discover -v
```

Add `--json` for a machine-readable report. Exit codes are `0` approved, `1` review required, `2` rejected, and `3` for input errors that prevent a useful review. A rejected sample returning exit code `2` is expected.

## Run contextual review with local Ollama

The implementation uses an OpenAI-compatible chat-completions interface. It has been smoke-tested with **Ollama and the `llama3.2` model**. Ollama runs locally; after downloading a model, the review request goes to the local machine rather than a hosted model service. The `ollama` API-key value below is a compatibility placeholder required by this client, not a cloud secret; Ollama ignores it.

Install Ollama for Windows, then in PowerShell download the model:

```powershell
ollama pull llama3.2
```

From a PowerShell terminal in this project directory, configure the current session:

```powershell
$env:REVIEW_SENTINEL_API_KEY = "ollama"
$env:REVIEW_SENTINEL_ENDPOINT = "http://localhost:11434/v1/chat/completions"
$env:REVIEW_SENTINEL_MODEL = "llama3.2"
```

Run without `--static-only` to invoke the LLM:

```powershell
.\.venv\Scripts\python.exe -m app.cli .\examples\vulnerable.py --json
```

A successful live response reports `"llm_status": "ok"`. One tested run returned `context_retries: 1` and `decision: REJECTED`; the final rejection was due to deterministic HIGH-severity findings. The LLM made one contextual follow-up because it omitted a static finding, within the fixed retry cap. The configured request timeout is 120 seconds, allowing a local model time to start and respond.

The same adapter can use another OpenAI-compatible chat-completions provider. Set `REVIEW_SENTINEL_API_KEY`, `REVIEW_SENTINEL_ENDPOINT`, and `REVIEW_SENTINEL_MODEL` for that provider. The default endpoint is OpenAI; credentials are never stored in source files. If no key is configured, the CLI runs static checks and reports `llm_status: not_configured`. If the provider times out or returns malformed data, the error is reflected in `llm_status` and deterministic results are retained.

## Architecture

```text
 Python file / repository (UNTRUSTED; never executed)
                         |
           Input, file filtering, size/parse checks [deterministic]
                         |
         +---------------+------------------+
         |                                  |
 Static AST checks [deterministic]     LLM review [probabilistic]
 SQL interpolation, likely secrets,    local Ollama or compatible endpoint;
 eval/exec                              untrusted source; validated JSON
         |                                  |
         +---------------+------------------+
                         |
 Bounded state/revisit [deterministic control, max 1 context retry]
                         |
 Decision policy + deduplication [deterministic]
                         |
 JSON/human-readable report + exit status
```

**Deterministic:** file collection, parsing, security rules, response validation, retry limit, finding merge/deduplication, and final decision.
**Probabilistic:** the LLM's contextual observations. It cannot set the final decision or downgrade static findings.

## What it checks

- **SQL injection:** flags dynamically interpolated/concatenated SQL passed to common `execute`-style calls, including a simple variable assignment before the call. Bound parameters passed separately are not flagged in the standard safe pattern.
- **Hard-coded secrets:** looks for non-placeholder string literals assigned to credential-like variable names and applies length/composition heuristics. Environment lookups and common placeholders are excluded.
- **Dynamic execution:** flags direct `eval()`/`exec()` calls and common aliases imported from `builtins`.

The tool reads source as text and parses it with `ast`; it never imports or executes reviewed code. It ignores common virtualenv/cache/build directories, limits individual files to 1 MB, and records unreadable or unparsable files in `analysis_errors` rather than silently treating them as clean.

## Example output

Running the bundled deliberately vulnerable sample in static-only mode:

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

## Decision policy, reliability, and source safety

A deterministic HIGH/CRITICAL finding always yields `REJECTED`, even if the LLM says the code is safe. If static analysis has no high-severity finding but the LLM reports an issue, the result is at least `REVIEW_REQUIRED`; an LLM-only claim cannot automatically reject code. `APPROVED` requires no actionable findings and no analysis errors. A static-only approval is explicitly reduced-coverage, not proof that all vulnerabilities have been ruled out.

The LLM response must be valid JSON with findings tied to an in-review file and valid line. Severity and text fields are validated and bounded. Invalid output or request failures are reported through `llm_status`; static findings are retained. The state machine makes at most one targeted contextual revisit when the model is uncertain or disagrees with/omits a static finding, then terminates.

Source code is untrusted data. The prompt instructs the model to ignore instructions inside comments, strings, and docstrings; code is never executed; and source text or model output cannot alter the decision policy.

## Tests

Run `python -m unittest discover -v`. The 17 tests use a fake reviewer and local code samples; they make no API calls. Coverage includes SQL injection and safe parameters, secrets and placeholder suppression, `eval`/`exec`, conflicting evidence, prompt injection, malformed model data, offline fallback, retry termination, parse failures, repeatability, and CLI JSON output. The separate Ollama smoke test was a live local-model request. Captured results are in [`TEST_OUTPUTS.md`](TEST_OUTPUTS.md).

## Known limitations

- SQL detection is local and heuristic, not full taint analysis; it may miss flows through helper functions or custom wrappers and may flag trusted dynamic SQL.
- Secret detection is heuristic; generic variable names can evade it, and unusual test credentials can be flagged.
- `eval`/`exec` are flagged even when a particular input may be trusted.
- LLM review is probabilistic and not a guarantee of correctness. Human review is still needed for uncertain outcomes.
- The CLI reviews current files/directories rather than patch semantics; line numbers refer to the current source.
