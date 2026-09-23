# Captured test and demo outputs

These outputs were produced by the submitted implementation. Static-only examples and the unit suite do not require a model; the Ollama smoke test below is a separate live local-model run.

## Test 1 — interpolated SQL, hard-coded secret, and eval

Command: `python -m app.cli examples/vulnerable.py --static-only`

```text
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

## Test 2 — parameterized query and environment-based key

Command: `python -m app.cli examples/safe.py --static-only`

```text
Decision: APPROVED
LLM: not_configured; context retries: 0
```

## Test 3 — automated suite

Command: `python -m unittest discover -v`

```text
Ran 17 tests in 0.019s

OK
```

The exact duration varies by machine. The tests use a fake reviewer and cover static checks, both conflict directions, prompt injection, malformed model data, fallback, retry termination, parse failures, repeatability, and CLI JSON. They do not call a live model.

## Live LLM smoke test — local Ollama

Ollama was configured as the OpenAI-compatible local endpoint with model `llama3.2`; the command was run without `--static-only`:

```text
python -m app.cli examples/vulnerable.py --json
```

Actual report fields included:

```json
{
  "context_retries": 1,
  "decision": "REJECTED",
  "llm_status": "ok"
}
```

The complete report retained the deterministic HIGH findings for the sample secret, SQL injection, and `eval()`. The successful LLM response did not override them. Ollama runs locally; `ollama` is the adapter's placeholder key, not a hosted API credential.
