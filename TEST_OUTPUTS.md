# Captured test and demo outputs

These are actual outputs from the submitted CLI/tests after running them locally in the project directory. Examples use `--static-only`, so they do not depend on an API key.

## Test 1 — true SQL interpolation, hard-coded secret, and eval

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
Ran 17 tests in 0.006s

OK
```

The exact duration varies by machine. The unit tests exercise these outputs and failure paths against the submitted implementation; tests do not call an external model.
