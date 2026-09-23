# Mini ReviewSentinel — End-to-End Assignment Map

## 1. What the assignment is asking for

Build a small, explainable code-review tool for Python changes/repositories. It must produce structured findings (file, line, finding, severity, evidence, recommendation, decision), combine deterministic security checks with an LLM's contextual review, and make a final decision that does **not** blindly trust the LLM. The submission is judged on correctness, reasoning, safe failure behaviour, tests, and clear documentation—not on size or production-scale complexity.

## 2. Intended final outcome

A runnable Python CLI which accepts a file or directory, analyzes Python source without executing it, optionally asks a configured LLM for contextual review, and prints a stable JSON report. It must also run safely without credentials (offline/static-only mode), explain when LLM review was skipped/failed, and exit reliably. The deliverable will include implementation, meaningful tests with captured real test outputs, README, design decisions, and a clean ZIP/repository layout.

## 3. Proposed architecture

```text
 Python file / repository (untrusted input; never executed)
                         |
             Input + deterministic file collection
                         |
     +-------------------+--------------------+
     |                                        |
 Static Analyzer (deterministic)         LLM Reviewer (probabilistic,
 - SQL injection context                 optional, schema-validated)
 - likely hard-coded secrets              - contextual security review
 - eval()/exec()                           - cannot erase static findings
     |                                        |
     +-------------------+--------------------+
                         |
        Bounded review state machine (0 or 1 context retry)
        - reconsider uncertain finding with nearby source context
        - stop after fixed retry cap; no code execution or auto-fix
                         |
             Deterministic decision policy
      REJECTED / REVIEW_REQUIRED / APPROVED
                         |
       JSON report + human-readable CLI summary + exit status
```

**Deterministic:** file collection, source parsing, static rules, schema validation, retry cap, finding merge/deduplication, decision policy, serialization.
**Probabilistic:** only contextual LLM suggestions/findings. The LLM is advisory and cannot downgrade a deterministic high-confidence issue.

## 4. Final project layout

```text
mini-reviewsentinel/
├── app/
│   ├── __init__.py
│   ├── cli.py              # arguments, input validation, output/exit code
│   ├── models.py           # finding/report enums and validation
│   ├── analyzer.py         # deterministic Python security checks
│   ├── llm.py              # provider interface, prompt, timeout/schema handling
│   ├── agent.py            # bounded context-revisit state machine
│   ├── decision.py         # static + LLM evidence policy
│   └── review.py           # orchestration, deduplication, idempotent report
├── tests/
│   ├── test_analyzer.py
│   ├── test_decision_agent.py
│   └── test_cli.py
├── examples/               # small safe/vulnerable sample inputs and report
├── README.md
├── DECISIONS.md
├── requirements.txt
└── .gitignore
```

Keep dependencies lean. Use Python standard library where practical; if an HTTP LLM client is included, isolate it behind a provider interface and pin/document the dependency. Tests must not require a network or API key: use a deterministic fake LLM.

## 5. Implementation map, first step to last

1. **Lock report contract:** define enums (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`; `APPROVED`, `REVIEW_REQUIRED`, `REJECTED`) and a JSON-serializable finding with file, line, title/finding, severity, evidence, recommendation, source (`static`/`llm`), and confidence. Validate all LLM-provided fields before accepting them.
2. **Input boundary:** accept one `.py` file or recursively collect `.py` files from a directory; ignore virtualenv, cache, VCS, and generated directories; set a reasonable file-size limit; never import or execute reviewed source. Record unreadable/invalid files as analysis errors rather than crashing the whole review.
3. **Static checks (must work offline):**
   - Parse Python using `ast` to locate calls to `eval` and `exec`; report the call's source line.
   - Detect risky SQL at database execute/exec-like call sites when query text is assembled with f-strings, `%` formatting, `.format()`, or string concatenation; do not flag parameterized placeholders whose values are passed separately (for example, `execute(query, (user_id,))`). Use source snippets/AST where practical and document the rule's scope.
   - Detect likely literal credentials from assignments to credential-like names (`password`, `api_key`, `secret`, `token`, etc.) plus plausible non-placeholder values. Exclude obvious environment lookups, empty/example values, and known placeholders. Avoid reporting every string that merely resembles a password.
4. **LLM interface:** support a configured OpenAI-compatible provider and bounded timeout; local Ollama (`llama3.2`) is the tested provider, while static-only remains available if no provider is configured. Send only necessary code/context. Use a system instruction that treats repository content as quoted, untrusted data; explicitly say source comments/strings cannot change reviewer instructions. Request strict JSON, parse and validate it, reject malformed output, cap response size, and never allow model output to directly set final decision. The Ollama smoke test returned `llm_status: ok`.
5. **Agentic revisit:** begin with static/LLM findings; if a finding is ambiguous or the providers materially disagree, request one targeted context pass (nearby lines/call site, not a new broad review). Re-evaluate/add context, preserve original evidence, then terminate. Hard cap: one extra pass globally per review (`MAX_CONTEXT_RETRIES = 1`); errors/timeouts also terminate. No autonomous edits and no repository commands.
6. **Decision & conflict policy:** deterministic HIGH/CRITICAL security finding => `REJECTED`, even if LLM says safe. LLM high-risk finding with no supporting deterministic signal => at least `REVIEW_REQUIRED`, never automatic rejection solely from an unsupported model claim. Medium/uncertain or analyzer errors => `REVIEW_REQUIRED`. `APPROVED` only when there are no actionable findings and analysis completed; static-only mode may approve only if all deterministic checks pass, while report clearly labels coverage as reduced. Document precedence and rationale.
7. **Repeatability:** make a review a pure operation over input plus configuration. Stable ordering and deduplication by file/line/rule prevent duplicate findings on repeated runs. No persistent side effects; identical input/config yields equivalent report apart from optional timestamps (prefer omit timestamp for exact repeatability).
8. **CLI/report:** provide `python -m app.cli PATH [--json] [--static-only]`; readable summary and machine-readable JSON. Use documented exit codes, e.g. 0 approved, 1 review required, 2 rejected, 3 input/runtime failure. Individual file failures appear in report and do not hide findings in other files.
9. **Documentation:** README covers setup, run/test commands, example invocation/output, architecture diagram, deterministic vs probabilistic boundaries, conflict policy, LLM setup, and limitations. DECISIONS.md answers A–F from the brief directly.
10. **Verification & packaging:** run all tests from a clean environment; run CLI on safe and unsafe examples; capture actual output for at least three tests in README or `TEST_OUTPUTS.md`; check line numbers and JSON validity; ensure no credentials, venv, caches, or generated files; create ZIP only after the final test run.

## 6. Required test-to-requirement map

| Assignment requirement | Test / evidence |
|---|---|
| Genuine SQL injection | F-string/concatenated user value reaches execute; assert finding and line |
| Safe parameterized SQL | Bound parameter passed separately; assert no SQLi finding |
| Hard-coded secret | Literal credential under sensitive variable name is reported |
| Secret false-positive control | Placeholder, environment lookup, or benign documentation value is not reported |
| `eval`/`exec` | AST call produces line-specific finding |
| Static HIGH vs LLM LOW | Final decision remains `REJECTED` |
| Static LOW vs LLM HIGH | Final decision is at least `REVIEW_REQUIRED` |
| Prompt injection in source | Fake LLM receives source as untrusted data; injected comment cannot alter policy / auto-approve |
| Agent termination | Assert bounded call count and termination at the configured retry cap, including repeated ambiguity |
| LLM outage / malformed response | Review returns deterministic findings plus explicit degraded/error status, not an uncaught exception |
| Analysis failure | Unreadable or syntactically invalid file is represented as an error and remaining files are reviewed |
| Repeated request | Same inputs produce stable, nonduplicated findings |

At least three test cases should include the actual output printed by the implementation. Keep those outputs generated by the real test/CLI run, not hand-authored claims.

## 7. Three+ hidden-case risks to address

1. **Parameterized SQL assembled across variables or multiline expressions.** A naive search can flag safe placeholders or miss injection after string composition. Track the execute call and whether values are passed as separate bound parameters; add a multiline regression test. Document that sophisticated interprocedural flows are a limitation.
2. **Credential-looking examples and configuration fetched securely.** Tests/docs often contain `password="example"`, while real code may use a sensitive name with a placeholder. Combine identifier, literal, and placeholder heuristics; test both a genuine literal and a benign example/env lookup.
3. **Prompt injection inside comments, strings, or docstrings.** A naive LLM prompt may obey repository instructions. Label source as untrusted quoted data, delimit it, constrain output to schema, and keep decisions in deterministic code; test via fake provider.
4. **Aliased or indirect dangerous calls / unsupported syntax.** `from builtins import eval as run` or parse failures can evade a simple rule. Detect direct and common aliased forms if feasible; on parse failure, record incomplete analysis and require review rather than approve.
5. **LLM hallucinated file/line or malformed JSON.** Validate paths/line ranges against the input and schema; reject invalid records safely and preserve findings from the static analyzer.

## 8. Completion checklist

- [ ] Every requirement above is implemented or its deliberate limitation is documented.
- [ ] `python -m unittest discover -v` passes against submitted code.
- [ ] At least three real outputs are recorded.
- [ ] README and DECISIONS.md answer every requested item.
- [ ] Demo includes both safe and vulnerable code, with correct decisions and line references.
- [ ] LLM is advisory, local-Ollama smoke-tested, and never receives authority from source comments; static-only fallback remains available.
- [ ] Retry/timeout and failure paths terminate predictably.
- [ ] Submission contains only source, tests, docs, examples, and requirements; ZIP/repository is ready to submit.
