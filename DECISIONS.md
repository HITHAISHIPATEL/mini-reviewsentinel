# Design decisions — Mini ReviewSentinel

## A. Static vs. LLM disagreement

A deterministic HIGH/CRITICAL finding yields `REJECTED`, even if the LLM says LOW risk or returns no finding. The static checks cover a narrow set of recognizable patterns and are deliberately treated as hard evidence for these cases. If static analysis has no high-severity finding but the LLM reports an issue, the result is at least `REVIEW_REQUIRED`; an LLM-only concern does not automatically reject code. This favors human review over either ignoring a contextual warning or treating a probabilistic claim as established fact. Medium/low static findings and analysis errors also require review.

## B. LLM failure

The LLM is optional. If no key is configured, review continues in static-only mode and reports `llm_status: not_configured`. If a request times out, the provider fails, or output is malformed, the error is recorded in `llm_status`; deterministic findings and the final decision still work. Static-only `APPROVED` means only that the implemented deterministic checks found no issue; it is reduced-coverage approval, not a claim that all vulnerabilities were ruled out.

## C. LLM output validation

The provider must return a JSON object with a `findings` list. Each accepted item must have a known in-review file, an in-range integer line, bounded nonempty text fields, a recognized severity, and normalized confidence. Invalid items are discarded; malformed top-level output is treated as an LLM error. Model output cannot directly set the final decision or downgrade a static finding. This keeps parsing and authority in ordinary application code.

## D. Agent termination

The state machine makes one initial LLM request and at most one targeted context revisit (`MAX_CONTEXT_RETRIES = 1`) when confidence is low, a model finding overlaps a static finding, or the model omits a static finding. It then merges/deduplicates findings and exits through the deterministic decision layer. Provider failure also terminates. The tool never asks the reviewed repository to fix itself and never runs repository code, so there is no unbounded review/fix loop.

## E. False positives

Credential detection is particularly difficult: test fixtures and examples often contain strings such as `password`, while production secrets can be short or stored under arbitrary names. This implementation requires a sensitive-looking assignment name, a literal value, and a simple length/composition test; it excludes common placeholders and secure environment lookups. This lowers obvious false positives but will still miss credentials in generic variables and can flag a convincing test token. The rule is a triage heuristic, not proof of credential validity.

SQL detection has a related limitation: f-strings can be trusted in some contexts, but proving provenance would require interprocedural taint analysis. This implementation reports dynamic SQL expressions at common execute call sites; bound query parameters passed separately in the standard pattern are not flagged.

## F. Deliberate simplicity trade-off

Instead of adding a full taint-analysis framework or multi-agent graph, the project uses Python's built-in AST, small focused heuristics, and a single bounded contextual revisit. This keeps installation, tests, and behavior explainable under the assignment's time constraint. The trade-off is reduced coverage for aliases, helper functions, custom database wrappers, and complex dataflow; known limits are documented and analysis errors do not silently become clean approvals.
