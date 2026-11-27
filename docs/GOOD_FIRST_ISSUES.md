# Good first issues

These are intentionally small, reviewable starter specifications. Each one
should include unit tests and should preserve zero runtime dependencies.

## 1. Add a compact pattern fingerprint

Implement a deterministic SHA-256 fingerprint of the normalized pattern text,
flags, and policy limits on `AnalysisResult`. Do not include timestamps,
machine paths, or object addresses. Add tests proving that the same input
produces the same fingerprint in two fresh analysis calls.

## 2. Add branch spans to overlap findings

When `REDOS_OVERLAPPING_ALTERNATION` reports two branches, include the exact
branch spans in `Finding` properties or structured message data without
breaking the existing dataclass API. Add tests for `(a|ab)+` and
`([a-z]|[a-f])+`.

## 3. Improve condition expression validation

Compare conditional group behavior with `re.compile` for valid numeric and
named references. Add tests for references to closed groups, open groups,
unknown names, conditional branches with zero branches, and more than two
branches. Keep the parser independent of private CPython internals.

## 4. Add JSON output schema documentation

Write a small reference page for `pyregexshield check --json` and
`pyregexshield scan --format json`. Document every field, type, stability
promise, and example. Add tests that compare the implementation keys with the
documentation table.

## 5. Support constant tuple flag combinations in the scanner

The scanner already handles integer constants, `re` attributes, and bitwise
OR expressions. Extend it to evaluate simple module-level constant assignments
such as `FLAGS = re.IGNORECASE | re.MULTILINE` when the value is a literal AST
expression. Do not execute code. Add positive and dynamic negative tests.

## 6. Add a baseline suppression file

Design and implement an optional scan baseline format that suppresses only
exact matches on filename, line, column, finding code, and pattern hash.
Changing the pattern or moving the call must invalidate the suppression. Add
round-trip, tamper, and wrong-line tests.

## 7. Measure analyzer scaling

Add a benchmark script under `tests/perf` or `tools/` that measures linear or
near-linear completion for repeated literals, deep but legal nesting, many
alternation branches, and many character class items. Do not require the
benchmark in unit tests. Document representative local numbers without
claiming cross-machine guarantees.

## 8. Add a SARIF validation test

Add a strict structural test for required SARIF 2.1.0 keys, artifact URI
consistency, result rule references, severity mapping, line numbers, and
stable fingerprints. The test should use only the standard library. Do not
add a JSON schema dependency.

## 9. Improve verbose-mode parser coverage

Add differential tests for escaped spaces, character class spaces, comments
containing brackets or parentheses, inline scoped verbose mode, plain global
verbose mode, carriage return line endings, and comments at end of pattern.
Document any intentional difference from `re.compile`.

## 10. Add safe iterator convenience helpers

Add `safe_finditer` and `safe_split` module-level helpers mirroring the
existing `SafePattern` methods. Keep argument order explicit, enforce input
length before creating the iterator, type check inputs, and test lazy input
validation behavior.

## Before submitting

Run:

```
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Include one dangerous regex and one safe regex in the pull request whenever a
detector changes. Explain the security tradeoff plainly.
