# Contributing to pyregexshield

Thank you for helping improve pyregexshield. This project is a security
library, so correctness and reproducibility matter more than cleverness.

## Ground rules

- Keep the runtime dependency free. Only the Python standard library may be
  imported by `src/pyregexshield`.
- Support Python 3.9 through 3.13. Do not use syntax or stdlib APIs that are
  unavailable on Python 3.9 unless they are behind a documented runtime
  guard.
- Do not use private CPython regex internals such as `sre_parse` or
  `re._parser`.
- Do not execute an untrusted regex while statically analyzing it.
- Keep every parser and analyzer operation bounded by explicit length, depth,
  quantifier, file size, and file count limits.
- Add regression tests for every detector change, false positive fix, and
  parser compatibility fix.
- Do not include real credentials, private URLs, or machine-specific paths in
  tests or documentation.

## Development setup

No third-party runtime package is needed. From the repository root:

```
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m pyregexshield check "(a+)+"
```

Build distributions when packaging changes:

```
python3 -m pip install build
python3 -m build
```

## What a good patch includes

1. A clear statement of the regex shape or scanner behavior being changed.
2. A minimal dangerous pattern and a minimal safe pattern.
3. Tests proving that the dangerous pattern is still caught.
4. Tests proving that the safe pattern is not newly blocked.
5. Documentation updates when public behavior changes.

## Detector patches

Detector findings must remain stable and actionable:

- Use an existing stable code when the same vulnerability class is detected.
- Choose severity conservatively and explain the reason in the test name or
  test data.
- Include a useful pattern span.
- Include remediation text that tells the maintainer how to rewrite the
  pattern.
- Check sibling interactions. For example, a nested quantifier patch must be
  tested against alternation overlap, disjoint separators, atomic groups, and
  possessive quantifiers.

## Source scanner patches

The scanner must remain static. It may inspect Python syntax with `ast`, but
it must not import target modules, execute partial expressions, or evaluate
non-literal regexes. Filesystem tests should cover symlinks, FIFOs where the
platform supports them, binary files, oversized files, encoding cookies, and
file count caps.

## Commit and pull request style

- Keep patches focused.
- Explain security tradeoffs plainly in the pull request.
- Include the exact local test command and result.
- Do not claim performance without measurements.
- Do not suppress a finding only because a test corpus expects zero findings.

## Security reports

Do not open a public issue for an exploitable vulnerability. Follow
`SECURITY.md` instead.
