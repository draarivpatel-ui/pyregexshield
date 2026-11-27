# Security policy

## Supported versions

The initial supported release line is `1.0.x`.

| Version | Supported |
| ------- | --------- |
| 1.0.x   | yes       |

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that can be exploited
before a fix is available. Use GitHub private vulnerability reporting on the
repository security advisories page:

https://github.com/draarivpatel-ui/pyregexshield/security/advisories/new

Include:

- The affected version and Python version.
- A minimal regex or source file that reproduces the issue.
- Whether the issue is a false negative, false positive, parser panic,
  unbounded analysis time, filesystem escape, or unsafe runtime behavior.
- A rough input length and measured time when reporting performance behavior.
- Whether remote attacker input can realistically reach the regex.

Please do not include secrets, production data, or large exploit corpora in
the initial report.

## Scope

In scope:

- Regex structures that bypass a documented detector.
- Analysis that becomes non-linear or effectively unbounded on allowed input.
- Parser panics, recursion failures, or memory growth outside configured
  limits.
- Source scanner symlink, device-file, archive, encoding, or path handling
  bypasses.
- `SafePattern` methods that execute input beyond the configured length.
- Incorrect SARIF output that hides or misattributes a security finding.
- CI or release workflow changes that weaken trusted publishing.

Out of scope:

- The exponential worst case of CPython `re` itself when a user compiles and
  runs a regex without this library.
- A finding on a pattern that the documentation already classifies as
  conservative.
- Denial of service caused by choosing a very large `max_input_length`.
- Vulnerabilities in applications merely because they use regular
  expressions.

## Response expectations

Reports are triaged as time permits. A reporter can expect an initial
acknowledgement within 14 days and a severity assessment or request for more
information within 30 days. Security fixes are prioritized over feature work.

## Security design notes

- Analysis is static and never executes the analyzed regex.
- Compilation through `safe_compile` occurs only after analysis.
- `SafePattern` applies an input length budget before every match operation and
  an output length budget during substitution.
- The scanner uses AST parsing rather than importing target code.
- The directory scanner does not follow symlinks and skips non-regular files.
- PyPI publication uses GitHub OIDC trusted publishing rather than a stored
  PyPI token.
