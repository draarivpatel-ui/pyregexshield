# pyregexshield

`pyregexshield` is a zero-dependency Python 3.9+ library for static regular
expression denial of service analysis, regex AST inspection, safe compilation,
and Python source scanning. It detects the nested quantifiers, ambiguous
alternations, overlapping adjacent repetitions, quantified lookarounds,
backreference risks, excessive numeric bounds, and hard input shapes behind
classic ReDoS incidents.

The runtime package uses only the Python standard library. It ships type
information through `py.typed`.

PyPI release status: pending. Install from a checkout until the first release
is published.

```
python3 -m pip install .
```

## Threat model

Python's `re` engine backtracks. A regex can be syntactically valid and still
consume exponential or polynomial time on a non-matching string. This is a
security problem when a pattern or its input is influenced by an attacker.
Common examples are form validation, log parsing, markdown parsing, routing,
and user-controlled allowlists.

`pyregexshield` addresses two parts of that problem:

1. Static analysis rejects high-risk regex structure before the pattern is
   compiled or executed.
2. `SafePattern` enforces a maximum input length at runtime as defense in
   depth.

Static analysis cannot prove that every regex is fast. See the limitations
section before relying on it in a security boundary.

## Quick analysis

```python
from pyregexshield import analyze_regex

result = analyze_regex(r"(a+)+")
assert not result.safe

for finding in result.findings:
    print(finding.code)
    print(finding.severity)
    print(finding.span)
    print(finding.remediation)
```

`AnalysisResult` is frozen and contains:

- `safe`: whether no finding meets the policy blocking severity.
- `risk_level`: `safe`, `low`, `medium`, `high`, or `critical`.
- `score`: a deterministic 0 to 100 risk score.
- `findings`: stable structured findings with remediation text.
- `stats`: parser and repetition statistics.
- `attack_hint`: a short description of the input shape that stresses the
  pattern. It is not a weaponized generator.

By default, low findings are informational and medium or higher findings are
blocking. Use `RegexPolicy().strict()` or the CLI `--strict` option to block low
findings too.

## Safe compile and bounded execution

```python
from pyregexshield import UnsafeRegexError, safe_compile

try:
    pattern = safe_compile(r"^[a-z0-9_-]{1,64}$")
except UnsafeRegexError as exc:
    print(exc.result.risk_level)
else:
    assert pattern.fullmatch("valid-name_01")
```

`safe_compile` first runs static analysis, then validates the pattern with the
active Python runtime's `re.compile`. It raises `UnsafeRegexError`, a
`ValueError` subclass with `.result` and `.findings`, when either layer rejects
the pattern.

The returned frozen `SafePattern` supports `match`, `search`, `fullmatch`,
`findall`, `finditer`, `split`, `sub`, and `subn`. Every method rejects input
longer than `policy.max_input_length`, which defaults to 65536 characters. The
underlying compiled `re.Pattern` object is intentionally private so callers use
the bounded methods. Substitutions are built incrementally and reject output
longer than `policy.max_output_length`, which defaults to 1048576 characters:

```python
from pyregexshield import InputTooLongError, RegexPolicy, safe_compile

policy = RegexPolicy(max_input_length=128)
pattern = safe_compile(r"^[a-z]+$", policy=policy)

try:
    pattern.fullmatch("a" * 129)
except InputTooLongError:
    print("input rejected before regex execution")
```

Module-level helpers include `safe_match`, `safe_search`, `safe_fullmatch`,
`safe_findall`, and `safe_sub`.

## What the analyzer detects

| Code | Meaning |
| ---- | ------- |
| `REDOS_STAR_HEIGHT_NESTED_QUANTIFIER` | Nested variable repetition such as `(a+)+`, `(a*)*`, and `(a{1,5})+` |
| `REDOS_OVERLAPPING_ALTERNATION` | Quantified alternation branches with overlapping first character sets, such as `(a|ab)+` |
| `REDOS_OVERLAPPING_ADJACENT_QUANTIFIERS` | Ambiguous neighboring repetitions such as `\s+\s+`, `[a-z]+[a-z]+`, and broad wildcard chains |
| `REDOS_UNANCHORED_LEADING_WILDCARD` | A leading broad wildcard before a complex suffix |
| `REDOS_BACKREFERENCE_QUANTIFIED` | Backreferences, with higher severity when repeated or tied to variable-length captures |
| `REDOS_EXCESSIVE_REPETITION_BOUND` | Very large numeric bounds or nested bounded expansion |
| `REDOS_COMPLEX_LOOKAROUND` | Quantified or nested lookarounds, plus low severity unbounded lookaround content |
| `REDOS_PATTERN_TOO_LONG` | Hard pattern length limit |
| `REDOS_EXCESSIVE_DEPTH` | Hard nesting depth limit |
| `REDOS_SYNTAX_ERROR` | Invalid or unsupported syntax, fail closed |

The detector understands deterministic separators. For example,
`(?:[a-z]+,)+` is not treated like `([a-z]+)*` because the comma is mandatory
inside every outer iteration and does not overlap `[a-z]`. Similarly,
`^[a-z]+(?:\.[a-z]+)*$` is accepted as a bounded ambiguity-safe shape. This is
the difference between a useful linter and a naive star-height check.

## Character set overlap algebra

Analysis uses exact interval-set operations for literals, ranges, negated
classes, dot, ASCII shorthand classes, and Unicode shorthand classes. It
accounts for `re.IGNORECASE`, scoped inline flags such as `(?i:...)`, plain
inline flags such as `(?i)`, `re.ASCII`, and `re.DOTALL`.

That means `(a|b)+` is not flagged as overlapping, while `(a|A)+` with
`re.IGNORECASE` is flagged. It also distinguishes `([0-9]+|[a-z]+)+` style
nested repetition from direct first-set overlap in `(\d|\w)+`.

## Independent parser

The package does not use `sre_parse`, `re._parser`, or other private CPython
parser internals. `parse_regex` is an independent bounded recursive-descent
parser for Python regex syntax. It supports:

- Literals, dot, anchors, word boundaries, and character classes.
- ASCII and Unicode shorthand classes.
- Hex, Unicode, unicode-name, octal, and control escapes.
- Capturing, non-capturing, named, conditional, atomic, and inline-flag
  groups.
- Lookahead and fixed-width lookbehind assertions.
- Greedy, lazy, and possessive quantifiers.
- Numeric and named backreferences.
- Alternation and empty branches.
- `re.VERBOSE` whitespace and comments.

Parsing never executes the untrusted pattern. Pattern length defaults to 4096
characters, nesting depth to 64, and one numeric quantifier upper bound to
100000. All three limits are configurable through `RegexPolicy`.

The parser intentionally understands Python 3.11 atomic groups and possessive
quantifiers even when running on older interpreters. `safe_compile` still
validates with the active runtime and rejects those forms on Python versions
that do not support them.

## Scan Python source and emit SARIF

The source scanner uses Python's stdlib `ast` module. It does not import or
execute the target file. It finds literal regex arguments to `re.compile`,
`re.match`, `re.search`, `re.fullmatch`, `re.findall`, `re.finditer`,
`re.sub`, `re.subn`, and `re.split`, including common import and assignment
aliases, explicit concatenation of string literals, and literal flag expressions.

```python
from pyregexshield import scan_python_source

source = '''import re
re.compile(r"(a+)+")
'''

report = scan_python_source(source, filename="example.py")
print(report.to_text())

sarif = report.to_sarif()
assert sarif["version"] == "2.1.0"
```

`scan_directory(path)` recursively scans `.py` files. The filesystem layer
does not follow symlinks, skips FIFOs and other non-regular files, skips files
with NUL bytes, enforces a byte limit, decodes Python source through the
stdlib encoding detector, and stops at a deterministic file count cap.

## CLI

Analyze one pattern:

```
pyregexshield check "(a+)+"
pyregexshield check "(a|A)+" --ignorecase --strict
pyregexshield check "(a+)+" --json
```

Exit codes are 0 for safe, 1 for unsafe, and 2 for usage or regex parse
errors.

Scan source:

```
pyregexshield scan src/
pyregexshield scan src/ --format json
pyregexshield scan src/ --format sarif --strict --max-files 5000
```

JSON output is intended for automation. SARIF output is version 2.1.0 and can
be consumed by code scanning systems that accept external SARIF files.

## Policy configuration

```python
from pyregexshield import RegexPolicy

policy = RegexPolicy(
    max_pattern_length=2048,
    max_depth=32,
    max_quantifier=10000,
    max_safe_repeat=256,
    max_expansion_factor=2048,
    max_input_length=8192,
    max_output_length=65536,
    minimum_block_severity="low",
)
```

The hard parser limits and analysis thresholds are separate. A regex can be
small enough to parse but still too repetitive to be accepted. The input
length limit is used by `SafePattern` at runtime.

## Limitations

- Static ReDoS analysis is conservative. It cannot model every optimization
  in CPython's regex engine, and a warning does not mean a real input will
  always be slow.
- The disjoint-separator analysis handles common deterministic separators but
  does not solve arbitrary language ambiguity.
- Unicode case folding is represented with exact ASCII and Latin-1 handling
  plus conservative broader Unicode closure. Unicode edge cases can therefore
  be conservative.
- Backreferences make matching NP-complete in general. The analyzer flags
  them even when one particular use appears fixed-width and benign.
- `max_input_length` reduces the maximum work available to a backtracking
  pattern, but CPython `re` has no execution timeout. A large enough budget
  can still be expensive. Use a process boundary or a non-backtracking engine
  when you need a hard time guarantee. Python objects in the same process are
  not a hard privilege boundary, so `max_output_length` limits accidental or
  attacker-influenced substitution amplification rather than malicious Python
  code that already runs in the process.
- The source scanner analyzes literal strings and addition of literal strings.
  It intentionally does not evaluate variables, f-strings, concatenation helper
  functions, or imported constants.
- Possessive quantifiers and atomic groups can reduce backtracking on Python
  3.11+, but the analyzer remains conservative around complex surrounding
  structure.

## Development

Run the tests from a checkout:

```
PYTHONPATH=src python3 -m unittest discover -s tests
```

The suite currently contains 1108 tests.

Run the CLI without installing:

```
PYTHONPATH=src python3 -m pyregexshield check "(a+)+"
```

The project has no runtime dependencies. Please read `CONTRIBUTING.md` before
sending a patch and `SECURITY.md` before reporting a vulnerability.
