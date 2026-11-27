"""Safe compilation and bounded execution helpers."""

from __future__ import annotations

import operator
import re
from dataclasses import FrozenInstanceError, replace
from types import MappingProxyType
from typing import Optional

from .analyzer import AnalysisResult, Finding, analyze_regex
from .errors import UnsafeRegexError
from .policy import DEFAULT_POLICY, RegexPolicy


class InputTooLongError(ValueError):
    """Raised when SafePattern input exceeds the configured input budget."""

    def __init__(self, length: int, maximum: int) -> None:
        super().__init__("input length %d exceeds limit %d" % (length, maximum))
        self.length = length
        self.maximum = maximum


class OutputTooLongError(ValueError):
    """Raised when substitution output would exceed the configured budget."""

    def __init__(self, length: int, maximum: int) -> None:
        super().__init__("output length %d exceeds limit %d" % (length, maximum))
        self.length = length
        self.maximum = maximum


class SafePattern:
    """A compiled pattern wrapper with runtime input and output budgets.

    The compiled regex object is intentionally private. Callers should use the
    bounded methods on this wrapper rather than bypassing them through the
    underlying re.Pattern object.
    """

    __slots__ = ("_pattern", "_flags", "_compiled", "_policy", "_result")

    def __init__(self, pattern: str, flags: int, compiled, policy: RegexPolicy, result: AnalysisResult) -> None:
        object.__setattr__(self, "_pattern", pattern)
        object.__setattr__(self, "_flags", flags)
        object.__setattr__(self, "_compiled", compiled)
        object.__setattr__(self, "_policy", policy)
        object.__setattr__(self, "_result", result)

    def __setattr__(self, name, value) -> None:
        raise FrozenInstanceError("SafePattern is immutable")

    def __delattr__(self, name) -> None:
        raise FrozenInstanceError("SafePattern is immutable")

    @property
    def pattern(self) -> str:
        return self._pattern

    @property
    def flags(self) -> int:
        return self._flags

    @property
    def policy(self) -> RegexPolicy:
        return self._policy

    @property
    def result(self) -> AnalysisResult:
        return self._result

    def __repr__(self) -> str:
        return "SafePattern(pattern=%r, flags=%r)" % (self._pattern, self._flags)

    def _check_input(self, string: str) -> str:
        if not isinstance(string, str):
            raise TypeError("input must be str")
        if len(string) > self._policy.max_input_length:
            raise InputTooLongError(len(string), self._policy.max_input_length)
        return string

    def match(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self._compiled.match(string, pos)
        return self._compiled.match(string, pos, endpos)

    def search(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self._compiled.search(string, pos)
        return self._compiled.search(string, pos, endpos)

    def fullmatch(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self._compiled.fullmatch(string, pos)
        return self._compiled.fullmatch(string, pos, endpos)

    def findall(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self._compiled.findall(string, pos)
        return self._compiled.findall(string, pos, endpos)

    def finditer(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self._compiled.finditer(string, pos)
        return self._compiled.finditer(string, pos, endpos)

    def split(self, string: str, maxsplit: int = 0):
        string = self._check_input(string)
        return self._compiled.split(string, maxsplit)

    def _substitute(self, repl, string: str, count: int):
        string = self._check_input(string)
        count = operator.index(count)
        if count < 0:
            return string, 0

        maximum = self._policy.max_output_length
        pieces = []
        total = 0

        def append(piece: str) -> None:
            nonlocal total
            total += len(piece)
            if total > maximum:
                raise OutputTooLongError(total, maximum)
            pieces.append(piece)

        end = 0
        replacements = 0
        for match in self._compiled.finditer(string):
            if count and replacements >= count:
                break
            append(string[end:match.start()])
            if callable(repl):
                expansion = repl(match)
            else:
                if isinstance(repl, str) and len(repl) > maximum:
                    raise OutputTooLongError(len(repl), maximum)
                expansion = match.expand(repl)
            if not isinstance(expansion, str):
                raise TypeError("replacement must return str")
            append(expansion)
            end = match.end()
            replacements += 1
        append(string[end:])
        return "".join(pieces), replacements

    def sub(self, repl, string: str, count: int = 0):
        return self._substitute(repl, string, count)[0]

    def subn(self, repl, string: str, count: int = 0):
        return self._substitute(repl, string, count)

    @property
    def groups(self) -> int:
        return self._compiled.groups

    @property
    def groupindex(self):
        return MappingProxyType(dict(self._compiled.groupindex))


def _syntax_failure_result(result: AnalysisResult, error: re.error) -> AnalysisResult:
    position = getattr(error, "pos", None)
    if position is None or position < 0:
        position = 0
    finding = Finding(
        "REDOS_SYNTAX_ERROR",
        "critical",
        "Python re.compile rejected the pattern: %s" % error,
        (position, position + 1),
        "Fix the regular expression syntax for the Python runtime in use",
    )
    findings = tuple(result.findings) + (finding,)
    return replace(result, safe=False, risk_level="critical", score=100, findings=findings)


def assert_safe_regex(pattern: str, flags: int = 0, *, policy: Optional[RegexPolicy] = None) -> AnalysisResult:
    """Return the analysis result or raise UnsafeRegexError."""

    policy = policy or DEFAULT_POLICY
    result = analyze_regex(pattern, flags=flags, policy=policy)
    if not result.safe:
        raise UnsafeRegexError("unsafe regular expression", result)
    return result


def safe_compile(pattern: str, flags: int = 0, *, policy: Optional[RegexPolicy] = None) -> SafePattern:
    """Analyze, validate, compile, and wrap a regular expression.

    Static analysis runs before compilation. A second re.compile validation
    catches version-specific syntax that the portable parser accepts, such as
    atomic groups on Python versions before 3.11.
    """

    policy = policy or DEFAULT_POLICY
    result = assert_safe_regex(pattern, flags, policy=policy)
    try:
        compiled = re.compile(pattern, flags)
    except re.error as error:
        failure = _syntax_failure_result(result, error)
        raise UnsafeRegexError("regular expression failed runtime syntax validation", failure) from error
    return SafePattern(pattern, flags, compiled, policy, result)


def safe_match(pattern: str, string: str, flags: int = 0, *, policy: Optional[RegexPolicy] = None):
    return safe_compile(pattern, flags, policy=policy).match(string)


def safe_search(pattern: str, string: str, flags: int = 0, *, policy: Optional[RegexPolicy] = None):
    return safe_compile(pattern, flags, policy=policy).search(string)


def safe_fullmatch(pattern: str, string: str, flags: int = 0, *, policy: Optional[RegexPolicy] = None):
    return safe_compile(pattern, flags, policy=policy).fullmatch(string)


def safe_findall(pattern: str, string: str, flags: int = 0, *, policy: Optional[RegexPolicy] = None):
    return safe_compile(pattern, flags, policy=policy).findall(string)


def safe_sub(pattern: str, repl, string: str, count: int = 0, flags: int = 0, *, policy: Optional[RegexPolicy] = None):
    return safe_compile(pattern, flags, policy=policy).sub(repl, string, count)
