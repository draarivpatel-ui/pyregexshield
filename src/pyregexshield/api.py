"""Safe compilation and bounded execution helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
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


@dataclass(frozen=True)
class SafePattern:
    """A compiled pattern wrapper with a runtime input length budget."""

    pattern: str
    flags: int
    compiled: object
    policy: RegexPolicy
    result: AnalysisResult

    def _check_input(self, string: str) -> str:
        if not isinstance(string, str):
            raise TypeError("input must be str")
        if len(string) > self.policy.max_input_length:
            raise InputTooLongError(len(string), self.policy.max_input_length)
        return string

    def match(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self.compiled.match(string, pos)
        return self.compiled.match(string, pos, endpos)

    def search(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self.compiled.search(string, pos)
        return self.compiled.search(string, pos, endpos)

    def fullmatch(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self.compiled.fullmatch(string, pos)
        return self.compiled.fullmatch(string, pos, endpos)

    def findall(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self.compiled.findall(string, pos)
        return self.compiled.findall(string, pos, endpos)

    def finditer(self, string: str, pos: int = 0, endpos: Optional[int] = None):
        string = self._check_input(string)
        if endpos is None:
            return self.compiled.finditer(string, pos)
        return self.compiled.finditer(string, pos, endpos)

    def split(self, string: str, maxsplit: int = 0):
        string = self._check_input(string)
        return self.compiled.split(string, maxsplit)

    def sub(self, repl, string: str, count: int = 0):
        string = self._check_input(string)
        return self.compiled.sub(repl, string, count)

    def subn(self, repl, string: str, count: int = 0):
        string = self._check_input(string)
        return self.compiled.subn(repl, string, count)

    @property
    def groups(self) -> int:
        return self.compiled.groups

    @property
    def groupindex(self):
        return MappingProxyType(dict(self.compiled.groupindex))


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
