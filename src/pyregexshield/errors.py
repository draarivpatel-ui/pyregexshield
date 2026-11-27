"""Exception types used by pyregexshield."""

from __future__ import annotations

from typing import Optional


class PyRegexShieldError(Exception):
    """Base class for package exceptions."""


class RegexPatternError(ValueError, PyRegexShieldError):
    """A pattern cannot be parsed or violates a hard parser limit."""

    def __init__(self, message: str, position: Optional[int] = None, code: str = "REDOS_SYNTAX_ERROR") -> None:
        super().__init__(message)
        self.message = message
        self.position = position
        self.code = code

    def __str__(self) -> str:
        if self.position is None:
            return self.message
        return "%s at position %d" % (self.message, self.position)


class UnsafeRegexError(ValueError, PyRegexShieldError):
    """Raised when a pattern is rejected by the static security policy."""

    def __init__(self, message: str, result) -> None:
        super().__init__(message)
        self.message = message
        self.result = result
        self.findings = result.findings

    def __str__(self) -> str:
        if not self.findings:
            return self.message
        codes = ", ".join(finding.code for finding in self.findings[:4])
        if len(self.findings) > 4:
            codes += ", ..."
        return "%s (%s)" % (self.message, codes)
