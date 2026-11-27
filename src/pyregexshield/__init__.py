"""pyregexshield public API."""

from __future__ import annotations

from .analyzer import AnalysisResult, Finding, analyze_regex
from .api import (
    InputTooLongError,
    OutputTooLongError,
    SafePattern,
    assert_safe_regex,
    safe_compile,
    safe_findall,
    safe_fullmatch,
    safe_match,
    safe_search,
    safe_sub,
)
from .charset import CharSet
from .errors import PyRegexShieldError, RegexPatternError, UnsafeRegexError
from .parser import parse_regex
from .policy import DEFAULT_POLICY, RegexPolicy
from .scanner import ScanDiagnostic, ScanReport, SourceFinding, scan_directory, scan_python_file, scan_python_source

__version__ = "1.0.0"

__all__ = [
    "AnalysisResult",
    "CharSet",
    "DEFAULT_POLICY",
    "Finding",
    "InputTooLongError",
    "OutputTooLongError",
    "PyRegexShieldError",
    "RegexPatternError",
    "RegexPolicy",
    "SafePattern",
    "ScanDiagnostic",
    "ScanReport",
    "SourceFinding",
    "UnsafeRegexError",
    "__version__",
    "analyze_regex",
    "assert_safe_regex",
    "parse_regex",
    "safe_compile",
    "safe_findall",
    "safe_fullmatch",
    "safe_match",
    "safe_search",
    "safe_sub",
    "scan_directory",
    "scan_python_file",
    "scan_python_source",
]
