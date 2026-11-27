"""Security policy configuration for pyregexshield."""

from __future__ import annotations

from dataclasses import dataclass, replace

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class RegexPolicy:
    """Limits and blocking behavior for analysis and safe execution.

    max_pattern_length and max_depth are hard parser limits. max_quantifier is
    a hard parser cap for a single numeric upper bound. max_safe_repeat and
    max_expansion_factor are analysis thresholds for syntactically valid but
    dangerous repetition. max_input_length and max_output_length are enforced
    by SafePattern at runtime.
    """

    max_pattern_length: int = 4096
    max_depth: int = 64
    max_quantifier: int = 100000
    max_safe_repeat: int = 1000
    max_expansion_factor: int = 10000
    max_input_length: int = 65536
    max_output_length: int = 1048576
    max_scan_file_bytes: int = 1048576
    minimum_block_severity: str = "medium"

    def __post_init__(self) -> None:
        integer_fields = (
            "max_pattern_length",
            "max_depth",
            "max_quantifier",
            "max_safe_repeat",
            "max_expansion_factor",
            "max_input_length",
            "max_output_length",
            "max_scan_file_bytes",
        )
        for field in integer_fields:
            value = getattr(self, field)
            if not isinstance(value, int) or value < 1:
                raise ValueError("%s must be a positive integer" % field)
        if self.minimum_block_severity not in SEVERITY_ORDER:
            raise ValueError("unknown minimum_block_severity %r" % self.minimum_block_severity)
        if SEVERITY_ORDER[self.minimum_block_severity] < SEVERITY_ORDER["low"]:
            raise ValueError("minimum_block_severity must be low, medium, high, or critical")

    def strict(self) -> "RegexPolicy":
        """Return a copy that treats low severity findings as blocking."""

        return replace(self, minimum_block_severity="low")


DEFAULT_POLICY = RegexPolicy()
