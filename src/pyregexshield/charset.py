"""Character set algebra for static regular expression analysis.

The analyzer needs set operations, not a regex engine. This module represents
a set of Unicode code points as normalized, closed, non-overlapping ranges.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

UNICODE_MAX = 0x10FFFF
CASE_CLOSURE_SCAN_MAX = 0x2FF

Range = Tuple[int, int]


def _normalize_ranges(ranges: Iterable[Range]) -> Tuple[Range, ...]:
    valid = []
    for start, end in ranges:
        if start > end:
            continue
        start = max(0, start)
        end = min(UNICODE_MAX, end)
        if start <= end:
            valid.append((start, end))
    valid.sort()
    merged = []
    for start, end in valid:
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        elif end > merged[-1][1]:
            merged[-1][1] = end
    return tuple((start, end) for start, end in merged)


@dataclass(frozen=True)
class CharSet:
    """An immutable set of Unicode code points.

    Ranges are inclusive and sorted. All operations are exact for literals,
    ranges, negations, dot, ASCII shorthand classes, and the shorthand classes
    exposed by Python's Unicode database.
    """

    ranges: Tuple[Range, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "ranges", _normalize_ranges(self.ranges))

    @classmethod
    def empty(cls) -> "CharSet":
        return cls(())

    @classmethod
    def full(cls) -> "CharSet":
        return cls(((0, UNICODE_MAX),))

    @classmethod
    def from_char(cls, char: str) -> "CharSet":
        if len(char) != 1:
            raise ValueError("from_char expects exactly one character")
        value = ord(char)
        return cls(((value, value),))

    @classmethod
    def from_range(cls, start: str, end: str) -> "CharSet":
        if len(start) != 1 or len(end) != 1:
            raise ValueError("from_range expects single character endpoints")
        return cls(((ord(start), ord(end)),))

    @classmethod
    def from_chars(cls, chars: Iterable[str]) -> "CharSet":
        ranges = []
        for char in chars:
            if len(char) != 1:
                raise ValueError("from_chars expects single characters")
            ranges.append((ord(char), ord(char)))
        return cls(tuple(ranges))

    def is_empty(self) -> bool:
        return not self.ranges

    def is_full(self) -> bool:
        return self.ranges == ((0, UNICODE_MAX),)

    def size(self, cap: Optional[int] = None) -> int:
        total = 0
        for start, end in self.ranges:
            total += end - start + 1
            if cap is not None and total > cap:
                return total
        return total

    def contains(self, char: str) -> bool:
        if len(char) != 1:
            raise ValueError("contains expects exactly one character")
        value = ord(char)
        low = 0
        high = len(self.ranges)
        while low < high:
            middle = (low + high) // 2
            start, end = self.ranges[middle]
            if value < start:
                high = middle
            elif value > end:
                low = middle + 1
            else:
                return True
        return False

    def union(self, other: "CharSet") -> "CharSet":
        return CharSet(self.ranges + other.ranges)

    def intersection(self, other: "CharSet") -> "CharSet":
        result = []
        left = 0
        right = 0
        a = self.ranges
        b = other.ranges
        while left < len(a) and right < len(b):
            start = max(a[left][0], b[right][0])
            end = min(a[left][1], b[right][1])
            if start <= end:
                result.append((start, end))
            if a[left][1] < b[right][1]:
                left += 1
            else:
                right += 1
        return CharSet(tuple(result))

    def complement(self) -> "CharSet":
        result = []
        next_start = 0
        for start, end in self.ranges:
            if next_start < start:
                result.append((next_start, start - 1))
            next_start = max(next_start, end + 1)
        if next_start <= UNICODE_MAX:
            result.append((next_start, UNICODE_MAX))
        return CharSet(tuple(result))

    def subtract(self, other: "CharSet") -> "CharSet":
        return self.intersection(other.complement())

    def overlaps(self, other: "CharSet") -> bool:
        return not self.intersection(other).is_empty()

    def ignorecase_closure(self) -> "CharSet":
        """Return the closure under Unicode-aware simple case matching.

        Python's simple case folding table is not exposed directly by the
        standard library. The closure is derived once from the runtime Unicode
        character transformations, connected through inverse variant edges,
        with the capital dotted-I special case matched by CPython. This keeps
        ASCII exact while also covering inverse pairs such as K and the
        Kelvin sign.
        """

        additions = []
        for component in _case_components():
            present = False
            for value in component:
                if self._contains_value(value):
                    present = True
                    break
            if present:
                additions.extend((value, value) for value in component)
        if not additions:
            return self
        return self.union(CharSet(tuple(additions)))

    def _contains_value(self, value: int) -> bool:
        low = 0
        high = len(self.ranges)
        while low < high:
            middle = (low + high) // 2
            start, end = self.ranges[middle]
            if value < start:
                high = middle
            elif value > end:
                low = middle + 1
            else:
                return True
        return False

    def sample_chars(self, limit: int = 8) -> Tuple[str, ...]:
        """Return up to limit deterministic sample characters from the set."""

        samples = []
        for start, end in self.ranges:
            value = start
            while value <= end and len(samples) < limit:
                samples.append(chr(value))
                value += 1
            if len(samples) >= limit:
                break
        return tuple(samples)

    def describe(self, limit: int = 6) -> str:
        """Return a compact deterministic description for diagnostics."""

        if self.is_empty():
            return "empty"
        if self.is_full():
            return "any Unicode code point"
        pieces = []
        for start, end in self.ranges[:limit]:
            if start == end:
                pieces.append("U+%04X" % start)
            else:
                pieces.append("U+%04X..U+%04X" % (start, end))
        if len(self.ranges) > limit:
            pieces.append("...")
        return ", ".join(pieces)


_UNICODE_CLASS_SETS = None
_CASE_COMPONENT_CACHE = None

# Blocks that contain cased characters in Unicode 13 through 16, padded to
# cover nearby future allocations. If an unknown newer Unicode database is
# encountered, the builder falls back to a complete scan for correctness.
_CASE_SCAN_RANGES = (
    (0x0041, 0x0586),
    (0x10A0, 0x10FF),
    (0x13A0, 0x13FF),
    (0x1C80, 0x1DFF),
    (0x1E00, 0x1FFF),
    (0x2126, 0x218F),
    (0x24B6, 0x24E9),
    (0x2C00, 0x2DFF),
    (0xA640, 0xA7FF),
    (0xAB30, 0xABBF),
    (0xFF21, 0xFF5A),
    (0x10400, 0x105FF),
    (0x10C80, 0x10D8F),
    (0x11380, 0x113FF),
    (0x118A0, 0x118FF),
    (0x11BC0, 0x11BFF),
    (0x16100, 0x1613F),
    (0x16D40, 0x16DFF),
    (0x16E40, 0x16E9F),
    (0x1E5D0, 0x1E5FF),
    (0x1E900, 0x1E94F),
)
_KNOWN_UNICODE_VERSIONS = frozenset(("13.0.0", "14.0.0", "15.0.0", "15.1.0", "16.0.0"))


def _ranges_from_positions(positions) -> Tuple[Range, ...]:
    ranges = []
    start = None
    previous = None
    for position in positions:
        if start is None:
            start = position
            previous = position
        elif position == previous + 1:
            previous = position
        else:
            ranges.append((start, previous))
            start = position
            previous = position
    if start is not None:
        ranges.append((start, previous))
    return tuple(ranges)


def _unicode_sets():
    """Return exact runtime Unicode digit, word, and space sets.

    CPython's regex documentation defines these classes through the active
    Unicode database. Instead of approximating the tables, we measure fixed,
    internally generated shorthand patterns against a string containing every
    code point. No user supplied pattern is compiled or executed here.
    """

    global _UNICODE_CLASS_SETS
    if _UNICODE_CLASS_SETS is not None:
        return _UNICODE_CLASS_SETS

    text = "".join(chr(value) for value in range(UNICODE_MAX + 1))
    measured = []
    for pattern in (r"\d", r"\w", r"\s"):
        compiled = re.compile(pattern)
        measured.append(CharSet(_ranges_from_positions(match.start() for match in compiled.finditer(text))))
    _UNICODE_CLASS_SETS = tuple(measured)
    return _UNICODE_CLASS_SETS


def _case_candidate_values():
    if unicodedata.unidata_version in _KNOWN_UNICODE_VERSIONS:
        for start, end in _CASE_SCAN_RANGES:
            for value in range(start, end + 1):
                yield value
    else:
        for value in range(UNICODE_MAX + 1):
            yield value


def _case_components():
    """Build connected Unicode case-equivalence components."""

    global _CASE_COMPONENT_CACHE
    if _CASE_COMPONENT_CACHE is not None:
        return _CASE_COMPONENT_CACHE

    adjacency = {}

    def add_case_edges(values):
        values = frozenset(values)
        if len(values) < 2:
            return
        for value in values:
            bucket = adjacency.setdefault(value, set())
            bucket.update(other for other in values if other != value)

    for value in _case_candidate_values():
        char = chr(value)
        variants = {value}
        for variant in (char.lower(), char.upper(), char.title(), char.casefold()):
            if len(variant) == 1:
                variants.add(ord(variant))
        if value == 0x0130:
            variants.add(ord("i"))
        add_case_edges(variants)

    components = []
    seen = set()
    for seed in sorted(adjacency):
        if seed in seen:
            continue
        stack = [seed]
        component = set()
        while stack:
            value = stack.pop()
            if value in component:
                continue
            component.add(value)
            stack.extend(adjacency.get(value, ()))
        seen.update(component)
        if len(component) > 1:
            components.append(tuple(sorted(component)))

    _CASE_COMPONENT_CACHE = tuple(components)
    return _CASE_COMPONENT_CACHE


def ascii_digit_set() -> CharSet:
    return CharSet(((ord("0"), ord("9")),))


def ascii_word_set() -> CharSet:
    return CharSet(
        (
            (ord("0"), ord("9")),
            (ord("A"), ord("Z")),
            (ord("_"), ord("_")),
            (ord("a"), ord("z")),
        )
    )


def ascii_space_set() -> CharSet:
    return CharSet.from_chars(" \t\n\r\f\v")


def shorthand_charset(kind: str, flags: int = 0) -> CharSet:
    """Return the character set for a regex shorthand class.

    kind must be one of d, D, w, W, s, or S. re.ASCII selects the ASCII
    definitions. The Unicode definitions are derived from the runtime Unicode
    database and cached.
    """

    if kind not in "dDwWsS":
        raise ValueError("unknown shorthand class %r" % kind)

    if flags & re.ASCII:
        if kind.lower() == "d":
            base = ascii_digit_set()
        elif kind.lower() == "w":
            base = ascii_word_set()
        else:
            base = ascii_space_set()
    else:
        digit, word, space = _unicode_sets()
        if kind.lower() == "d":
            base = digit
        elif kind.lower() == "w":
            base = word
        else:
            base = space

    if kind.isupper():
        return base.complement()
    return base


def dot_charset(flags: int = 0) -> CharSet:
    if flags & re.DOTALL:
        return CharSet.full()
    return CharSet.from_char("\n").complement()
