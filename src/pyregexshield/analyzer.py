"""Static ReDoS analysis for parsed Python regular expressions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, Optional, Tuple

from .charset import CharSet, dot_charset, shorthand_charset
from .errors import RegexPatternError
from .nodes import (
    AlternationNode,
    AnchorNode,
    BackReferenceNode,
    CharClassNode,
    ConcatNode,
    ConditionalNode,
    DotNode,
    GroupNode,
    LiteralNode,
    Node,
    RepeatNode,
    is_zero_width,
    iter_nodes,
    node_children,
    unwrap_transparent,
)
from .parser import parse_regex
from .policy import DEFAULT_POLICY, SEVERITY_ORDER, RegexPolicy

_INFINITY_CAP = 10 ** 12


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    span: Tuple[int, int]
    remediation: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER or self.severity == "info":
            raise ValueError("severity must be low, medium, high, or critical")
        if len(self.span) != 2 or self.span[0] < 0 or self.span[1] < self.span[0]:
            raise ValueError("span must be a valid (start, end) pair")


@dataclass(frozen=True)
class AnalysisResult:
    safe: bool
    risk_level: str
    score: int
    findings: Tuple[Finding, ...]
    stats: object
    attack_hint: Optional[str] = None


class _Metrics:
    def __init__(self, root: Node) -> None:
        self.root = root
        self.groups_by_index = {}
        self.groups_by_name = {}
        self.parent = {}
        self._first_cache = {}
        self._nullable_cache = {}
        self._width_cache = {}
        self._alphabet_cache = {}
        self._build_indexes(root, None)

    def _build_indexes(self, node: Node, parent: Optional[Node]) -> None:
        self.parent[id(node)] = parent
        if isinstance(node, GroupNode) and node.kind == "capture":
            if node.index is not None:
                self.groups_by_index[node.index] = node
            if node.name is not None:
                self.groups_by_name[node.name] = node
        for child in node_children(node):
            self._build_indexes(child, node)

    def resolve_reference(self, ref):
        if isinstance(ref, int):
            return self.groups_by_index.get(ref)
        return self.groups_by_name.get(ref)

    def first(self, node: Node) -> CharSet:
        return self._first(node, frozenset())

    def _first(self, node: Node, visiting) -> CharSet:
        key = id(node)
        if key in self._first_cache:
            return self._first_cache[key]

        if isinstance(node, LiteralNode):
            result = CharSet.from_char(node.char)
            if node.flags & re.IGNORECASE:
                result = result.ignorecase_closure(bool(node.flags & re.ASCII))
        elif isinstance(node, DotNode):
            result = dot_charset(node.flags)
        elif isinstance(node, CharClassNode):
            result = charclass_charset(node)
        elif isinstance(node, AnchorNode):
            result = CharSet.empty()
        elif isinstance(node, BackReferenceNode):
            target = self.resolve_reference(node.ref)
            if target is None or id(target) in visiting:
                result = CharSet.full()
            else:
                result = self._first(target.child, visiting | frozenset((id(target),)))
        elif isinstance(node, GroupNode):
            if node.kind in ("lookahead", "negative_lookahead", "lookbehind", "negative_lookbehind"):
                result = CharSet.empty()
            else:
                result = self._first(node.child, visiting)
        elif isinstance(node, ConditionalNode):
            result = self._first(node.yes, visiting)
            if node.no is not None:
                result = result.union(self._first(node.no, visiting))
        elif isinstance(node, ConcatNode):
            result = CharSet.empty()
            for child in node.items:
                result = result.union(self._first(child, visiting))
                if not self.nullable(child):
                    break
        elif isinstance(node, AlternationNode):
            result = CharSet.empty()
            for branch in node.branches:
                result = result.union(self._first(branch, visiting))
        elif isinstance(node, RepeatNode):
            result = self._first(node.child, visiting)
        else:
            result = CharSet.empty()

        self._first_cache[key] = result
        return result

    def nullable(self, node: Node) -> bool:
        key = id(node)
        if key in self._nullable_cache:
            return self._nullable_cache[key]
        self._nullable_cache[key] = False
        result = self._nullable(node, frozenset())
        self._nullable_cache[key] = result
        return result

    def _nullable(self, node: Node, visiting) -> bool:
        if isinstance(node, (LiteralNode, DotNode, CharClassNode)):
            return False
        if isinstance(node, AnchorNode):
            return True
        if isinstance(node, BackReferenceNode):
            target = self.resolve_reference(node.ref)
            if target is None or id(target) in visiting:
                return False
            return self._nullable(target.child, visiting | frozenset((id(target),)))
        if isinstance(node, GroupNode):
            if node.kind in ("lookahead", "negative_lookahead", "lookbehind", "negative_lookbehind"):
                return True
            return self._nullable(node.child, visiting)
        if isinstance(node, ConditionalNode):
            return self._nullable(node.yes, visiting) or (node.no is not None and self._nullable(node.no, visiting))
        if isinstance(node, ConcatNode):
            return all(self.nullable(child) for child in node.items)
        if isinstance(node, AlternationNode):
            return any(self.nullable(branch) for branch in node.branches)
        if isinstance(node, RepeatNode):
            return node.min_count == 0 or self.nullable(node.child)
        return False

    def width(self, node: Node) -> Tuple[int, Optional[int]]:
        key = id(node)
        if key in self._width_cache:
            return self._width_cache[key]
        result = self._width(node, frozenset())
        self._width_cache[key] = result
        return result

    @staticmethod
    def _sat_add(left: int, right: int) -> int:
        return min(_INFINITY_CAP, left + right)

    @staticmethod
    def _sat_mul(left: int, right: int) -> int:
        if not left or not right:
            return 0
        if left >= _INFINITY_CAP or right >= _INFINITY_CAP or left * right > _INFINITY_CAP:
            return _INFINITY_CAP
        return left * right

    def _width(self, node: Node, visiting) -> Tuple[int, Optional[int]]:
        if isinstance(node, (LiteralNode, DotNode, CharClassNode)):
            return 1, 1
        if isinstance(node, AnchorNode):
            return 0, 0
        if isinstance(node, BackReferenceNode):
            target = self.resolve_reference(node.ref)
            if target is None or id(target) in visiting:
                return 0, None
            return self._width(target.child, visiting | frozenset((id(target),)))
        if isinstance(node, GroupNode):
            if node.kind in ("lookahead", "negative_lookahead", "lookbehind", "negative_lookbehind"):
                return 0, 0
            return self.width(node.child)
        if isinstance(node, ConditionalNode):
            yes = self.width(node.yes)
            no = self.width(node.no) if node.no is not None else (0, 0)
            maximum = None if yes[1] is None or no[1] is None else max(yes[1], no[1])
            return min(yes[0], no[0]), maximum
        if isinstance(node, ConcatNode):
            minimum = 0
            maximum = 0
            unbounded = False
            for child in node.items:
                child_min, child_max = self.width(child)
                minimum = self._sat_add(minimum, child_min)
                if child_max is None:
                    unbounded = True
                else:
                    maximum = self._sat_add(maximum, child_max)
            return minimum, None if unbounded else maximum
        if isinstance(node, AlternationNode):
            if not node.branches:
                return 0, 0
            widths = [self.width(branch) for branch in node.branches]
            minimum = min(item[0] for item in widths)
            maximum = None if any(item[1] is None for item in widths) else max(item[1] for item in widths)
            return minimum, maximum
        if isinstance(node, RepeatNode):
            child_min, child_max = self.width(node.child)
            minimum = self._sat_mul(child_min, node.min_count)
            if node.max_count is None or child_max is None:
                maximum = None if node.max_count != 0 else 0
            else:
                maximum = self._sat_mul(child_max, node.max_count)
            return minimum, maximum
        return 0, 0

    def alphabet(self, node: Node) -> CharSet:
        """Conservative union of every character a node can consume."""

        key = id(node)
        if key in self._alphabet_cache:
            return self._alphabet_cache[key]
        result = CharSet.empty()
        if isinstance(node, (LiteralNode, DotNode, CharClassNode, BackReferenceNode)):
            result = self.first(node)
        for child in node_children(node):
            result = result.union(self.alphabet(child))
        self._alphabet_cache[key] = result
        return result

    def has_atomic_ancestor_within(self, node: Node, boundary: Node) -> bool:
        current = self.parent.get(id(node))
        boundary_id = id(boundary)
        while current is not None:
            if isinstance(current, GroupNode) and current.kind == "atomic":
                return True
            if id(current) == boundary_id:
                break
            current = self.parent.get(id(current))
        return False


def charclass_charset(node: CharClassNode) -> CharSet:
    result = CharSet.empty()
    for item in node.items:
        if item.kind == "literal":
            addition = CharSet.from_char(item.value)
        elif item.kind == "range":
            start, end = item.value
            addition = CharSet.from_range(start, end)
        elif item.kind == "shorthand":
            addition = shorthand_charset(item.value, node.flags)
        else:
            addition = CharSet.empty()
        result = result.union(addition)
    if node.flags & re.IGNORECASE:
        result = result.ignorecase_closure(bool(node.flags & re.ASCII))
    if node.negated:
        result = result.complement()
    return result


def _is_multiple_repeat(node: RepeatNode) -> bool:
    return node.max_count is None or node.max_count > 1


def _is_variable_repeat(node: RepeatNode) -> bool:
    return node.max_count is None or node.max_count != node.min_count


def _is_significant_adjacent_repeat(node: RepeatNode) -> bool:
    """Return whether a variable repeat can create asymptotic splitting work.

    A small bounded pair such as a{1,4}a{1,4} has a fixed maximum input width
    and is noisy rather than dangerous. Sixteen or more possible repetitions
    leaves enough branch combinations to matter in a 64 KiB input budget.
    """

    return _is_variable_repeat(node) and (node.max_count is None or node.max_count >= 16)


def _flatten_concat(node: Node):
    node = unwrap_transparent(node)
    if isinstance(node, ConcatNode):
        result = []
        for child in node.items:
            result.extend(_flatten_concat(child))
        return result
    return [node]


def _surface_repeat(node: Node) -> Optional[RepeatNode]:
    node = unwrap_transparent(node)
    if isinstance(node, RepeatNode):
        return node
    return None


def _mandatory_separator_between(metrics: _Metrics, items, start: int, end: int, left_alphabet: CharSet, right_alphabet: CharSet) -> bool:
    for item in items[start:end]:
        if is_zero_width(item):
            continue
        minimum, _maximum = metrics.width(item)
        if minimum < 1:
            continue
        separator_alphabet = metrics.alphabet(item)
        if separator_alphabet.is_empty():
            continue
        if not separator_alphabet.overlaps(left_alphabet) and not separator_alphabet.overlaps(right_alphabet):
            return True
    return False


def _repeat_alphabet(metrics: _Metrics, repeat: RepeatNode) -> CharSet:
    return metrics.alphabet(repeat.child)


def _repeat_edge_separator(metrics: _Metrics, repeat: RepeatNode, edge: str) -> CharSet:
    """Return the mandatory first or last consumed alphabet in one iteration."""

    sequence = _flatten_concat(repeat.child)
    if edge == "prefix":
        candidates = sequence
    else:
        candidates = reversed(sequence)
    for candidate in candidates:
        if is_zero_width(candidate):
            continue
        minimum, _maximum = metrics.width(candidate)
        if minimum < 1:
            return CharSet.empty()
        return metrics.alphabet(candidate)
    return CharSet.empty()


def _nested_separator_guard(metrics: _Metrics, outer_child: Node, nested: RepeatNode) -> bool:
    sequence = _flatten_concat(outer_child)
    index = None
    for position, candidate in enumerate(sequence):
        if candidate is nested:
            index = position
            break
    if index is None:
        return False

    nested_alphabet = metrics.alphabet(nested.child)
    if nested_alphabet.is_empty():
        return False

    for candidate in reversed(sequence[:index]):
        if is_zero_width(candidate):
            continue
        minimum, _maximum = metrics.width(candidate)
        if minimum >= 1:
            separator = metrics.alphabet(candidate)
            if not separator.is_empty() and not separator.overlaps(nested_alphabet):
                return True
            break

    for candidate in sequence[index + 1:]:
        if is_zero_width(candidate):
            continue
        minimum, _maximum = metrics.width(candidate)
        if minimum >= 1:
            separator = metrics.alphabet(candidate)
            if not separator.is_empty() and not separator.overlaps(nested_alphabet):
                return True
            break
    return False


def _detect_nested_quantifiers(root: Node, metrics: _Metrics, findings) -> None:
    reported = set()
    for node in iter_nodes(root):
        if not isinstance(node, RepeatNode):
            continue
        if node.possessive or not _is_multiple_repeat(node):
            continue
        nested_repeats = []
        for descendant in iter_nodes(node.child):
            if not isinstance(descendant, RepeatNode):
                continue
            if descendant.possessive or not _is_variable_repeat(descendant):
                continue
            if metrics.has_atomic_ancestor_within(descendant, node.child):
                continue
            nested_repeats.append(descendant)
        if not nested_repeats:
            continue
        unguarded = [
            nested for nested in nested_repeats
            if not _nested_separator_guard(metrics, node.child, nested)
        ]
        if not unguarded:
            continue
        key = (node.span, "nested")
        if key in reported:
            continue
        reported.add(key)
        nullable_inner = any(metrics.nullable(nested.child) or nested.min_count == 0 for nested in unguarded)
        severity = "critical" if nullable_inner or any(nested.max_count is None for nested in unguarded) else "high"
        findings.append(Finding(
            "REDOS_STAR_HEIGHT_NESTED_QUANTIFIER",
            severity,
            "Nested repetition can divide one input run into many backtracking splits",
            node.span,
            "Remove the nested quantifier, make the repeated separator explicit, or use an atomic or possessive construct after verifying runtime support",
        ))


def _transparent_alternation_child(node: Node) -> Optional[AlternationNode]:
    node = unwrap_transparent(node)
    if isinstance(node, AlternationNode):
        return node
    return None


def _detect_overlapping_alternations(root: Node, metrics: _Metrics, findings) -> None:
    for node in iter_nodes(root):
        if not isinstance(node, RepeatNode) or not _is_multiple_repeat(node):
            continue
        alternation = _transparent_alternation_child(node.child)
        if alternation is None:
            continue
        branches = alternation.branches
        nullable_count = sum(1 for branch in branches if metrics.nullable(branch))
        if nullable_count:
            findings.append(Finding(
                "REDOS_OVERLAPPING_ALTERNATION",
                "critical",
                "A quantified alternation has an empty branch, so the engine can retry empty matches exponentially",
                alternation.span,
                "Remove the empty branch or move the optional behavior outside the repeated alternation",
            ))
            continue

        first_sets = [metrics.first(branch) for branch in branches]
        events = {}
        for charset in first_sets:
            for start, end in charset.ranges:
                events[start] = events.get(start, 0) + 1
                events[end + 1] = events.get(end + 1, 0) - 1
        coverage = 0
        overlap_point = None
        for position in sorted(events):
            coverage += events[position]
            if coverage >= 2 and position <= 0x10FFFF:
                overlap_point = position
                break
        overlap_pair = None
        if overlap_point is not None:
            point_char = chr(overlap_point)
            matching = [index for index, charset in enumerate(first_sets) if charset.contains(point_char)]
            if len(matching) >= 2:
                overlap_pair = (matching[0], matching[1])
        if overlap_pair is None:
            continue
        left, right = overlap_pair
        same = first_sets[left] == first_sets[right]
        severity = "critical" if same else "high"
        findings.append(Finding(
            "REDOS_OVERLAPPING_ALTERNATION",
            severity,
            "Branches %d and %d of a quantified alternation can start with the same characters" % (left + 1, right + 1),
            alternation.span,
            "Reorder or rewrite branches so their first character sets are disjoint, or factor the common prefix",
        ))


def _detect_adjacent_quantifiers(root: Node, metrics: _Metrics, findings) -> None:
    reported = set()
    for node in iter_nodes(root):
        if not isinstance(node, ConcatNode):
            continue
        items = list(node.items)
        surface = [_surface_repeat(item) for item in items]

        for index in range(len(items) - 1):
            left = surface[index]
            right = surface[index + 1]
            if left is None or right is None:
                continue
            if not _is_significant_adjacent_repeat(left) or not _is_significant_adjacent_repeat(right):
                continue
            left_alphabet = _repeat_alphabet(metrics, left)
            right_alphabet = _repeat_alphabet(metrics, right)
            if not left_alphabet.overlaps(right_alphabet):
                continue
            right_prefix = _repeat_edge_separator(metrics, right, "prefix")
            if not right_prefix.is_empty() and not right_prefix.overlaps(left_alphabet):
                continue
            left_suffix = _repeat_edge_separator(metrics, left, "suffix")
            if not left_suffix.is_empty() and not left_suffix.overlaps(right_alphabet):
                continue
            key = ("direct", left.span, right.span)
            if key in reported:
                continue
            reported.add(key)
            severity = "high" if left.max_count is None and right.max_count is None else "medium"
            findings.append(Finding(
                "REDOS_OVERLAPPING_ADJACENT_QUANTIFIERS",
                severity,
                "Adjacent variable-length repetitions accept overlapping characters and can backtrack polynomially",
                (left.span[0], right.span[1]),
                "Insert a disjoint separator, make one boundary fixed-width, or combine the repeated character classes",
            ))

        repeat_indices = [index for index, repeat in enumerate(surface) if repeat is not None and repeat.max_count is None]
        if len(repeat_indices) < 2:
            continue
        offending_pair = None
        for position in range(len(repeat_indices) - 1):
            first_index = repeat_indices[position]
            candidate_index = repeat_indices[position + 1]
            first_repeat = surface[first_index]
            candidate = surface[candidate_index]
            first_alphabet = _repeat_alphabet(metrics, first_repeat)
            candidate_alphabet = _repeat_alphabet(metrics, candidate)
            if not first_alphabet.overlaps(candidate_alphabet):
                continue
            if candidate_index == first_index + 1:
                continue
            if _mandatory_separator_between(metrics, items, first_index + 1, candidate_index, first_alphabet, candidate_alphabet):
                continue
            offending_pair = (first_repeat, candidate)
            break
        if offending_pair is None:
            continue
        first_repeat, second_repeat = offending_pair
        key = ("chain", first_repeat.span, second_repeat.span)
        if key in reported:
            continue
        reported.add(key)
        findings.append(Finding(
            "REDOS_OVERLAPPING_ADJACENT_QUANTIFIERS",
            "medium",
            "Multiple unbounded repetitions in one sequence are separated only by overlapping text",
            (first_repeat.span[0], second_repeat.span[1]),
            "Anchor the pattern, use disjoint separators, or replace broad wildcards with narrower bounded classes",
        ))


def _detect_leading_wildcard(root: Node, metrics: _Metrics, findings) -> None:
    sequence = _flatten_concat(root)
    index = 0
    while index < len(sequence) and isinstance(sequence[index], AnchorNode):
        index += 1
    if index >= len(sequence):
        return
    repeat = _surface_repeat(sequence[index])
    if repeat is None or repeat.max_count is not None:
        return
    child = unwrap_transparent(repeat.child)
    broad = isinstance(child, DotNode)
    if not broad:
        alphabet = metrics.alphabet(repeat.child)
        broad = alphabet.size(cap=2048) > 2048
    if not broad:
        return
    remainder = sequence[index + 1:]
    complex_suffix = any(
        any(isinstance(descendant, (RepeatNode, AlternationNode, ConditionalNode)) or
            (isinstance(descendant, GroupNode) and descendant.kind in ("lookahead", "negative_lookahead", "lookbehind", "negative_lookbehind"))
            for descendant in iter_nodes(item))
        for item in remainder
    )
    if not complex_suffix:
        return
    findings.append(Finding(
        "REDOS_UNANCHORED_LEADING_WILDCARD",
        "low",
        "A leading broad wildcard can scan and backtrack across most non-matching input",
        repeat.span,
        "Anchor the pattern or replace the wildcard with a narrower bounded prefix",
    ))


def _detect_backreferences(root: Node, metrics: _Metrics, findings) -> None:
    for node in iter_nodes(root):
        if not isinstance(node, BackReferenceNode):
            continue
        inside_repeat = False
        parent = metrics.parent.get(id(node))
        while parent is not None:
            if isinstance(parent, RepeatNode):
                inside_repeat = True
                break
            parent = metrics.parent.get(id(parent))

        target = metrics.resolve_reference(node.ref)
        target_variable = False
        if target is not None:
            target_variable = any(
                isinstance(descendant, RepeatNode) and _is_variable_repeat(descendant)
                for descendant in iter_nodes(target.child)
            )

        if inside_repeat:
            severity = "critical"
            detail = "inside a repeated expression"
        elif target_variable:
            severity = "high"
            detail = "refers to a variable-length captured group"
        else:
            severity = "medium"
            detail = "forces backtracking matching semantics that are NP-complete in general"
        findings.append(Finding(
            "REDOS_BACKREFERENCE_QUANTIFIED",
            severity,
            "Backreference %s" % detail,
            node.span,
            "Replace the backreference with a deterministic comparison in application code",
        ))


def _detect_repetition_bounds(root: Node, policy: RegexPolicy, findings) -> None:
    for node in iter_nodes(root):
        if not isinstance(node, RepeatNode):
            continue
        if node.max_count is not None and node.max_count > policy.max_safe_repeat:
            findings.append(Finding(
                "REDOS_EXCESSIVE_REPETITION_BOUND",
                "high",
                "Upper repetition bound %d exceeds the safe analysis threshold %d" % (node.max_count, policy.max_safe_repeat),
                node.span,
                "Lower the bound or validate input length before matching",
            ))


def _detect_lookarounds(root: Node, metrics: _Metrics, findings) -> None:
    lookaround_kinds = ("lookahead", "negative_lookahead", "lookbehind", "negative_lookbehind")
    for node in iter_nodes(root):
        if not isinstance(node, GroupNode) or node.kind not in lookaround_kinds:
            continue
        parent = metrics.parent.get(id(node))
        quantifier_parent = parent
        while isinstance(quantifier_parent, GroupNode) and quantifier_parent.kind in ("capture", "noncapture"):
            quantifier_parent = metrics.parent.get(id(quantifier_parent))
        quantified = isinstance(quantifier_parent, RepeatNode) and _is_multiple_repeat(quantifier_parent)
        nested = any(
            isinstance(descendant, GroupNode) and descendant.kind in lookaround_kinds
            for descendant in iter_nodes(node.child)
        )
        if quantified:
            findings.append(Finding(
                "REDOS_COMPLEX_LOOKAROUND",
                "high",
                "A lookaround assertion is quantified, multiplying zero-width backtracking work",
                quantifier_parent.span if quantified else node.span,
                "Unroll the assertion or rewrite it as a consuming deterministic prefix",
            ))
        elif nested:
            findings.append(Finding(
                "REDOS_COMPLEX_LOOKAROUND",
                "high",
                "Nested lookaround assertions multiply backtracking states",
                node.span,
                "Flatten nested assertions or compute the predicate in application code",
            ))
        elif any(isinstance(descendant, RepeatNode) and descendant.max_count is None for descendant in iter_nodes(node.child)):
            findings.append(Finding(
                "REDOS_COMPLEX_LOOKAROUND",
                "low",
                "A lookaround contains an unbounded repetition",
                node.span,
                "Bound the repeated content inside the assertion",
            ))


def _max_depth(node: Node) -> int:
    children = node_children(node)
    if not children:
        return 1
    return 1 + max(_max_depth(child) for child in children)


def _expansion_factor(node: Node) -> int:
    def visit(current: Node) -> int:
        child_values = [visit(child) for child in node_children(current)]
        child_max = max(child_values) if child_values else 1
        if isinstance(current, RepeatNode) and current.max_count is not None and current.max_count > 1:
            return min(_INFINITY_CAP, max(current.max_count, current.max_count * child_max))
        return child_max

    return visit(node)


def _stats(root: Node, pattern: str) -> Dict[str, int]:
    nodes = list(iter_nodes(root))
    repeats = [node for node in nodes if isinstance(node, RepeatNode)]
    max_repeat = 0
    for repeat in repeats:
        if repeat.max_count is not None:
            max_repeat = max(max_repeat, repeat.max_count)
    return {
        "pattern_length": len(pattern),
        "node_count": len(nodes),
        "depth": _max_depth(root),
        "group_count": sum(1 for node in nodes if isinstance(node, GroupNode)),
        "alternation_count": sum(1 for node in nodes if isinstance(node, AlternationNode)),
        "quantifier_count": len(repeats),
        "backreference_count": sum(1 for node in nodes if isinstance(node, BackReferenceNode)),
        "max_repeat_bound": max_repeat,
        "expansion_factor": _expansion_factor(root),
    }


def _error_result(pattern: str, error: RegexPatternError, policy: RegexPolicy) -> AnalysisResult:
    position = error.position if error.position is not None else 0
    position = max(0, min(len(pattern), position))
    end = min(len(pattern), position + 1)
    severity = "critical"
    if error.code == "REDOS_EXCESSIVE_REPETITION_BOUND":
        severity = "high"
    finding = Finding(
        error.code,
        severity,
        str(error),
        (position, end),
        "Rewrite the pattern so it parses within the configured hard limits",
    )
    stats = MappingProxyType({
        "pattern_length": len(pattern),
        "node_count": 0,
        "depth": 0,
        "group_count": 0,
        "alternation_count": 0,
        "quantifier_count": 0,
        "backreference_count": 0,
        "max_repeat_bound": 0,
        "expansion_factor": 0,
    })
    return AnalysisResult(False, "critical", 100, (finding,), stats, "input that reaches the parser limit")


def _attack_hint(findings) -> Optional[str]:
    if not findings:
        return None
    priority = {
        "REDOS_STAR_HEIGHT_NESTED_QUANTIFIER": "a long run of one repeated character followed by a character outside the class",
        "REDOS_OVERLAPPING_ALTERNATION": "a long concatenation of strings accepted by overlapping branches followed by a rejection suffix",
        "REDOS_OVERLAPPING_ADJACENT_QUANTIFIERS": "a long run accepted by both adjacent repetitions followed by a rejection suffix",
        "REDOS_BACKREFERENCE_QUANTIFIED": "a long input whose duplicated fragments force backreference backtracking",
        "REDOS_COMPLEX_LOOKAROUND": "a long prefix that keeps the lookaround almost satisfied",
        "REDOS_UNANCHORED_LEADING_WILDCARD": "a long non-matching input without the expected suffix",
        "REDOS_EXCESSIVE_REPETITION_BOUND": "input near the excessive repetition bound",
    }
    for finding in findings:
        if finding.code in priority:
            return priority[finding.code]
    return "a long input chosen to maximize backtracking"


def analyze_regex(pattern: str, *, flags: int = 0, policy: Optional[RegexPolicy] = None) -> AnalysisResult:
    """Statically analyze a Python regex without executing it.

    The result is fail closed: parser errors and hard limit violations are
    represented as blocking findings rather than exceptions.
    """

    policy = policy or DEFAULT_POLICY
    if not isinstance(pattern, str):
        raise TypeError("pattern must be str")
    if not isinstance(flags, int):
        raise TypeError("flags must be int")

    try:
        root = parse_regex(pattern, flags, policy=policy)
    except RegexPatternError as error:
        return _error_result(pattern, error, policy)

    metrics = _Metrics(root)
    findings = []
    _detect_nested_quantifiers(root, metrics, findings)
    _detect_overlapping_alternations(root, metrics, findings)
    _detect_adjacent_quantifiers(root, metrics, findings)
    _detect_leading_wildcard(root, metrics, findings)
    _detect_backreferences(root, metrics, findings)
    _detect_repetition_bounds(root, policy, findings)
    _detect_lookarounds(root, metrics, findings)

    stats_dict = _stats(root, pattern)
    if stats_dict["expansion_factor"] > policy.max_expansion_factor:
        findings.append(Finding(
            "REDOS_EXCESSIVE_REPETITION_BOUND",
            "high",
            "Nested bounded repetitions can expand by a factor of %d" % stats_dict["expansion_factor"],
            (0, len(pattern)),
            "Reduce nested numeric bounds or validate input length before matching",
        ))
        stats_dict["expansion_factor"] = stats_dict["expansion_factor"]

    deduplicated = []
    seen_findings = set()
    for finding in findings:
        key = (finding.code, finding.span)
        if key in seen_findings:
            continue
        seen_findings.add(key)
        deduplicated.append(finding)
    findings = deduplicated

    findings.sort(key=lambda item: (item.span[0], item.span[1], item.code))
    highest = 0
    for finding in findings:
        highest = max(highest, SEVERITY_ORDER[finding.severity])
    if not findings:
        risk_level = "safe"
        score = 0
    else:
        inverse = {value: key for key, value in SEVERITY_ORDER.items()}
        risk_level = inverse[highest]
        weights = {"low": 15, "medium": 40, "high": 75, "critical": 100}
        score = max(weights[finding.severity] for finding in findings)
        score = min(100, score + max(0, len(findings) - 1) * 3)

    blocking_order = SEVERITY_ORDER[policy.minimum_block_severity]
    safe = all(SEVERITY_ORDER[finding.severity] < blocking_order for finding in findings)
    stats = MappingProxyType(stats_dict)
    return AnalysisResult(safe, risk_level, score, tuple(findings), stats, _attack_hint(findings))
