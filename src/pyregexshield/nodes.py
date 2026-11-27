"""Typed regular expression syntax tree nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union

Span = Tuple[int, int]


class Node:
    """Marker base class for all regex syntax tree nodes."""

    span: Span
    flags: int


@dataclass(frozen=True)
class LiteralNode(Node):
    char: str
    span: Span
    flags: int


@dataclass(frozen=True)
class DotNode(Node):
    span: Span
    flags: int


@dataclass(frozen=True)
class ClassItem:
    """One literal, range, or shorthand inside a bracket expression."""

    kind: str
    value: object
    span: Span


@dataclass(frozen=True)
class CharClassNode(Node):
    items: Tuple[ClassItem, ...]
    negated: bool
    span: Span
    flags: int


@dataclass(frozen=True)
class AnchorNode(Node):
    kind: str
    span: Span
    flags: int


@dataclass(frozen=True)
class BackReferenceNode(Node):
    ref: Union[int, str]
    span: Span
    flags: int


@dataclass(frozen=True)
class GroupNode(Node):
    """A capturing, non-capturing, lookaround, or atomic group.

    kind is capture, noncapture, lookahead, negative_lookahead, lookbehind,
    negative_lookbehind, or atomic.
    """

    kind: str
    child: Node
    span: Span
    flags: int
    name: Optional[str] = None
    index: Optional[int] = None


@dataclass(frozen=True)
class ConditionalNode(Node):
    condition: Union[int, str]
    yes: Node
    no: Optional[Node]
    span: Span
    flags: int


@dataclass(frozen=True)
class ConcatNode(Node):
    items: Tuple[Node, ...]
    span: Span
    flags: int


@dataclass(frozen=True)
class AlternationNode(Node):
    branches: Tuple[Node, ...]
    span: Span
    flags: int


@dataclass(frozen=True)
class RepeatNode(Node):
    child: Node
    min_count: int
    max_count: Optional[int]
    greedy: bool
    possessive: bool
    span: Span
    flags: int


def node_children(node: Node) -> Tuple[Node, ...]:
    if isinstance(node, GroupNode):
        return (node.child,)
    if isinstance(node, ConditionalNode):
        if node.no is None:
            return (node.yes,)
        return (node.yes, node.no)
    if isinstance(node, ConcatNode):
        return node.items
    if isinstance(node, AlternationNode):
        return node.branches
    if isinstance(node, RepeatNode):
        return (node.child,)
    return ()


def iter_nodes(node: Node):
    yield node
    for child in node_children(node):
        for descendant in iter_nodes(child):
            yield descendant


def unwrap_transparent(node: Node) -> Node:
    """Remove grouping that does not change matching or backtracking semantics."""

    while isinstance(node, GroupNode) and node.kind in ("capture", "noncapture"):
        node = node.child
    return node


def is_zero_width(node: Node) -> bool:
    if isinstance(node, AnchorNode):
        return True
    return isinstance(node, GroupNode) and node.kind in (
        "lookahead",
        "negative_lookahead",
        "lookbehind",
        "negative_lookbehind",
    )
