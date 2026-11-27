"""Bounded parser for Python regular expression syntax.

This parser is independent of private CPython modules such as sre_parse and
re._parser. It consumes each input character at most once, caps nesting depth,
caps pattern length, and never executes the pattern being parsed.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Optional, Tuple

from .errors import RegexPatternError
from .nodes import (
    AlternationNode,
    AnchorNode,
    BackReferenceNode,
    CharClassNode,
    ClassItem,
    ConcatNode,
    ConditionalNode,
    DotNode,
    GroupNode,
    LiteralNode,
    Node,
    RepeatNode,
    Span,
    iter_nodes,
    node_children,
)
from .policy import DEFAULT_POLICY, RegexPolicy

_HEX = set("0123456789abcdefABCDEF")
_FLAG_VALUES = {
    "a": re.ASCII,
    "i": re.IGNORECASE,
    "L": re.LOCALE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "u": re.UNICODE,
    "x": re.VERBOSE,
}


def scan_plain_inline_flags(pattern: str) -> int:
    """Find plain (?flags) directives that Python applies globally.

    This linear lexical scan skips escaped text, bracket expressions, and (?#...)
    comments. It intentionally accepts only positive letters because Python
    requires a colon after a hyphenated inline flag list.
    """

    flags = 0
    index = 0
    in_class = False
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            in_class = True
            index += 1
            continue
        if pattern.startswith("(?#", index):
            close = pattern.find(")", index + 3)
            if close < 0:
                return flags
            index = close + 1
            continue
        if pattern.startswith("(?", index):
            cursor = index + 2
            value = 0
            while cursor < len(pattern) and pattern[cursor] in _FLAG_VALUES:
                value |= _FLAG_VALUES[pattern[cursor]]
                cursor += 1
            if value and cursor < len(pattern) and pattern[cursor] == ")":
                flags |= value
                index = cursor + 1
                continue
        index += 1
    return flags


@dataclass(frozen=True)
class _Escape:
    kind: str
    value: object
    span: Span


@dataclass(frozen=True)
class _FlagDirective:
    add: int
    remove: int
    span: Span


class RegexParser:
    """Recursive descent parser with hard input and recursion bounds."""

    def __init__(self, pattern: str, flags: int = 0, policy: Optional[RegexPolicy] = None) -> None:
        self.pattern = pattern
        self.initial_flags = int(flags)
        self.policy = policy or DEFAULT_POLICY
        self.pos = 0
        self.length = len(pattern)
        self.group_count = 0
        self.group_names = {}
        self.open_group_indices = []
        self.open_group_names = []

    def parse(self) -> Node:
        self.initial_flags |= scan_plain_inline_flags(self.pattern)
        if self.length > self.policy.max_pattern_length:
            raise RegexPatternError(
                "pattern length %d exceeds limit %d" % (self.length, self.policy.max_pattern_length),
                self.policy.max_pattern_length,
                "REDOS_PATTERN_TOO_LONG",
            )
        if self.initial_flags & re.LOCALE:
            raise RegexPatternError("re.LOCALE cannot be used with a str pattern", 0)
        root = self._parse_alternation(0, self.initial_flags, False)
        if self.pos < self.length:
            if self.pattern[self.pos] == ")":
                self._error("unbalanced parenthesis", self.pos)
            self._error("unexpected trailing input", self.pos)
        self._validate_lookbehind_widths(root)
        return root

    def _validate_lookbehind_widths(self, root: Node) -> None:
        groups_by_index = {}
        groups_by_name = {}
        for node in iter_nodes(root):
            if isinstance(node, GroupNode) and node.kind == "capture":
                if node.index is not None:
                    groups_by_index[node.index] = node
                if node.name is not None:
                    groups_by_name[node.name] = node

        def exact_width(node: Node, visiting) -> Optional[int]:
            if isinstance(node, (LiteralNode, DotNode, CharClassNode)):
                return 1
            if isinstance(node, AnchorNode):
                return 0
            if isinstance(node, BackReferenceNode):
                if isinstance(node.ref, int):
                    target = groups_by_index.get(node.ref)
                else:
                    target = groups_by_name.get(node.ref)
                if target is None or id(target) in visiting:
                    return None
                return exact_width(target.child, visiting | frozenset((id(target),)))
            if isinstance(node, GroupNode):
                if node.kind in ("lookahead", "negative_lookahead", "lookbehind", "negative_lookbehind"):
                    return 0
                return exact_width(node.child, visiting)
            if isinstance(node, ConditionalNode):
                yes = exact_width(node.yes, visiting)
                no = exact_width(node.no, visiting) if node.no is not None else 0
                if yes is None or no is None or yes != no:
                    return None
                return yes
            if isinstance(node, ConcatNode):
                total = 0
                for child in node.items:
                    width = exact_width(child, visiting)
                    if width is None:
                        return None
                    total += width
                    if total > self.policy.max_quantifier:
                        return None
                return total
            if isinstance(node, AlternationNode):
                if not node.branches:
                    return 0
                widths = [exact_width(branch, visiting) for branch in node.branches]
                first = widths[0]
                if first is None or any(width != first for width in widths[1:]):
                    return None
                return first
            if isinstance(node, RepeatNode):
                if node.max_count != node.min_count:
                    return None
                width = exact_width(node.child, visiting)
                if width is None:
                    return None
                return width * node.min_count
            return None

        for node in iter_nodes(root):
            if isinstance(node, GroupNode) and node.kind in ("lookbehind", "negative_lookbehind"):
                if exact_width(node.child, frozenset()) is None:
                    self._error("lookbehind requires a fixed-width pattern", node.span[0])

    def _error(self, message: str, position: Optional[int] = None, code: str = "REDOS_SYNTAX_ERROR") -> None:
        raise RegexPatternError(message, self.pos if position is None else position, code)

    def _peek(self) -> str:
        if self.pos >= self.length:
            return ""
        return self.pattern[self.pos]

    def _take(self) -> str:
        if self.pos >= self.length:
            self._error("unexpected end of pattern", self.pos)
        char = self.pattern[self.pos]
        self.pos += 1
        return char

    def _skip_verbose_ignored(self, flags: int) -> None:
        if not flags & re.VERBOSE:
            return
        while self.pos < self.length:
            char = self.pattern[self.pos]
            if char.isspace():
                self.pos += 1
                continue
            if char == "#":
                while self.pos < self.length and self.pattern[self.pos] not in "\r\n":
                    self.pos += 1
                continue
            break

    def _parse_alternation(self, depth: int, flags: int, in_group: bool) -> Node:
        branches = []
        branch_items = []
        branch_start = self.pos
        current_flags = flags

        while True:
            self._skip_verbose_ignored(current_flags)
            if self.pos >= self.length:
                if in_group:
                    self._error("missing closing parenthesis", self.pos)
                break

            char = self._peek()
            if char == ")":
                if in_group:
                    break
                self._error("unbalanced parenthesis", self.pos)
            if char == "|":
                branches.append(self._finish_concat(branch_items, branch_start, self.pos, current_flags))
                self.pos += 1
                branch_items = []
                branch_start = self.pos
                continue

            atom_start = self.pos
            atom = self._parse_atom(depth, current_flags)
            if isinstance(atom, _FlagDirective):
                current_flags = (current_flags | atom.add) & ~atom.remove
                if current_flags & re.LOCALE:
                    self._error("re.LOCALE cannot be used with a str pattern", atom.span[0])
                if current_flags & re.ASCII and current_flags & re.UNICODE:
                    self._error("ASCII and UNICODE inline flags are incompatible", atom.span[0])
                continue

            self._skip_verbose_ignored(current_flags)
            if self._is_quantifier_start(self.pos):
                if isinstance(atom, AnchorNode):
                    self._error("nothing to repeat", atom_start)
                atom = self._parse_quantifier(atom, current_flags)
                self._skip_verbose_ignored(current_flags)
                if self._is_quantifier_start(self.pos):
                    self._error("multiple repeat", self.pos)
            branch_items.append(atom)

        branches.append(self._finish_concat(branch_items, branch_start, self.pos, current_flags))
        if len(branches) == 1:
            return branches[0]
        start = branches[0].span[0]
        end = branches[-1].span[1]
        return AlternationNode(tuple(branches), (start, end), flags)

    def _finish_concat(self, items, start: int, end: int, flags: int) -> Node:
        if len(items) == 1:
            return items[0]
        return ConcatNode(tuple(items), (start, end), flags)

    def _is_quantifier_start(self, position: int) -> bool:
        if position >= self.length:
            return False
        char = self.pattern[position]
        if char in "*+?":
            return True
        if char != "{":
            return False
        close = self.pattern.find("}", position + 1)
        if close < 0:
            return False
        content = self.pattern[position + 1:close]
        return self._valid_brace_content(content)

    @staticmethod
    def _valid_brace_content(content: str) -> bool:
        if not content:
            return False
        if "," not in content:
            return content.isdigit()
        if content.count(",") != 1:
            return False
        left, right = content.split(",", 1)
        return (left == "" or left.isdigit()) and (right == "" or right.isdigit())

    def _parse_quantifier(self, atom: Node, flags: int) -> RepeatNode:
        start = atom.span[0]
        char = self._take()
        minimum = 0
        maximum = None
        if char == "*":
            minimum, maximum = 0, None
        elif char == "+":
            minimum, maximum = 1, None
        elif char == "?":
            minimum, maximum = 0, 1
        elif char == "{":
            close = self.pattern.find("}", self.pos)
            if close < 0:
                self._error("unterminated repetition", self.pos)
            content = self.pattern[self.pos:close]
            if not self._valid_brace_content(content):
                self._error("bad repetition range", self.pos)
            self.pos = close + 1
            if "," in content:
                left, right = content.split(",", 1)
                minimum = int(left) if left else 0
                maximum = int(right) if right else None
            else:
                minimum = int(content)
                maximum = minimum
            if maximum is not None and minimum > maximum:
                self._error("minimum repeat is greater than maximum repeat", start)
            cap_value = maximum if maximum is not None else minimum
            if cap_value > self.policy.max_quantifier:
                raise RegexPatternError(
                    "quantifier bound %d exceeds hard limit %d" % (cap_value, self.policy.max_quantifier),
                    start,
                    "REDOS_EXCESSIVE_REPETITION_BOUND",
                )
        else:
            self._error("internal quantifier error", self.pos)

        greedy = True
        possessive = False
        if self.pos < self.length:
            suffix = self.pattern[self.pos]
            if suffix == "?":
                greedy = False
                self.pos += 1
            elif suffix == "+":
                possessive = True
                self.pos += 1
        return RepeatNode(atom, minimum, maximum, greedy, possessive, (start, self.pos), flags)

    def _parse_atom(self, depth: int, flags: int):
        self._skip_verbose_ignored(flags)
        start = self.pos
        if self.pos >= self.length:
            self._error("unexpected end of pattern", start)
        char = self._take()

        if char in "*+?":
            self._error("nothing to repeat", start)
        if char == "{" and self._is_quantifier_start(start):
            self._error("nothing to repeat", start)
        if char == ".":
            return DotNode((start, self.pos), flags)
        if char == "^":
            return AnchorNode("start", (start, self.pos), flags)
        if char == "$":
            return AnchorNode("end", (start, self.pos), flags)
        if char == "[":
            return self._parse_character_class(start, flags)
        if char == "(":
            return self._parse_group(start, depth, flags)
        if char == "\\":
            escape = self._parse_escape(start, False)
            if escape.kind == "literal":
                return LiteralNode(escape.value, escape.span, flags)
            if escape.kind == "shorthand":
                item = ClassItem("shorthand", escape.value, escape.span)
                return CharClassNode((item,), False, escape.span, flags)
            if escape.kind == "anchor":
                return AnchorNode(escape.value, escape.span, flags)
            if escape.kind == "backreference":
                return self._make_backreference(escape.value, escape.span, flags)
            self._error("unsupported escape outside a character class", start)
        return LiteralNode(char, (start, self.pos), flags)

    def _make_backreference(self, ref, span: Span, flags: int) -> BackReferenceNode:
        if isinstance(ref, int):
            if ref < 1 or ref > self.group_count:
                self._error("invalid group reference %d" % ref, span[0])
            if ref in self.open_group_indices:
                self._error("cannot refer to an open group", span[0])
        else:
            if ref not in self.group_names:
                self._error("unknown group name %r" % ref, span[0])
            if ref in self.open_group_names:
                self._error("cannot refer to an open group", span[0])
        return BackReferenceNode(ref, span, flags)

    def _parse_group(self, start: int, depth: int, flags: int) -> Node:
        if depth + 1 > self.policy.max_depth:
            raise RegexPatternError(
                "group nesting exceeds limit %d" % self.policy.max_depth,
                start,
                "REDOS_EXCESSIVE_DEPTH",
            )

        kind = "capture"
        name = None
        index = None
        child_flags = flags
        directive = None
        conditional = None

        if self._peek() != "?":
            self.group_count += 1
            index = self.group_count
            self.open_group_indices.append(index)
            child = self._parse_alternation(depth + 1, child_flags, True)
            self._expect_close(start)
            self.open_group_indices.pop()
            return GroupNode("capture", child, (start, self.pos), flags, None, index)

        self.pos += 1
        if self.pos >= self.length:
            self._error("unterminated group extension", self.pos)
        extension = self._peek()

        if extension == ":":
            self.pos += 1
            kind = "noncapture"
        elif extension == "P":
            self.pos += 1
            if self._peek() == "<":
                self.pos += 1
                name_start = self.pos
                while self.pos < self.length and self.pattern[self.pos] != ">":
                    self.pos += 1
                if self.pos >= self.length:
                    self._error("unterminated named group", name_start)
                name = self.pattern[name_start:self.pos]
                self.pos += 1
                if not name or not name.isidentifier():
                    self._error("bad named group name", name_start)
                if name in self.group_names:
                    self._error("duplicate group name %r" % name, name_start)
                self.group_count += 1
                index = self.group_count
                self.group_names[name] = index
                self.open_group_indices.append(index)
                self.open_group_names.append(name)
                child = self._parse_alternation(depth + 1, child_flags, True)
                self._expect_close(start)
                self.open_group_indices.pop()
                self.open_group_names.pop()
                return GroupNode("capture", child, (start, self.pos), flags, name, index)
            if self._peek() == "=":
                self.pos += 1
                name_start = self.pos
                while self.pos < self.length and self.pattern[self.pos] != ")":
                    self.pos += 1
                if self.pos >= self.length:
                    self._error("unterminated named backreference", name_start)
                refname = self.pattern[name_start:self.pos]
                self.pos += 1
                if not refname:
                    self._error("empty named backreference", name_start)
                return self._make_backreference(refname, (start, self.pos), flags)
            self._error("unknown group extension ?P", self.pos)
        elif extension == "=":
            self.pos += 1
            kind = "lookahead"
        elif extension == "!":
            self.pos += 1
            kind = "negative_lookahead"
        elif extension == "<":
            self.pos += 1
            if self._peek() == "=":
                self.pos += 1
                kind = "lookbehind"
            elif self._peek() == "!":
                self.pos += 1
                kind = "negative_lookbehind"
            else:
                self._error("unknown group extension ?<", self.pos)
        elif extension == "#":
            self.pos += 1
            while self.pos < self.length and self.pattern[self.pos] != ")":
                self.pos += 1
            if self.pos >= self.length:
                self._error("unterminated comment", start)
            self.pos += 1
            return _FlagDirective(0, 0, (start, self.pos))
        elif extension == ">":
            self.pos += 1
            kind = "atomic"
        elif extension == "(":
            self.pos += 1
            conditional = self._parse_conditional_header(start)
        elif extension in "aiLmsux-" or extension == ")":
            add, remove, terminator = self._parse_inline_flags(start)
            if terminator == ")":
                if remove:
                    self._error("inline flags cannot be turned off without a scoped group", start)
                directive = _FlagDirective(add, remove, (start, self.pos))
                return directive
            if remove & (re.ASCII | re.UNICODE | re.LOCALE):
                self._error("ASCII, UNICODE, and LOCALE inline flags cannot be turned off", start)
            child_flags = (flags | add) & ~remove
            kind = "noncapture"
        else:
            self._error("unknown group extension", self.pos)

        if conditional is not None:
            condition_ref, condition_span = conditional
            self._validate_conditional_reference(condition_ref, condition_span[0])
            parsed = self._parse_alternation(depth + 1, child_flags, True)
            self._expect_close(start)
            if isinstance(parsed, AlternationNode):
                if len(parsed.branches) > 2:
                    self._error("conditional groups accept at most two branches", condition_span[0])
                yes = parsed.branches[0]
                no = parsed.branches[1] if len(parsed.branches) == 2 else None
            else:
                yes = parsed
                no = None
            return ConditionalNode(condition_ref, yes, no, (start, self.pos), flags)

        child = self._parse_alternation(depth + 1, child_flags, True)
        self._expect_close(start)
        return GroupNode(kind, child, (start, self.pos), flags, name, index)

    def _expect_close(self, start: int) -> None:
        self._skip_verbose_ignored(self.initial_flags)
        if self.pos >= self.length or self.pattern[self.pos] != ")":
            self._error("missing closing parenthesis", start)
        self.pos += 1

    def _parse_conditional_header(self, group_start: int):
        ref_start = self.pos
        while self.pos < self.length and self.pattern[self.pos] != ")":
            self.pos += 1
        if self.pos >= self.length:
            self._error("unterminated conditional group", group_start)
        text = self.pattern[ref_start:self.pos]
        self.pos += 1
        if not text:
            self._error("empty conditional group reference", ref_start)
        if text.isdigit():
            ref = int(text)
        elif text.isidentifier():
            ref = text
        else:
            self._error("bad conditional group reference", ref_start)
        return ref, (ref_start, self.pos)

    def _validate_conditional_reference(self, ref, position: int) -> None:
        if isinstance(ref, int):
            if ref < 1 or ref > self.group_count:
                self._error("invalid group reference %d" % ref, position)
            if ref in self.open_group_indices:
                self._error("cannot refer to an open group", position)
        else:
            if ref not in self.group_names:
                self._error("unknown group name %r" % ref, position)
            if ref in self.open_group_names:
                self._error("cannot refer to an open group", position)

    def _parse_inline_flags(self, start: int):
        add = 0
        remove = 0
        removing = False
        saw_flag = False
        while self.pos < self.length:
            char = self._peek()
            if char in ":)":
                terminator = self._take()
                if not saw_flag:
                    self._error("missing inline flags", start)
                return add, remove, terminator
            if char == "-":
                if removing:
                    self._error("duplicate inline flag separator", self.pos)
                removing = True
                self.pos += 1
                continue
            if char not in _FLAG_VALUES:
                self._error("unknown inline flag %r" % char, self.pos)
            saw_flag = True
            value = _FLAG_VALUES[char]
            if removing:
                remove |= value
            else:
                add |= value
            self.pos += 1
        self._error("unterminated inline flags", start)
        return 0, 0, ")"

    def _parse_character_class(self, start: int, flags: int) -> CharClassNode:
        negated = False
        if self._peek() == "^":
            negated = True
            self.pos += 1

        items = []
        first = True
        while True:
            if self.pos >= self.length:
                self._error("unterminated character class", start)
            if self._peek() == "]" and not first:
                self.pos += 1
                break

            item = self._parse_class_item(flags)
            first = False

            if self.pos < self.length and self.pattern[self.pos] == "-":
                hyphen_pos = self.pos
                if hyphen_pos + 1 < self.length and self.pattern[hyphen_pos + 1] != "]":
                    self.pos += 1
                    end_item = self._parse_class_item(flags)
                    if item.kind == "shorthand" or end_item.kind == "shorthand":
                        self._error("bad character range with shorthand class", hyphen_pos)
                    left = item.value
                    right = end_item.value
                    if ord(left) > ord(right):
                        self._error("bad character range", hyphen_pos)
                    items.append(ClassItem("range", (left, right), (item.span[0], end_item.span[1])))
                    continue

            items.append(item)

        if not items:
            self._error("empty character class", start)
        return CharClassNode(tuple(items), negated, (start, self.pos), flags)

    def _parse_class_item(self, flags: int) -> ClassItem:
        start = self.pos
        char = self._take()
        if char == "\\":
            escape = self._parse_escape(start, True)
            if escape.kind not in ("literal", "shorthand"):
                self._error("unsupported escape in character class", start)
            return ClassItem(escape.kind, escape.value, escape.span)
        return ClassItem("literal", char, (start, self.pos))

    def _parse_escape(self, start: int, in_class: bool) -> _Escape:
        if self.pos >= self.length:
            self._error("trailing backslash", start)
        char = self._take()
        escape_start = start

        control = {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "f": "\f",
            "v": "\v",
            "a": "\a",
        }
        if char in control:
            return _Escape("literal", control[char], (escape_start, self.pos))

        if not in_class and char in "AZbB":
            kinds = {"A": "absolute_start", "Z": "absolute_end", "b": "word_boundary", "B": "not_word_boundary"}
            return _Escape("anchor", kinds[char], (escape_start, self.pos))

        if in_class and char == "b":
            return _Escape("literal", "\b", (escape_start, self.pos))

        if char in "dDwWsS":
            return _Escape("shorthand", char, (escape_start, self.pos))

        if char == "x":
            return _Escape("literal", chr(self._read_hex(2, "x", escape_start)), (escape_start, self.pos))
        if char == "u":
            return _Escape("literal", chr(self._read_hex(4, "u", escape_start)), (escape_start, self.pos))
        if char == "U":
            return _Escape("literal", chr(self._read_hex(8, "U", escape_start)), (escape_start, self.pos))

        if char == "N":
            if self._peek() != "{":
                self._error("bad unicode name escape", escape_start)
            self.pos += 1
            name_start = self.pos
            while self.pos < self.length and self.pattern[self.pos] != "}":
                self.pos += 1
            if self.pos >= self.length:
                self._error("unterminated unicode name escape", escape_start)
            name = self.pattern[name_start:self.pos]
            self.pos += 1
            try:
                value = unicodedata.lookup(name)
            except KeyError:
                self._error("unknown unicode character name", name_start)
            return _Escape("literal", value, (escape_start, self.pos))

        if char.isdigit():
            digits = char
            while len(digits) < 3 and self.pos < self.length and self.pattern[self.pos].isdigit():
                digits += self.pattern[self.pos]
                self.pos += 1
            if in_class:
                if not all(digit in "01234567" for digit in digits):
                    self._error("bad escape \\%s" % digits[0], escape_start)
                value = int(digits, 8)
                if value > 0o377:
                    self._error("octal escape outside range 0 to 0o377", escape_start)
                return _Escape("literal", chr(value), (escape_start, self.pos))

            if char == "0" or (len(digits) == 3 and all(digit in "01234567" for digit in digits)):
                value = int(digits, 8)
                if value > 0o377:
                    self._error("octal escape outside range 0 to 0o377", escape_start)
                return _Escape("literal", chr(value), (escape_start, self.pos))

            ref_digits = digits[:2]
            leftover = digits[2:]
            if leftover:
                self.pos -= len(leftover)
            try:
                ref = int(ref_digits)
            except ValueError:
                self._error("bad group reference", escape_start)
            return _Escape("backreference", ref, (escape_start, self.pos))

        if char.isalpha():
            self._error("bad escape \\%s" % char, escape_start)

        return _Escape("literal", char, (escape_start, self.pos))

    def _read_hex(self, width: int, marker: str, start: int) -> int:
        if self.pos + width > self.length:
            self._error("incomplete escape \\%s" % marker, start)
        text = self.pattern[self.pos:self.pos + width]
        if len(text) != width or any(char not in _HEX for char in text):
            self._error("incomplete escape \\%s" % marker, start)
        self.pos += width
        value = int(text, 16)
        if value > UNICODE_MAX_LOCAL:
            self._error("escape value outside Unicode range", start)
        return value


UNICODE_MAX_LOCAL = 0x10FFFF


def parse_regex(pattern: str, flags: int = 0, *, policy: Optional[RegexPolicy] = None) -> Node:
    """Parse a Python str regular expression into a typed immutable AST.

    Raises RegexPatternError for invalid syntax or hard policy limits. The
    parser never invokes re.compile and never evaluates the untrusted pattern.
    """

    if not isinstance(pattern, str):
        raise TypeError("pattern must be str")
    if not isinstance(flags, int):
        raise TypeError("flags must be int")
    return RegexParser(pattern, flags, policy).parse()
