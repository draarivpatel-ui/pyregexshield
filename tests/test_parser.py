from __future__ import annotations

import re
import time
import unittest

from pyregexshield import RegexPolicy
from pyregexshield.errors import RegexPatternError
from pyregexshield.nodes import (
    AlternationNode,
    AnchorNode,
    BackReferenceNode,
    CharClassNode,
    ConcatNode,
    ConditionalNode,
    DotNode,
    GroupNode,
    LiteralNode,
    RepeatNode,
)
from pyregexshield.parser import parse_regex, scan_plain_inline_flags

from helpers import add_matrix_tests


_VALID_PATTERNS = (
    "", "a", "ab", "abc", "]", "{", "a{", "a{}", "a{x}", " ", "#",
    ".", "^", "$", r"\A", r"\Z", r"\b", r"\B",
    r"\d", r"\D", r"\w", r"\W", r"\s", r"\S",
    r"\n", r"\r", r"\t", r"\f", r"\v", r"\a", r"\*", r"\.", r"\\",
    r"\x41", r"\x00", r"\xff", r"\u0041", r"\U00000041", r"\N{LATIN CAPITAL LETTER A}",
    r"\0", r"\00", r"\000", r"\07", r"\111", r"\123", r"\377",
    "a|b", "a|", "|a", "|", "a|b|c", "ab|cd|ef",
    "(a)", "(ab)", "((a))", "(?:a)", "(?P<x>a)", "(?P<name_1>ab)",
    "(?=a)", "(?!a)", "(?<=a)", "(?<!a)", "(?<=ab|cd)", "(?<=a{2})", "(?<=\b)",
    "(?#comment)a", "(?#)a", "(?>a)", "(?>a+)",
    "(?i)a", "(?m)a", "(?s)a", "(?x)a b", "(?a)\w", "(?u)a", "(?im)a",
    "(?i:a)", "(?-i:a)", "(?i-m:a)", "(?x:a b)", "(?a:\w)",
    "a*", "a+", "a?", "a*?", "a+?", "a??", "a*+", "a++", "a?+",
    "a{0}", "a{1}", "a{2}", "a{2,}", "a{2,4}", "a{,4}", "a{,}", "a{2,4}?", "a{2,4}+",
    "[a]", "[ab]", "[^a]", "[]a]", "[^]a]", "[a-z]", "[a-z0-9]", "[-a]", "[a-]", "[--0]",
    r"[\d]", r"[\D]", r"[\w]", r"[\W]", r"[\s]", r"[\S]", r"[\x41-z]", r"[\b]", r"[\]]", r"[\-]",
    r"(a)\1", r"(a)(b)\2", "(?P<x>a)(?P=x)", "(a)(?(1)b|c)", "(a)(?(1)|c)", "(a)(?(1)b|)",
    "(?P<x>a)(?(x)b|c)", "a(b)c", "a(?:b|c)d", "^[a-z0-9_-]{1,64}$",
    "(?x)a#comment\nb", "(?x)a\ b", "(?x)[a b]", "a b(?x)c d",
)


def _valid_runner(self, pattern):
    try:
        node = parse_regex(pattern)
    except RegexPatternError as error:
        self.fail("valid pattern %r raised %s" % (pattern, error))
    self.assertGreaterEqual(node.span[1], node.span[0])


class ValidPatternMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(ValidPatternMatrixTests, _VALID_PATTERNS, "valid", _valid_runner)


_INVALID_PATTERNS = (
    "(", ")", "(a", "a)", "(?:a", "(?", "(?P", "(?P<", "(?P<>a)", "(?P<1>a)",
    "(?P<x>a)(?P<x>b)", "(?P=x)", r"\1", r"\8", "(a)\\2", r"(a\1)", r"(\1a)",
    "a**", "a*+*", "a*{1}", "^*", "$*", r"\b+", r"\A*",
    "a{2,1}", "a{999999999999999999999}", "a{100001}",
    "[", "[a", "[^", "[z-a]", r"[\d-z]", r"[a-\d]", r"[\8]", r"[\400]",
    "\\", r"\q", r"\x", r"\x4", r"\u004", r"\U0000041", r"\N", r"\N{}", r"\N{NO SUCH CHARACTER}",
    "(?i", "(?i-", "(?i-m)", "(?-i)", "(?z)a", "(?a-u:a)", "(?(1)a|b)", "(a)(?(2)b|c)",
    "(a)(?(1)b|c|d)", "(?<=a+)", "(?<=a?)", "(?<=a{1,2})", "(?<=a|bc)", "(?<!a+)",
)


def _invalid_runner(self, pattern):
    with self.assertRaises(RegexPatternError, msg=repr(pattern)):
        parse_regex(pattern)


class InvalidPatternMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(InvalidPatternMatrixTests, _INVALID_PATTERNS, "invalid", _invalid_runner)


class ParserStructureTests(unittest.TestCase):
    def test_empty_pattern_is_concat(self):
        node = parse_regex("")
        self.assertIsInstance(node, ConcatNode)
        self.assertEqual(node.items, ())

    def test_literal_node(self):
        node = parse_regex("x")
        self.assertIsInstance(node, LiteralNode)
        self.assertEqual(node.char, "x")
        self.assertEqual(node.span, (0, 1))

    def test_concatenation_shape(self):
        node = parse_regex("ab")
        self.assertIsInstance(node, ConcatNode)
        self.assertEqual([item.char for item in node.items], ["a", "b"])

    def test_alternation_shape(self):
        node = parse_regex("a|b|c")
        self.assertIsInstance(node, AlternationNode)
        self.assertEqual(len(node.branches), 3)

    def test_group_capture_index_and_name(self):
        node = parse_regex("(?P<word>a)")
        self.assertIsInstance(node, GroupNode)
        self.assertEqual(node.kind, "capture")
        self.assertEqual(node.name, "word")
        self.assertEqual(node.index, 1)

    def test_unnamed_capture_index(self):
        node = parse_regex("(a)")
        self.assertIsInstance(node, GroupNode)
        self.assertEqual(node.kind, "capture")
        self.assertEqual(node.index, 1)

    def test_noncapture_group(self):
        node = parse_regex("(?:a)")
        self.assertIsInstance(node, GroupNode)
        self.assertEqual(node.kind, "noncapture")
        self.assertIsNone(node.index)

    def test_repeat_counts(self):
        node = parse_regex("a{2,5}")
        self.assertIsInstance(node, RepeatNode)
        self.assertEqual(node.min_count, 2)
        self.assertEqual(node.max_count, 5)

    def test_open_repeat(self):
        node = parse_regex("a+")
        self.assertEqual(node.min_count, 1)
        self.assertIsNone(node.max_count)

    def test_lazy_repeat(self):
        node = parse_regex("a+?")
        self.assertFalse(node.greedy)
        self.assertFalse(node.possessive)

    def test_possessive_repeat_ast(self):
        node = parse_regex("a+ +".replace(" ", ""))
        self.assertTrue(node.possessive)

    def test_dot_node(self):
        self.assertIsInstance(parse_regex("."), DotNode)

    def test_anchor_nodes(self):
        node = parse_regex(r"^$\A\Z\b\B")
        self.assertIsInstance(node, ConcatNode)
        self.assertTrue(all(isinstance(item, AnchorNode) for item in node.items))
        self.assertEqual([item.kind for item in node.items], ["start", "end", "absolute_start", "absolute_end", "word_boundary", "not_word_boundary"])

    def test_backreference_node(self):
        node = parse_regex(r"(a)\1")
        self.assertIsInstance(node.items[1], BackReferenceNode)
        self.assertEqual(node.items[1].ref, 1)

    def test_named_backreference_node(self):
        node = parse_regex(r"(?P<x>a)(?P=x)")
        self.assertIsInstance(node.items[1], BackReferenceNode)
        self.assertEqual(node.items[1].ref, "x")

    def test_conditional_node(self):
        node = parse_regex("(a)(?(1)b|c)")
        conditional = node.items[1]
        self.assertIsInstance(conditional, ConditionalNode)
        self.assertEqual(conditional.condition, 1)
        self.assertIsNotNone(conditional.no)

    def test_character_class_range(self):
        node = parse_regex("[a-z]")
        self.assertIsInstance(node, CharClassNode)
        self.assertFalse(node.negated)
        self.assertEqual(node.items[0].kind, "range")
        self.assertEqual(node.items[0].value, ("a", "z"))

    def test_negated_character_class(self):
        node = parse_regex("[^a]")
        self.assertTrue(node.negated)

    def test_verbose_space_is_ignored(self):
        node = parse_regex("(?x)a b")
        self.assertEqual([item.char for item in node.items], ["a", "b"])

    def test_verbose_escaped_space_is_literal(self):
        node = parse_regex("(?x)a\ b")
        self.assertEqual([item.char for item in node.items], ["a", " ", "b"])

    def test_verbose_comment_is_ignored(self):
        node = parse_regex("(?x)a#comment\nb")
        self.assertEqual([item.char for item in node.items], ["a", "b"])

    def test_scoped_ignorecase_flag(self):
        node = parse_regex("(?i:a)")
        self.assertTrue(node.child.flags & re.IGNORECASE)

    def test_plain_inline_flag_scans_globally(self):
        self.assertTrue(scan_plain_inline_flags(r"a(?i)b") & re.IGNORECASE)
        node = parse_regex(r"a(?i)b")
        self.assertTrue(node.items[0].flags & re.IGNORECASE)

    def test_inline_flag_in_class_is_not_scanned(self):
        self.assertEqual(scan_plain_inline_flags("[(?i)]"), 0)

    def test_atomic_group_node(self):
        node = parse_regex("(?>a)")
        self.assertIsInstance(node, GroupNode)
        self.assertEqual(node.kind, "atomic")

    def test_span_includes_group_delimiters(self):
        node = parse_regex("x(a)y")
        self.assertEqual(node.items[1].span, (1, 4))

    def test_comment_is_zero_width_noop(self):
        node = parse_regex("a(?#comment)b")
        self.assertEqual(len(node.items), 2)

    def test_brace_literal_when_not_numeric(self):
        node = parse_regex("a{x}")
        self.assertEqual([item.char for item in node.items], ["a", "{", "x", "}"])


class ParserLimitTests(unittest.TestCase):
    def test_pattern_length_limit(self):
        policy = RegexPolicy(max_pattern_length=10)
        result = parse_regex("a" * 10, policy=policy)
        self.assertIsNotNone(result)
        with self.assertRaises(RegexPatternError) as caught:
            parse_regex("a" * 11, policy=policy)
        self.assertEqual(caught.exception.code, "REDOS_PATTERN_TOO_LONG")

    def test_depth_limit(self):
        policy = RegexPolicy(max_depth=5)
        parse_regex("((((a))))", policy=policy)
        with self.assertRaises(RegexPatternError) as caught:
            parse_regex("((((((a))))))", policy=policy)
        self.assertEqual(caught.exception.code, "REDOS_EXCESSIVE_DEPTH")

    def test_quantifier_hard_limit(self):
        policy = RegexPolicy(max_quantifier=100)
        parse_regex("a{100}", policy=policy)
        with self.assertRaises(RegexPatternError) as caught:
            parse_regex("a{101}", policy=policy)
        self.assertEqual(caught.exception.code, "REDOS_EXCESSIVE_REPETITION_BOUND")

    def test_open_quantifier_uses_minimum_for_hard_cap(self):
        policy = RegexPolicy(max_quantifier=100)
        with self.assertRaises(RegexPatternError):
            parse_regex("a{101,}", policy=policy)

    def test_pathological_open_groups_fail_fast(self):
        pattern = "(" * 500
        start = time.perf_counter()
        with self.assertRaises(RegexPatternError):
            parse_regex(pattern)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_many_repeated_classes_parse_linearly(self):
        pattern = "[a-z]" * 500
        start = time.perf_counter()
        node = parse_regex(pattern)
        elapsed = time.perf_counter() - start
        self.assertEqual(len(node.items), 500)
        self.assertLess(elapsed, 1.0)

    def test_many_alternations_parse_bounded(self):
        pattern = "a|" * 500 + "a"
        start = time.perf_counter()
        node = parse_regex(pattern)
        elapsed = time.perf_counter() - start
        self.assertIsInstance(node, AlternationNode)
        self.assertLess(elapsed, 1.0)

    def test_nested_alternation_prefix_fails_fast(self):
        pattern = "(a|" * 200
        start = time.perf_counter()
        with self.assertRaises(RegexPatternError):
            parse_regex(pattern)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_non_string_pattern_rejected(self):
        with self.assertRaises(TypeError):
            parse_regex(b"abc")

    def test_non_integer_flags_rejected(self):
        with self.assertRaises(TypeError):
            parse_regex("abc", "i")

class ParserAdversarialRegressionTests(unittest.TestCase):
    def test_leading_zero_octal_stops_before_non_octal_digit(self):
        node = parse_regex(r"\08")
        self.assertEqual([item.char for item in node.items], ["\x00", "8"])
        node = parse_regex(r"\018")
        self.assertEqual([item.char for item in node.items], ["\x01", "8"])

    def test_class_octal_stops_before_non_octal_digit(self):
        node = parse_regex(r"[\18]")
        self.assertEqual(len(node.items), 2)
        self.assertEqual(node.items[0].value, "\x01")
        self.assertEqual(node.items[1].value, "8")
        node = parse_regex(r"[\1118]")
        self.assertEqual(len(node.items), 2)
        self.assertEqual(node.items[0].value, "I")
        self.assertEqual(node.items[1].value, "8")

    def test_verbose_unicode_whitespace_is_literal(self):
        node = parse_regex("(?x)a\u00a0b")
        self.assertEqual([item.char for item in node.items], ["a", "\u00a0", "b"])
        node = parse_regex("(?x)a\u2003b")
        self.assertEqual([item.char for item in node.items], ["a", "\u2003", "b"])

    def test_verbose_comment_does_not_contribute_global_flags(self):
        pattern = "(?x)# (?i)\na"
        self.assertFalse(scan_plain_inline_flags(pattern) & re.IGNORECASE)
        node = parse_regex(pattern)
        self.assertFalse(node.flags & re.IGNORECASE)
        self.assertTrue(node.flags & re.VERBOSE)

    def test_inline_flag_overlap_is_rejected(self):
        for pattern in ("(?i-i:a)", "(?im-m:a)", "(?i-mi:a)"):
            with self.assertRaises(RegexPatternError, msg=pattern):
                parse_regex(pattern)

    def test_empty_inline_flag_removal_is_rejected(self):
        for pattern in ("(?i-:a)", "(?i-)"):
            with self.assertRaises(RegexPatternError, msg=pattern):
                parse_regex(pattern)

    def test_scoped_locale_is_rejected_for_str_patterns(self):
        with self.assertRaises(RegexPatternError):
            parse_regex("(?L:a)")

    def test_initial_ascii_unicode_combination_is_rejected(self):
        with self.assertRaises(RegexPatternError):
            parse_regex("a", re.ASCII | re.UNICODE)

    def test_scoped_unicode_overrides_outer_ascii(self):
        node = parse_regex(r"(?u:\w)", re.ASCII)
        self.assertTrue(node.child.flags & re.UNICODE)
        self.assertFalse(node.child.flags & re.ASCII)

    def test_forward_numeric_conditional_is_accepted(self):
        node = parse_regex("(?(1)a|b)(a)")
        self.assertIsNotNone(node)

    def test_open_numeric_conditional_is_accepted(self):
        node = parse_regex("(a(?(1)b|c))")
        self.assertIsNotNone(node)

    def test_unresolved_forward_numeric_conditional_fails_at_end(self):
        with self.assertRaises(RegexPatternError):
            parse_regex("(?(2)a|b)(a)")
