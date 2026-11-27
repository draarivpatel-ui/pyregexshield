from __future__ import annotations

import re
import sys
import unittest
from dataclasses import FrozenInstanceError

from pyregexshield import (
    InputTooLongError,
    RegexPolicy,
    UnsafeRegexError,
    assert_safe_regex,
    safe_compile,
    safe_findall,
    safe_fullmatch,
    safe_match,
    safe_search,
    safe_sub,
)

from helpers import add_matrix_tests


_SAFE_COMPILE_PATTERNS = (
    r"^[a-z]+$", r"^\d{4}-\d{2}-\d{2}$", r"^[a-z0-9_-]{1,64}$", r"^[A-F0-9]{32}$",
    r"^(?:foo|bar|baz)$", r"(foo|bar)+", r"(?:[a-z]+,)+", r"^[a-z]+(?:\.[a-z]+)*$",
    r"\s+\S+", r"[a-z]+#[a-z]+", r"a{1,4}a{1,4}", r"^[^,]+$", r"^x(?:[0-9a-f]{2})+$",
    r"^[+-]?\d+(\.\d+)?$", r"^[A-Z][a-z]*$", r"^\w{1,32}:\w{1,32}$",
)

_UNSAFE_COMPILE_PATTERNS = (
    r"(a+)+", r"(a*)*", r"([a-z]+)*", r"(a|a)+", r"(a|ab)+", r"(\w|\d)+",
    r".*.*", r"\s+\s+", r"[a-z]+[a-z]+", r"a+a+", r"(\w+)\1", r"(?=a)+",
    r"a{0,50000}", r"(a{101}){101}", "(", r"\q", r"a{2,1}",
)


def _compile_safe_runner(self, pattern):
    compiled = safe_compile(pattern)
    self.assertEqual(compiled.pattern, pattern)


def _compile_unsafe_runner(self, pattern):
    with self.assertRaises(UnsafeRegexError, msg=repr(pattern)):
        safe_compile(pattern)


class SafeCompileMatrixTests(unittest.TestCase):
    pass


class UnsafeCompileMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(SafeCompileMatrixTests, _SAFE_COMPILE_PATTERNS, "compile_safe", _compile_safe_runner)
add_matrix_tests(UnsafeCompileMatrixTests, _UNSAFE_COMPILE_PATTERNS, "compile_unsafe", _compile_unsafe_runner)


class SafeCompileApiTests(unittest.TestCase):
    def test_match(self):
        compiled = safe_compile(r"^[a-z]+")
        self.assertEqual(compiled.match("abc").group(0), "abc")
        self.assertIsNone(compiled.match("123"))

    def test_search(self):
        compiled = safe_compile(r"[a-z]+")
        self.assertEqual(compiled.search("123abc").group(0), "abc")

    def test_fullmatch(self):
        compiled = safe_compile(r"[a-z]+")
        self.assertIsNotNone(compiled.fullmatch("abc"))
        self.assertIsNone(compiled.fullmatch("abc1"))

    def test_findall(self):
        compiled = safe_compile(r"[a-z]+")
        self.assertEqual(compiled.findall("ab1cd"), ["ab", "cd"])

    def test_finditer(self):
        compiled = safe_compile(r"[a-z]+")
        self.assertEqual([match.group(0) for match in compiled.finditer("ab1cd")], ["ab", "cd"])

    def test_split(self):
        compiled = safe_compile(r",")
        self.assertEqual(compiled.split("a,b,c"), ["a", "b", "c"])

    def test_sub_string_replacement(self):
        compiled = safe_compile(r"[0-9]")
        self.assertEqual(compiled.sub("#", "a1b2"), "a#b#")

    def test_sub_callable_replacement(self):
        compiled = safe_compile(r"[0-9]")
        self.assertEqual(compiled.sub(lambda match: str(int(match.group(0)) + 1), "a1"), "a2")

    def test_subn(self):
        compiled = safe_compile(r"[0-9]")
        self.assertEqual(compiled.subn("#", "a1b2"), ("a#b#", 2))

    def test_pos_and_endpos(self):
        compiled = safe_compile(r"[a-z]+")
        self.assertEqual(compiled.search("zzabczz", 2, 5).group(0), "abc")

    def test_groups_and_groupindex(self):
        compiled = safe_compile(r"(?P<word>[a-z]+)([0-9])")
        self.assertEqual(compiled.groups, 2)
        self.assertEqual(compiled.groupindex["word"], 1)

    def test_result_is_preserved(self):
        compiled = safe_compile(r"^[a-z]+$")
        self.assertTrue(compiled.result.safe)
        self.assertEqual(compiled.result.findings, ())

    def test_safe_pattern_is_frozen(self):
        compiled = safe_compile(r"^[a-z]+$")
        with self.assertRaises(FrozenInstanceError):
            compiled.pattern = "other"

    def test_assert_safe_regex_returns_result(self):
        result = assert_safe_regex(r"^[a-z]+$")
        self.assertTrue(result.safe)

    def test_assert_safe_regex_raises(self):
        with self.assertRaises(UnsafeRegexError) as caught:
            assert_safe_regex(r"(a+)+")
        self.assertEqual(caught.exception.findings[0].code, "REDOS_STAR_HEIGHT_NESTED_QUANTIFIER")
        self.assertFalse(caught.exception.result.safe)

    def test_error_message_contains_stable_code(self):
        with self.assertRaises(UnsafeRegexError) as caught:
            safe_compile(r"(a+)+")
        self.assertIn("REDOS_STAR_HEIGHT_NESTED_QUANTIFIER", str(caught.exception))

    def test_runtime_compile_validation(self):
        with self.assertRaises(UnsafeRegexError):
            safe_compile(r"\q")

    def test_atomic_group_runtime_version_validation(self):
        if sys.version_info < (3, 11):
            with self.assertRaises(UnsafeRegexError):
                safe_compile(r"(?>a+)")
        else:
            self.assertIsNotNone(safe_compile(r"(?>a+)"))

    def test_possessive_runtime_version_validation(self):
        if sys.version_info < (3, 11):
            with self.assertRaises(UnsafeRegexError):
                safe_compile(r"a++")
        else:
            self.assertIsNotNone(safe_compile(r"a++"))

    def test_module_safe_match(self):
        self.assertIsNotNone(safe_match(r"^[a-z]+$", "abc"))

    def test_module_safe_search(self):
        self.assertIsNotNone(safe_search(r"[a-z]+", "123abc"))

    def test_module_safe_fullmatch(self):
        self.assertIsNotNone(safe_fullmatch(r"[a-z]+", "abc"))

    def test_module_safe_findall(self):
        self.assertEqual(safe_findall(r"[a-z]+", "ab1cd"), ["ab", "cd"])

    def test_module_safe_sub(self):
        self.assertEqual(safe_sub(r"[0-9]", "#", "a1"), "a#")

    def test_module_helpers_raise_for_unsafe_pattern(self):
        with self.assertRaises(UnsafeRegexError):
            safe_match(r"(a+)+", "aaa")

    def test_ignorecase_compilation(self):
        compiled = safe_compile(r"^[a-z]+$", re.IGNORECASE)
        self.assertIsNotNone(compiled.fullmatch("ABC"))

    def test_custom_input_limit(self):
        policy = RegexPolicy(max_input_length=4)
        compiled = safe_compile(r"[a-z]+", policy=policy)
        self.assertIsNotNone(compiled.fullmatch("abcd"))
        with self.assertRaises(InputTooLongError):
            compiled.fullmatch("abcde")

    def test_input_limit_match(self):
        compiled = safe_compile(r"[a-z]+", policy=RegexPolicy(max_input_length=2))
        with self.assertRaises(InputTooLongError):
            compiled.match("abc")

    def test_input_limit_search(self):
        compiled = safe_compile(r"[a-z]+", policy=RegexPolicy(max_input_length=2))
        with self.assertRaises(InputTooLongError):
            compiled.search("abc")

    def test_input_limit_findall(self):
        compiled = safe_compile(r"[a-z]+", policy=RegexPolicy(max_input_length=2))
        with self.assertRaises(InputTooLongError):
            compiled.findall("abc")

    def test_input_limit_finditer_happens_before_iteration(self):
        compiled = safe_compile(r"[a-z]+", policy=RegexPolicy(max_input_length=2))
        with self.assertRaises(InputTooLongError):
            compiled.finditer("abc")

    def test_input_limit_split(self):
        compiled = safe_compile(r",", policy=RegexPolicy(max_input_length=2))
        with self.assertRaises(InputTooLongError):
            compiled.split("a,b")

    def test_input_limit_sub(self):
        compiled = safe_compile(r"a", policy=RegexPolicy(max_input_length=2))
        with self.assertRaises(InputTooLongError):
            compiled.sub("b", "aaa")

    def test_input_limit_subn(self):
        compiled = safe_compile(r"a", policy=RegexPolicy(max_input_length=2))
        with self.assertRaises(InputTooLongError):
            compiled.subn("b", "aaa")

    def test_input_type_must_be_str(self):
        compiled = safe_compile(r"[a-z]+")
        with self.assertRaises(TypeError):
            compiled.match(b"abc")

    def test_input_error_fields(self):
        compiled = safe_compile(r"[a-z]+", policy=RegexPolicy(max_input_length=2))
        with self.assertRaises(InputTooLongError) as caught:
            compiled.search("abcd")
        self.assertEqual(caught.exception.length, 4)
        self.assertEqual(caught.exception.maximum, 2)

    def test_policy_rejects_zero_input_length(self):
        with self.assertRaises(ValueError):
            RegexPolicy(max_input_length=0)

    def test_policy_rejects_bad_severity(self):
        with self.assertRaises(ValueError):
            RegexPolicy(minimum_block_severity="notice")

    def test_strict_policy_factory(self):
        policy = RegexPolicy().strict()
        self.assertEqual(policy.minimum_block_severity, "low")

    def test_compile_rejects_non_string_pattern(self):
        with self.assertRaises(TypeError):
            safe_compile(b"abc")

    def test_compile_rejects_non_integer_flags(self):
        with self.assertRaises(TypeError):
            safe_compile("abc", "i")
