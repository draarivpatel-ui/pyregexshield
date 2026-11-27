from __future__ import annotations

import re
import time
import unittest
from dataclasses import FrozenInstanceError

from pyregexshield import RegexPolicy, analyze_regex
from pyregexshield.analyzer import AnalysisResult, Finding

from helpers import add_matrix_tests


_NESTED_QUANTIFIER_PATTERNS = (
    r"(a+)+", r"(a*)*", r"(a?)*", r"(a+)*", r"(a*)+", r"([a-z]+)*", r"(\w+)+", r"(.*)+", r"(.+)*",
    r"(a{1,5})+", r"(a{1,5}){2,}", r"(a+){2}", r"(a+){2,}", r"((a+))+", r"(?:a+)+", r"(?:[a-z]+)+",
    r"(?:\d+)+", r"(x+x+)+y", r"(x+)+y", r"((x+)x+)+y", r"([a-zA-Z]+)*", r"([0-9]+)*", r"(\s*)*",
    r"(a|b+)+", r"(a+|b)+", r"(a+|b+)+", r"((a|b)+)+", r"(?:a+(?:b+)?)+", r"(a+)+$", r"^(a+)+",
)

_OVERLAPPING_ALTERNATION_PATTERNS = (
    r"(a|a)+", r"(a|ab)+", r"(ab|a)+", r"(a|a*)+", r"(\w|\d)+", r"(\d|\w)+", r"([a-z]|[a-f])+",
    r"(.|\s)+", r"(foo|foobar)+", r"(bar|ba)+", r"(a{2}|aa)+", r"(x|xy)+", r"(xy|x)+",
    r"([0-9]|[0-8])+", r"([a-c]|[b-d])+", r"(\S|\w)+", r"(\W|\s)+",
    r"((?i)a|A)+", r"(?i)(a|A)+", r"(?i:(a|A)+)", r"(?i:a|A)+", r"(aa|aA)+", r"(\w|[a-z])+",
    r"([a-z]|\w)+", r"([^z]|[a-y])+", r"(.|\w)+", r"([\s\S]|\w)+", r"(a|aa|aaa)+",
)

_ADJACENT_QUANTIFIER_PATTERNS = (
    r".*.*", r".+.+", r".*.+", r".+.*", r"\s+\s+", r"\S+\S+", r"\w+\w+", r"\d+\d+",
    r"[a-z]+[a-z]+", r"[a-z]*[a-z]*", r"a+a+", r"a*a*", r"a+a*", r"a*a+", r"[ab]+[ab]+",
    r".*foo.*bar.*", r"^.*foo.*bar.*", r"\w+foo\w+bar\w+", r"[a-z]+x[a-z]+x[a-z]+",
    r"\d+\d*", r"\w+\w*", r"[a-z]{1,20}[a-z]{1,20}", r"a{1,20}a{1,20}", r"a*a+",
)

_BACKREFERENCE_PATTERNS = (
    r"(a)\1", r"(\w+)\1", r"(?P<x>\w+)(?P=x)", r"((a)+)\1", r"(a+)\1", r"(\d{2,4})\1",
    r"(?P<x>[a-z]+)x(?P=x)", r"((\w+))\2", r"(\w+)(\1)+", r"((a)\2+)",
)

_LOOKAROUND_PATTERNS = (
    r"(?=a)+", r"(?!a)*", r"(?<=a){2,}", r"(?<!a)+", r"(?=(?=a)a)", r"(?!(?!a)a)",
    r"(?<=(?=a)b)c", r"((?=a))+", r"(?:(?=a))+",
)

_BOUND_PATTERNS = (
    r"a{0,50000}", r"a{1001}", r"a{0,1001}", r"(a{101}){101}", r"(a{10,101}){10,101}",
    r"[a-z]{2000}", r"\w{0,5000}", r"a{0,1000000}",
)


def _expect_code(pattern, code):
    result = analyze_regex(pattern)
    codes = {finding.code for finding in result.findings}
    return result, codes, code


def _nested_runner(self, pattern):
    result, codes, code = _expect_code(pattern, "REDOS_STAR_HEIGHT_NESTED_QUANTIFIER")
    self.assertIn(code, codes, pattern)
    self.assertFalse(result.safe, pattern)
    self.assertIn(result.risk_level, ("high", "critical"), pattern)


def _overlap_runner(self, pattern):
    result, codes, code = _expect_code(pattern, "REDOS_OVERLAPPING_ALTERNATION")
    self.assertIn(code, codes, pattern)
    self.assertFalse(result.safe, pattern)


def _adjacent_runner(self, pattern):
    result, codes, code = _expect_code(pattern, "REDOS_OVERLAPPING_ADJACENT_QUANTIFIERS")
    self.assertIn(code, codes, pattern)
    self.assertFalse(result.safe, pattern)


def _backreference_runner(self, pattern):
    result, codes, code = _expect_code(pattern, "REDOS_BACKREFERENCE_QUANTIFIED")
    self.assertIn(code, codes, pattern)
    self.assertFalse(result.safe, pattern)


def _lookaround_runner(self, pattern):
    result, codes, code = _expect_code(pattern, "REDOS_COMPLEX_LOOKAROUND")
    self.assertIn(code, codes, pattern)
    self.assertFalse(result.safe, pattern)


def _bound_runner(self, pattern):
    result, codes, code = _expect_code(pattern, "REDOS_EXCESSIVE_REPETITION_BOUND")
    self.assertIn(code, codes, pattern)
    self.assertFalse(result.safe, pattern)


class NestedQuantifierMatrixTests(unittest.TestCase):
    pass


class OverlappingAlternationMatrixTests(unittest.TestCase):
    pass


class AdjacentQuantifierMatrixTests(unittest.TestCase):
    pass


class BackreferenceMatrixTests(unittest.TestCase):
    pass


class LookaroundMatrixTests(unittest.TestCase):
    pass


class BoundMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(NestedQuantifierMatrixTests, _NESTED_QUANTIFIER_PATTERNS, "nested", _nested_runner)
add_matrix_tests(OverlappingAlternationMatrixTests, _OVERLAPPING_ALTERNATION_PATTERNS, "overlap", _overlap_runner)
add_matrix_tests(AdjacentQuantifierMatrixTests, _ADJACENT_QUANTIFIER_PATTERNS, "adjacent", _adjacent_runner)
add_matrix_tests(BackreferenceMatrixTests, _BACKREFERENCE_PATTERNS, "backref", _backreference_runner)
add_matrix_tests(LookaroundMatrixTests, _LOOKAROUND_PATTERNS, "lookaround", _lookaround_runner)
add_matrix_tests(BoundMatrixTests, _BOUND_PATTERNS, "bound", _bound_runner)


_SAFE_PATTERNS = (
    "", "a", "abc", "literal text", r"\.", r"\*", ".", "^$", r"\A\Z", r"\bword\b",
    "a*", "a+", "a?", "a*?", "a+?", "a??", "a{2}", "a{2,4}", "a{1,64}", "[a-z]", "[^a-z]", "[a-z0-9_-]",
    r"\d", r"\w", r"\s", r"\D", r"\W", r"\S", r"\d{4}", r"\w{1,32}", r"\s?\S+",
    r"^[a-z0-9_-]{1,64}$", r"^\d{4}-\d{2}-\d{2}$", r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    r"^[A-F0-9]{32}$", r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", r"^[a-z]+(?:\.[a-z]+)*$",
    r"^(?:foo|bar|baz)$", r"(foo|bar)+", r"(ab|cd)+", r"(a|b)+", r"(\d|[a-f])+",
    r"(?:[a-z]+,)+", r"(?:\d+,)+", r"(?:[a-z]+;)+", r"(?:,[a-z]+)+", r"(?:ab+c)+", r"(?:(?:a+),)+",
    r"[a-z]+#[a-z]+", r"[a-z]+[0-9]+", r"\s+\S+", r"\S+\s+", r"a{1,4}a{1,4}", r"[a-z]{1,4}[a-z]{1,4}",
    r".*\n.*", r"^.*\n.*", r"^[^,]+$", r"^[^@\s]+@[^@\s.]+\.[^@\s.]+$", r"^[A-Za-z0-9+/]{4}={0,2}$",
    r"^[+-]?\d+(\.\d+)?$", r"^(?:GET|POST|PUT|DELETE)\s+/[^\s]*\s+HTTP/1\.[01]$",
    r"^[A-Z][a-z]*$", r"^\w{1,32}:\w{1,32}$", r"^[0-7]{3,4}$", r"^x(?:[0-9a-f]{2})+$",
    r"(?=(?:fixed))abc", r"(?<=abc)def", r"(?<!abc)def", r"(?>a+)+", r"(a++)+", r"(?>a+)b",
    r"(?i:foo|bar)+", r"(?i)(foo|bar)+", r"(?i)^[a-z]{1,16}$", r"(?x) ^ [a-z]+ $",
    r"^$",
)


def _safe_runner(self, pattern):
    result = analyze_regex(pattern)
    blocking = [finding for finding in result.findings if finding.severity in ("medium", "high", "critical")]
    self.assertEqual(blocking, [], pattern)
    self.assertTrue(result.safe, pattern)


class SafePatternMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(SafePatternMatrixTests, _SAFE_PATTERNS, "safe", _safe_runner)


_STRICT_CLEAN_PATTERNS = (
    r"^[a-z0-9_-]{1,64}$", r"^\d{4}-\d{2}-\d{2}$", r"^(?:foo|bar|baz)$",
    r"^[a-z]+(?:\.[a-z]+)*$", r"(?:[a-z]+,)+", r"[a-z]+#[a-z]+", r"\s+\S+",
    r"^[A-F0-9]{32}$", r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
)


def _strict_clean_runner(self, pattern):
    result = analyze_regex(pattern, policy=RegexPolicy().strict())
    self.assertEqual(result.findings, (), pattern)
    self.assertTrue(result.safe, pattern)


class StrictCleanMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(StrictCleanMatrixTests, _STRICT_CLEAN_PATTERNS, "strict_clean", _strict_clean_runner)


class AnalyzerCoreTests(unittest.TestCase):
    def test_result_is_frozen(self):
        result = analyze_regex("abc")
        with self.assertRaises(FrozenInstanceError):
            result.safe = False

    def test_finding_is_frozen(self):
        finding = Finding("REDOS_SYNTAX_ERROR", "critical", "message", (0, 1), "fix")
        with self.assertRaises(FrozenInstanceError):
            finding.message = "changed"

    def test_finding_rejects_bad_severity(self):
        with self.assertRaises(ValueError):
            Finding("X", "notice", "message", (0, 1), "fix")

    def test_finding_rejects_bad_span(self):
        with self.assertRaises(ValueError):
            Finding("X", "low", "message", (2, 1), "fix")

    def test_safe_result_shape(self):
        result = analyze_regex(r"^[a-z]+$")
        self.assertTrue(result.safe)
        self.assertEqual(result.risk_level, "safe")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.findings, ())
        self.assertIsNone(result.attack_hint)
        self.assertEqual(result.stats["pattern_length"], 8)

    def test_unsafe_result_shape(self):
        result = analyze_regex(r"(a+)+")
        self.assertFalse(result.safe)
        self.assertEqual(result.risk_level, "critical")
        self.assertEqual(result.score, 100)
        self.assertEqual(len(result.findings), 1)
        self.assertIsNotNone(result.attack_hint)
        self.assertEqual(result.stats["quantifier_count"], 2)

    def test_stats_counts(self):
        result = analyze_regex(r"(a|b)c(d)e")
        self.assertEqual(result.stats["group_count"], 2)
        self.assertEqual(result.stats["alternation_count"], 1)
        self.assertGreaterEqual(result.stats["node_count"], 6)
        self.assertGreaterEqual(result.stats["depth"], 2)

    def test_ignorecase_flag_changes_overlap(self):
        plain = analyze_regex(r"(a|A)+")
        folded = analyze_regex(r"(a|A)+", flags=re.IGNORECASE)
        self.assertTrue(plain.safe)
        self.assertIn("REDOS_OVERLAPPING_ALTERNATION", {finding.code for finding in folded.findings})

    def test_dotall_changes_overlap(self):
        plain = analyze_regex("(.|\\n)+")
        dotall = analyze_regex("(.|\\n)+", flags=re.DOTALL)
        self.assertFalse(plain.findings)
        self.assertIn("REDOS_OVERLAPPING_ALTERNATION", {finding.code for finding in dotall.findings})

    def test_ascii_shorthand_overlap_still_detected(self):
        result = analyze_regex(r"(\w|\d)+", flags=re.ASCII)
        self.assertIn("REDOS_OVERLAPPING_ALTERNATION", {finding.code for finding in result.findings})

    def test_scoped_ignorecase_changes_overlap(self):
        result = analyze_regex(r"(?i:(a|A)+)")
        self.assertIn("REDOS_OVERLAPPING_ALTERNATION", {finding.code for finding in result.findings})

    def test_plain_inline_ignorecase_is_global(self):
        result = analyze_regex(r"((?i)a|A)+")
        self.assertIn("REDOS_OVERLAPPING_ALTERNATION", {finding.code for finding in result.findings})

    def test_low_finding_is_not_blocking_by_default(self):
        result = analyze_regex(".*\\n.*")
        self.assertTrue(result.safe)
        self.assertEqual(result.risk_level, "low")
        self.assertTrue(result.findings)

    def test_low_finding_blocks_in_strict_mode(self):
        result = analyze_regex(".*\\n.*", policy=RegexPolicy().strict())
        self.assertFalse(result.safe)
        self.assertEqual(result.risk_level, "low")

    def test_syntax_error_is_fail_closed(self):
        result = analyze_regex("(")
        self.assertFalse(result.safe)
        self.assertEqual(result.risk_level, "critical")
        self.assertEqual(result.findings[0].code, "REDOS_SYNTAX_ERROR")

    def test_pattern_length_error_is_fail_closed(self):
        result = analyze_regex("abcde", policy=RegexPolicy(max_pattern_length=4))
        self.assertFalse(result.safe)
        self.assertEqual(result.findings[0].code, "REDOS_PATTERN_TOO_LONG")

    def test_depth_error_is_fail_closed(self):
        result = analyze_regex("(((a)))", policy=RegexPolicy(max_depth=2))
        self.assertFalse(result.safe)
        self.assertEqual(result.findings[0].code, "REDOS_EXCESSIVE_DEPTH")

    def test_invalid_pattern_type(self):
        with self.assertRaises(TypeError):
            analyze_regex(b"abc")

    def test_invalid_flags_type(self):
        with self.assertRaises(TypeError):
            analyze_regex("abc", flags="i")

    def test_analysis_result_type(self):
        self.assertIsInstance(analyze_regex("a"), AnalysisResult)

    def test_many_alternation_branches_are_bounded(self):
        pattern = "(" + "|".join(chr(0x1000 + index) for index in range(300)) + ")+"
        start = time.perf_counter()
        result = analyze_regex(pattern)
        self.assertTrue(result.safe)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_many_literals_are_bounded(self):
        start = time.perf_counter()
        result = analyze_regex("[a-z]" * 500)
        self.assertTrue(result.safe)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_pathological_nested_input_fails_fast(self):
        start = time.perf_counter()
        result = analyze_regex("(a|" * 200)
        self.assertFalse(result.safe)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_atomic_group_suppresses_inner_backtracking_split(self):
        result = analyze_regex(r"(?>a+)+")
        self.assertNotIn("REDOS_STAR_HEIGHT_NESTED_QUANTIFIER", {finding.code for finding in result.findings})

    def test_possessive_inner_repeat_suppresses_split(self):
        result = analyze_regex(r"(a++)+")
        self.assertNotIn("REDOS_STAR_HEIGHT_NESTED_QUANTIFIER", {finding.code for finding in result.findings})

    def test_disjoint_suffix_separator_is_safe(self):
        self.assertEqual(analyze_regex(r"(?:[a-z]+,)+").findings, ())

    def test_disjoint_prefix_separator_is_safe(self):
        self.assertEqual(analyze_regex(r"(?:,[a-z]+)+").findings, ())

    def test_optional_separator_does_not_protect(self):
        result = analyze_regex(r"(?:a+;?)+")
        self.assertIn("REDOS_STAR_HEIGHT_NESTED_QUANTIFIER", {finding.code for finding in result.findings})

    def test_classic_email_shape_detected(self):
        result = analyze_regex(r"^([\w.]+)@([\w.]+)\.([a-z]+)$")
        self.assertFalse(result.safe)

    def test_classic_data_url_wildcard_detected(self):
        result = analyze_regex(r".*data:.*base64.*")
        self.assertIn("REDOS_OVERLAPPING_ADJACENT_QUANTIFIERS", {finding.code for finding in result.findings})

    def test_nested_bounded_expansion_detected(self):
        result = analyze_regex(r"(a{101}){101}")
        self.assertIn("REDOS_EXCESSIVE_REPETITION_BOUND", {finding.code for finding in result.findings})

    def test_excessive_hard_quantifier_fail_closed(self):
        result = analyze_regex(r"a{0,1000000}")
        self.assertFalse(result.safe)
        self.assertEqual(result.findings[0].code, "REDOS_EXCESSIVE_REPETITION_BOUND")

    def test_safe_small_bounded_adjacent_repeats(self):
        self.assertEqual(analyze_regex(r"a{1,4}a{1,4}").findings, ())

    def test_multiple_findings_are_sorted_by_span(self):
        result = analyze_regex(r"(a+)\1.*.*")
        spans = [finding.span for finding in result.findings]
        self.assertEqual(spans, sorted(spans))

class AnalyzerAdversarialRegressionTests(unittest.TestCase):
    def test_scoped_unicode_overrides_outer_ascii_for_overlap(self):
        result = analyze_regex(r"(?u:(\w|[α-ω])+)", flags=re.ASCII)
        self.assertIn("REDOS_OVERLAPPING_ALTERNATION", {finding.code for finding in result.findings})
        self.assertFalse(result.safe)

    def test_ascii_ignorecase_does_not_use_unicode_casefolding(self):
        result = analyze_regex(r"(k|\u212a)+", flags=re.IGNORECASE | re.ASCII)
        self.assertEqual(result.findings, ())
        self.assertTrue(result.safe)

    def test_unicode_ignorecase_uses_unicode_casefolding(self):
        result = analyze_regex(r"(k|\u212a)+", flags=re.IGNORECASE)
        self.assertIn("REDOS_OVERLAPPING_ALTERNATION", {finding.code for finding in result.findings})
        self.assertFalse(result.safe)
