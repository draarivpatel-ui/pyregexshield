from __future__ import annotations

import random
import re
import unittest

from pyregexshield.charset import CharSet, UNICODE_MAX, ascii_space_set, dot_charset, shorthand_charset

from helpers import add_matrix_tests


def _rangeset(*ranges):
    return CharSet(tuple(ranges))


class CharSetCoreTests(unittest.TestCase):
    def test_empty_and_full(self):
        self.assertTrue(CharSet.empty().is_empty())
        self.assertTrue(CharSet.full().is_full())
        self.assertFalse(CharSet.full().is_empty())

    def test_from_char_rejects_multicharacter_input(self):
        with self.assertRaises(ValueError):
            CharSet.from_char("ab")

    def test_from_range_reorders_nothing_and_normalizes_empty(self):
        self.assertTrue(CharSet.from_range("z", "a").is_empty())
        self.assertEqual(CharSet.from_range("a", "z").ranges, ((97, 122),))

    def test_constructor_merges_adjacent_ranges(self):
        value = _rangeset((10, 20), (21, 30), (0, 5), (40, 45))
        self.assertEqual(value.ranges, ((0, 5), (10, 30), (40, 45)))

    def test_constructor_clips_to_unicode_space(self):
        value = CharSet(((-10, 1), (UNICODE_MAX, UNICODE_MAX + 100)))
        self.assertEqual(value.ranges, ((0, 1), (UNICODE_MAX, UNICODE_MAX)))

    def test_contains_binary_search(self):
        value = _rangeset((10, 20), (30, 40))
        self.assertFalse(value.contains(chr(9)))
        self.assertTrue(value.contains(chr(10)))
        self.assertTrue(value.contains(chr(20)))
        self.assertFalse(value.contains(chr(21)))
        self.assertTrue(value.contains(chr(30)))
        self.assertTrue(value.contains(chr(40)))
        self.assertFalse(value.contains(chr(41)))

    def test_size_and_cap(self):
        value = _rangeset((0, 9), (20, 29))
        self.assertEqual(value.size(), 20)
        self.assertGreater(value.size(cap=5), 5)

    def test_complement_full_is_empty(self):
        self.assertTrue(CharSet.full().complement().is_empty())

    def test_complement_empty_is_full(self):
        self.assertTrue(CharSet.empty().complement().is_full())

    def test_subtract(self):
        left = _rangeset((0, 100))
        right = _rangeset((20, 30), (50, 60))
        self.assertEqual(left.subtract(right).ranges, ((0, 19), (31, 49), (61, 100)))

    def test_immutability(self):
        value = CharSet.from_char("a")
        with self.assertRaises(AttributeError):
            value.ranges = ()

    def test_sample_chars_deterministic(self):
        value = _rangeset((65, 67), (97, 99))
        self.assertEqual(value.sample_chars(4), ("A", "B", "C", "a"))

    def test_describe_empty_full_and_ranges(self):
        self.assertEqual(CharSet.empty().describe(), "empty")
        self.assertEqual(CharSet.full().describe(), "any Unicode code point")
        self.assertIn("U+0041", CharSet.from_char("A").describe())

    def test_dot_excludes_newline_by_default(self):
        value = dot_charset(0)
        self.assertFalse(value.contains("\n"))
        self.assertTrue(value.contains("a"))

    def test_dotall_includes_newline(self):
        self.assertTrue(dot_charset(re.DOTALL).contains("\n"))

    def test_ascii_space_definition(self):
        self.assertTrue(ascii_space_set().contains("\t"))
        self.assertFalse(ascii_space_set().contains("\x1c"))

    def test_shorthand_rejects_unknown_kind(self):
        with self.assertRaises(ValueError):
            shorthand_charset("x")

    def test_charset_equality(self):
        self.assertEqual(_rangeset((0, 1), (2, 3)), _rangeset((0, 3)))
        self.assertNotEqual(_rangeset((0, 2)), _rangeset((0, 3)))


def _make_algebra_cases(count=90):
    endpoints = [0, 1, 2, 8, 9, 10, 31, 32, 33, 64, 65, 66, 89, 90, 91, 96, 97, 98, 121, 122, 123, 127, 128, 160, 255]
    cases = []
    for index in range(count):
        rng = random.Random(7300 + index)
        sets = []
        for _which in range(2):
            ranges = []
            for _item in range(rng.randint(1, 5)):
                a = rng.choice(endpoints)
                b = rng.choice(endpoints)
                if a > b:
                    a, b = b, a
                ranges.append((a, b))
            sets.append(CharSet(tuple(ranges)))
        cases.append((index, sets[0], sets[1]))
    return cases


def _sample_values(left, right):
    values = {0, 1, 31, 32, 64, 65, 90, 97, 122, 127, 128, 160, 255, UNICODE_MAX}
    for charset in (left, right):
        for start, end in charset.ranges:
            values.add(start)
            values.add(end)
            if start < UNICODE_MAX:
                values.add(start + 1)
            if end:
                values.add(end - 1)
    return sorted(values)


def _algebra_runner(self, index, left, right):
    del index
    samples = _sample_values(left, right)
    operations = (
        ("union", left.union(right), set()),
        ("intersection", left.intersection(right), set()),
        ("subtract", left.subtract(right), set()),
    )
    expected = {
        "union": set(),
        "intersection": set(),
        "subtract": set(),
    }
    for value in samples:
        char = chr(value)
        a = left.contains(char)
        b = right.contains(char)
        if a or b:
            expected["union"].add(value)
        if a and b:
            expected["intersection"].add(value)
        if a and not b:
            expected["subtract"].add(value)
    for name, actual, _unused in operations:
        observed = {value for value in samples if actual.contains(chr(value))}
        self.assertEqual(observed, expected[name], name)


class CharSetAlgebraMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(CharSetAlgebraMatrixTests, _make_algebra_cases(), "algebra", _algebra_runner)


_UNICODE_PROBE_CHARS = (
    "0", "5", "9", "A", "Z", "_", "a", "z", " ", "\t", "\n", "\x1c", ".", "-",
    "\u0660", "\u0665", "\u2160", "\u00b2", "\u00aa", "\u00a0", "\u2000", "\u2028", "\u3000", "\U0001d7ce",
)


def _unicode_shorthand_cases():
    cases = []
    for kind in "dDwWsS":
        for index, char in enumerate(_UNICODE_PROBE_CHARS):
            cases.append((kind, char, index))
    return cases


def _unicode_shorthand_runner(self, kind, char, index):
    del index
    actual = shorthand_charset(kind, 0).contains(char)
    expected = bool(re.fullmatch("\\" + kind, char))
    self.assertEqual(actual, expected, "\\%s vs U+%04X" % (kind, ord(char)))


def _ascii_shorthand_runner(self, kind, char, index):
    del index
    actual = shorthand_charset(kind, re.ASCII).contains(char)
    expected = bool(re.fullmatch("\\" + kind, char, re.ASCII))
    self.assertEqual(actual, expected, "ASCII \\%s vs U+%04X" % (kind, ord(char)))


class UnicodeShorthandMatrixTests(unittest.TestCase):
    pass


class AsciiShorthandMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(UnicodeShorthandMatrixTests, _unicode_shorthand_cases(), "unicode_shorthand", _unicode_shorthand_runner)
add_matrix_tests(AsciiShorthandMatrixTests, _unicode_shorthand_cases(), "ascii_shorthand", _ascii_shorthand_runner)


_IGNORECASE_PAIRS = (
    ("a", "A"),
    ("A", "a"),
    ("z", "Z"),
    ("k", "K"),
    ("K", "\u212a"),
    ("\u212a", "k"),
    ("Σ", "σ"),
    ("Σ", "ς"),
    ("σ", "Σ"),
    ("İ", "i"),
    ("ſ", "s"),
    ("ß", "s"),
    ("Ⓐ", "ⓐ"),
    ("Ⅰ", "ⅰ"),
    ("Ａ", "ａ"),
    ("\U00010400", "\U00010428"),
)


def _ignorecase_runner(self, left, right):
    closure = CharSet.from_char(left).ignorecase_closure()
    expected = bool(re.fullmatch(re.escape(left), right, re.IGNORECASE))
    self.assertEqual(closure.contains(right), expected, "%r vs %r" % (left, right))


class IgnoreCaseMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(IgnoreCaseMatrixTests, _IGNORECASE_PAIRS, "ignorecase", _ignorecase_runner)
