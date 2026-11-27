from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from pyregexshield import RegexPolicy
from pyregexshield.scanner import scan_directory, scan_python_file, scan_python_source

from helpers import add_matrix_tests


_SOURCE_CASES = (
    ("import re\nre.compile(r'(a+)+')\n", 1, "compile"),
    ("import re\nre.search(r'(a|a)+', data)\n", 1, "search"),
    ("import re\nre.match(r'.*.*', data)\n", 2, "match"),
    ("import re\nre.fullmatch(r'(a*)*', data)\n", 1, "fullmatch"),
    ("import re\nre.findall(r'\\s+\\s+', data)\n", 1, "findall"),
    ("import re\nre.finditer(r'[a-z]+[a-z]+', data)\n", 1, "finditer"),
    ("import re\nre.sub(r'(a+)+', 'x', data)\n", 1, "sub"),
    ("import re\nre.subn(r'(a+)+', 'x', data)\n", 1, "subn"),
    ("import re\nre.split(r'(a+)+', data)\n", 1, "split"),
    ("import re as rx\nrx.compile(r'(a+)+')\n", 1, "compile"),
    ("from re import compile\ncompile(r'(a+)+')\n", 1, "compile"),
    ("from re import search as find\nfind(r'(a+)+', data)\n", 1, "search"),
    ("from re import *\ncompile(r'(a+)+')\n", 1, "compile"),
    ("import re\nre.compile(pattern=r'(a+)+')\n", 1, "compile"),
    ("import re\nre.compile(r'^[a-z]+$')\n", 0, "compile"),
    ("import re\nvalue = '(a+)+'\nre.compile(value)\n", 0, "compile"),
    ("import re\nre.compile(f'(a+)+{x}')\n", 0, "compile"),
)


def _source_runner(self, source, expected_count, function):
    report = scan_python_source(source, filename="sample.py")
    self.assertEqual(len(report.findings), expected_count, source)
    if expected_count:
        self.assertEqual(report.findings[0].function, function)
        self.assertEqual(report.findings[0].filename, "sample.py")


class SourceScannerMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(SourceScannerMatrixTests, _SOURCE_CASES, "source", _source_runner)


class ScannerCoreTests(unittest.TestCase):
    def test_bitwise_flags_are_evaluated(self):
        report = scan_python_source("import re\nre.compile(r'(a|A)+', re.I | re.M)\n")
        self.assertEqual(len(report.findings), 1)

    def test_long_flag_names_are_evaluated(self):
        report = scan_python_source("import re\nre.compile(r'(a|A)+', flags=re.IGNORECASE | re.MULTILINE)\n")
        self.assertEqual(len(report.findings), 1)

    def test_function_positional_flags_match(self):
        report = scan_python_source("import re\nre.match(r'(a|A)+', data, re.IGNORECASE)\n")
        self.assertEqual(len(report.findings), 1)

    def test_sub_positional_flags(self):
        report = scan_python_source("import re\nre.sub(r'(a|A)+', 'x', data, 0, re.IGNORECASE)\n")
        self.assertEqual(len(report.findings), 1)

    def test_split_positional_flags(self):
        report = scan_python_source("import re\nre.split(r'(a|A)+', data, 0, re.IGNORECASE)\n")
        self.assertEqual(len(report.findings), 1)

    def test_unknown_flag_expression_is_skipped_safely(self):
        report = scan_python_source("import re\nre.compile(r'(a|A)+', FLAGS)\n")
        self.assertEqual(len(report.findings), 0)

    def test_scan_syntax_error_diagnostic(self):
        report = scan_python_source("def broken(:\n", filename="broken.py")
        self.assertEqual(len(report.diagnostics), 1)
        self.assertEqual(report.diagnostics[0].code, "SCAN_PYTHON_SYNTAX_ERROR")
        self.assertEqual(report.files_scanned, 0)

    def test_report_to_dict(self):
        report = scan_python_source("import re\nre.compile(r'(a+)+')\n", filename="x.py")
        data = report.to_dict()
        self.assertEqual(data["summary"]["finding_count"], 1)
        self.assertEqual(data["findings"][0]["code"], "REDOS_STAR_HEIGHT_NESTED_QUANTIFIER")

    def test_report_to_json(self):
        report = scan_python_source("import re\nre.compile(r'(a+)+')\n")
        data = json.loads(report.to_json())
        self.assertEqual(data["summary"]["files_scanned"], 1)

    def test_report_to_text(self):
        report = scan_python_source("import re\nre.compile(r'(a+)+')\n", filename="x.py")
        self.assertIn("x.py:2:1", report.to_text())
        self.assertIn("REDOS_STAR_HEIGHT_NESTED_QUANTIFIER", report.to_text())

    def test_clean_text(self):
        report = scan_python_source("import re\nre.compile(r'^[a-z]+$')\n")
        self.assertEqual(report.to_text(), "No regex security findings.")

    def test_sarif_shape(self):
        report = scan_python_source("import re\nre.compile(r'(a+)+')\n", filename="x.py")
        sarif = report.to_sarif()
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", sarif["$schema"])
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "pyregexshield")
        self.assertEqual(run["tool"]["driver"]["version"], "1.0.0")
        self.assertEqual(len(run["results"]), 1)
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "REDOS_STAR_HEIGHT_NESTED_QUANTIFIER")
        self.assertEqual(result["level"], "error")
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 2)
        self.assertEqual(region["startColumn"], 1)
        self.assertEqual(run["artifacts"][0]["location"]["uri"], "x.py")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "REDOS_STAR_HEIGHT_NESTED_QUANTIFIER")

    def test_sarif_json_is_parseable(self):
        report = scan_python_source("import re\nre.compile(r'(a+)+')\n")
        data = json.loads(report.sarif_json())
        self.assertEqual(data["version"], "2.1.0")

    def test_sarif_empty_results(self):
        report = scan_python_source("import re\nre.compile(r'^[a-z]+$')\n")
        sarif = report.to_sarif()
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_low_severity_sarif_level(self):
        report = scan_python_source("import re\nre.compile('.*\\\\n.*')\n")
        self.assertEqual(report.to_sarif()["runs"][0]["results"][0]["level"], "note")

    def test_blocking_findings_respects_default_policy(self):
        report = scan_python_source("import re\nre.compile('.*\\\\n.*')\n")
        self.assertFalse(report.blocking_findings())
        self.assertFalse(report.has_blocking_findings)

    def test_strict_scan_blocks_low(self):
        report = scan_python_source("import re\nre.compile('.*\\\\n.*')\n", strict=True)
        self.assertTrue(report.blocking_findings(RegexPolicy().strict()))

    def test_multiple_calls_are_sorted(self):
        report = scan_python_source("import re\nre.compile(r'(a+)+')\nre.compile(r'(a|a)+')\n")
        self.assertEqual(len(report.findings), 2)
        self.assertLessEqual(report.findings[0].line, report.findings[1].line)


class ScannerFilesystemTests(unittest.TestCase):
    def test_scan_python_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.py"
            path.write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            report = scan_python_file(path)
            self.assertEqual(len(report.findings), 1)
            self.assertEqual(report.files_scanned, 1)

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "a.py").write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            Path(directory, "b.txt").write_text("re.compile(r'(a+)+')", encoding="utf-8")
            report = scan_directory(directory)
            self.assertEqual(report.files_scanned, 1)
            self.assertEqual(len(report.findings), 1)

    def test_scan_single_file_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.py"
            path.write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            self.assertEqual(len(scan_directory(path).findings), 1)

    def test_missing_path_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                scan_directory(Path(directory) / "missing")

    def test_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.py"
            target.write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            link = Path(directory) / "link.py"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            report = scan_python_file(link)
            self.assertEqual(report.files_scanned, 0)
            self.assertEqual(report.diagnostics[0].code, "SCAN_SYMLINK_SKIPPED")

    def test_directory_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real"
            real.mkdir()
            (real / "a.py").write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            link = Path(directory) / "linked"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            report = scan_directory(directory)
            self.assertEqual(len(report.findings), 1)
            self.assertTrue(any(item.code == "SCAN_SYMLINK_SKIPPED" for item in report.diagnostics))

    def test_binary_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary.py"
            path.write_bytes(b"\x00\x01\x02")
            report = scan_python_file(path)
            self.assertEqual(report.diagnostics[0].code, "SCAN_BINARY_SKIPPED")

    def test_oversized_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.py"
            path.write_text("#" * 100, encoding="utf-8")
            report = scan_python_file(path, policy=RegexPolicy(max_scan_file_bytes=10))
            self.assertEqual(report.diagnostics[0].code, "SCAN_FILE_TOO_LARGE")

    def test_fifo_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pipe.py"
            if not hasattr(os, "mkfifo"):
                self.skipTest("fifo unavailable")
            try:
                os.mkfifo(str(path))
            except OSError:
                self.skipTest("fifo creation unavailable")
            report = scan_python_file(path)
            self.assertEqual(report.diagnostics[0].code, "SCAN_NONREGULAR_SKIPPED")

    def test_max_files_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            for index in range(3):
                Path(directory, "f%d.py" % index).write_text("import re\nre.compile(r'^[a-z]+$')\n", encoding="utf-8")
            report = scan_directory(directory, max_files=2)
            self.assertEqual(report.files_scanned, 2)
            self.assertTrue(any(item.code == "SCAN_MAX_FILES_REACHED" for item in report.diagnostics))

    def test_encoding_cookie_latin1(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "latin.py"
            path.write_bytes("# coding: latin-1\nimport re\nre.compile(r'^[a-z]+$') # caf\xe9\n".encode("latin-1"))
            report = scan_python_file(path)
            self.assertEqual(report.files_scanned, 1)
            self.assertEqual(report.diagnostics, ())

    def test_python_syntax_error_in_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.py"
            path.write_text("def broken(:\n", encoding="utf-8")
            report = scan_python_file(path)
            self.assertEqual(report.diagnostics[0].code, "SCAN_PYTHON_SYNTAX_ERROR")

    def test_nonregular_device_like_file_mode_logic(self):
        self.assertFalse(stat.S_ISREG(stat.S_IFIFO))

    def test_scan_source_type_validation(self):
        with self.assertRaises(TypeError):
            scan_python_source(b"import re\n")

    def test_scan_max_files_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                scan_directory(directory, max_files=0)

class ScannerAdversarialRegressionTests(unittest.TestCase):
    def test_explicit_literal_concatenation_is_analyzed(self):
        report = scan_python_source("import re\nre.compile('(a+' + ')+')\n", filename="x.py")
        self.assertEqual(len(report.findings), 1)

    def test_compile_assignment_alias_is_analyzed(self):
        report = scan_python_source("import re\nrc = re.compile\nrc('(a+)+')\n", filename="x.py")
        self.assertEqual(len(report.findings), 1)

    def test_function_alias_assignment_is_analyzed(self):
        report = scan_python_source("from re import compile as rc\nrc2 = rc\nrc2('(a+)+')\n", filename="x.py")
        self.assertEqual(len(report.findings), 1)

    def test_module_assignment_alias_is_analyzed(self):
        report = scan_python_source("import re\nrx = re\nrx.compile('(a+)+')\n", filename="x.py")
        self.assertEqual(len(report.findings), 1)

    def test_nul_source_returns_diagnostic(self):
        report = scan_python_source("\x00", filename="bad.py")
        self.assertEqual(report.diagnostics[0].code, "SCAN_PYTHON_SYNTAX_ERROR")

    def test_sarif_column_kind_and_relative_percent_encoded_uri(self):
        report = scan_python_source("import re\nre.compile(r'(a+)+')\n", filename="sub dir/x y.py")
        sarif = report.to_sarif()
        run = sarif["runs"][0]
        self.assertEqual(run["columnKind"], "unicodeCodePoints")
        uri = run["artifacts"][0]["location"]["uri"]
        self.assertEqual(uri, "sub%20dir/x%20y.py")
        self.assertNotIn("/" + "Users" + "/", json.dumps(sarif))

    def test_sarif_columns_are_unicode_code_points(self):
        report = scan_python_source('x = "é"; re.compile(r"(a+)+")\n', filename="x.py")
        region = report.to_sarif()["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startColumn"], 10)

    def test_text_output_neutralizes_control_characters(self):
        report = scan_python_source("import re\nre.compile(r'(a+)+')\n", filename="x\x1b[31m.py")
        text = report.to_text()
        self.assertNotIn("\x1b", text)
        self.assertIn("\\x1B", text)

    def test_scan_directory_rejects_symlink_root(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real"
            real.mkdir()
            (real / "x.py").write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            link = Path(directory) / "linked-root"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            report = scan_directory(link)
            self.assertEqual(report.files_scanned, 0)
            self.assertEqual(report.diagnostics[0].code, "SCAN_SYMLINK_SKIPPED")
