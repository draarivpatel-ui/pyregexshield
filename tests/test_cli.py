from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from pyregexshield.cli import main

from helpers import add_matrix_tests


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "pyregexshield"] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=os.environ.copy(),
        check=False,
    )


_CHECK_CASES = (
    (r"^[a-z]+$", 0, "SAFE"),
    (r"^\d{4}-\d{2}-\d{2}$", 0, "SAFE"),
    (r"^(?:foo|bar|baz)$", 0, "SAFE"),
    (r"(a+)+", 1, "UNSAFE"),
    (r"(a*)*", 1, "UNSAFE"),
    (r"(a|a)+", 1, "UNSAFE"),
    (r".*.*", 1, "UNSAFE"),
    (r"(\w+)\1", 1, "UNSAFE"),
    (r"a{0,50000}", 1, "UNSAFE"),
    ("(", 2, "UNSAFE"),
)


def _check_runner(self, pattern, expected_exit, marker):
    completed = run_cli("check", pattern)
    self.assertEqual(completed.returncode, expected_exit, completed.stderr)
    self.assertIn(marker, completed.stdout)


class CliCheckMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(CliCheckMatrixTests, _CHECK_CASES, "check", _check_runner)


class CliCoreTests(unittest.TestCase):
    def test_main_returns_zero_for_safe_pattern(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["check", r"^[a-z]+$"]), 0)

    def test_main_returns_one_for_unsafe_pattern(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["check", r"(a+)+"]), 1)

    def test_main_returns_two_for_parse_error(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["check", "("]), 2)

    def test_json_output_shape(self):
        completed = run_cli("check", r"(a+)+", "--json")
        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["safe"])
        self.assertEqual(payload["risk_level"], "critical")
        self.assertEqual(payload["findings"][0]["code"], "REDOS_STAR_HEIGHT_NESTED_QUANTIFIER")
        self.assertEqual(payload["findings"][0]["span"], [0, 5])
        self.assertIn("stats", payload)
        self.assertIn("attack_hint", payload)

    def test_json_safe_output(self):
        completed = run_cli("check", r"^[a-z]+$", "--json")
        self.assertEqual(completed.returncode, 0)
        self.assertTrue(json.loads(completed.stdout)["safe"])

    def test_ignorecase_option(self):
        completed = run_cli("check", r"(a|A)+", "--ignorecase", "--json")
        self.assertEqual(completed.returncode, 1)

    def test_dotall_option(self):
        completed = run_cli("check", "(.|\\n)+", "--dotall", "--json")
        self.assertEqual(completed.returncode, 1)

    def test_low_finding_nonstrict_exit_zero(self):
        completed = run_cli("check", ".*\\n.*", "--json")
        self.assertEqual(completed.returncode, 0)

    def test_low_finding_strict_exit_one(self):
        completed = run_cli("check", ".*\\n.*", "--strict", "--json")
        self.assertEqual(completed.returncode, 1)

    def test_scan_safe_file_exit_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "ok.py").write_text("import re\nre.compile(r'^[a-z]+$')\n", encoding="utf-8")
            completed = run_cli("scan", directory)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("No regex security findings", completed.stdout)

    def test_scan_dangerous_file_exit_one(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "bad.py").write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            completed = run_cli("scan", directory)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertIn("REDOS_STAR_HEIGHT_NESTED_QUANTIFIER", completed.stdout)

    def test_scan_json(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "bad.py").write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            completed = run_cli("scan", directory, "--format", "json")
            self.assertEqual(completed.returncode, 1)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["summary"]["finding_count"], 1)

    def test_scan_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "bad.py").write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            completed = run_cli("scan", directory, "--format", "sarif")
            self.assertEqual(completed.returncode, 1)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["version"], "2.1.0")
            self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "REDOS_STAR_HEIGHT_NESTED_QUANTIFIER")

    def test_scan_strict_low_exit_one(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "low.py").write_text("import re\nre.compile('.*\\\\n.*')\n", encoding="utf-8")
            completed = run_cli("scan", directory, "--strict")
            self.assertEqual(completed.returncode, 1)

    def test_scan_missing_path_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = run_cli("scan", str(Path(directory) / "missing"))
            self.assertEqual(completed.returncode, 2)
            self.assertIn("pyregexshield scan", completed.stderr)

    def test_scan_invalid_max_files_exit_two(self):
        completed = run_cli("scan", ".", "--max-files", "0")
        self.assertEqual(completed.returncode, 2)

    def test_scan_max_files_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            for index in range(2):
                Path(directory, "f%d.py" % index).write_text("import re\nre.compile(r'^[a-z]+$')\n", encoding="utf-8")
            completed = run_cli("scan", directory, "--max-files", "1", "--format", "json")
            self.assertEqual(completed.returncode, 0)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["summary"]["files_scanned"], 1)

    def test_no_command_usage_error(self):
        completed = run_cli()
        self.assertEqual(completed.returncode, 2)

    def test_unknown_option_usage_error(self):
        completed = run_cli("check", "abc", "--unknown")
        self.assertEqual(completed.returncode, 2)

    def test_multiline_verbose_ascii_options_accepted(self):
        completed = run_cli("check", r"^[a-z]+$", "--multiline", "--verbose", "--ascii")
        self.assertEqual(completed.returncode, 0)

    def test_scan_file_path_directly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bad.py")
            path.write_text("import re\nre.compile(r'(a+)+')\n", encoding="utf-8")
            completed = run_cli("scan", str(path))
            self.assertEqual(completed.returncode, 1)
