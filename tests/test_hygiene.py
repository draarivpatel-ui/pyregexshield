from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

from pyregexshield import __version__
from pyregexshield.cli import main

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".toml", ".yml", ".txt", ".in", ".typed"}
TEXT_NAMES = {"LICENSE", "MANIFEST.in", ".gitignore"}


def tracked_text_files():
    result = []
    for path in ROOT.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            result.append(path)
    return sorted(result)


class RepositoryHygieneTests(unittest.TestCase):
    def test_expected_top_level_files_exist(self):
        for name in ("README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "MANIFEST.in", "pyproject.toml", ".gitignore"):
            self.assertTrue((ROOT / name).is_file(), name)

    def test_pytyped_exists(self):
        self.assertTrue((ROOT / "src" / "pyregexshield" / "py.typed").is_file())

    def test_version_is_one_point_zero(self):
        self.assertEqual(__version__, "1.0.0")

    def test_pyproject_metadata(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "pyregexshield"', text)
        self.assertIn('version = "1.0.0"', text)
        self.assertIn('requires-python = ">=3.9"', text)
        self.assertIn('license = "MIT"', text)
        self.assertIn('dependencies = []', text)
        self.assertIn('pyregexshield = "pyregexshield.cli:main"', text)
        self.assertIn('draarivpatel-ui/pyregexshield', text)

    def test_no_runtime_dependency_names(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^dependencies = \[\]$")

    def test_no_private_regex_parser_imports(self):
        for path in (ROOT / "src" / "pyregexshield").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(?m)^\s*(import|from)\s+sre_parse\b", path.name)
            self.assertNotRegex(text, r"(?m)^\s*(import|from)\s+re\._parser\b", path.name)

    def test_publish_workflow_uses_oidc(self):
        text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("id-token: write", text)
        self.assertIn("environment:", text)
        self.assertIn("name: pypi", text)
        self.assertIn("pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086 # v1.14.3", text)
        self.assertNotIn("PYPI_TOKEN", text)
        self.assertNotIn("password:", text)

    def test_ci_matrix_contains_all_versions(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"%s"' % version, text)
        self.assertIn("ubuntu-24.04", text)
        self.assertIn("python -m unittest discover -s tests", text)
        self.assertIn("python -m build", text)

    def test_good_first_issues_has_ten_specs(self):
        text = (ROOT / "docs" / "GOOD_FIRST_ISSUES.md").read_text(encoding="utf-8")
        count = len(re.findall(r"(?m)^## \d+\. ", text))
        self.assertEqual(count, 10)

    def test_no_pycache_or_pyc_in_checkout(self):
        completed = subprocess.run(
            ["git", "ls-files"],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        tracked = completed.stdout.splitlines()
        offenders = [
            path for path in tracked
            if path.endswith(".pyc") or "__pycache__/" in path or path == "__pycache__"
        ]
        self.assertEqual(offenders, [])

    def test_source_files_use_future_annotations(self):
        for path in (ROOT / "src" / "pyregexshield").glob("*.py"):
            if path.name == "py.typed":
                continue
            text = path.read_text(encoding="utf-8")
            self.assertIn("from __future__ import annotations", text, path.name)

    def test_no_match_case_syntax(self):
        for path in (ROOT / "src" / "pyregexshield").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(?m)^\s*match\s+\w")
            self.assertNotRegex(text, r"(?m)^\s*case\s+")

    def test_no_tomllib_import(self):
        for path in ROOT.rglob("*.py"):
            if ".git" in path.parts:
                continue
            self.assertNotRegex(path.read_text(encoding="utf-8"), r"(?m)^\s*import\s+tom" + "llib\b")

    def test_cli_entry_point_importable(self):
        self.assertTrue(callable(main))

    def test_docs_do_not_claim_pypi_published(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("PyPI release status: pending", text)

    def test_security_doc_private_reporting(self):
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("security/advisories/new", text)
        self.assertNotIn("@gmail.com", text)


def _hygiene_file_cases():
    return tuple((path,) for path in tracked_text_files())


def _hygiene_file_runner(self, path):
    data = path.read_bytes()
    rel = path.relative_to(ROOT).as_posix()
    self.assertNotIn(b"\r\n", data, rel)
    self.assertNotIn(chr(0x2014).encode("utf-8"), data, rel)
    self.assertNotIn(chr(0x2013).encode("utf-8"), data, rel)
    self.assertNotIn(("/" + "Users" + "/").encode("utf-8"), data, rel)
    self.assertNotIn(("someone" + "@" + "gmail.com").encode("utf-8"), data, rel)
    self.assertNotIn(("handle-redacted286" + "@" + "gmail.com").encode("utf-8"), data, rel)


class TextFileHygieneMatrixTests(unittest.TestCase):
    pass


for index, case in enumerate(_hygiene_file_cases()):
    def make_test(bound_path):
        def test_method(self):
            _hygiene_file_runner(self, bound_path)
        return test_method
    setattr(TextFileHygieneMatrixTests, "test_text_file_%03d" % index, make_test(case[0]))
