"""Static Python source scanner and SARIF emitter."""

from __future__ import annotations

import ast
import io
import json
import os
import stat
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import quote

from ._display import terminal_safe
from .analyzer import analyze_regex
from .policy import DEFAULT_POLICY, SEVERITY_ORDER, RegexPolicy

SCAN_FUNCTIONS = frozenset(("compile", "match", "search", "fullmatch", "findall", "finditer", "sub", "subn", "split"))
_FLAG_NAMES = {
    "ASCII": "A",
    "A": "A",
    "IGNORECASE": "I",
    "I": "I",
    "LOCALE": "L",
    "L": "L",
    "MULTILINE": "M",
    "M": "M",
    "DOTALL": "S",
    "S": "S",
    "VERBOSE": "X",
    "X": "X",
    "UNICODE": "U",
    "U": "U",
    "TEMPLATE": "T",
    "T": "T",
    "DEBUG": "DEBUG",
}
_FLAG_CONSTANTS = {
    "A": 256,
    "I": 2,
    "L": 4,
    "M": 8,
    "S": 16,
    "X": 64,
    "U": 32,
    "T": 1,
    "DEBUG": 128,
}


@dataclass(frozen=True)
class SourceFinding:
    filename: str
    line: int
    column: int
    end_line: int
    end_column: int
    function: str
    pattern: str
    flags: int
    code: str
    severity: str
    message: str
    pattern_span: Tuple[int, int]
    remediation: str

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "function": self.function,
            "pattern": self.pattern,
            "flags": self.flags,
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "pattern_span": list(self.pattern_span),
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class ScanDiagnostic:
    filename: str
    line: int
    column: int
    code: str
    message: str

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "line": self.line,
            "column": self.column,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True)
class ScanReport:
    findings: Tuple[SourceFinding, ...]
    diagnostics: Tuple[ScanDiagnostic, ...]
    files_scanned: int
    files_skipped: int

    @property
    def has_blocking_findings(self) -> bool:
        return bool(self.blocking_findings(DEFAULT_POLICY))

    def blocking_findings(self, policy: Optional[RegexPolicy] = None) -> Tuple[SourceFinding, ...]:
        policy = policy or DEFAULT_POLICY
        minimum = SEVERITY_ORDER[policy.minimum_block_severity]
        return tuple(finding for finding in self.findings if SEVERITY_ORDER[finding.severity] >= minimum)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "finding_count": len(self.findings),
                "diagnostic_count": len(self.diagnostics),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_text(self) -> str:
        lines = []
        for finding in self.findings:
            lines.append(
                "%s:%d:%d: %s %s: %s" % (
                    terminal_safe(finding.filename),
                    finding.line,
                    finding.column + 1,
                    finding.severity,
                    finding.code,
                    terminal_safe(finding.message),
                )
            )
        for diagnostic in self.diagnostics:
            lines.append(
                "%s:%d:%d: diagnostic %s: %s" % (
                    terminal_safe(diagnostic.filename),
                    diagnostic.line,
                    diagnostic.column,
                    diagnostic.code,
                    terminal_safe(diagnostic.message),
                )
            )
        if not lines:
            return "No regex security findings."
        return "\n".join(lines)

    def to_sarif(self) -> dict:
        rules = {}
        results = []
        artifacts = {}
        artifact_list = []
        for finding in self.findings:
            if finding.code not in rules:
                rules[finding.code] = {
                    "id": finding.code,
                    "name": finding.code,
                    "shortDescription": {"text": finding.code.replace("REDOS_", "").replace("_", " ").title()},
                    "fullDescription": {"text": finding.remediation},
                    "defaultConfiguration": {"level": _sarif_level(finding.severity)},
                    "properties": {"severity": finding.severity},
                }
            filename = _sarif_uri(finding.filename)
            if filename not in artifacts:
                artifacts[filename] = len(artifact_list)
                artifact_list.append({"location": {"uri": filename}})
            results.append({
                "ruleId": finding.code,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": filename},
                        "region": {
                            "startLine": finding.line,
                            "startColumn": finding.column + 1,
                            "endLine": finding.end_line,
                            "endColumn": finding.end_column + 1,
                        },
                    }
                }],
                "partialFingerprints": {
                    "pyregexshield/v1": "%s:%d:%d:%s" % (filename, finding.line, finding.column, finding.code),
                },
                "properties": {
                    "severity": finding.severity,
                    "function": finding.function,
                    "patternSpan": list(finding.pattern_span),
                },
            })
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "columnKind": "unicodeCodePoints",
                "tool": {
                    "driver": {
                        "name": "pyregexshield",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/draarivpatel-ui/pyregexshield",
                        "rules": list(rules.values()),
                    }
                },
                "artifacts": artifact_list,
                "results": results,
            }],
        }

    def sarif_json(self) -> str:
        return json.dumps(self.to_sarif(), indent=2, sort_keys=True)


def _sarif_level(severity: str) -> str:
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _relative_artifact_path(filename: str) -> str:
    if filename.startswith("<"):
        return filename
    try:
        absolute = os.path.abspath(filename)
        return os.path.relpath(absolute, os.getcwd())
    except (OSError, ValueError):
        return os.path.basename(filename) or "input.py"


def _sarif_uri(filename: str) -> str:
    filename = _relative_artifact_path(filename)
    if os.sep != "/":
        filename = filename.replace(os.sep, "/")
    return quote(filename, safe="/")


def _codepoint_column(lines, line: int, utf8_column: int) -> int:
    if line < 1 or line > len(lines):
        return utf8_column
    text = lines[line - 1]
    consumed = 0
    for index, char in enumerate(text):
        width = len(char.encode("utf-8"))
        if consumed + width > utf8_column:
            return index
        consumed += width
        if consumed == utf8_column:
            return index + 1
    return len(text)


def _static_string_concat(node):
    """Evaluate a finite tree of string literals joined only by addition."""

    values = {}
    stack = [(node, False)]
    while stack:
        current, expanded = stack.pop()
        if isinstance(current, ast.Constant) and isinstance(current.value, str):
            values[id(current)] = current.value
            continue
        if not isinstance(current, ast.BinOp) or not isinstance(current.op, ast.Add):
            return None
        if not expanded:
            stack.append((current, True))
            stack.append((current.left, False))
            stack.append((current.right, False))
            continue
        left = values.pop(id(current.left), None)
        right = values.pop(id(current.right), None)
        if left is None or right is None:
            return None
        values[id(current)] = left + right
    return values.get(id(node))


def _merge_reports(reports) -> ScanReport:
    findings = []
    diagnostics = []
    scanned = 0
    skipped = 0
    for report in reports:
        findings.extend(report.findings)
        diagnostics.extend(report.diagnostics)
        scanned += report.files_scanned
        skipped += report.files_skipped
    return ScanReport(tuple(findings), tuple(diagnostics), scanned, skipped)


def _collect_re_aliases(tree: ast.AST):
    module_aliases = set(("re",))
    function_aliases = {}
    star_import = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "re":
                    module_aliases.add(alias.asname or "re")
        elif isinstance(node, ast.ImportFrom) and node.module == "re":
            for alias in node.names:
                if alias.name == "*":
                    star_import = True
                elif alias.name in SCAN_FUNCTIONS:
                    function_aliases[alias.asname or alias.name] = alias.name
    if star_import:
        for name in SCAN_FUNCTIONS:
            function_aliases[name] = name

    assignments = []
    for node in ast.walk(tree):
        value = None
        targets = ()
        if isinstance(node, ast.Assign):
            value = node.value
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value = node.value
            targets = (node.target,)
        if value is not None:
            assignments.append((getattr(node, "lineno", 0), getattr(node, "col_offset", 0), value, targets))
    assignments.sort(key=lambda item: (item[0], item[1]))

    for _line, _column, value, targets in assignments:
        resolved_module = False
        resolved_function = None
        if isinstance(value, ast.Name):
            resolved_module = value.id in module_aliases
            resolved_function = function_aliases.get(value.id)
        elif isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            if value.value.id in module_aliases and value.attr in SCAN_FUNCTIONS:
                resolved_function = value.attr
        if not resolved_module and resolved_function is None:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if resolved_module:
                module_aliases.add(target.id)
            else:
                function_aliases[target.id] = resolved_function
    return module_aliases, function_aliases


def _call_target(call: ast.Call, module_aliases, function_aliases):
    function = call.func
    if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
        if function.value.id in module_aliases and function.attr in SCAN_FUNCTIONS:
            return function.attr
    if isinstance(function, ast.Name) and function.id in function_aliases:
        return function_aliases[function.id]
    return None


def _flag_value(node, module_aliases) -> Optional[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return int(node.value)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id in module_aliases and node.attr in _FLAG_NAMES:
            return _FLAG_CONSTANTS[_FLAG_NAMES[node.attr]]
    if isinstance(node, ast.Name) and node.id in _FLAG_NAMES:
        return _FLAG_CONSTANTS[_FLAG_NAMES[node.id]]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _flag_value(node.left, module_aliases)
        right = _flag_value(node.right, module_aliases)
        if left is not None and right is not None:
            return left | right
    return None


def _extract_calls(tree: ast.AST):
    module_aliases, function_aliases = _collect_re_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = _call_target(node, module_aliases, function_aliases)
        if function is None:
            continue
        pattern_node = node.args[0] if node.args else None
        if pattern_node is None:
            for keyword in node.keywords:
                if keyword.arg == "pattern":
                    pattern_node = keyword.value
                    break
        if pattern_node is None:
            continue
        pattern_value = _static_string_concat(pattern_node)
        if pattern_value is None:
            continue

        flags = 0
        flag_positions = {
            "compile": 1,
            "match": 2,
            "search": 2,
            "fullmatch": 2,
            "findall": 2,
            "finditer": 2,
            "split": 3,
            "sub": 4,
            "subn": 4,
        }
        flag_position = flag_positions[function]
        if len(node.args) > flag_position:
            value = _flag_value(node.args[flag_position], module_aliases)
            if value is not None:
                flags = value
        for keyword in node.keywords:
            if keyword.arg == "flags":
                value = _flag_value(keyword.value, module_aliases)
                if value is not None:
                    flags = value
        yield function, pattern_value, flags, node


def scan_python_source(
    source: str,
    filename: str = "<string>",
    *,
    policy: Optional[RegexPolicy] = None,
    strict: bool = False,
) -> ScanReport:
    """Statically scan Python source for regex literals used with re.

    Only literal strings are analyzed. Dynamic expressions are intentionally
    skipped because executing or partially evaluating them would be unsafe.
    """

    if not isinstance(source, str):
        raise TypeError("source must be str")
    policy = policy or DEFAULT_POLICY
    if strict:
        policy = policy.strict()
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as error:
        line = error.lineno or 1
        column = (error.offset or 1) - 1
        diagnostic = ScanDiagnostic(filename, line, column, "SCAN_PYTHON_SYNTAX_ERROR", error.msg)
        return ScanReport((), (diagnostic,), 0, 1)
    except (ValueError, RecursionError) as error:
        diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_PYTHON_SYNTAX_ERROR", str(error))
        return ScanReport((), (diagnostic,), 0, 1)

    source_lines = source.splitlines(True)
    findings = []
    for function, pattern, flags, call in _extract_calls(tree):
        result = analyze_regex(pattern, flags=flags, policy=policy)
        line = getattr(call, "lineno", 1)
        end_line = getattr(call, "end_lineno", line)
        column = _codepoint_column(source_lines, line, getattr(call, "col_offset", 0))
        end_column = _codepoint_column(
            source_lines,
            end_line,
            getattr(call, "end_col_offset", getattr(call, "col_offset", 0) + 1),
        )
        for item in result.findings:
            findings.append(SourceFinding(
                filename,
                line,
                column,
                end_line,
                end_column,
                function,
                pattern,
                flags,
                item.code,
                item.severity,
                item.message,
                item.span,
                item.remediation,
            ))
    findings.sort(key=lambda item: (item.filename, item.line, item.column, item.code))
    return ScanReport(tuple(findings), (), 1, 0)


def scan_python_file(path, *, policy: Optional[RegexPolicy] = None, strict: bool = False) -> ScanReport:
    """Scan one Python source file with file type, size, and binary guards."""

    policy = policy or DEFAULT_POLICY
    if strict:
        policy = policy.strict()
    path = Path(path)
    filename = _relative_artifact_path(str(path))
    try:
        info = path.lstat()
    except OSError as error:
        diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_FILE_ERROR", str(error))
        return ScanReport((), (diagnostic,), 0, 1)

    if stat.S_ISLNK(info.st_mode):
        diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_SYMLINK_SKIPPED", "symlink was not followed")
        return ScanReport((), (diagnostic,), 0, 1)
    if not stat.S_ISREG(info.st_mode):
        diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_NONREGULAR_SKIPPED", "not a regular file")
        return ScanReport((), (diagnostic,), 0, 1)
    if info.st_size > policy.max_scan_file_bytes:
        diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_FILE_TOO_LARGE", "file exceeds max_scan_file_bytes")
        return ScanReport((), (diagnostic,), 0, 1)

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    descriptor = None
    try:
        descriptor = os.open(str(path), flags)
        opened_info = os.fstat(descriptor)
        if not stat.S_ISREG(opened_info.st_mode):
            os.close(descriptor)
            descriptor = None
            diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_NONREGULAR_SKIPPED", "not a regular file")
            return ScanReport((), (diagnostic,), 0, 1)
        if opened_info.st_size > policy.max_scan_file_bytes:
            os.close(descriptor)
            descriptor = None
            diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_FILE_TOO_LARGE", "file exceeds max_scan_file_bytes")
            return ScanReport((), (diagnostic,), 0, 1)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            data = handle.read(policy.max_scan_file_bytes + 1)
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_FILE_ERROR", str(error))
        return ScanReport((), (diagnostic,), 0, 1)

    if len(data) > policy.max_scan_file_bytes:
        diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_FILE_TOO_LARGE", "file exceeds max_scan_file_bytes")
        return ScanReport((), (diagnostic,), 0, 1)
    if b"\x00" in data:
        diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_BINARY_SKIPPED", "binary file was not scanned")
        return ScanReport((), (diagnostic,), 0, 1)
    try:
        encoding, _lines = tokenize.detect_encoding(io.BytesIO(data).readline)
        source = data.decode(encoding)
    except (SyntaxError, UnicodeDecodeError, LookupError) as error:
        diagnostic = ScanDiagnostic(filename, 1, 0, "SCAN_DECODE_ERROR", str(error))
        return ScanReport((), (diagnostic,), 0, 1)

    report = scan_python_source(source, filename=filename, policy=policy, strict=False)
    return report


def scan_directory(
    path,
    *,
    policy: Optional[RegexPolicy] = None,
    strict: bool = False,
    max_files: int = 10000,
) -> ScanReport:
    """Recursively scan .py files without following symlinks or devices."""

    if max_files < 1:
        raise ValueError("max_files must be positive")
    policy = policy or DEFAULT_POLICY
    if strict:
        policy = policy.strict()
    root = Path(path)
    root_display = _relative_artifact_path(str(root))
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        raise FileNotFoundError(str(root))
    except OSError as error:
        diagnostic = ScanDiagnostic(root_display, 1, 0, "SCAN_FILE_ERROR", str(error))
        return ScanReport((), (diagnostic,), 0, 1)
    if stat.S_ISLNK(root_info.st_mode):
        diagnostic = ScanDiagnostic(root_display, 1, 0, "SCAN_SYMLINK_SKIPPED", "symlink was not followed")
        return ScanReport((), (diagnostic,), 0, 1)
    if stat.S_ISREG(root_info.st_mode):
        return scan_python_file(root, policy=policy, strict=False)
    if not stat.S_ISDIR(root_info.st_mode):
        diagnostic = ScanDiagnostic(root_display, 1, 0, "SCAN_NONREGULAR_SKIPPED", "not a directory or regular file")
        return ScanReport((), (diagnostic,), 0, 1)

    reports = []
    diagnostics = []
    scanned_candidates = 0
    stopped = False
    for directory, dirnames, filenames in os.walk(str(root), followlinks=False):
        dirnames.sort()
        filenames.sort()
        kept_dirnames = []
        for dirname in dirnames:
            candidate = Path(directory) / dirname
            try:
                if candidate.is_symlink():
                    diagnostics.append(ScanDiagnostic(str(candidate), 1, 0, "SCAN_SYMLINK_SKIPPED", "directory symlink was not followed"))
                else:
                    kept_dirnames.append(dirname)
            except OSError:
                diagnostics.append(ScanDiagnostic(str(candidate), 1, 0, "SCAN_FILE_ERROR", "could not inspect directory"))
        dirnames[:] = kept_dirnames

        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            if scanned_candidates >= max_files:
                stopped = True
                break
            scanned_candidates += 1
            reports.append(scan_python_file(Path(directory) / filename, policy=policy, strict=False))
        if stopped:
            diagnostics.append(ScanDiagnostic(str(root), 1, 0, "SCAN_MAX_FILES_REACHED", "file scan cap was reached"))
            break

    merged = _merge_reports(reports)
    if diagnostics:
        merged = ScanReport(
            merged.findings,
            tuple(diagnostics) + merged.diagnostics,
            merged.files_scanned,
            merged.files_skipped,
        )
    return merged
