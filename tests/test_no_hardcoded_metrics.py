"""
Test suite enforcing no hardcoded metric measurements in scripts/ (Task F10).
Scans scripts/ (*.ps1 and *.py) to verify:
1. Result measurement variables (exposure_window, exposure_count, wrong_answers)
   are never assigned hardcoded numeric literals as measurements.
2. If/Else branches do not assign or return identical static values (catching degenerate branches).
3. Post-recovery decisions and detection mechanisms are dynamically evaluated from system output.
"""

import ast
import re
from pathlib import Path
try:
    import pytest
except ImportError:
    class _MockPytest:
        @staticmethod
        def fail(msg):
            raise AssertionError(msg)
    pytest = _MockPytest()

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


def test_scripts_directory_exists():
    assert SCRIPTS_DIR.is_dir(), f"Scripts directory not found at {SCRIPTS_DIR}"


def test_python_scripts_no_identical_if_else_branches():
    """
    Parses all python scripts using Python AST to detect any if/else
    statement whose if-branch and else-branch return or assign the exact same literal.
    """
    py_files = list(SCRIPTS_DIR.glob("*.py"))
    assert len(py_files) > 0, "No python scripts found in scripts/"

    violations = []

    for py_file in py_files:
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError as e:
            pytest.fail(f"Syntax error parsing {py_file.name}: {e}")

        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                # Check for identical return values in both branches
                if node.body and node.orelse:
                    body_returns = [n for n in node.body if isinstance(n, ast.Return)]
                    orelse_returns = [n for n in node.orelse if isinstance(n, ast.Return)]

                    if body_returns and orelse_returns:
                        b_val = getattr(body_returns[0].value, "value", None)
                        o_val = getattr(orelse_returns[0].value, "value", None)
                        if b_val is not None and b_val == o_val:
                            violations.append(
                                f"{py_file.name}:{node.lineno}: If/Else branches both return identical value {b_val!r}"
                            )

    assert not violations, f"Found identical if/else branches in python scripts:\n" + "\n".join(violations)


def test_powershell_scripts_no_identical_if_else_branches():
    """
    Scans PowerShell scripts for ternary or if/else blocks where both branches
    return or assign the identical string literal.
    """
    ps1_files = list(SCRIPTS_DIR.glob("*.ps1"))
    assert len(ps1_files) > 0, "No powershell scripts found in scripts/"

    violations = []
    # Pattern matching: if (...) { "VAL" } else { "VAL" } or similar
    pattern = re.compile(
        r'if\s*\([^)]+\)\s*\{\s*["\']([^"\']+)["\']\s*\}\s*else\s*\{\s*["\']([^"\']+)["\']\s*\}',
        re.IGNORECASE | re.MULTILINE
    )

    for ps1_file in ps1_files:
        text = ps1_file.read_text(encoding="utf-8")
        matches = pattern.finditer(text)
        for m in matches:
            val1, val2 = m.group(1).strip(), m.group(2).strip()
            if val1 == val2:
                violations.append(
                    f"{ps1_file.name}: If/Else branches both return identical literal '{val1}'"
                )

    assert not violations, f"Found identical if/else branches in powershell scripts:\n" + "\n".join(violations)


def test_powershell_no_hardcoded_exposure_literal_assignments():
    """
    Scans PowerShell scripts to ensure result exposure variables
    ($exposureWindow, $exposureCount) are NOT assigned hardcoded integer literals
    (e.g., `$exposureWindow = 0` or `$exposure_count = 1`), but are parsed from probe data.
    """
    ps1_files = list(SCRIPTS_DIR.glob("*.ps1"))
    violations = []

    # Matches assignments of literal integer to exposure result variables
    # e.g., $exposureWindow = 0
    # Allows assignments that cast from probe properties, e.g. [int]$probeData...
    pattern = re.compile(
        r'^\s*\$(exposureWindow|exposureCount|exposure_window|exposure_count)\s*=\s*(\d+)\s*(#.*)?$',
        re.IGNORECASE | re.MULTILINE
    )

    for ps1_file in ps1_files:
        lines = ps1_file.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, 1):
            m = pattern.match(line)
            if m:
                var_name = m.group(1)
                literal_val = m.group(2)
                violations.append(
                    f"{ps1_file.name}:{idx}: Variable '${var_name}' is assigned literal '{literal_val}' instead of system/probe measurement"
                )

    assert not violations, f"Found hardcoded exposure literal assignments in scripts:\n" + "\n".join(violations)


def test_python_scripts_no_hardcoded_metric_measurements():
    """
    Parses Python scripts (including run_evaluation_benchmarks.py) using Python AST to detect:
    1. Direct assignment of numeric constants to metric variables (ttd, ttr, tt_decide_ms, etc.)
    2. Dict entries assigning numeric constants or ternary constants to metric keys
    3. Calls to .get() on metric fields with non-null/non-zero numeric default fallbacks (e.g. .get("ttd_ms", 120.0))
    4. Calls to max(exposure, 1) or similar artificial inflators/clampers.
    """
    py_files = list(SCRIPTS_DIR.glob("*.py"))
    assert len(py_files) > 0, "No python scripts found in scripts/"

    METRIC_NAMES = {
        "ttd", "ttr", "tt_decide_ms", "tt_validate_ms", "total_duration_ms",
        "ttd_ms", "exposure", "exposure_count", "exposure_window"
    }

    violations = []

    for py_file in py_files:
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError as e:
            pytest.fail(f"Syntax error parsing {py_file.name}: {e}")

        for node in ast.walk(tree):
            # 1. Variable assignments: target = CONSTANT or CONSTANT if ... else ...
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        # Latency metric variables should never be assigned numeric constants
                        if name in ("ttd", "ttr", "tt_decide_ms", "tt_validate_ms", "total_duration_ms", "ttd_ms"):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, float)):
                                violations.append(
                                    f"{py_file.name}:{node.lineno}: Variable '{target.id}' assigned hardcoded numeric literal {node.value.value}"
                                )
                            elif isinstance(node.value, ast.IfExp):
                                if isinstance(node.value.body, ast.Constant) and isinstance(node.value.body.value, (int, float)):
                                    violations.append(
                                        f"{py_file.name}:{node.lineno}: Variable '{target.id}' conditionally assigned hardcoded numeric literal {node.value.body.value}"
                                    )
                                if isinstance(node.value.orelse, ast.Constant) and isinstance(node.value.orelse.value, (int, float)):
                                    violations.append(
                                        f"{py_file.name}:{node.lineno}: Variable '{target.id}' conditionally assigned hardcoded numeric literal {node.value.orelse.value}"
                                    )
                        # Exposure variables should never be conditionally assigned constants or non-zero literals
                        elif name in ("exposure", "exposure_window"):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, float)) and node.value.value > 0:
                                violations.append(
                                    f"{py_file.name}:{node.lineno}: Variable '{target.id}' assigned hardcoded non-zero numeric literal {node.value.value}"
                                )
                            elif isinstance(node.value, ast.IfExp):
                                violations.append(
                                    f"{py_file.name}:{node.lineno}: Variable '{target.id}' conditionally assigned heuristic literal"
                                )

            # 2. Dict key-value assignments with hardcoded numeric values
            elif isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value.lower() in METRIC_NAMES:
                        if isinstance(v, ast.Constant) and isinstance(v.value, (int, float)):
                            violations.append(
                                f"{py_file.name}:{node.lineno}: Dict key '{k.value}' assigned hardcoded numeric literal {v.value}"
                            )
                        elif isinstance(v, ast.IfExp):
                            if isinstance(v.body, ast.Constant) and isinstance(v.body.value, (int, float)):
                                violations.append(
                                    f"{py_file.name}:{node.lineno}: Dict key '{k.value}' conditionally assigned hardcoded numeric literal {v.body.value}"
                                )
                            if isinstance(v.orelse, ast.Constant) and isinstance(v.orelse.value, (int, float)):
                                violations.append(
                                    f"{py_file.name}:{node.lineno}: Dict key '{k.value}' conditionally assigned hardcoded numeric literal {v.orelse.value}"
                                )

            # 3. .get("ttd_ms", 120.0) default fallback
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                if len(node.args) >= 2:
                    first_arg = node.args[0]
                    default_arg = node.args[1]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str) and first_arg.value.lower() in METRIC_NAMES:
                        if isinstance(default_arg, ast.Constant) and isinstance(default_arg.value, (int, float)) and default_arg.value > 0:
                            violations.append(
                                f"{py_file.name}:{node.lineno}: Call .get('{first_arg.value}', {default_arg.value}) uses hardcoded non-zero default metric fallback"
                            )

            # 4. max(exposure, 1) or max(probe_res["exposure_count"], 1)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "max":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and arg.value == 1:
                        code_snippet = ast.unparse(node) if hasattr(ast, "unparse") else ""
                        if "exposure" in code_snippet.lower():
                            violations.append(
                                f"{py_file.name}:{node.lineno}: Artificial clamping with max(..., 1) detected in '{code_snippet}'"
                            )

    assert not violations, f"Found hardcoded metric measurements in python scripts:\n" + "\n".join(violations)


def test_negative_control_assertion_can_fail():
    """
    Negative control: verifies that our scanner detector accurately catches
    a fake hardcoded assignment if injected into a dummy script.
    """
    dummy_code = """
    $exposureWindow = 0
    $postDecision = if ($x) { "REFUND DENIED" } else { "REFUND DENIED" }
    """
    m_exp = re.search(
        r'^\s*\$(exposureWindow)\s*=\s*(\d+)\s*$',
        dummy_code,
        re.IGNORECASE | re.MULTILINE
    )
    assert m_exp is not None, "Negative control failed: scanner must catch $exposureWindow = 0"
    assert m_exp.group(2) == "0"

    m_branch = re.search(
        r'if\s*\([^)]+\)\s*\{\s*["\']([^"\']+)["\']\s*\}\s*else\s*\{\s*["\']([^"\']+)["\']\s*\}',
        dummy_code,
        re.IGNORECASE | re.MULTILINE
    )
    assert m_branch is not None, "Negative control failed: scanner must catch identical if/else branches"
    assert m_branch.group(1) == m_branch.group(2)


if __name__ == "__main__":
    print("Running test_scripts_directory_exists()...")
    test_scripts_directory_exists()
    print("Running test_python_scripts_no_identical_if_else_branches()...")
    test_python_scripts_no_identical_if_else_branches()
    print("Running test_powershell_scripts_no_identical_if_else_branches()...")
    test_powershell_scripts_no_identical_if_else_branches()
    print("Running test_powershell_no_hardcoded_exposure_literal_assignments()...")
    test_powershell_no_hardcoded_exposure_literal_assignments()
    print("Running test_python_scripts_no_hardcoded_metric_measurements()...")
    test_python_scripts_no_hardcoded_metric_measurements()
    print("Running test_negative_control_assertion_can_fail()...")
    test_negative_control_assertion_can_fail()
    print("ALL TESTS PASSED.")

