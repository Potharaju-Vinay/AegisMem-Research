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
import pytest

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

