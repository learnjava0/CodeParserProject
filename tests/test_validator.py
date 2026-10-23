import glob
import os
import tempfile
from unittest.mock import patch

from src.agent.patcher.patch_validator import (
    clean_patch_code,
    validate_patch,
    validate_patch_detailed,
)
from src.agent.schemas import ScannerResult, ScanStatus


def test_invalid_syntax_rejected():
    # Missing closing parenthesis creates a syntax error
    bad_code = "def foo():\n    print('hello'"
    assert validate_patch(bad_code) is False
    res = validate_patch_detailed(bad_code)
    assert res.is_valid is False
    assert res.syntax_valid is False
    assert len(res.diagnostics) > 0


def test_valid_syntax_passed():
    # Valid Python syntax
    good_code = "def foo():\n    print('hello')\n"
    assert validate_patch(good_code) is True
    res = validate_patch_detailed(good_code)
    assert res.is_valid is True
    assert res.syntax_valid is True
    assert res.security_passed is True


def test_markdown_fence_cleaning():
    wrapped = "```python\ndef bar():\n    return 42\n```"
    cleaned = clean_patch_code(wrapped)
    assert cleaned == "def bar():\n    return 42"
    assert validate_patch(wrapped) is True


def test_empty_patch_rejected():
    res = validate_patch_detailed("   ")
    assert res.is_valid is False
    assert "empty" in res.diagnostics[0]


def test_patch_with_remaining_vulnerability_rejected():
    # Code that still contains an SQL injection
    vulnerable_patch = """def get_user(uid):
    query = f"SELECT * FROM users WHERE id = {uid}"
    cursor.execute(query)
"""
    # Bandit detects B608
    res = validate_patch_detailed(vulnerable_patch, target_rule_id="B608")
    assert res.is_valid is False
    assert res.security_passed is False
    assert any("B608" in d or "SQL Injection" in d for d in res.diagnostics)


def test_temp_file_cleanup_on_completion():
    temp_dir = tempfile.gettempdir()
    initial_patch_files = set(glob.glob(os.path.join(temp_dir, "aegis_patch_*")))

    code = "def temp_test(): pass\n"
    validate_patch_detailed(code)

    after_patch_files = set(glob.glob(os.path.join(temp_dir, "aegis_patch_*")))
    # Verify no leaked temporary patch files remain
    leaked = after_patch_files - initial_patch_files
    assert len(leaked) == 0


def test_scanner_failure_handling_in_validator():
    failed_res = ScannerResult(
        scanner_name="bandit",
        status=ScanStatus.FAILED,
        error_message="Bandit crashed unexpectedly",
    )
    with patch("src.agent.patcher.patch_validator.scan_with_bandit", return_value=failed_res):
        res = validate_patch_detailed("def foo(): pass")
        assert res.is_valid is False
        assert res.security_passed is False
        assert any("Bandit crashed" in d for d in res.diagnostics)

