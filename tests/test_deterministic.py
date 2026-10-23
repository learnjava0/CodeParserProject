import os
import subprocess
from unittest.mock import MagicMock, patch

from src.agent.scanners.deterministic import (
    run_bandit,
    run_deterministic_scanners,
    run_semgrep,
    scan_with_bandit,
    scan_with_semgrep,
)
from src.agent.schemas import ScanStatus


def test_bandit_vulnerable_fixture_detection():
    vulnerable_file = os.path.join("tests", "fixtures", "vulnerable.py")
    res = scan_with_bandit(vulnerable_file)

    assert res.status == ScanStatus.FINDINGS_DETECTED
    assert len(res.findings) >= 3

    categories = {f.vuln_type for f in res.findings}
    assert "SQL Injection" in categories
    assert "Command Injection" in categories
    assert "Hardcoded Credentials" in categories

    # Check line numbers
    sql_finding = next(f for f in res.findings if f.vuln_type == "SQL Injection")
    assert sql_finding.line_start == 9
    assert sql_finding.scanner_source == "bandit"
    assert sql_finding.rule_id == "B608"


def test_bandit_missing_executable_handling():
    with patch("src.agent.scanners.deterministic._find_executable", return_value=None):
        res = scan_with_bandit("tests/fixtures/vulnerable.py")
        assert res.status == ScanStatus.SKIPPED
        assert "not found" in res.error_message


def test_bandit_timeout_handling():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["bandit"], timeout=5)):
        res = scan_with_bandit("tests/fixtures/vulnerable.py", timeout=5)
        assert res.status == ScanStatus.FAILED
        assert "timed out" in res.error_message


def test_bandit_malformed_output():
    mock_proc = MagicMock()
    mock_proc.stdout = "This is not json at all"
    mock_proc.stderr = "Fatal scanner corruption"
    mock_proc.returncode = 2

    with patch("subprocess.run", return_value=mock_proc):
        res = scan_with_bandit("tests/fixtures/vulnerable.py")
        assert res.status == ScanStatus.FAILED
        assert "unparseable" in res.error_message or "Fatal" in res.error_message


def test_semgrep_missing_or_unsupported_on_windows():
    # If semgrep is not found, should safely return SKIPPED
    with patch("src.agent.scanners.deterministic._find_executable", return_value=None):
        res = scan_with_semgrep("tests/fixtures/vulnerable.py")
        assert res.status == ScanStatus.SKIPPED
        assert "not installed or unsupported" in res.error_message


def test_semgrep_successful_parsing():
    mock_proc = MagicMock()
    mock_proc.stdout = """{
        "results": [
            {
                "check_id": "python.lang.security.audit.sqli",
                "start": {"line": 12},
                "end": {"line": 14},
                "extra": {
                    "message": "Potential SQL injection",
                    "severity": "ERROR"
                }
            }
        ]
    }"""
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    with (
        patch("src.agent.scanners.deterministic._find_executable", return_value="/usr/bin/semgrep"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        res = scan_with_semgrep("tests/fixtures/vulnerable.py")
        assert res.status == ScanStatus.FINDINGS_DETECTED
        assert len(res.findings) == 1
        assert res.findings[0].vuln_type == "SQL Injection"
        assert res.findings[0].severity == "high"


def test_backward_compatibility_run_bandit():
    vulnerable_file = os.path.join("tests", "fixtures", "vulnerable.py")
    raw = run_bandit(vulnerable_file)
    assert "results" in raw
    assert len(raw["results"]) >= 3


def test_backward_compatibility_run_semgrep_skipped():
    with patch("src.agent.scanners.deterministic._find_executable", return_value=None):
        raw = run_semgrep("tests/fixtures/vulnerable.py")
        assert raw.get("skipped") is True
        assert raw.get("results") == []


def test_run_deterministic_scanners_aggregation():
    results = run_deterministic_scanners("tests/fixtures/vulnerable.py")
    assert len(results) == 2
    scanner_names = {r.scanner_name for r in results}
    assert scanner_names == {"bandit", "semgrep"}
