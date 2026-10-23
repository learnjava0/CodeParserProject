import json
import logging
import os
import shutil
import subprocess
import sys
import time
from typing import Any

from src.agent.schemas import Finding, ScannerResult, ScanStatus

logger = logging.getLogger(__name__)


def _find_executable(name: str) -> str | None:
    """Safely locate scanner binary across PATH and current Python environment."""
    # 1. Standard PATH
    found = shutil.which(name)
    if found:
        return found

    # 2. Virtual environment Scripts / bin directory
    py_dir = os.path.dirname(sys.executable)
    candidates = [
        os.path.join(py_dir, name),
        os.path.join(py_dir, f"{name}.exe"),
        os.path.join(py_dir, "Scripts", name),
        os.path.join(py_dir, "Scripts", f"{name}.exe"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def _extract_json(raw_text: str) -> dict[str, Any] | None:
    """Extracts JSON object from CLI tool output that may contain log headers."""
    if not raw_text or not raw_text.strip():
        return None
    try:
        return json.loads(raw_text.strip())
    except json.JSONDecodeError:
        pass

    # Extract outermost JSON object delimiters
    start = raw_text.find("{")
    end = raw_text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(raw_text[start : end + 1])
        except json.JSONDecodeError:
            pass

    return None


def _map_vulnerability_category(rule_id: str, issue_text: str) -> tuple[str, str]:
    """Maps scanner-specific rule IDs and text to standard categories and remediation."""
    rule_upper = rule_id.upper()
    text_lower = issue_text.lower()

    if "B608" in rule_upper or "sql" in text_lower:
        return (
            "SQL Injection",
            "Use parameterized queries, prepared statements, or ORM parameter binding rather than string formatting or concatenation.",
        )
    if any(k in rule_upper for k in ("B602", "B605", "B607")) or "shell" in text_lower or "command injection" in text_lower:
        return (
            "Command Injection",
            "Avoid executing commands through a shell (e.g. shell=True or os.system). Use subprocess.run with argument arrays.",
        )
    if any(k in rule_upper for k in ("B105", "B106", "B107")) or "password" in text_lower or "secret" in text_lower or "credential" in text_lower:
        return (
            "Hardcoded Credentials",
            "Extract credentials into secure environment variables or a dedicated secret management service.",
        )

    return (
        f"Security Weakness ({rule_id})",
        "Refactor code to adhere to secure coding standards and eliminate untrusted input flows.",
    )


def _normalize_severity(sev: str | None) -> str:
    """Normalize severity into low, medium, high, or critical."""
    if not sev:
        return "medium"
    s = str(sev).lower().strip()
    if "crit" in s:
        return "critical"
    if "high" in s or "error" in s:
        return "high"
    if "med" in s or "warn" in s:
        return "medium"
    if "low" in s or "info" in s:
        return "low"
    return "medium"


def _normalize_confidence(conf: str | None) -> float:
    if not conf:
        return 0.8
    c = str(conf).lower().strip()
    if "high" in c:
        return 0.95
    if "med" in c:
        return 0.75
    if "low" in c:
        return 0.50
    return 0.8


def scan_with_bandit(filepath: str, timeout: int = 30) -> ScannerResult:
    """
    Executes Bandit securely using subprocess argument arrays.
    Distinguishes scanner crashes from detected vulnerabilities.
    """
    start_time = time.time()
    bandit_bin = _find_executable("bandit")
    if not bandit_bin:
        msg = "Bandit executable not found on system PATH or virtual environment."
        logger.warning(msg)
        return ScannerResult(
            scanner_name="bandit",
            status=ScanStatus.SKIPPED,
            execution_time_seconds=0.0,
            error_message=msg,
        )

    cmd = [bandit_bin, "-f", "json", "-q", filepath]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        msg = f"Bandit execution timed out after {timeout} seconds on {filepath}."
        logger.error(msg)
        return ScannerResult(
            scanner_name="bandit",
            status=ScanStatus.FAILED,
            execution_time_seconds=duration,
            error_message=msg,
        )
    except Exception as e:
        duration = time.time() - start_time
        msg = f"Failed to execute Bandit: {e}"
        logger.error(msg)
        return ScannerResult(
            scanner_name="bandit",
            status=ScanStatus.FAILED,
            execution_time_seconds=duration,
            error_message=msg,
        )

    duration = time.time() - start_time
    parsed = _extract_json(proc.stdout)
    if parsed is None:
        # If output could not be parsed, mark failed
        err_msg = proc.stderr.strip() or f"Bandit produced unparseable output (exit code {proc.returncode})"
        logger.error(f"Bandit parse error: {err_msg}")
        return ScannerResult(
            scanner_name="bandit",
            status=ScanStatus.FAILED,
            execution_time_seconds=duration,
            error_message=err_msg,
        )

    raw_results = parsed.get("results", [])
    findings: list[Finding] = []
    for r in raw_results:
        rule_id = str(r.get("test_id", "BANDIT_RULE"))
        issue_text = str(r.get("issue_text", "Potential security issue"))
        category, remediation = _map_vulnerability_category(rule_id, issue_text)
        sev = _normalize_severity(r.get("issue_severity"))
        conf = _normalize_confidence(r.get("issue_confidence"))

        line_start = int(r.get("line_number", 1))
        line_range = r.get("line_range", [line_start])
        line_end = max(line_range) if line_range else line_start

        findings.append(
            Finding(
                vuln_type=category,
                severity=sev,  # type: ignore[arg-type]
                line_start=line_start,
                line_end=line_end,
                explanation=issue_text,
                confidence=conf,
                rule_id=rule_id,
                scanner_source="bandit",
                file_path=filepath,
                remediation=remediation,
            )
        )

    status = ScanStatus.FINDINGS_DETECTED if findings else ScanStatus.COMPLETED
    return ScannerResult(
        scanner_name="bandit",
        status=status,
        findings=findings,
        execution_time_seconds=duration,
    )


def scan_with_semgrep(filepath: str, timeout: int = 45, config: str = "auto") -> ScannerResult:
    """
    Executes Semgrep safely using subprocess argument arrays.
    Handles unavailable executables or environments gracefully.
    """
    start_time = time.time()
    semgrep_bin = _find_executable("semgrep")
    if not semgrep_bin:
        msg = "Semgrep executable not found (Semgrep is not installed or unsupported on host OS)."
        logger.warning(msg)
        return ScannerResult(
            scanner_name="semgrep",
            status=ScanStatus.SKIPPED,
            execution_time_seconds=0.0,
            error_message=msg,
        )

    cmd = [semgrep_bin, "scan", "--json", "--config", config, filepath]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        msg = f"Semgrep scan timed out after {timeout} seconds on {filepath}."
        logger.error(msg)
        return ScannerResult(
            scanner_name="semgrep",
            status=ScanStatus.FAILED,
            execution_time_seconds=duration,
            error_message=msg,
        )
    except Exception as e:
        duration = time.time() - start_time
        msg = f"Failed to execute Semgrep: {e}"
        logger.error(msg)
        return ScannerResult(
            scanner_name="semgrep",
            status=ScanStatus.FAILED,
            execution_time_seconds=duration,
            error_message=msg,
        )

    duration = time.time() - start_time
    parsed = _extract_json(proc.stdout)
    if parsed is None:
        err_msg = proc.stderr.strip() or f"Semgrep returned unparseable output (exit code {proc.returncode})"
        logger.error(f"Semgrep parse error: {err_msg}")
        return ScannerResult(
            scanner_name="semgrep",
            status=ScanStatus.FAILED,
            execution_time_seconds=duration,
            error_message=err_msg,
        )

    raw_results = parsed.get("results", [])
    findings: list[Finding] = []
    for r in raw_results:
        check_id = str(r.get("check_id", "SEMGREP_RULE"))
        extra = r.get("extra", {})
        message = extra.get("message", "Semgrep security finding")
        category, remediation = _map_vulnerability_category(check_id, message)
        sev = _normalize_severity(extra.get("severity"))
        start_line = r.get("start", {}).get("line", 1)
        end_line = r.get("end", {}).get("line", start_line)

        findings.append(
            Finding(
                vuln_type=category,
                severity=sev,  # type: ignore[arg-type]
                line_start=start_line,
                line_end=end_line,
                explanation=message,
                confidence=0.9,
                rule_id=check_id,
                scanner_source="semgrep",
                file_path=filepath,
                remediation=remediation,
            )
        )

    status = ScanStatus.FINDINGS_DETECTED if findings else ScanStatus.COMPLETED
    return ScannerResult(
        scanner_name="semgrep",
        status=status,
        findings=findings,
        execution_time_seconds=duration,
    )


def run_deterministic_scanners(filepath: str) -> list[ScannerResult]:
    """Runs all available deterministic scanners and returns structured results."""
    results = []
    results.append(scan_with_bandit(filepath))
    results.append(scan_with_semgrep(filepath))
    return results


# Backward compatibility wrappers:
def run_bandit(filepath: str) -> dict[str, Any]:
    """Backward-compatible Bandit runner returning raw dict."""
    result = scan_with_bandit(filepath)
    if result.status == ScanStatus.FAILED:
        return {"error": result.error_message or "Bandit scan failed"}
    if result.status == ScanStatus.SKIPPED:
        return {"skipped": True, "error": result.error_message, "results": []}

    return {
        "results": [
            {
                "test_id": f.rule_id,
                "issue_text": f.explanation,
                "issue_severity": f.severity.upper(),
                "line_number": f.line_start,
                "line_range": list(range(f.line_start, f.line_end + 1)),
                "filename": filepath,
            }
            for f in result.findings
        ]
    }


def run_semgrep(filepath: str) -> dict[str, Any]:
    """Backward-compatible Semgrep runner returning raw dict."""
    result = scan_with_semgrep(filepath)
    if result.status == ScanStatus.FAILED:
        return {"error": result.error_message or "Semgrep scan failed"}
    if result.status == ScanStatus.SKIPPED:
        return {"skipped": True, "error": result.error_message, "results": []}

    return {
        "results": [
            {
                "check_id": f.rule_id,
                "extra": {"message": f.explanation, "severity": f.severity.upper()},
                "start": {"line": f.line_start},
                "end": {"line": f.line_end},
            }
            for f in result.findings
        ]
    }

