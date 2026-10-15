import ast
import logging
import os
import tempfile

from src.agent.parser.ast_parser import parse_source
from src.agent.scanners.deterministic import scan_with_bandit, scan_with_semgrep
from src.agent.schemas import PatchValidationResult, ScannerResult, ScanStatus

logger = logging.getLogger(__name__)


def clean_patch_code(patch_code: str) -> str:
    """Safely extracts clean source code from markdown fences and trailing whitespace."""
    code = patch_code.strip()
    if code.startswith("```"):
        lines = code.splitlines()
        # Drop opening ``` or ```python
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        # Drop closing ```
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        code = "\n".join(lines).strip()
    return code


def validate_patch_detailed(
    patched_code: str,
    original_code: str | None = None,
    target_rule_id: str | None = None,
) -> PatchValidationResult:
    """
    Validates a generated patch through an isolated multi-stage process:
    Stage 1: Verify well-formedness and strip markdown encapsulation.
    Stage 2: Validate complete Python syntax via AST and Tree-Sitter.
    Stage 3: Run isolated deterministic security scans on patched code.
    Stage 4: Verify target vulnerability neutralization without introducing new high/critical issues.
    Stage 5: Clean up all temporary files safely.
    Stage 6: Return structured diagnostic results.
    """
    diagnostics: list[str] = []
    scanner_results: list[ScannerResult] = []

    # Stage 1: Clean code
    cleaned = clean_patch_code(patched_code)
    if not cleaned:
        return PatchValidationResult(
            is_valid=False,
            syntax_valid=False,
            security_passed=False,
            scanner_results=[],
            diagnostics=["Generated patch is empty."],
            cleaned_code=None,
        )

    # Stage 2: Syntax integrity check via tree-sitter & standard ast
    ts_res = parse_source(cleaned, language="python")
    syntax_valid = True
    if ts_res.has_syntax_errors:
        syntax_valid = False
        diagnostics.extend([f"AST syntax error: {e}" for e in ts_res.syntax_errors])

    # Also verify with Python built-in ast parser for standard compliance
    try:
        ast.parse(cleaned)
    except SyntaxError as e:
        syntax_valid = False
        diagnostics.append(f"Python parser SyntaxError at line {e.lineno}: {e.msg}")

    if not syntax_valid:
        return PatchValidationResult(
            is_valid=False,
            syntax_valid=False,
            security_passed=False,
            scanner_results=[],
            diagnostics=diagnostics,
            cleaned_code=cleaned,
        )

    # Stage 3: Isolated security scanning
    # Write to an isolated temp file with strict permissions
    temp_fd, temp_path = tempfile.mkstemp(suffix=".py", prefix="aegis_patch_")
    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            f.write(cleaned)

        # Run Bandit
        bandit_res = scan_with_bandit(temp_path)
        scanner_results.append(bandit_res)

        # Run Semgrep
        semgrep_res = scan_with_semgrep(temp_path)
        scanner_results.append(semgrep_res)

        # Stage 4: Analyze scanner outcomes
        security_passed = True

        for res in scanner_results:
            if res.status == ScanStatus.FAILED:
                # Critical scanner failure during validation
                diagnostics.append(f"Scanner {res.scanner_name} failed: {res.error_message}")
                security_passed = False
            elif res.status == ScanStatus.SKIPPED:
                diagnostics.append(f"Scanner {res.scanner_name} skipped: {res.error_message}")
            elif res.status == ScanStatus.FINDINGS_DETECTED:
                # If target rule was specified, check if it remains
                unresolved = []
                for finding_item in res.findings:
                    if target_rule_id and finding_item.rule_id == target_rule_id:
                        unresolved.append(f"Target vulnerability '{target_rule_id}' still detected.")
                    elif finding_item.severity in ("high", "critical"):
                        unresolved.append(
                            f"Patch introduced new {finding_item.severity} severity "
                            f"{finding_item.vuln_type} ({finding_item.rule_id})."
                        )
                    else:
                        unresolved.append(f"Vulnerability {finding_item.vuln_type} detected at line {finding_item.line_start}.")

                if unresolved:
                    security_passed = False
                    diagnostics.extend(unresolved)

        is_valid = syntax_valid and security_passed
        return PatchValidationResult(
            is_valid=is_valid,
            syntax_valid=syntax_valid,
            security_passed=security_passed,
            scanner_results=scanner_results,
            diagnostics=diagnostics,
            cleaned_code=cleaned,
        )

    finally:
        # Stage 5: Clean up temporary file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError as err:
                logger.warning(f"Could not remove temporary patch file {temp_path}: {err}")


def validate_patch(patched_code: str) -> bool:
    """
    Backward-compatible entry point for patch validation.
    Returns True if the patch is syntax-valid and passes security checks.
    """
    result = validate_patch_detailed(patched_code)
    if not result.is_valid:
        for diag in result.diagnostics:
            logger.info(f"Patch validation check: {diag}")
    return result.is_valid

