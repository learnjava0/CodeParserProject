import argparse
import json
import logging
import os
import sys
import tempfile

from src.agent.config import GEMINI_API_KEY
from src.agent.github.comment_publisher import publish_pr_review, write_github_step_summary
from src.agent.github.diff_mapper import map_diff_to_functions
from src.agent.github.pr_client import PRClient, PRClientError
from src.agent.masking.secrets_masker import redact_secrets
from src.agent.parser.ast_parser import parse_source
from src.agent.patcher.patch_validator import validate_patch_detailed
from src.agent.scanners.deterministic import run_deterministic_scanners
from src.agent.scanners.llm_scanner import scan_code_llm
from src.agent.schemas import Finding, PRAnalysisReport, ScanStatus


class SecretRedactingFormatter(logging.Formatter):
    """Custom log formatter ensuring no raw secrets or tokens appear in log streams."""

    def format(self, record: logging.LogRecord) -> str:
        orig = super().format(record)
        return redact_secrets(orig)


def configure_logging(level_name: str = "INFO") -> None:
    """Configures structured standard logging with credential masking."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    formatter = SecretRedactingFormatter("[%(asctime)s] [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    # Remove existing handlers to prevent duplicate lines
    root_logger.handlers = [handler]


logger = logging.getLogger("aegis.main")


def analyze_file(
    filepath: str,
    output_json: str | None = None,
    use_llm: bool = True,
) -> list[Finding]:
    """
    Core pipeline for scanning a single local file:
    Parse AST -> Deterministic Scans -> Optional LLM Analysis -> Validate Proposed Patches.
    """
    logger.info(f"Analyzing local file: {filepath}")
    if not os.path.exists(filepath):
        logger.error(f"File not found: {filepath}")
        return []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as file_obj:
            source = file_obj.read()
    except Exception as e:
        logger.error(f"Failed to read file {filepath}: {e}")
        return []

    # Step 1: AST Extraction
    parse_res = parse_source(source)
    if parse_res.has_syntax_errors:
        logger.warning(f"Syntax issues detected in {filepath}: {parse_res.syntax_errors}")

    functions = parse_res.functions
    logger.info(f"Extracted {len(functions)} functions from {filepath}.")

    all_findings: list[Finding] = []
    seen_ids: set[str] = set()

    # Step 2: Deterministic Scans
    det_results = run_deterministic_scanners(filepath)
    for res in det_results:
        logger.info(f"Scanner '{res.scanner_name}' finished with status: {res.status.value}")
        for finding in res.findings:
            if finding.identifier not in seen_ids:
                seen_ids.add(finding.identifier)
                all_findings.append(finding)

    # Step 3: Optional LLM Analysis (per-function)
    if use_llm and GEMINI_API_KEY:
        for func in functions:
            func_name = func["qualified_name"]
            logger.debug(f"Running LLM security scan on function: {func_name}")
            llm_res = scan_code_llm(func["code"], filepath=filepath)
            for f in llm_res.findings:
                # Adjust relative line numbers to file line numbers
                f.line_start = func["start_line"] + f.line_start - 1
                f.line_end = func["start_line"] + f.line_end - 1
                f.file_path = filepath
                if f.identifier not in seen_ids:
                    seen_ids.add(f.identifier)
                    all_findings.append(f)

    # Step 4: Validate Patches for Detected Findings
    for finding in all_findings:
        if finding.suggested_fix:
            logger.info(f"Validating remediation patch for {finding.vuln_type}...")
            val_res = validate_patch_detailed(finding.suggested_fix, target_rule_id=finding.rule_id)
            finding.patch_validation = {
                "is_valid": val_res.is_valid,
                "syntax_valid": val_res.syntax_valid,
                "security_passed": val_res.security_passed,
                "diagnostics": val_res.diagnostics,
            }

    # Reporting
    logger.info(f"File analysis complete. Total findings: {len(all_findings)}")
    for f in all_findings:
        val_status = "Not Validated"
        if f.patch_validation:
            val_status = "VALIDATED" if f.patch_validation["is_valid"] else "FAILED_VALIDATION"
        logger.warning(
            f"[{f.severity.upper()}] {f.vuln_type} at line {f.line_start} (Scanner: {f.scanner_source}, Patch: {val_status})"
        )

    if output_json:
        try:
            with open(output_json, "w", encoding="utf-8") as out_f:
                json.dump([f.model_dump() for f in all_findings], out_f, indent=2)
            logger.info(f"Saved analysis findings to {output_json}")
        except Exception as e:
            logger.error(f"Failed to write output JSON to {output_json}: {e}")

    return all_findings


def analyze_pull_request(
    repo_name: str,
    pr_number: int,
    output_json: str | None = None,
    publish: bool = True,
    use_llm: bool = True,
) -> PRAnalysisReport:
    """
    End-to-end pull request analysis workflow:
    1. Retrieve PR metadata & changed files via PRClient
    2. Parse modified unified diff hunks
    3. Map changes to AST functions
    4. Run deterministic security scanners on modified content
    5. Run LLM security analysis on affected functions
    6. Validate proposed remediation patches
    7. Deduplicate findings
    8. Publish review comments and write job summaries
    """
    logger.info(f"Starting security review for PR #{pr_number} on {repo_name}")
    client = PRClient()
    errors: list[str] = []

    try:
        pr_meta = client.get_pr_metadata(repo_name, pr_number)
    except PRClientError as pe:
        logger.error(f"Failed to fetch PR metadata: {pe}")
        return PRAnalysisReport(
            repo_name=repo_name,
            pr_number=pr_number,
            head_sha="unknown",
            base_sha="unknown",
            errors=[str(pe)],
        )

    head_sha = pr_meta["head_sha"]
    base_sha = pr_meta["base_sha"]
    logger.info(f"Target PR: {pr_meta['title']} (Head: {head_sha[:8]}, Fork: {pr_meta['is_fork']})")

    try:
        file_diffs = client.get_changed_files(repo_name, pr_number)
    except PRClientError as pe:
        logger.error(f"Failed to retrieve changed files: {pe}")
        return PRAnalysisReport(
            repo_name=repo_name,
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            errors=[str(pe)],
        )

    logger.info(f"Retrieved {len(file_diffs)} relevant changed files for analysis.")

    all_findings: list[Finding] = []
    seen_ids: set[str] = set()
    files_scanned: list[str] = []
    scanner_statuses: dict[str, ScanStatus] = {}

    for file_diff in file_diffs:
        filename = file_diff.filename
        raw_content = file_diff.raw_content
        if not raw_content:
            logger.debug(f"Skipping {filename}: no raw content available.")
            continue

        files_scanned.append(filename)
        logger.info(f"Scanning diff in: {filename} ({len(file_diff.changed_lines)} modified lines)")

        # Parse AST functions
        parse_res = parse_source(raw_content)
        diff_mapping = map_diff_to_functions(
            file_diff.changed_lines,
            parse_res.functions,
            file_diff.line_to_diff_position,
        )

        # Write to isolated temp file for deterministic CLI scanners
        temp_fd, temp_path = tempfile.mkstemp(suffix=".py", prefix="aegis_pr_")
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as tf:
                tf.write(raw_content)

            # Deterministic scan
            det_results = run_deterministic_scanners(temp_path)
            for res in det_results:
                scanner_statuses[res.scanner_name] = res.status
                for f in res.findings:
                    # Filter: Only report findings that intersect with changed lines in this PR
                    if file_diff.changed_lines and f.line_start not in file_diff.changed_lines:
                        logger.debug(
                            f"Skipping pre-existing finding at line {f.line_start} (outside PR modified lines)"
                        )
                        continue

                    f.file_path = filename
                    f.diff_position = file_diff.line_to_diff_position.get(f.line_start)
                    if f.identifier not in seen_ids:
                        seen_ids.add(f.identifier)
                        all_findings.append(f)

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        # LLM scan for overlapping functions
        if use_llm and GEMINI_API_KEY:
            for func in diff_mapping.overlapping_functions:
                func_name = func.get("qualified_name", func.get("name", "unknown"))
                logger.debug(f"LLM scan on modified function: {func_name}")
                llm_res = scan_code_llm(func["code"], filepath=filename)
                scanner_statuses["gemini"] = llm_res.status
                for f in llm_res.findings:
                    # Map relative function line to file line
                    f.line_start = func["start_line"] + f.line_start - 1
                    f.line_end = func["start_line"] + f.line_end - 1
                    f.file_path = filename
                    f.diff_position = file_diff.line_to_diff_position.get(f.line_start)
                    if f.identifier not in seen_ids:
                        seen_ids.add(f.identifier)
                        all_findings.append(f)

    # Validate suggested patches
    for finding in all_findings:
        if finding.suggested_fix:
            val_res = validate_patch_detailed(finding.suggested_fix, target_rule_id=finding.rule_id)
            finding.patch_validation = {
                "is_valid": val_res.is_valid,
                "syntax_valid": val_res.syntax_valid,
                "security_passed": val_res.security_passed,
                "diagnostics": val_res.diagnostics,
            }

    # Publish Review Comments if authorized
    published_count = 0
    if publish:
        published_count = publish_pr_review(
            repo_name=repo_name,
            pr_number=pr_number,
            commit_id=head_sha,
            findings=all_findings,
            publish=publish,
        )
    else:
        # Still record GitHub Actions Step Summary if in CI environment
        write_github_step_summary(repo_name, pr_number, all_findings)

    report = PRAnalysisReport(
        repo_name=repo_name,
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
        files_scanned=files_scanned,
        total_findings=len(all_findings),
        findings=all_findings,
        scanner_statuses=scanner_statuses,
        errors=errors,
        published_comments=published_count,
    )

    if output_json:
        try:
            with open(output_json, "w", encoding="utf-8") as out_f:
                out_f.write(report.model_dump_json(indent=2))
            logger.info(f"Saved PR analysis report to {output_json}")
        except Exception as e:
            logger.error(f"Failed to write report JSON to {output_json}: {e}")

    logger.info(
        f"PR review complete. Files scanned: {len(files_scanned)}, "
        f"Findings detected: {len(all_findings)}, Comments published: {published_count}"
    )
    return report


def main() -> None:
    """CLI Entrypoint for Aegis Security Agent."""
    parser = argparse.ArgumentParser(
        description="Aegis: Autonomous Code Security & Health Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Backward compatibility: positional file argument
    parser.add_argument("positional_file", nargs="?", default=None, help="Local file to analyze (legacy)")
    parser.add_argument("--file", "-f", dest="file_path", default=None, help="Path to local file for analysis")
    parser.add_argument("--repo", "-r", dest="repo", default=None, help="Target GitHub repository (owner/repo)")
    parser.add_argument("--pr", "-p", dest="pr_number", type=int, default=None, help="Pull Request number to review")
    parser.add_argument("--output", "-o", dest="output_json", default=None, help="Path to output JSON results")
    parser.add_argument(
        "--publish",
        dest="publish",
        action="store_true",
        default=True,
        help="Publish review comments to GitHub PR (default)",
    )
    parser.add_argument(
        "--no-publish",
        dest="publish",
        action="store_false",
        help="Disable posting comments to GitHub PR",
    )
    parser.add_argument(
        "--no-llm",
        dest="use_llm",
        action="store_false",
        default=True,
        help="Disable Gemini LLM scanning and use deterministic scanners only",
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity level (default: INFO)",
    )
    parser.add_argument(
        "--fail-on-findings",
        dest="fail_on_findings",
        action="store_true",
        default=False,
        help="Exit with non-zero status code (2) if security findings are detected",
    )

    args = parser.parse_args()
    configure_logging(args.log_level)

    target_file = args.file_path or args.positional_file

    if args.repo and args.pr_number:
        report = analyze_pull_request(
            repo_name=args.repo,
            pr_number=args.pr_number,
            output_json=args.output_json,
            publish=args.publish,
            use_llm=args.use_llm,
        )
        if args.fail_on_findings and report.total_findings > 0:
            sys.exit(2)
        if report.errors:
            sys.exit(1)
        sys.exit(0)

    elif target_file:
        findings = analyze_file(
            filepath=target_file,
            output_json=args.output_json,
            use_llm=args.use_llm,
        )
        if args.fail_on_findings and len(findings) > 0:
            sys.exit(2)
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

