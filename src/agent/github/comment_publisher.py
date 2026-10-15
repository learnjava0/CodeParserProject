import logging
import os
import re
from typing import Any

from github import BadCredentialsException, Github, GithubException
from src.agent.config import GITHUB_TOKEN
from src.agent.masking.secrets_masker import redact_secrets
from src.agent.schemas import Finding

logger = logging.getLogger(__name__)

FINDING_TAG_REGEX = re.compile(r"<!--\s*aegis-finding-id:\s*(.*?)\s*-->")


def format_finding_comment(finding: Finding) -> str:
    """
    Constructs an actionable, clean review comment for a security finding.
    Ensures secrets are redacted and validation status is accurately presented.
    """
    safe_explanation = redact_secrets(finding.explanation)
    safe_remediation = redact_secrets(
        finding.remediation or "Refactor the affected code to neutralize the vulnerability."
    )

    validation_section = ""
    if finding.patch_validation:
        if finding.patch_validation.get("is_valid"):
            validation_section = (
                "\n> **Validation:** Remediation suggestion passed the available syntax and security checks.\n"
            )
        else:
            diagnostics = ", ".join(finding.patch_validation.get("diagnostics", ["Check failed"]))
            validation_section = f"\n> **Validation Note:** Proposed fix requires manual review ({diagnostics}).\n"

    patch_section = ""
    if finding.suggested_fix:
        safe_fix = redact_secrets(finding.suggested_fix.strip())
        patch_section = f"""
**Suggested Patch:**
```python
{safe_fix}
```
"""

    return f"""### 🛡️ Aegis Security Finding: {finding.vuln_type}
- **Severity:** {finding.severity.capitalize()}
- **Scanner:** `{finding.scanner_source}` {f"(Rule: {finding.rule_id})" if finding.rule_id else ""}
- **Target Line:** {finding.line_start}

**Details:**
{safe_explanation}

**Recommendation:**
{safe_remediation}
{validation_section}{patch_section}
<!-- aegis-finding-id: {finding.identifier} -->
"""


def get_existing_finding_ids(pr: Any) -> set[str]:
    """Retrieves finding IDs from existing comments to prevent comment spam."""
    existing_ids = set()
    try:
        # Check inline review comments
        for comment in pr.get_review_comments():
            if comment.body:
                match = FINDING_TAG_REGEX.search(comment.body)
                if match:
                    existing_ids.add(match.group(1))

        # Check top-level issue comments
        for comment in pr.get_issue_comments():
            if comment.body:
                matches = FINDING_TAG_REGEX.findall(comment.body)
                for m in matches:
                    existing_ids.add(m)
    except Exception as e:
        logger.warning(f"Could not retrieve existing PR comments for deduplication: {e}")
    return existing_ids


def write_github_step_summary(repo_name: str, pr_number: int, findings: list[Finding]) -> None:
    """Writes structured summary to GITHUB_STEP_SUMMARY environment file."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    content = [
        f"## 🛡️ Aegis PR Security Report — #{pr_number} ({repo_name})\n",
        f"Total Security Findings: **{len(findings)}**\n\n",
    ]

    if not findings:
        content.append("✅ **No security vulnerabilities detected by completed scanners.**\n")
    else:
        content.append("| Severity | Vulnerability | File | Line | Scanner |\n")
        content.append("|---|---|---|---|---|\n")
        for f in findings:
            sev_badge = f"**{f.severity.upper()}**"
            content.append(
                f"| {sev_badge} | {f.vuln_type} | `{f.file_path or 'unknown'}` | {f.line_start} | `{f.scanner_source}` |\n"
            )

    try:
        with open(summary_path, "a", encoding="utf-8") as sf:
            sf.write("".join(content))
    except Exception as e:
        logger.warning(f"Failed to write GITHUB_STEP_SUMMARY: {e}")


def publish_pr_review(
    repo_name: str,
    pr_number: int,
    commit_id: str,
    findings: list[Finding],
    token: str | None = None,
    publish: bool = True,
) -> int:
    """
    Publishes security review comments on a GitHub PR.
    Handles forked PR permissions, deduplication, diff positions, and step summaries.
    Returns count of successfully posted comments.
    """
    auth_token = token or GITHUB_TOKEN
    write_github_step_summary(repo_name, pr_number, findings)

    if not publish:
        logger.info("PR comment publication disabled (--no-publish).")
        return 0

    if not auth_token:
        logger.warning("GITHUB_TOKEN not provided. Skipping review publication.")
        return 0

    if not findings:
        logger.info("No security findings to publish.")
        return 0

    published_count = 0
    try:
        gh = Github(auth_token)
        repo = gh.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        commit = repo.get_commit(commit_id)

        existing_ids = get_existing_finding_ids(pr)
        unpositioned_findings: list[Finding] = []

        for finding in findings:
            if finding.identifier in existing_ids:
                logger.info(f"Skipping duplicate finding comment: {finding.identifier}")
                continue

            body = format_finding_comment(finding)

            # Try publishing as an inline comment on the specific line
            if finding.file_path and finding.line_start:
                try:
                    pr.create_review_comment(
                        body=body,
                        commit=commit,
                        path=finding.file_path,
                        line=finding.line_start,
                    )
                    logger.info(f"Published inline comment on {finding.file_path}:{finding.line_start}")
                    published_count += 1
                    existing_ids.add(finding.identifier)
                    continue
                except GithubException as ge:
                    logger.debug(
                        f"Inline comment rejected for {finding.file_path}:{finding.line_start} ({ge.status}): {ge.data}. "
                        "Queueing for top-level review summary."
                    )
                    unpositioned_findings.append(finding)
            else:
                unpositioned_findings.append(finding)

        # Post top-level comment for findings that could not be placed inline
        if unpositioned_findings:
            combined_body = "### 🛡️ Aegis Security Review — Additional Findings\n\n"
            for f in unpositioned_findings:
                combined_body += format_finding_comment(f) + "\n---\n"

            try:
                pr.create_issue_comment(combined_body)
                published_count += len(unpositioned_findings)
                logger.info(f"Published top-level comment with {len(unpositioned_findings)} findings.")
            except GithubException as ge:
                logger.warning(f"Could not publish top-level PR comment: {ge}")

    except BadCredentialsException:
        logger.error("Invalid GITHUB_TOKEN supplied for review publishing.")
    except GithubException as ge:
        if ge.status == 403:
            logger.warning(
                "Write permission denied for PR review comments. "
                "This is expected for external forked PRs without write secrets."
            )
        else:
            logger.error(f"GitHub API error during review publication ({ge.status}): {ge.data}")
    except Exception as e:
        logger.error(f"Unexpected error publishing PR review: {e}")

    return published_count


def publish_pr_comment(
    repo_name: str,
    pr_number: int,
    commit_id: str,
    filepath: str,
    line: int,
    body: str,
) -> None:
    """
    Backward-compatible entry point to publish a single PR review comment.
    """
    if not GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN not set. Skipping PR comment.")
        return

    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        commit = repo.get_commit(commit_id)

        pr.create_review_comment(body=body, commit=commit, path=filepath, line=line)
        logger.info(f"Successfully posted comment on {filepath}:{line}")
    except Exception as e:
        logger.error(f"Failed to post PR comment: {e}")

