import os
import tempfile
from unittest.mock import MagicMock, patch

from github import GithubException

from src.agent.github.comment_publisher import (
    format_finding_comment,
    get_existing_finding_ids,
    publish_pr_review,
    write_github_step_summary,
)
from src.agent.schemas import Finding


def test_format_finding_comment():
    finding = Finding(
        vuln_type="SQL Injection",
        severity="high",
        line_start=15,
        line_end=15,
        explanation="Untrusted user input formatted into query string.",
        confidence=0.95,
        rule_id="B608",
        scanner_source="bandit",
        file_path="app/views.py",
        remediation="Use parameterized query.",
        suggested_fix="cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))",
        patch_validation={"is_valid": True},
    )

    body = format_finding_comment(finding)
    assert "🛡️ Aegis Security Finding: SQL Injection" in body
    assert "**Severity:** High" in body
    assert "**Target Line:** 15" in body
    assert "Use parameterized query." in body
    assert "Remediation suggestion passed the available syntax and security checks." in body
    assert "cursor.execute" in body
    assert f"<!-- aegis-finding-id: {finding.identifier} -->" in body


def test_format_finding_comment_redacts_secrets():
    finding = Finding(
        vuln_type="Hardcoded Secret",
        severity="medium",
        line_start=10,
        line_end=10,
        explanation="Secret found: api_key = 'super_secret_token_12345'",
        confidence=0.9,
        scanner_source="bandit",
        suggested_fix="api_key = os.getenv('API_KEY')",
    )
    body = format_finding_comment(finding)
    assert "super_secret_token_12345" not in body
    assert "[REDACTED_SECRET]" in body


def test_get_existing_finding_ids_deduplication():
    mock_pr = MagicMock()
    c1 = MagicMock()
    c1.body = "Previous comment <!-- aegis-finding-id: file.py:10:SQL Injection:B608 -->"
    c2 = MagicMock()
    c2.body = "Another comment without tag"
    mock_pr.get_review_comments.return_value = [c1, c2]
    mock_pr.get_issue_comments.return_value = []

    ids = get_existing_finding_ids(mock_pr)
    assert "file.py:10:SQL Injection:B608" in ids
    assert len(ids) == 1


def test_publish_pr_review_inline_success():
    mock_gh = MagicMock()
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_commit = MagicMock()

    mock_pr.get_review_comments.return_value = []
    mock_pr.get_issue_comments.return_value = []
    mock_repo.get_pull.return_value = mock_pr
    mock_repo.get_commit.return_value = mock_commit
    mock_gh.get_repo.return_value = mock_repo

    finding = Finding(
        vuln_type="Command Injection",
        severity="high",
        line_start=20,
        line_end=20,
        explanation="os.system call",
        confidence=0.9,
        file_path="src/utils.py",
    )

    with patch("src.agent.github.comment_publisher.Github", return_value=mock_gh):
        count = publish_pr_review(
            repo_name="owner/repo",
            pr_number=10,
            commit_id="sha123",
            findings=[finding],
            token="token123",
            publish=True,
        )

    assert count == 1
    mock_pr.create_review_comment.assert_called_once()


def test_publish_pr_review_fallback_on_invalid_position():
    mock_gh = MagicMock()
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_commit = MagicMock()

    mock_pr.get_review_comments.return_value = []
    mock_pr.get_issue_comments.return_value = []
    # Inline comment fails with 422 (e.g. line outside diff)
    mock_pr.create_review_comment.side_effect = GithubException(422, {"message": "Line not in diff"})
    mock_repo.get_pull.return_value = mock_pr
    mock_repo.get_commit.return_value = mock_commit
    mock_gh.get_repo.return_value = mock_repo

    finding = Finding(
        vuln_type="Command Injection",
        severity="high",
        line_start=20,
        line_end=20,
        explanation="os.system call",
        confidence=0.9,
        file_path="src/utils.py",
    )

    with patch("src.agent.github.comment_publisher.Github", return_value=mock_gh):
        count = publish_pr_review(
            repo_name="owner/repo",
            pr_number=10,
            commit_id="sha123",
            findings=[finding],
            token="token123",
            publish=True,
        )

    # Should fall back to top-level issue comment
    mock_pr.create_issue_comment.assert_called_once()
    assert count == 1


def test_publish_pr_review_fork_permission_denied():
    mock_gh = MagicMock()
    mock_repo = MagicMock()
    # 403 Forbidden on forked PR
    mock_repo.get_pull.side_effect = GithubException(403, {"message": "Resource not accessible by integration"})
    mock_gh.get_repo.return_value = mock_repo

    with patch("src.agent.github.comment_publisher.Github", return_value=mock_gh):
        # Must not raise an exception
        count = publish_pr_review(
            repo_name="owner/repo",
            pr_number=10,
            commit_id="sha123",
            findings=[],
            token="token123",
            publish=True,
        )
    assert count == 0


def test_write_github_step_summary():
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
        temp_file = tf.name

    try:
        with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": temp_file}):
            f = Finding(
                vuln_type="SQL Injection",
                severity="high",
                line_start=5,
                line_end=5,
                explanation="sqli",
                confidence=0.9,
                file_path="app.py",
                scanner_source="bandit",
            )
            write_github_step_summary("owner/repo", 12, [f])

            with open(temp_file, "r", encoding="utf-8") as f_read:
                content = f_read.read()

            assert "🛡️ Aegis PR Security Report — #12 (owner/repo)" in content
            assert "SQL Injection" in content
            assert "app.py" in content
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
