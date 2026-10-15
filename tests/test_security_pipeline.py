import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from src.agent.main import analyze_file, analyze_pull_request
from src.agent.schemas import FileDiff, ScanStatus


@pytest.fixture
def mock_pr_client():
    with patch("src.agent.main.PRClient") as mock_cls:
        instance = MagicMock()
        mock_cls.return_value = instance
        yield instance


def test_scenario_a_vulnerable_pr(mock_pr_client):
    """Scenario A: PR containing an SQL injection vulnerability."""
    mock_pr_client.get_pr_metadata.return_value = {
        "repo_name": "owner/repo",
        "pr_number": 101,
        "title": "Add user query endpoint",
        "state": "open",
        "base_sha": "base_sha_1",
        "head_sha": "head_sha_1",
        "is_fork": False,
        "head_repo_name": "owner/repo",
        "author": "alice",
    }

    vulnerable_code = """import sqlite3

def query_user(user_id):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # SQL injection on line 8
    sql = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(sql)
    return cursor.fetchall()
"""
    patch_diff = "@@ -0,0 +1,10 @@\n" + "\n".join(f"+{line}" for line in vulnerable_code.splitlines())

    file_diff = FileDiff(
        filename="app/db.py",
        status="added",
        changed_lines=list(range(1, 11)),
        patch=patch_diff,
        raw_content=vulnerable_code,
        line_to_diff_position={i: i + 1 for i in range(1, 11)},
    )
    mock_pr_client.get_changed_files.return_value = [file_diff]

    with patch("src.agent.main.publish_pr_review", return_value=1) as mock_pub:
        report = analyze_pull_request(
            repo_name="owner/repo",
            pr_number=101,
            publish=True,
            use_llm=False,
        )

    assert report.total_findings >= 1
    sql_findings = [f for f in report.findings if f.vuln_type == "SQL Injection"]
    assert len(sql_findings) > 0
    f = sql_findings[0]
    assert f.file_path == "app/db.py"
    assert f.line_start == 7
    assert f.scanner_source == "bandit"
    assert mock_pub.called


def test_scenario_b_secure_pr(mock_pr_client):
    """Scenario B: PR containing secure Python code."""
    mock_pr_client.get_pr_metadata.return_value = {
        "repo_name": "owner/repo",
        "pr_number": 102,
        "title": "Add math utility",
        "state": "open",
        "base_sha": "base_sha_2",
        "head_sha": "head_sha_2",
        "is_fork": False,
        "head_repo_name": "owner/repo",
        "author": "bob",
    }

    secure_code = """def add_numbers(a: int, b: int) -> int:
    # Pure mathematical operation
    return a + b
"""
    file_diff = FileDiff(
        filename="utils/math.py",
        status="added",
        changed_lines=[1, 2, 3],
        patch="@@ -0,0 +1,3 @@\n+def add_numbers(a: int, b: int) -> int:\n+    return a + b\n",
        raw_content=secure_code,
        line_to_diff_position={1: 2, 2: 3, 3: 4},
    )
    mock_pr_client.get_changed_files.return_value = [file_diff]

    with patch("src.agent.main.publish_pr_review", return_value=0) as mock_pub:
        report = analyze_pull_request(
            repo_name="owner/repo",
            pr_number=102,
            publish=True,
            use_llm=False,
        )

    assert report.total_findings == 0
    assert len(report.findings) == 0
    # No security findings published
    assert report.published_comments == 0
    assert mock_pub.call_args.kwargs["findings"] == []


def test_scenario_c_scanner_failure(mock_pr_client):
    """Scenario C: Scanner fails with timeout or crash."""
    mock_pr_client.get_pr_metadata.return_value = {
        "repo_name": "owner/repo",
        "pr_number": 103,
        "title": "Test PR",
        "state": "open",
        "base_sha": "base3",
        "head_sha": "head3",
        "is_fork": False,
        "head_repo_name": "owner/repo",
        "author": "carol",
    }

    file_diff = FileDiff(
        filename="foo.py",
        status="modified",
        changed_lines=[1],
        patch="@@ -1 +1 @@\n-1\n+2",
        raw_content="x = 2\n",
        line_to_diff_position={1: 2},
    )
    mock_pr_client.get_changed_files.return_value = [file_diff]

    from src.agent.schemas import ScannerResult
    failed_bandit = ScannerResult(
        scanner_name="bandit",
        status=ScanStatus.FAILED,
        error_message="Bandit crashed unexpectedly",
    )

    with patch("src.agent.main.run_deterministic_scanners", return_value=[failed_bandit]):
        report = analyze_pull_request(
            repo_name="owner/repo",
            pr_number=103,
            publish=False,
            use_llm=False,
        )

    # Scanner status accurately reflects failure, not false success
    assert report.scanner_statuses["bandit"] == ScanStatus.FAILED


def test_scenario_d_forked_pr_safe_handling(mock_pr_client):
    """Scenario D: External forked PR with write permissions disabled."""
    mock_pr_client.get_pr_metadata.return_value = {
        "repo_name": "upstream/repo",
        "pr_number": 104,
        "title": "Community contribution",
        "state": "open",
        "base_sha": "base4",
        "head_sha": "head4",
        "is_fork": True,
        "head_repo_name": "fork/repo",
        "author": "external_user",
    }

    file_diff = FileDiff(
        filename="feature.py",
        status="added",
        changed_lines=[1, 2],
        patch="@@ -0,0 +1,2 @@\n+def f():\n+    pass\n",
        raw_content="def f():\n    pass\n",
        line_to_diff_position={1: 2, 2: 3},
    )
    mock_pr_client.get_changed_files.return_value = [file_diff]

    with patch("src.agent.main.publish_pr_review", return_value=0):
        # Without GITHUB_TOKEN write access
        report = analyze_pull_request(
            repo_name="upstream/repo",
            pr_number=104,
            publish=True,
            use_llm=False,
        )

    assert report.total_findings == 0
    assert report.head_sha == "head4"


def test_scenario_e_repeated_execution_deduplication(mock_pr_client):
    """Scenario E: Repeated analysis runs against unchanged PR."""
    mock_pr_client.get_pr_metadata.return_value = {
        "repo_name": "owner/repo",
        "pr_number": 105,
        "title": "Idempotency test",
        "state": "open",
        "base_sha": "b5",
        "head_sha": "h5",
        "is_fork": False,
        "head_repo_name": "owner/repo",
        "author": "alice",
    }

    code = "import os\ndef ping(h): os.system(f'ping {h}')"
    file_diff = FileDiff(
        filename="net.py",
        status="added",
        changed_lines=[1, 2],
        patch="@@ -0,0 +1,2 @@\n+import os\n+def ping(h): os.system(f'ping {h}')",
        raw_content=code,
        line_to_diff_position={1: 2, 2: 3},
    )
    mock_pr_client.get_changed_files.return_value = [file_diff]

    report1 = analyze_pull_request("owner/repo", 105, publish=False, use_llm=False)
    report2 = analyze_pull_request("owner/repo", 105, publish=False, use_llm=False)

    assert report1.total_findings == report2.total_findings
    assert [f.identifier for f in report1.findings] == [f.identifier for f in report2.findings]


def test_analyze_file_with_output_json():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_json = tf.name

    try:
        findings = analyze_file("tests/fixtures/vulnerable.py", output_json=out_json, use_llm=False)
        assert len(findings) >= 3

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) >= 3
        types = {d["vuln_type"] for d in data}
        assert "SQL Injection" in types
    finally:
        if os.path.exists(out_json):
            os.remove(out_json)
