from unittest.mock import MagicMock, patch

import pytest
from github import BadCredentialsException, RateLimitExceededException

from src.agent.github.pr_client import PRClient, PRClientError


@pytest.fixture
def mock_github():
    with patch("src.agent.github.pr_client.Github") as mock_gh_cls:
        mock_instance = MagicMock()
        mock_gh_cls.return_value = mock_instance
        yield mock_instance


def test_get_pr_metadata_success(mock_github):
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_pr.title = "Add feature"
    mock_pr.state = "open"
    mock_pr.base.sha = "base123"
    mock_pr.head.sha = "head456"
    mock_pr.head.repo.fork = False
    mock_pr.head.repo.full_name = "owner/repo"
    mock_pr.user.login = "contributor"

    mock_repo.get_pull.return_value = mock_pr
    mock_github.get_repo.return_value = mock_repo

    client = PRClient(token="dummy_token")
    meta = client.get_pr_metadata("owner/repo", 42)

    assert meta["pr_number"] == 42
    assert meta["base_sha"] == "base123"
    assert meta["head_sha"] == "head456"
    assert meta["is_fork"] is False
    assert meta["author"] == "contributor"


def test_get_pr_metadata_fork_detection(mock_github):
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_pr.head.repo.fork = True
    mock_pr.head.repo.full_name = "external-fork/repo"

    mock_repo.get_pull.return_value = mock_pr
    mock_github.get_repo.return_value = mock_repo

    client = PRClient(token="dummy_token")
    meta = client.get_pr_metadata("owner/repo", 99)
    assert meta["is_fork"] is True
    assert meta["head_repo_name"] == "external-fork/repo"


def test_get_changed_files_with_pagination_and_types(mock_github):
    mock_repo = MagicMock()
    mock_pr = MagicMock()

    # File 1: Added python file with patch
    f1 = MagicMock()
    f1.filename = "src/new_module.py"
    f1.status = "added"
    f1.patch = "@@ -0,0 +1,2 @@\n+def foo():\n+    return 1"

    # File 2: Non-python file (unsupported)
    f2 = MagicMock()
    f2.filename = "docs/README.md"
    f2.status = "modified"

    # File 3: Removed python file (should be ignored)
    f3 = MagicMock()
    f3.filename = "legacy.py"
    f3.status = "removed"

    mock_pr.get_files.return_value = [f1, f2, f3]
    mock_repo.get_pull.return_value = mock_pr

    # Content for f1
    content_mock = MagicMock()
    content_mock.size = 200
    content_mock.content = None
    content_mock.decoded_content = b"def foo():\n    return 1\n"
    mock_repo.get_contents.return_value = content_mock
    mock_github.get_repo.return_value = mock_repo

    client = PRClient(token="dummy_token")
    diffs = client.get_changed_files("owner/repo", 1)

    assert len(diffs) == 1
    assert diffs[0].filename == "src/new_module.py"
    assert diffs[0].status == "added"
    assert diffs[0].changed_lines == [1, 2]
    assert "def foo():" in diffs[0].raw_content


def test_missing_patch_fallback(mock_github):
    mock_repo = MagicMock()
    mock_pr = MagicMock()

    # Large file where GitHub omits patch
    f = MagicMock()
    f.filename = "big_file.py"
    f.status = "modified"
    f.patch = None

    mock_pr.get_files.return_value = [f]
    mock_repo.get_pull.return_value = mock_pr

    content_mock = MagicMock()
    content_mock.size = 500
    content_mock.content = None
    content_mock.decoded_content = b"line 1\nline 2\nline 3\n"
    mock_repo.get_contents.return_value = content_mock
    mock_github.get_repo.return_value = mock_repo

    client = PRClient(token="dummy_token")
    diffs = client.get_changed_files("owner/repo", 5)

    assert len(diffs) == 1
    # Fallback marks all 3 lines as changed
    assert diffs[0].changed_lines == [1, 2, 3]


def test_file_size_limit_exceeded(mock_github):
    mock_repo = MagicMock()
    mock_pr = MagicMock()

    f = MagicMock()
    f.filename = "huge_data.py"
    f.status = "modified"
    f.patch = "@@ -1 +1 @@\n-1\n+2"

    mock_pr.get_files.return_value = [f]
    mock_repo.get_pull.return_value = mock_pr

    # Size 2000 KB exceeds threshold of 500 KB
    content_mock = MagicMock()
    content_mock.size = 2000 * 1024
    mock_repo.get_contents.return_value = content_mock
    mock_github.get_repo.return_value = mock_repo

    client = PRClient(token="dummy_token")
    diffs = client.get_changed_files("owner/repo", 5, max_file_size_kb=500)
    assert len(diffs) == 0


def test_rate_limit_error_handling(mock_github):
    mock_github.get_repo.side_effect = RateLimitExceededException(403, {"message": "Rate limit exceeded"})

    client = PRClient(token="dummy_token")
    with pytest.raises(PRClientError, match="rate limit exceeded"):
        client.get_pr_metadata("owner/repo", 1)


def test_bad_credentials_error_handling(mock_github):
    mock_github.get_repo.side_effect = BadCredentialsException(401, {"message": "Bad credentials"})

    client = PRClient(token="invalid_token")
    with pytest.raises(PRClientError, match="authentication failed"):
        client.get_pr_metadata("owner/repo", 1)
