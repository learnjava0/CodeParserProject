import base64
import logging
import os
from typing import Any

from github import BadCredentialsException, Github, GithubException, RateLimitExceededException
from src.agent.config import GITHUB_TOKEN
from src.agent.github.diff_mapper import parse_unified_diff
from src.agent.schemas import FileDiff

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {".py"}
DEFAULT_MAX_FILE_SIZE_KB = 1024


class PRClientError(Exception):
    """Base exception for PR client operations."""


class PRClient:
    """
    High-reliability GitHub Pull Request client.
    Safely retrieves PR metadata, diffs, and changed file contents without code execution.
    """

    def __init__(self, token: str | None = None):
        self.token = token or GITHUB_TOKEN
        self.gh = Github(self.token) if self.token else Github()

    def get_pr_metadata(self, repo_name: str, pr_number: int) -> dict[str, Any]:
        """
        Retrieves pull request metadata including commit SHAs and fork status.
        """
        try:
            repo = self.gh.get_repo(repo_name)
            pr = repo.get_pull(pr_number)

            is_fork = False
            head_repo_name = repo_name
            if pr.head.repo:
                is_fork = pr.head.repo.fork or (pr.head.repo.full_name != repo_name)
                head_repo_name = pr.head.repo.full_name

            return {
                "repo_name": repo_name,
                "pr_number": pr_number,
                "title": pr.title,
                "state": pr.state,
                "base_sha": pr.base.sha,
                "head_sha": pr.head.sha,
                "is_fork": is_fork,
                "head_repo_name": head_repo_name,
                "author": pr.user.login if pr.user else "unknown",
            }
        except RateLimitExceededException as rle:
            logger.error(f"GitHub API rate limit exceeded: {rle}")
            raise PRClientError(f"GitHub rate limit exceeded: {rle}") from rle
        except BadCredentialsException as bce:
            logger.error(f"GitHub authentication failed: {bce}")
            raise PRClientError(f"GitHub authentication failed: {bce}") from bce
        except GithubException as ge:
            logger.error(f"GitHub API error fetching PR #{pr_number} from {repo_name}: {ge}")
            raise PRClientError(f"GitHub API error ({ge.status}): {ge.data}") from ge
        except Exception as e:
            logger.error(f"Unexpected error retrieving PR #{pr_number}: {e}")
            raise PRClientError(f"Failed to fetch PR metadata: {e}") from e

    def get_changed_files(
        self,
        repo_name: str,
        pr_number: int,
        max_file_size_kb: int = DEFAULT_MAX_FILE_SIZE_KB,
        target_extensions: set[str] | None = None,
    ) -> list[FileDiff]:
        """
        Retrieves changed files for a pull request with pagination, diff parsing,
        size limit enforcement, and safe content retrieval at the HEAD commit.
        """
        extensions = target_extensions or SUPPORTED_EXTENSIONS
        file_diffs: list[FileDiff] = []

        try:
            repo = self.gh.get_repo(repo_name)
            pr = repo.get_pull(pr_number)
            head_sha = pr.head.sha

            # Paginates through all changed files in the pull request
            pr_files = pr.get_files()

            for file in pr_files:
                filename = file.filename
                status = file.status or "modified"

                # Check if file has a supported extension
                _, ext = os.path.splitext(filename)
                if ext.lower() not in extensions:
                    logger.debug(f"Skipping unsupported file extension: {filename}")
                    continue

                # Removed / deleted files do not need security analysis
                if status == "removed":
                    logger.debug(f"Skipping removed file: {filename}")
                    continue

                # Parse unified diff patch if provided by GitHub
                changed_lines: list[int] = []
                line_to_pos: dict[int, int] = {}
                if file.patch:
                    changed_lines, line_to_pos = parse_unified_diff(file.patch)
                else:
                    logger.warning(
                        f"GitHub omitted diff patch for {filename} (status: {status}). "
                        "Diff may be truncated or large."
                    )

                # Safely retrieve full raw content at HEAD commit
                raw_content: str | None = None
                try:
                    content_file = repo.get_contents(filename, ref=head_sha)
                    if isinstance(content_file, list):
                        # Directory match, skip
                        continue

                    # Enforce file size limit
                    size_kb = (content_file.size or 0) / 1024
                    if size_kb > max_file_size_kb:
                        logger.warning(
                            f"File {filename} ({size_kb:.1f} KB) exceeds size threshold "
                            f"({max_file_size_kb} KB). Skipping analysis."
                        )
                        continue

                    if content_file.content:
                        # Decode base64
                        decoded_bytes = base64.b64decode(content_file.content)
                        raw_content = decoded_bytes.decode("utf-8", errors="replace")
                    elif content_file.decoded_content:
                        raw_content = content_file.decoded_content.decode("utf-8", errors="replace")

                except GithubException as ge:
                    logger.warning(f"Could not retrieve content for {filename} at {head_sha}: {ge}")
                    continue

                # If patch was omitted by GitHub but file content is available, mark all lines as changed
                if not changed_lines and raw_content:
                    total_lines = len(raw_content.splitlines())
                    changed_lines = list(range(1, total_lines + 1))
                    logger.info(f"Fallback: Marked all {total_lines} lines of {filename} as changed for scanning.")

                old_fn = getattr(file, "previous_filename", None)
                if not isinstance(old_fn, str):
                    old_fn = None

                file_diffs.append(
                    FileDiff(
                        filename=filename,
                        status=status,
                        old_filename=old_fn,
                        changed_lines=changed_lines,
                        patch=file.patch,
                        raw_content=raw_content,
                        line_to_diff_position=line_to_pos,
                    )
                )

            return file_diffs

        except RateLimitExceededException as rle:
            logger.error(f"GitHub rate limit exceeded during file retrieval: {rle}")
            raise PRClientError(f"GitHub rate limit exceeded: {rle}") from rle
        except BadCredentialsException as bce:
            logger.error(f"GitHub authentication error: {bce}")
            raise PRClientError(f"GitHub authentication failed: {bce}") from bce
        except Exception as e:
            logger.error(f"Failed to fetch changed files for PR #{pr_number}: {e}")
            raise PRClientError(f"Failed to retrieve changed files: {e}") from e
