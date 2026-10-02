from github import Github
from src.agent.config import GITHUB_TOKEN

def publish_pr_comment(repo_name: str, pr_number: int, commit_id: str, filepath: str, line: int, body: str):
    """
    Publishes an inline review comment on a specific line of a GitHub Pull Request.
    Requires GITHUB_TOKEN to be set in the environment or secrets.
    """
    if not GITHUB_TOKEN:
        print("GITHUB_TOKEN not set. Skipping PR comment.")
        return
        
    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        commit = repo.get_commit(commit_id)
        
        pr.create_review_comment(
            body=body,
            commit=commit,
            path=filepath,
            line=line
        )
        print(f"Successfully posted comment on {filepath}:{line}")
    except Exception as e:
        print(f"Failed to post PR comment: {e}")
