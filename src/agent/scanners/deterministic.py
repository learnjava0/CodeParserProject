import subprocess
import json

def run_bandit(filepath: str) -> dict:
    """Run Bandit scanner on a specific file and return JSON results."""
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", filepath],
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout) if result.stdout else {}
    except Exception as e:
        return {"error": str(e)}

def run_semgrep(filepath: str) -> dict:
    """Run Semgrep scanner on a specific file and return JSON results."""
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--json", "--config", "auto", filepath],
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout) if result.stdout else {}
    except Exception as e:
        return {"error": str(e)}
