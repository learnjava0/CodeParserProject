import os
import tempfile

from src.agent.parser.ast_parser import parser
from src.agent.scanners.deterministic import run_bandit, run_semgrep


def validate_patch(patched_code: str) -> bool:
    """
    Validates a generated patch through a two-step process:
    1. Syntax Check: Uses tree-sitter to ensure the patched code parses correctly.
    2. Security Check: Re-runs Semgrep/Bandit to confirm the vulnerability is resolved.
    
    Returns True if the patch is valid and secure, False otherwise.
    """
    # Clean up markdown formatting if the LLM returned it wrapped in backticks
    patched_code = patched_code.strip()
    if patched_code.startswith("```"):
        # Remove the first line (e.g. ```python)
        patched_code = "\n".join(patched_code.split("\n")[1:])
    if patched_code.endswith("```"):
        # Remove the last line (e.g. ```)
        patched_code = "\n".join(patched_code.split("\n")[:-1])
        
    patched_code = patched_code.strip()

    # 1. Syntax check using tree-sitter
    tree = parser.parse(patched_code.encode())
    if tree.root_node.has_error:
        print(f"Patch failed syntax validation: The LLM introduced a syntax error.\nLLM Output was:\n---\n{patched_code}\n---")
        return False
        
    # 2. Security validation
    # Write the patched code to a temporary file to run CLI scanners
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode='w') as temp:
        temp.write(patched_code)
        temp_path = temp.name
        
    try:
        # Run Semgrep
        semgrep_results = run_semgrep(temp_path)
        if "error" in semgrep_results:
            print(f"Semgrep execution error: {semgrep_results['error']}")
            return False
            
        # If the scan yields findings, the patch didn't fix the issue completely
        if semgrep_results.get("results", []):
            print("Patch failed security validation: Semgrep still detects vulnerabilities.")
            return False
            
        # Run Bandit (optional second pass)
        bandit_results = run_bandit(temp_path)
        if bandit_results.get("results", []):
            print("Patch failed security validation: Bandit still detects vulnerabilities.")
            return False
            
        return True
    finally:
        # Clean up temporary file
        os.remove(temp_path)
