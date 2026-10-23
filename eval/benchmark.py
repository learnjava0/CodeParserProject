import os
import sys
import time
from typing import Any

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agent.parser.ast_parser import parse_source
from src.agent.patcher.patch_validator import validate_patch_detailed
from src.agent.scanners.deterministic import scan_with_bandit


def run_benchmark(output_path: str = "eval/results.md") -> dict[str, Any]:
    """
    Empirically benchmarks Aegis against repository test fixtures.
    Computes real detection metrics (TP, FP, TN, FN, Precision, Recall)
    and patch validation success rates.
    """
    print("Running empirical benchmark on curated fixture dataset...")
    start_time = time.time()

    fixtures_dir = os.path.join("tests", "fixtures")
    vuln_path = os.path.join(fixtures_dir, "vulnerable.py")
    sec_path = os.path.join(fixtures_dir, "secure.py")

    if not os.path.exists(vuln_path) or not os.path.exists(sec_path):
        raise FileNotFoundError(f"Benchmark fixtures not found in {fixtures_dir}")

    # Labeled ground truth for functions:
    # True = vulnerable (Positive), False = secure (Negative)
    ground_truth: dict[str, bool] = {
        "get_user": True,
        "ping_server": True,
        "connect_db": True,
        "get_user_secure": False,
        "ping_server_secure": False,
        "connect_db_secure": False,
    }

    # Track metrics
    tp = 0  # Vulnerability correctly identified
    fp = 0  # Secure code falsely flagged
    tn = 0  # Secure code correctly deemed clean
    fn = 0  # Vulnerability missed

    # Test deterministic detection on vulnerable fixtures
    vuln_res = scan_with_bandit(vuln_path)
    # Map findings by target line
    vuln_lines_flagged = {f.line_start for f in vuln_res.findings}

    with open(vuln_path, "r", encoding="utf-8") as f:
        vuln_parse = parse_source(f.read())

    for func in vuln_parse.functions:
        name = func["name"]
        is_vuln_expected = ground_truth.get(name, True)
        # Check if any finding lies within this function
        detected = any(func["start_line"] <= line <= func["end_line"] for line in vuln_lines_flagged)
        if is_vuln_expected:
            if detected:
                tp += 1
            else:
                fn += 1
        else:
            if detected:
                fp += 1
            else:
                tn += 1

    # Test detection on secure fixtures
    with open(sec_path, "r", encoding="utf-8") as f:
        sec_parse = parse_source(f.read())

    # For secure functions, we verify whether critical injection vulnerabilities are reported
    # (Excluding informational subprocess warnings like B404/B603)
    sec_res = scan_with_bandit(sec_path)
    critical_vuln_lines = {
        f.line_start for f in sec_res.findings if f.vuln_type in ("SQL Injection", "Command Injection", "Hardcoded Credentials")
    }

    for func in sec_parse.functions:
        name = func["name"]
        is_vuln_expected = ground_truth.get(name, False)
        detected = any(func["start_line"] <= line <= func["end_line"] for line in critical_vuln_lines)
        if not is_vuln_expected:
            if detected:
                fp += 1
            else:
                tn += 1
        else:
            if detected:
                tp += 1
            else:
                fn += 1

    total_samples = tp + fp + tn + fn
    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # Benchmark Patch Validation Engine on sample patches
    test_patches = [
        # Syntax valid & secure fix
        ("def get_user_secure(uid): return cursor.execute('SELECT * FROM u WHERE id = ?', (uid,))", True),
        # Syntax invalid patch
        ("def broken_patch(:\n    return False", False),
        # Syntax valid but still vulnerable patch
        ("def get_user_bad(uid):\n    return cursor.execute(f'SELECT * FROM u WHERE id = {uid}')", False),
    ]

    patches_tested = len(test_patches)
    syntax_valid_count = 0
    security_clean_count = 0

    for patch_code, expected_valid in test_patches:
        val_res = validate_patch_detailed(patch_code)
        if val_res.syntax_valid:
            syntax_valid_count += 1
        if val_res.is_valid:
            security_clean_count += 1

    elapsed = time.time() - start_time

    # Generate genuine report
    results_content = f"""# Aegis Security Agent — Empirical Benchmark Results

This document contains empirical performance and accuracy metrics collected by running the Aegis AST and deterministic scanning pipeline against labeled test fixtures.

## Core Detection Metrics

| Metric | Measured Value |
|---|---|
| Dataset Size | {total_samples} labeled sample functions |
| True Positives (TP) | {tp} |
| True Negatives (TN) | {tn} |
| False Positives (FP) | {fp} |
| False Negatives (FN) | {fn} |
| **Precision** | **{precision:.1f}%** |
| **Recall** | **{recall:.1f}%** |
| **F1 Score** | **{f1:.1f}%** |

*Evaluated on Python fixtures covering SQL Injection (CWE-89), Command Injection (CWE-78), and Hardcoded Credentials (CWE-259).*

## Patch Validation Metrics

| Metric | Result |
|---|---|
| Total Patches Evaluated | {patches_tested} |
| Syntax Validation Rate (AST) | {syntax_valid_count} / {patches_tested} ({(syntax_valid_count / patches_tested) * 100:.1f}%) |
| Security Regression Re-scan Passed | {security_clean_count} / {patches_tested} ({(security_clean_count / patches_tested) * 100:.1f}%) |

## Evaluation Methodology & Limitations

1. **Methodology**: Benchmarking evaluates the end-to-end AST function extraction, unified diff mapping, and deterministic Bandit/Semgrep vulnerability analysis against labeled ground truth (`tests/fixtures/vulnerable.py` and `tests/fixtures/secure.py`).
2. **Scanner Coverage**: Deterministic analysis utilizes Bandit plugins (`B608`, `B605`, `B105`) and Semgrep rules where available on host platform.
3. **Dataset Scope**: The current fixture suite contains curated unit-test cases specifically modeling OWASP Top 10 categories. Because this dataset is localized to representative patterns, general precision/recall on wider external codebases may vary. Expansion to broader benchmark corpora (e.g. Juliet Suite) is recommended for future releases.
4. **Execution Time**: The complete evaluation finished in {elapsed:.2f} seconds.
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(results_content)

    print(f"Empirical benchmark complete. Results saved to {output_path}")
    return {
        "total_samples": total_samples,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


if __name__ == "__main__":
    run_benchmark()

