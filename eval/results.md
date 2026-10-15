# Aegis Security Agent — Empirical Benchmark Results

This document contains empirical performance and accuracy metrics collected by running the Aegis AST and deterministic scanning pipeline against labeled test fixtures.

## Core Detection Metrics

| Metric | Measured Value |
|---|---|
| Dataset Size | 6 labeled sample functions |
| True Positives (TP) | 3 |
| True Negatives (TN) | 2 |
| False Positives (FP) | 1 |
| False Negatives (FN) | 0 |
| **Precision** | **75.0%** |
| **Recall** | **100.0%** |
| **F1 Score** | **85.7%** |

*Evaluated on Python fixtures covering SQL Injection (CWE-89), Command Injection (CWE-78), and Hardcoded Credentials (CWE-259).*

## Patch Validation Metrics

| Metric | Result |
|---|---|
| Total Patches Evaluated | 3 |
| Syntax Validation Rate (AST) | 2 / 3 (66.7%) |
| Security Regression Re-scan Passed | 1 / 3 (33.3%) |

## Evaluation Methodology & Limitations

1. **Methodology**: Benchmarking evaluates the end-to-end AST function extraction, unified diff mapping, and deterministic Bandit/Semgrep vulnerability analysis against labeled ground truth (`tests/fixtures/vulnerable.py` and `tests/fixtures/secure.py`).
2. **Scanner Coverage**: Deterministic analysis utilizes Bandit plugins (`B608`, `B605`, `B105`) and Semgrep rules where available on host platform.
3. **Dataset Scope**: The current fixture suite contains curated unit-test cases specifically modeling OWASP Top 10 categories. Because this dataset is localized to representative patterns, general precision/recall on wider external codebases may vary. Expansion to broader benchmark corpora (e.g. Juliet Suite) is recommended for future releases.
4. **Execution Time**: The complete evaluation finished in 2.04 seconds.
