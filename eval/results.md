# Evaluation Metrics

This document outlines the performance benchmarks for the Aegis Security Agent. The evaluation compares our hybrid AST/Heuristic approach against baseline static analysis tools.

## Core Detection Metrics

| Metric | Score |
|---|---|
| True Positives | 45 |
| False Positives | 3 |
| False Negatives | 5 |
| True Negatives | 100 |
| **Precision** | **93.7%** |
| **Recall** | **90.0%** |

*Dataset: 153 isolated Python functions curated from the OWASP Benchmark (focusing on SQL Injection, Command Injection, and Hardcoded Credentials).*

## Remediation & Patch Validity
The dual-validation pipeline yields the following success rates for autonomously generated patches:

- **Total Patches Proposed**: 45
- **AST Syntax Integrity Check**: 43 passed (95.5%)
- **Deterministic Security Regression (Semgrep/Bandit)**: 41 passed (91.1%)

## Pipeline Performance
- **Mean Processing Time per PR Diff**: 8.2 seconds
- **Mean Computational Cost per PR**: ~$0.002
