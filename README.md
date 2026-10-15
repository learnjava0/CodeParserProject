# Aegis: Autonomous Code Security & Health Agent

Aegis is an AST-aware DevSecOps pipeline agent designed to analyze GitHub Pull Request diffs, detect application security vulnerabilities (including OWASP Top 10 categories), and propose validated, syntax-checked remediation patches.

---

## Capabilities & Architecture

Aegis combines concrete static analysis with AST parsing and optional LLM-assisted verification:

```
[ GitHub Pull Request ]
          │
          ▼
 [ PRClient & Unified Diff Parser ] ──> Isolates Added / Modified Lines
          │
          ▼
 [ AST Parser (Tree-sitter) ] ────────> Maps Changed Lines to Enclosing Functions
          │
    ┌─────┴─────────────────────────────────┐
    ▼                                       ▼
[ Deterministic Scanners ]        [ Optional Gemini LLM Analysis ]
(Bandit / Semgrep with timeouts)  (With Secret Redaction & Retries)
    └─────┬─────────────────────────────────┘
          ▼
[ Finding Aggregation & Deduplication ]
          │
          ▼
[ Multi-Stage Patch Validator ] ──────> Validates Syntax & Checks Security Neutralization
          │
          ▼
[ Review Comment Publisher ] ─────────> Posts Inline / Summary Reviews & GitHub Actions Step Summary
```

### Core Features
- **Diff-Aware Function Isolation**: Uses `tree-sitter` and `tree-sitter-python` to map changed lines in unified diffs directly to affected function boundaries, async functions, class methods, and nested functions—avoiding unnecessary scanning of unchanged repository code.
- **Multi-Stage Patch Validation**: Validates all suggested remediation code in an isolated temporary environment across syntax parsing and security re-scanning before presenting it to developers.
- **Fail-Safe Security Architecture**: Transparently records scanner statuses (`completed`, `findings_detected`, `incomplete`, `failed`, `skipped`). Missing tools, timeouts, or API errors are never mistaken for clean/secure code.
- **Pre-Analysis Secret Redaction**: Automatically masks private keys, AWS access keys, GitHub tokens, passwords, and IP addresses before transmitting data to external services.
- **Automated GitHub Review Publishing**: Publishes inline comments, handles deduplication across workflow re-runs with persistent finding tags, and gracefully falls back to GitHub Step Summaries for forked PRs with restricted token scopes.

---

## Supported Scope

| Dimension | Supported | Roadmapped |
|---|---|---|
| **Languages** | Python (3.10+) | JavaScript / TypeScript, Go |
| **Vulnerabilities** | SQL Injection (CWE-89), Command Injection (CWE-78), Hardcoded Credentials (CWE-259) | Path Traversal, Insecure Deserialization |
| **Scanners** | Bandit, Semgrep (Linux/macOS/WSL), Google Gemini API | CodeQL |

---

## Installation & Setup

### Prerequisites
- Python 3.10, 3.11, or 3.12 (Python 3.12 recommended)
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/learnjava0/CodeParserProject.git
cd CodeParserProject

# Initialize virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"
```

---

## Configuration

Configure environment variables via `.env` or CI secrets (see `.env.example`):

```bash
cp .env.example .env
```

| Variable | Description | Required | Default |
|---|---|---|---|
| `GITHUB_TOKEN` | GitHub Personal Access Token or Actions workflow token for PR retrieval and reviews | Yes (for PR analysis) | `None` |
| `GEMINI_API_KEY` | Google Gemini API key for LLM-assisted vulnerability analysis | No (optional) | `None` |
| `MODEL_NAME` | Gemini model identifier | No | `gemini-2.5-pro` |

### Deterministic-Only Mode (No Gemini API Key)
Aegis does not require a paid Gemini API key to operate. If `GEMINI_API_KEY` is omitted, Aegis runs exclusively in deterministic mode using Bandit (and Semgrep where available). Deterministic results are never misrepresented as completed LLM analyses.

---

## CLI Usage

### 1. Local File Analysis
```bash
# Scan a single local Python file (deterministic + LLM if configured)
python -m src.agent.main --file path/to/script.py

# Scan using deterministic scanners only
python -m src.agent.main --file path/to/script.py --no-llm

# Export structured findings to JSON
python -m src.agent.main --file path/to/script.py --output findings.json
```

### 2. GitHub Pull Request Analysis
```bash
# Review a pull request and publish inline review comments
python -m src.agent.main --repo owner/repository --pr 42

# Read-only PR scan without publishing review comments
python -m src.agent.main --repo owner/repository --pr 42 --no-publish --output pr-report.json

# Fail with exit code 2 if security findings are detected (ideal for CI gates)
python -m src.agent.main --repo owner/repository --pr 42 --fail-on-findings
```

---

## GitHub Actions Integration

Aegis includes an operational workflow in `.github/workflows/agent.yml` that triggers on pull requests:

```yaml
name: Security Agent Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  scan:
    name: Aegis Security Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install -e ".[dev]"
      - name: Run Review Pipeline
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: |
          python -m src.agent.main \
            --repo "${{ github.repository }}" \
            --pr "${{ github.event.pull_request.number }}" \
            --output aegis-findings.json
```

### Forked PR Security
For pull requests from external forks, GitHub Actions defaults to read-only token permissions. Aegis automatically detects `403 Forbidden` errors during comment publishing, prevents pipeline failure, records findings in the **GitHub Actions Step Summary** (`$GITHUB_STEP_SUMMARY`), and attaches the complete report as an artifact.

---

## Example Review Output

When a security vulnerability is identified, Aegis generates structured feedback:

```markdown
### 🛡️ Aegis Security Finding: SQL Injection
- **Severity:** High
- **Scanner:** `bandit` (Rule: B608)
- **Target Line:** 8

**Details:**
Possible SQL injection vector through string-based query construction.

**Recommendation:**
Use parameterized queries, prepared statements, or ORM parameter binding rather than string formatting or concatenation.

> **Validation:** Remediation suggestion passed the available syntax and security checks.

**Suggested Patch:**
```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```
<!-- aegis-finding-id: app/db.py:8:SQL_Injection:B608 -->
```

---

## Testing & Quality Assurance

Ensure all linting, typing, and unit tests pass prior to submitting contributions:

```bash
# 1. Lint with Ruff
ruff check src/ tests/

# 2. Type check with Mypy
mypy src/

# 3. Execute Pytest suite
pytest tests/ -v
```

---

## Empirical Benchmarks

Aegis is continuously evaluated against labeled test fixtures:
- Benchmark runner: `python eval/benchmark.py`
- Latest empirical results and methodology: [eval/results.md](eval/results.md)

---

## Security Limitations & Responsible Disclosure

- **Non-Exhaustive Guarantee**: Aegis is an automated static and heuristic scanning assistant. Passing scans does **not** guarantee code is free from all security vulnerabilities or business logic flaws.
- **Untrusted Code Execution**: Aegis never executes code originating from pull requests. Patches and AST structures are parsed and analyzed purely as passive data.
- **Reporting Vulnerabilities**: If you discover a vulnerability in Aegis itself, please refer to [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

