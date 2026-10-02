# Aegis: Autonomous Code Security & Health Agent

Aegis is an AST-aware DevSecOps pipeline agent designed to parse Pull Request diffs, identify security vulnerabilities (e.g., OWASP Top 10), and autonomously propose validated, syntax-correct patches.

## Architecture

Aegis departs from standard static analysis workflows by combining AST parsing with dynamic heuristic analysis. It utilizes a dual-validation pipeline to guarantee that proposed patches do not disrupt the target repository's build state.

### Core Capabilities
- **Precision AST Mapping**: Utilizes `tree-sitter` (and language-specific bindings like `tree-sitter-python`) to isolate modified code blocks at the function level, minimizing processing overhead.
- **Dual-Validation Engine**: All generated patches are subjected to a rigorous two-stage validation process:
  1. **Syntax Integrity**: Patched code is verified against the AST to prevent compilation or runtime syntax failures.
  2. **Security Regression Analysis**: The patched block is re-scanned using deterministic tools (Semgrep/Bandit) to empirically prove the vulnerability has been neutralized.
- **Pre-Analysis Redaction**: Built-in masking layers automatically strip IP addresses and sensitive tokens before heuristic analysis occurs.

## Installation & Setup

Aegis requires Python 3.10 or higher.

```bash
# Clone the repository
git clone https://github.com/your-org/security-agent.git
cd security-agent

# Initialize the environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
# For development and testing environments:
# pip install -e .[dev]

# Configure environment variables
cp .env.example .env
```

## Configuration

System parameters and model configurations are managed dynamically via `src/agent/config.py`. Environment variables are loaded through the `.env` file.

*Note: Ensure your `.env` file is never committed to version control.*

## Benchmarks & Evaluation

We prioritize empirical validation. Continuous benchmarking is conducted against a curated subset of the OWASP vulnerability dataset. Aegis tracks precision, recall, false-positive rates, and patch validity metrics.

For the latest performance metrics, refer to [eval/results.md](eval/results.md).

## Current Scope & Limitations
- **Language Support**: Currently optimized for Python environments. Support for JavaScript/TypeScript and Go is roadmapped for the next major release.
- **Detection Scope**: The current ruleset prioritizes SQL Injection, Command Injection, and Hardcoded Credentials.

## License
Distributed under the MIT License. See `LICENSE` for more information.
