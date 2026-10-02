# Contributing Guidelines

We welcome external contributions to the Aegis Security Agent. To maintain codebase integrity, please adhere to the following workflow.

## Local Development Setup
1. Fork and clone the repository.
2. Initialize your virtual environment and install the development dependencies:
   ```bash
   pip install -e .[dev]
   ```
3. Prior to submitting a Pull Request, ensure the following local checks pass:
   - Linting: `ruff check src/`
   - Type Checking: `mypy src/`
   - Unit Tests: `pytest tests/`

## Extending Language Support
To introduce support for a new programming language, follow this implementation path:
1. Append the requisite `tree-sitter` language binding to `pyproject.toml`.
2. Implement a new AST parsing module within `src/agent/parser/`.
3. Integrate the target language's deterministic rulesets (e.g., Semgrep configurations) into `src/agent/scanners/deterministic.py`.
4. Supply comprehensive test fixtures (both vulnerable and secure variants) in `tests/fixtures/`.

## Pull Request Lifecycle
1. Ensure your branch name follows standard conventions (e.g., `feat/add-go-support`, `fix/ast-parsing-bug`).
2. Verify that the automated CI pipeline (`.github/workflows/ci.yml`) passes successfully.
3. Provide a detailed summary of the architectural changes in your Pull Request description.
4. All Pull Requests require at least one approving review from a core maintainer before merging into the `main` branch.
