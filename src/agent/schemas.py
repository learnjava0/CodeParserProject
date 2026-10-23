from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    COMPLETED = "completed"
    FINDINGS_DETECTED = "findings_detected"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    SKIPPED = "skipped"


class Finding(BaseModel):
    vuln_type: str
    severity: Literal["low", "medium", "high", "critical"]
    line_start: int
    line_end: int
    explanation: str
    confidence: float = 1.0
    suggested_fix: str | None = None
    rule_id: str | None = None
    scanner_source: str = "llm"  # "bandit", "semgrep", "gemini", etc.
    file_path: str | None = None
    remediation: str | None = None
    patch_validation: dict[str, Any] | None = None
    diff_position: int | None = None  # Position in GitHub PR diff for review comments

    @property
    def identifier(self) -> str:
        """Stable unique fingerprint for comment deduplication."""
        safe_type = self.vuln_type.replace(" ", "_")
        return f"{self.file_path or 'unknown'}:{self.line_start}:{safe_type}:{self.rule_id or 'default'}"


class ScannerResult(BaseModel):
    scanner_name: str
    status: ScanStatus
    findings: list[Finding] = Field(default_factory=list)
    execution_time_seconds: float = 0.0
    error_message: str | None = None


class PatchValidationResult(BaseModel):
    is_valid: bool
    syntax_valid: bool
    security_passed: bool
    scanner_results: list[ScannerResult] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
    cleaned_code: str | None = None


class FileDiff(BaseModel):
    filename: str
    status: str = "modified"  # "added", "modified", "renamed", "removed"
    old_filename: str | None = None
    changed_lines: list[int] = Field(default_factory=list)
    patch: str | None = None
    raw_content: str | None = None
    line_to_diff_position: dict[int, int] = Field(default_factory=dict)


class PRAnalysisReport(BaseModel):
    repo_name: str
    pr_number: int
    head_sha: str
    base_sha: str
    files_scanned: list[str] = Field(default_factory=list)
    total_findings: int = 0
    findings: list[Finding] = Field(default_factory=list)
    scanner_statuses: dict[str, ScanStatus] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    published_comments: int = 0

