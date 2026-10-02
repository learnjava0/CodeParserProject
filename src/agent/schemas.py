from typing import Literal

from pydantic import BaseModel


class Finding(BaseModel):
    vuln_type: str
    severity: Literal["low", "medium", "high", "critical"]
    line_start: int
    line_end: int
    explanation: str
    confidence: float
    suggested_fix: str | None
