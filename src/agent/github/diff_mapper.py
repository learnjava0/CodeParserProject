import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

HUNK_HEADER_REGEX = re.compile(r"^@@\s+-(?:\d+)(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@")


@dataclass
class DiffMappingResult:
    """Structured mapping of unified diff to file lines and AST functions."""
    changed_lines: list[int] = field(default_factory=list)
    line_to_diff_position: dict[int, int] = field(default_factory=dict)
    overlapping_functions: list[dict[str, Any]] = field(default_factory=list)
    unscoped_lines: list[int] = field(default_factory=list)


def parse_unified_diff(patch: str) -> tuple[list[int], dict[int, int]]:
    """
    Parses a unified diff string (e.g. from git diff or GitHub API).
    Returns:
        (changed_lines, line_to_diff_position)
        - changed_lines: List of line numbers in the new file that were added or modified.
        - line_to_diff_position: Mapping from new file line number to 1-based GitHub diff position.
    """
    if not patch:
        return [], {}

    changed_lines: list[int] = []
    line_to_diff_position: dict[int, int] = {}

    lines = patch.splitlines()
    diff_position = 0
    current_new_line = 0
    in_hunk = False

    for line in lines:
        diff_position += 1
        hunk_match = HUNK_HEADER_REGEX.match(line)
        if hunk_match:
            in_hunk = True
            current_new_line = int(hunk_match.group(1))
            continue

        if not in_hunk:
            continue

        if line.startswith("+"):
            changed_lines.append(current_new_line)
            line_to_diff_position[current_new_line] = diff_position
            current_new_line += 1
        elif line.startswith("-"):
            # Deletion applies to old file; diff_position still increments
            pass
        elif line.startswith(" ") or line == "":
            # Context line
            line_to_diff_position[current_new_line] = diff_position
            current_new_line += 1
        elif line.startswith("\\"):
            # e.g., "\ No newline at end of file"
            pass

    return sorted(set(changed_lines)), line_to_diff_position


def map_diff_to_functions(
    changed_lines: list[int],
    functions: list[dict[str, Any]],
    line_to_diff_position: dict[int, int] | None = None,
) -> DiffMappingResult:
    """
    Maps changed line numbers to AST function definitions, detecting whether
    changes are contained inside functions or at top-level module scope.
    """
    line_pos = line_to_diff_position or {}
    overlapping: list[dict[str, Any]] = []
    covered_lines: set[int] = set()

    for func in functions:
        start = func.get("start_line", 0)
        end = func.get("end_line", 0)

        # Find which changed lines fall within this function
        func_changed_lines = [l for l in changed_lines if start <= l <= end]
        if func_changed_lines:
            func_copy = dict(func)
            func_copy["modified_lines"] = func_changed_lines
            func_copy["diff_positions"] = [line_pos[l] for l in func_changed_lines if l in line_pos]
            overlapping.append(func_copy)
            covered_lines.update(func_changed_lines)

    # Any changed lines not in any function are unscoped/module-level
    unscoped = [l for l in changed_lines if l not in covered_lines]

    return DiffMappingResult(
        changed_lines=changed_lines,
        line_to_diff_position=line_pos,
        overlapping_functions=overlapping,
        unscoped_lines=unscoped,
    )


def get_overlapping_functions(changed_lines: list[int], functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Backward-compatible function.
    Filters AST-parsed functions to only include those that overlap with the changed lines.
    """
    res = map_diff_to_functions(changed_lines, functions)
    return res.overlapping_functions

