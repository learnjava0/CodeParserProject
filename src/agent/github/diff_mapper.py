def get_overlapping_functions(changed_lines: list[int], functions: list[dict]) -> list[dict]:
    """
    Filters AST-parsed functions to only include those that overlap with the changed lines in a PR diff.
    This saves tokens and ensures we only analyze modified code blocks.
    
    Args:
        changed_lines: List of line numbers modified in the file.
        functions: List of dictionaries representing functions parsed by tree-sitter.
    
    Returns:
        List of functions that overlap with the changed lines.
    """
    overlapping = []
    for func in functions:
        start = func["start_line"]
        end = func["end_line"]
        # If any of the changed lines fall within the function's boundaries
        if any(start <= line <= end for line in changed_lines):
            overlapping.append(func)
    return overlapping
