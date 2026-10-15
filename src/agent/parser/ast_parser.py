import logging
from dataclasses import dataclass, field
from typing import Any

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

logger = logging.getLogger(__name__)

# Initialize Python grammar
PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)


@dataclass
class ParseResult:
    """Encapsulates parsing output, extracted functions, and syntax diagnostics."""
    functions: list[dict[str, Any]] = field(default_factory=list)
    has_syntax_errors: bool = False
    syntax_errors: list[str] = field(default_factory=list)


def parse_source(source: bytes | str, language: str = "python") -> ParseResult:
    """
    Parses source code into AST and extracts functions, detecting any syntax errors.
    Designed with a multi-language interface for future language support.

    Args:
        source: The source code as bytes or string.
        language: Language identifier ('python' currently supported).

    Returns:
        ParseResult containing list of functions and syntax error diagnostics.
    """
    if language.lower() != "python":
        logger.warning(f"Language '{language}' is not yet supported for AST parsing. Supported: python")
        return ParseResult(
            functions=[],
            has_syntax_errors=True,
            syntax_errors=[f"Unsupported language: {language}"],
        )

    # Convert to bytes if string
    if isinstance(source, str):
        source_bytes = source.encode("utf-8")
    else:
        source_bytes = source

    if not source_bytes.strip():
        return ParseResult(functions=[], has_syntax_errors=False, syntax_errors=[])

    tree = parser.parse(source_bytes)
    has_error = tree.root_node.has_error
    syntax_errors: list[str] = []

    if has_error:
        # Collect error nodes and diagnostic information
        def find_errors(node):
            if node.type == "ERROR" or node.is_missing:
                line = node.start_point[0] + 1
                col = node.start_point[1] + 1
                err_text = node.text.decode("utf-8", errors="replace") if node.text else "<empty>"
                syntax_errors.append(f"Syntax error at line {line}, col {col}: near '{err_text}'")
            for child in node.children:
                find_errors(child)

        find_errors(tree.root_node)
        if not syntax_errors:
            syntax_errors.append("Syntax error detected in source code AST.")

    out: list[dict[str, Any]] = []

    def walk(node, current_class: str | None = None, func_stack: list[str] | None = None):
        if func_stack is None:
            func_stack = []

        is_func = node.type in ("function_definition", "async_function_definition")
        is_class = node.type == "class_definition"

        next_class = current_class
        next_funcs = list(func_stack)

        if is_class:
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text:
                cls_name = name_node.text.decode("utf-8", errors="replace")
                next_class = f"{current_class}.{cls_name}" if current_class else cls_name

        elif is_func:
            name_node = node.child_by_field_name("name")
            func_name = name_node.text.decode("utf-8", errors="replace") if (name_node and name_node.text) else "unknown"

            # Check if function is async (either async keyword child or async node type)
            is_async = (
                node.type == "async_function_definition"
                or any(child.type == "async" for child in node.children)
            )

            parent_func = func_stack[-1] if func_stack else None
            qualified_parts = []
            if current_class:
                qualified_parts.append(current_class)
            qualified_parts.extend(func_stack)
            qualified_parts.append(func_name)
            qualified_name = ".".join(qualified_parts)

            func_dict: dict[str, Any] = {
                "name": func_name,
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "code": node.text.decode("utf-8", errors="replace") if node.text else "",
                "is_async": is_async,
                "class_name": current_class,
                "parent_function": parent_func,
                "qualified_name": qualified_name,
                "has_error": node.has_error,
            }
            out.append(func_dict)
            next_funcs.append(func_name)

        for child in node.children:
            walk(child, current_class=next_class, func_stack=next_funcs)

    walk(tree.root_node)
    return ParseResult(
        functions=out,
        has_syntax_errors=has_error,
        syntax_errors=syntax_errors,
    )


def extract_functions(source: bytes | str) -> list[dict[str, Any]]:
    """
    Backward-compatible function to extract functions from Python source.
    Returns list of dicts with name, start_line, end_line, and code,
    as well as enriched metadata (is_async, class_name, qualified_name).
    """
    res = parse_source(source, language="python")
    return res.functions

