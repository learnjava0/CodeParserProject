import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY = Language(tspython.language())
parser = Parser(PY)

def extract_functions(source: bytes) -> list[dict]:
    tree = parser.parse(source)
    out = []
    
    def walk(node):
        if node.type == "function_definition":
            out.append({
                "name": node.child_by_field_name("name").text.decode() if node.child_by_field_name("name") else "unknown",
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "code": node.text.decode(),
            })
        for c in node.children:
            walk(c)
            
    walk(tree.root_node)
    return out
