# parsing/ast_parser.py
# Uses tree-sitter to extract C/C++ function definitions.

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

_C_LANGUAGE = Language(tsc.language())
_parser = Parser(_C_LANGUAGE)

# Query captures function definitions and their names
_FUNC_QUERY = _C_LANGUAGE.query("""
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name)) @function
""")


def parse_c_file(file_path: str) -> list:
    """
    Parse a C/C++ source file and extract all function definitions using tree-sitter.

    Returns a list of dicts with keys: name, code, start_line, end_line, file_path.
    Returns [] on any read error.
    """
    try:
        with open(file_path, "rb") as f:
            source_bytes = f.read()
    except (OSError, IOError) as e:
        print(f"[ast_parser] Cannot read {file_path}: {e}")
        return []

    tree = _parser.parse(source_bytes)

    raw = _FUNC_QUERY.captures(tree.root_node)

    # tree-sitter 0.22+ returns dict; older versions return list of (node, tag)
    if isinstance(raw, dict):
        func_nodes = raw.get("function", [])
        name_nodes = raw.get("name", [])
    else:
        func_nodes = [n for n, tag in raw if tag == "function"]
        name_nodes = [n for n, tag in raw if tag == "name"]

    functions = []
    for func_node in func_nodes:
        # Find the name node that falls within this function's byte range
        name = None
        for name_node in name_nodes:
            if func_node.start_byte <= name_node.start_byte < func_node.end_byte:
                name = source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                break

        if not name:
            continue

        code = source_bytes[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")
        start_line = func_node.start_point[0] + 1  # 0-indexed → 1-indexed
        end_line = func_node.end_point[0] + 1

        if len(code) < 20:
            continue

        functions.append({
            "name": name,
            "code": code,
            "start_line": start_line,
            "end_line": end_line,
            "file_path": file_path,
        })

    return functions
