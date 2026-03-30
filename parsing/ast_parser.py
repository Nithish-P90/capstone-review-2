# parsing/ast_parser.py

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

# Initialise once at import time (avoid repeated overhead)
C_LANGUAGE = Language(tsc.language())
_parser = Parser(C_LANGUAGE)


def _find_function_name(node) -> str:
    """
    Recursively walk a declarator node to find the identifier (function name).
    tree-sitter C grammar nests: function_declarator → pointer_declarator → identifier
    """
    if node.type == "identifier":
        return node.text.decode("utf-8")
    for child in node.children:
        result = _find_function_name(child)
        if result:
            return result
    return ""


def _extract_functions(tree, source_bytes: bytes, file_path: str) -> list:
    """Walk the CST and collect all function_definition nodes."""
    functions = []

    def walk(node):
        if node.type == "function_definition":
            # Find the declarator child to get the function name
            name = ""
            for child in node.children:
                if child.type in ("function_declarator", "pointer_declarator",
                                  "abstract_declarator", "declarator"):
                    name = _find_function_name(child)
                    if name:
                        break

            if not name:
                # Last resort: grab first identifier in the node
                for child in node.children:
                    if child.type == "identifier":
                        name = child.text.decode("utf-8")
                        break

            start_line = node.start_point[0] + 1  # 0-indexed → 1-indexed
            end_line   = node.end_point[0]   + 1
            code       = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

            functions.append({
                "name":       name or "<anonymous>",
                "code":       code,
                "start_line": start_line,
                "end_line":   end_line,
                "file_path":  file_path,
            })

        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return functions


def parse_c_file(file_path: str) -> list:
    """
    Parse a C/C++ source file and extract all top-level function definitions.

    Parameters
    ----------
    file_path : str
        Path to a .c or .cpp file.

    Returns
    -------
    list of dict with keys: name, code, start_line, end_line, file_path
    Returns [] on any read or parse error.
    """
    try:
        source_bytes = open(file_path, "rb").read()
    except (OSError, IOError) as e:
        print(f"[ast_parser] Cannot read {file_path}: {e}")
        return []

    try:
        tree = _parser.parse(source_bytes)
    except Exception as e:
        print(f"[ast_parser] Parse error on {file_path}: {e}")
        return []

    if tree.root_node.has_error:
        print(f"[ast_parser] Warning: parse errors in {file_path} — extracting what we can")

    return _extract_functions(tree, source_bytes, file_path)
