# parsing/ast_parser.py
# Uses regex + brace-depth walking to extract C/C++ function definitions.
# This approach is dependency-free and works reliably on structured C code.

import re

# Matches standard C/C++ function signatures:
#   return_type function_name(params) {   OR
#   return_type function_name(params)\n{
_FUNC_RE = re.compile(
    r'^\s*'
    r'(?:static\s+|inline\s+|extern\s+|__attribute__\s*\(.*?\)\s*)*'  # optional qualifiers
    r'(?:const\s+)?'
    r'(?:unsigned\s+|signed\s+|long\s+|short\s+)*'                    # type qualifiers
    r'(?:void|int|char|float|double|long|short|bool|size_t|ssize_t'
    r'|uint\w*|int\w*|FILE|struct\s+\w+|\w+_t|\w+)\s*\*{0,2}\s*'     # return type
    r'(\w+)\s*'                                                         # function name ← group 1
    r'\([^;{]*\)\s*\{?\s*$',                                           # params + optional {
    re.MULTILINE,
)


def _extract_functions(text: str, file_path: str) -> list:
    """
    Extract function definitions from C/C++ source text using
    regex matching + brace-depth walking.
    """
    functions = []

    for match in _FUNC_RE.finditer(text):
        func_name = match.group(1)

        # Skip common false positives (macros, keywords mistaken for functions)
        if func_name in {"if", "while", "for", "switch", "else", "return",
                         "sizeof", "typedef", "struct", "enum", "union"}:
            continue

        # Find opening brace — may be on same line as signature or next line
        brace_pos = text.find("{", match.start())
        if brace_pos == -1:
            continue

        # Walk braces to find matching closing brace
        depth = 0
        end_pos = brace_pos
        for i in range(brace_pos, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_pos = i + 1
                    break
        else:
            continue  # unmatched brace — skip

        # Calculate 1-indexed line numbers
        start_line = text[:match.start()].count("\n") + 1
        end_line   = text[:end_pos].count("\n") + 1
        code       = text[match.start():end_pos].strip()

        # Skip very short snippets (likely false positive matches)
        if len(code) < 20 or code.count("\n") < 1:
            continue

        functions.append({
            "name":       func_name,
            "code":       code,
            "start_line": start_line,
            "end_line":   end_line,
            "file_path":  file_path,
        })

    return functions


def parse_python_file(file_path: str) -> list:
    """
    Parse a Python source file and extract all function definitions
    (including async functions) using the stdlib ast module.

    Parameters
    ----------
    file_path : str
        Path to a .py file.

    Returns
    -------
    list of dict with keys: name, code, start_line, end_line, file_path
    Returns [] on any read or syntax error.
    """
    import ast as _ast

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except (OSError, IOError) as e:
        print(f"[ast_parser] Cannot read {file_path}: {e}")
        return []

    try:
        tree = _ast.parse(source, filename=file_path)
    except SyntaxError as e:
        print(f"[ast_parser] SyntaxError in {file_path}: {e}")
        return []

    functions = []
    for node in _ast.walk(tree):
        if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue

        start_line = node.lineno
        end_line   = getattr(node, "end_lineno", node.lineno)

        # Extract source text for this function
        code = _ast.get_source_segment(source, node)
        if code is None:
            # Fallback for Python < 3.8
            lines = source.splitlines()
            code  = "\n".join(lines[start_line - 1:end_line])

        if not code or len(code) < 10:
            continue

        functions.append({
            "name":       node.name,
            "code":       code,
            "start_line": start_line,
            "end_line":   end_line,
            "file_path":  file_path,
        })

    return functions


def parse_c_file(file_path: str) -> list:
    """
    Parse a C/C++ source file and extract all function definitions.

    Parameters
    ----------
    file_path : str
        Path to a .c, .cpp, or .h file.

    Returns
    -------
    list of dict with keys: name, code, start_line, end_line, file_path
    Returns [] on any read error.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except (OSError, IOError) as e:
        print(f"[ast_parser] Cannot read {file_path}: {e}")
        return []

    return _extract_functions(text, file_path)
