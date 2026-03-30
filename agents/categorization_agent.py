# agents/categorization_agent.py

import json
import re

import requests
from rich.progress import track

from rag.threat_retriever import query_threat_db

# ─── Ollama config ─────────────────────────────────────────
OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "deepseek-coder:6.7b"
OLLAMA_TIMEOUT = 120  # seconds

# C/C++ CWEs (memory safety, injection)
TARGET_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122",
    "CWE-125", "CWE-787", "CWE-416", "CWE-415",
    "CWE-476", "CWE-190", "CWE-191", "CWE-134",
    "CWE-362", "CWE-78",  "CWE-20",
}

# Python CWEs (injection, deserialization, web security)
PYTHON_TARGET_CWES = {
    "CWE-89",   # SQL Injection
    "CWE-79",   # Cross-site Scripting (XSS)
    "CWE-22",   # Path Traversal
    "CWE-502",  # Deserialization of Untrusted Data (pickle, yaml.load)
    "CWE-94",   # Code Injection (eval, exec, compile)
    "CWE-78",   # OS Command Injection (shared with C set)
    "CWE-798",  # Hard-coded Credentials
    "CWE-312",  # Cleartext Storage of Sensitive Information
    "CWE-20",   # Improper Input Validation (shared with C set)
    "CWE-918",  # Server-Side Request Forgery (SSRF)
}

# ─── Ollama wrapper ────────────────────────────────────────
def call_ollama(prompt: str, timeout: int = OLLAMA_TIMEOUT) -> str:
    """
    POST a prompt to the local Ollama instance.
    Raises RuntimeError on connection failure, timeout, or bad response.
    """
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()["response"]
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Cannot reach Ollama at localhost:11434. "
            "Run: ollama serve  (then: ollama pull deepseek-coder:6.7b)"
        )
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Ollama timed out after {timeout}s")
    except (KeyError, ValueError) as e:
        raise RuntimeError(f"Malformed Ollama response: {e}")

# ─── Prompt builders ───────────────────────────────────────
def _build_c_prompt(code: str) -> str:
    return f"""You are a C/C++ security vulnerability analyzer.

Analyze this function for security vulnerabilities:
```c
{code}
```

Check for these vulnerability types ONLY:
- CWE-119/120/121/122/125: Buffer overflow / overread
- CWE-787: Out-of-bounds write
- CWE-416/415: Use-after-free / double free
- CWE-476: Null pointer dereference
- CWE-190/191: Integer overflow / underflow
- CWE-134: Format string vulnerability
- CWE-362: Race condition
- CWE-78: OS command injection
- CWE-20: Improper input validation

Respond with JSON ONLY — no explanation, no markdown, no extra text:
{{"vulnerabilities": [{{"cwe_id": "CWE-120", "severity": "HIGH", "description": "brief one-line reason"}}]}}
If no vulnerabilities found: {{"vulnerabilities": []}}"""


def _build_python_prompt(code: str) -> str:
    return f"""You are a Python security vulnerability analyzer.

Analyze this function for security vulnerabilities:
```python
{code}
```

Check for these vulnerability types ONLY:
- CWE-89: SQL Injection (string-formatted queries, no parameterization)
- CWE-79: Cross-site Scripting (unescaped user input in HTML output)
- CWE-22: Path Traversal (user-controlled file paths, os.path.join with untrusted input)
- CWE-502: Deserialization (pickle.loads, yaml.load without Loader, marshal.loads)
- CWE-94: Code Injection (eval, exec, compile with user input)
- CWE-78: OS Command Injection (subprocess, os.system with unsanitized input)
- CWE-798: Hard-coded Credentials (passwords, API keys, tokens in source)
- CWE-312: Cleartext Storage (sensitive data written to logs or files unencrypted)
- CWE-20: Improper Input Validation (missing bounds/type checks on external input)
- CWE-918: SSRF (user-controlled URLs passed to requests.get or urllib)

Respond with JSON ONLY — no explanation, no markdown, no extra text:
{{"vulnerabilities": [{{"cwe_id": "CWE-89", "severity": "HIGH", "description": "brief one-line reason"}}]}}
If no vulnerabilities found: {{"vulnerabilities": []}}"""


def build_categorization_prompt(code: str, language: str = "C") -> str:
    if language == "Python":
        return _build_python_prompt(code)
    return _build_c_prompt(code)

# ─── JSON parser ───────────────────────────────────────────
def parse_llm_json(response_text: str) -> dict:
    """
    Extract JSON from LLM output.
    Primary: json.loads() on the full response.
    Fallback: regex to find first {...} block.
    Returns {"vulnerabilities": []} on total failure.
    """
    try:
        return json.loads(response_text.strip())
    except json.JSONDecodeError:
        pass

    match = re.search(r'\{.*\}', response_text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return {"vulnerabilities": []}

# ─── Core agent logic ──────────────────────────────────────
def categorize_function(function_info: dict, language: str = "C") -> list:
    """
    Ask Ollama to identify vulnerabilities in a single function.
    Returns a list of Finding dicts (one per detected CWE), or [] on failure.
    """
    try:
        prompt   = build_categorization_prompt(function_info["code"], language)
        response = call_ollama(prompt)
        parsed   = parse_llm_json(response)
    except RuntimeError as e:
        print(f"\n[categorization] Ollama error on {function_info['name']}: {e}")
        return []

    active_cwes = PYTHON_TARGET_CWES if language == "Python" else TARGET_CWES

    findings = []
    for vuln in parsed.get("vulnerabilities", []):
        cwe_id = vuln.get("cwe_id", "").upper().replace(" ", "-")
        if cwe_id not in active_cwes:
            continue

        description = vuln.get("description", "")
        severity    = vuln.get("severity", "MEDIUM").upper()

        # Cross-reference NVD for matching CVEs
        try:
            cve_results = query_threat_db(description, top_k=5)
            cve_matches = [r.payload for r in cve_results]
        except Exception:
            cve_matches = []

        findings.append({
            "function_name": function_info["name"],
            "code":          function_info["code"],
            "start_line":    function_info["start_line"],
            "end_line":      function_info["end_line"],
            "file_path":     function_info["file_path"],
            "language":      language,
            "cwe_id":        cwe_id,
            "severity":      severity,
            "description":   description,
            "cve_matches":   cve_matches,
        })

    return findings


def categorize_functions(functions: list, language: str = "C") -> list:
    """
    Run categorize_function over all parsed functions.
    Returns a flat list of all Finding dicts.
    """
    all_findings = []
    for fn in track(functions, description="  Analyzing functions..."):
        findings = categorize_function(fn, language)
        all_findings.extend(findings)
    return all_findings
