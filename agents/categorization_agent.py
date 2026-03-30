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

# Same 15 CWEs targeted by the NVD ingestion pipeline
TARGET_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122",
    "CWE-125", "CWE-787", "CWE-416", "CWE-415",
    "CWE-476", "CWE-190", "CWE-191", "CWE-134",
    "CWE-362", "CWE-78",  "CWE-20",
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
def build_categorization_prompt(code: str) -> str:
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
def categorize_function(function_info: dict) -> list:
    """
    Ask Ollama to identify vulnerabilities in a single function.
    Returns a list of Finding dicts (one per detected CWE), or [] on failure.
    """
    try:
        prompt   = build_categorization_prompt(function_info["code"])
        response = call_ollama(prompt)
        parsed   = parse_llm_json(response)
    except RuntimeError as e:
        print(f"\n[categorization] Ollama error on {function_info['name']}: {e}")
        return []

    findings = []
    for vuln in parsed.get("vulnerabilities", []):
        cwe_id = vuln.get("cwe_id", "").upper().replace(" ", "-")
        if cwe_id not in TARGET_CWES:
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
            "cwe_id":        cwe_id,
            "severity":      severity,
            "description":   description,
            "cve_matches":   cve_matches,
        })

    return findings


def categorize_functions(functions: list) -> list:
    """
    Run categorize_function over all parsed functions.
    Returns a flat list of all Finding dicts.
    """
    all_findings = []
    for fn in track(functions, description="  Analyzing functions..."):
        findings = categorize_function(fn)
        all_findings.extend(findings)
    return all_findings
