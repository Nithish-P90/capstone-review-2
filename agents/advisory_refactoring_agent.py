# agents/advisory_refactoring_agent.py

import re

from rich.progress import track
from agents.categorization_agent import call_ollama

_FIXED_RE  = re.compile(r'FIXED:\s*```(?:c|cpp)?\s*(.*?)```', re.DOTALL | re.IGNORECASE)
_CHANGE_RE = re.compile(r'CHANGE:\s*(.+)',                    re.DOTALL)


def build_advisory_prompt(code: str, cwe_id: str, explanation: str) -> str:
    return f"""You are a C security expert. Provide a minimal, correct fix for this vulnerability.

Vulnerable code:
```c
{code}
```

Issue: {cwe_id} — {explanation}

Reply using EXACTLY this format (no extra text):
FIXED:
```c
<corrected code here>
```
CHANGE: <one sentence describing what you changed>"""


def parse_advisory_response(response_text: str) -> dict:
    """
    Extract FIXED code block and CHANGE description from LLM response.
    Falls back gracefully if the format is not followed.
    """
    fixed_match  = _FIXED_RE.search(response_text)
    change_match = _CHANGE_RE.search(response_text)

    fixed_code      = fixed_match.group(1).strip()  if fixed_match  else None
    fix_description = change_match.group(1).strip().split("\n")[0] if change_match else None

    return {
        "fixed_code":      fixed_code      or response_text.strip(),
        "fix_description": fix_description or "See suggested fix above.",
    }


def advise_finding(finding: dict) -> dict:
    """
    Add 'fixed_code' and 'fix_description' keys to the finding.
    Never raises — returns the original code + a fallback message on failure.
    """
    try:
        prompt   = build_advisory_prompt(
            finding["code"],
            finding["cwe_id"],
            finding.get("explanation", finding["description"]),
        )
        response = call_ollama(prompt)
        advisory = parse_advisory_response(response)
    except RuntimeError:
        advisory = {
            "fixed_code":      finding["code"],
            "fix_description": "[Advisory unavailable — Ollama not reachable]",
        }

    return {**finding, **advisory}


def advise_findings(explained: list) -> list:
    """Run advise_finding over all explained findings with a progress bar."""
    return [
        advise_finding(f)
        for f in track(explained, description="  Generating advisories...")
    ]
