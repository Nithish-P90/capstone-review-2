# agents/explainable_ai_agent.py

from rich.progress import track
from agents.categorization_agent import call_ollama


def _format_cve_context(cve_matches: list) -> str:
    if not cve_matches:
        return "No related CVEs retrieved."
    lines = []
    for m in cve_matches[:3]:
        cve_id  = m.get("cve_id", "N/A")
        sev     = m.get("severity", "N/A")
        desc    = (m.get("description") or "")[:100]
        lines.append(f"- {cve_id} ({sev}): {desc}")
    return "\n".join(lines)


def build_explanation_prompt(code: str, cwe_id: str, description: str, cve_matches: list) -> str:
    cve_context = _format_cve_context(cve_matches)
    return f"""You are a security educator explaining a vulnerability to a developer.

Vulnerable code:
```c
{code}
```

Vulnerability: {cwe_id} — {description}

Related CVEs for context:
{cve_context}

In 2-3 clear sentences, explain:
1. What specifically makes this code vulnerable
2. What an attacker could do to exploit it

Be concrete and specific. Do not repeat the CVE IDs. Plain text only, no markdown."""


def explain_finding(finding: dict) -> dict:
    """
    Add an 'explanation' key to the finding.
    Never raises — returns a fallback string on Ollama failure.
    """
    try:
        prompt      = build_explanation_prompt(
            finding["code"],
            finding["cwe_id"],
            finding["description"],
            finding.get("cve_matches", []),
        )
        explanation = call_ollama(prompt).strip()
    except RuntimeError as e:
        explanation = f"[Explanation unavailable] {finding['cwe_id']}: {finding['description']}"

    return {**finding, "explanation": explanation}


def explain_findings(verified: list) -> list:
    """Run explain_finding over all verified findings with a progress bar."""
    return [
        explain_finding(f)
        for f in track(verified, description="  Generating explanations...")
    ]
