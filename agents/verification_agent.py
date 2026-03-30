# agents/verification_agent.py

from rich.console import Console
from rag.dataset_retriever import query_dataset

console = Console()


def verify_finding(finding: dict):
    """
    Cross-check a finding against the labeled security dataset.

    Keep rules:
      - verdict == "vulnerable"                          → keep
      - verdict == "ambiguous"  AND confidence > 0.6    → keep
      - verdict == "false_positive" AND confidence >= 0.75 → discard
      - anything else (low-confidence ambiguous)         → discard

    Returns the enriched finding dict, or None if discarded.
    """
    try:
        result = query_dataset(finding["code"], finding["cwe_id"], top_k=10,
                               language=finding.get("language", "C"))
    except Exception as e:
        console.print(f"[yellow]  [verification] Dataset query failed for "
                      f"{finding['function_name']}: {e}[/yellow]")
        # On error, keep the finding (don't silently discard)
        return {**finding, "verdict": "ambiguous", "confidence": 0.0, "top_matches": []}

    verdict    = result["verdict"]
    confidence = result["confidence"]

    if verdict == "false_positive" and confidence >= 0.75:
        return None

    if verdict == "ambiguous" and confidence <= 0.6:
        return None

    return {
        **finding,
        "verdict":     verdict,
        "confidence":  confidence,
        "top_matches": result["top_matches"],
    }


def verify_findings(findings: list) -> list:
    """
    Run verify_finding over all findings and return only confirmed ones.
    """
    verified = []
    for finding in findings:
        result = verify_finding(finding)
        if result is not None:
            verified.append(result)

    console.print(
        f"  Verified [bold green]{len(verified)}[/bold green] / "
        f"{len(findings)} findings (discarded {len(findings) - len(verified)} false positives)"
    )
    return verified
