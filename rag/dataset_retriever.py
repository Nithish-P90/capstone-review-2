# rag/dataset_retriever.py

from statistics import mean

from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue
from sentence_transformers import SentenceTransformer

client = QdrantClient(host="localhost", port=6333)
model = SentenceTransformer("all-MiniLM-L6-v2")
COLLECTION_NAME = "security_dataset"

# Confidence thresholds for the verification agent
THRESHOLD_HIGH = 0.75   # clear signal
THRESHOLD_LOW  = 0.50   # ambiguous — forward with low-confidence flag


def _truncate(text: str, max_chars: int = 512) -> str:
    return text[:max_chars] + "..." if len(text) > max_chars else text


def query_dataset(code_snippet: str, cwe_id: str, top_k: int = 10) -> dict:
    """
    Query the security_dataset collection for code examples similar to
    `code_snippet` filtered to `cwe_id`.

    Returns:
        {
            "verdict":     "vulnerable" | "false_positive" | "ambiguous",
            "confidence":  float (0.0–1.0),
            "top_matches": list of up to 3 payload dicts,
        }
    """
    query_text = f"CWE: {cwe_id} | Language: C\n\n{_truncate(code_snippet)}"
    query_vector = model.encode(query_text).tolist()

    results = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=query_vector,
        query_filter=Filter(
            must=[FieldCondition(key="cwe_id", match=MatchValue(value=cwe_id))]
        ),
        limit=top_k,
        with_payload=True,
    )

    if not results:
        return {"verdict": "ambiguous", "confidence": 0.0, "top_matches": []}

    vuln_scores = [r.score for r in results if r.payload.get("label") == "vulnerable"]
    safe_scores  = [r.score for r in results if r.payload.get("label") == "safe"]

    avg_vuln = mean(vuln_scores) if vuln_scores else 0.0
    avg_safe  = mean(safe_scores)  if safe_scores  else 0.0

    confidence = round(max(avg_vuln, avg_safe), 4)

    if avg_vuln > avg_safe:
        if avg_vuln >= THRESHOLD_HIGH:
            verdict = "vulnerable"
        elif avg_vuln >= THRESHOLD_LOW:
            verdict = "ambiguous"
        else:
            verdict = "ambiguous"
    else:
        if avg_safe >= THRESHOLD_HIGH:
            verdict = "false_positive"
        elif avg_safe >= THRESHOLD_LOW:
            verdict = "ambiguous"
        else:
            verdict = "ambiguous"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "top_matches": [r.payload for r in results[:3]],
    }


def query_dataset_bulk(candidates: list) -> list:
    """
    Run query_dataset for a list of candidate vulnerabilities.

    Each candidate must be a dict with keys:
        - code_snippet (str)
        - cwe_id (str)
        - confidence_score (float, from categorization agent)

    Returns the list enriched with a "verification" key per candidate.
    """
    results = []
    for candidate in candidates:
        verification = query_dataset(
            code_snippet=candidate["code_snippet"],
            cwe_id=candidate["cwe_id"],
        )
        results.append({**candidate, "verification": verification})
    return results
