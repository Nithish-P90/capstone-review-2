# test_pipeline.py — quick validation without downloading full datasets

import sys
import hashlib
from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue
from sentence_transformers import SentenceTransformer
from statistics import mean

print("=" * 60)
print("  Security Dataset Pipeline — Smoke Test")
print("=" * 60)

# ── 1. Imports from our modules ────────────────────────────
print("\n[1] Testing imports...")
sys.path.insert(0, str(Path(__file__).parent))
from datasets.preprocess_security_datasets import (
    extract_functions, parse_cwe_from_path, truncate_snippet,
    normalize_cwe, create_collection, store_in_qdrant, deduplicate
)
from rag.dataset_retriever import query_dataset
print("    ✅ All imports OK")

# ── 2. Test extract_functions with synthetic code ──────────
print("\n[2] Testing function extractor...")

synthetic_c = """
void bad() {
    char buf[10];
    strcpy(buf, "this is too long and will overflow");
}

void good() {
    char buf[10];
    strncpy(buf, "hello", sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\\0';
}
"""

from tempfile import NamedTemporaryFile
with NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
    f.write(synthetic_c)
    tmp_path = Path(f.name)

funcs = extract_functions(tmp_path)
tmp_path.unlink()

assert len(funcs) == 2, f"Expected 2 functions, got {len(funcs)}"
labels = {f["function_name"]: f["label"] for f in funcs}
assert labels["bad"] == "vulnerable", "bad() should be labeled 'vulnerable'"
assert labels["good"] == "safe", "good() should be labeled 'safe'"
print(f"    ✅ Extracted {len(funcs)} functions: {labels}")

# ── 3. Test CWE path parsing ───────────────────────────────
print("\n[3] Testing CWE path parser...")
test_paths = [
    (Path("/testcases/CWE120_Buffer_Copy/bad.c"), "CWE-120"),
    (Path("/testcases/CWE787_OOB_Write/s01/bad.cpp"), "CWE-787"),
    (Path("/testcases/CWE-78_OS_Command/bad.c"), "CWE-78"),
]
for path, expected in test_paths:
    result = parse_cwe_from_path(path)
    assert result == expected, f"Expected {expected}, got {result} for {path}"
    print(f"    ✅ {path.parts[-2]} → {result}")

# ── 4. Test CWE normalization (BigVul) ─────────────────────
print("\n[4] Testing CWE normalization...")
assert normalize_cwe("CWE-120") == "CWE-120"
assert normalize_cwe("120") == "CWE-120"
assert normalize_cwe("CWE119") == "CWE-119"
print("    ✅ CWE normalization OK")

# ── 5. Test truncate_snippet ───────────────────────────────
print("\n[5] Testing snippet truncation...")
long_text = "x" * 600
truncated = truncate_snippet(long_text, max_chars=512)
assert len(truncated) <= 515, "Truncated text too long"
assert truncated.endswith("..."), "Should end with ..."
short_text = "short"
assert truncate_snippet(short_text) == "short", "Short text should not be modified"
print("    ✅ Truncation OK")

# ── 6. Test Qdrant collection creation ────────────────────
print("\n[6] Testing Qdrant connection + collection creation...")
create_collection()
print("    ✅ Collection created/verified")

# ── 7. Insert synthetic data + test retriever ─────────────
print("\n[7] Inserting synthetic snippets and testing retriever...")

model = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(host="localhost", port=6333)

synthetic_data = [
    {
        "id": int(hashlib.md5(b"test:vuln:strcpy").hexdigest()[:8], 16),
        "text": "CWE: CWE-120 | Language: C | Label: vulnerable\n\nvoid bad() { char buf[10]; strcpy(buf, input); }",
        "payload": {
            "code_snippet": "void bad() { char buf[10]; strcpy(buf, input); }",
            "label": "vulnerable", "cwe_id": "CWE-120",
            "source": "test", "language": "C",
            "function_name": "bad", "file_path": "test/bad.c",
        },
    },
    {
        "id": int(hashlib.md5(b"test:vuln:memcpy").hexdigest()[:8], 16),
        "text": "CWE: CWE-120 | Language: C | Label: vulnerable\n\nvoid bad2() { char buf[10]; memcpy(buf, src, 100); }",
        "payload": {
            "code_snippet": "void bad2() { char buf[10]; memcpy(buf, src, 100); }",
            "label": "vulnerable", "cwe_id": "CWE-120",
            "source": "test", "language": "C",
            "function_name": "bad2", "file_path": "test/bad2.c",
        },
    },
    {
        "id": int(hashlib.md5(b"test:safe:strncpy").hexdigest()[:8], 16),
        "text": "CWE: CWE-120 | Language: C | Label: safe\n\nvoid good() { char buf[10]; strncpy(buf, input, 9); buf[9]='\\0'; }",
        "payload": {
            "code_snippet": "void good() { char buf[10]; strncpy(buf, input, 9); buf[9]='\\0'; }",
            "label": "safe", "cwe_id": "CWE-120",
            "source": "test", "language": "C",
            "function_name": "good", "file_path": "test/good.c",
        },
    },
]

store_in_qdrant(synthetic_data)
print("    ✅ Synthetic data stored")

# ── 8. Query the retriever ─────────────────────────────────
print("\n[8] Testing query_dataset() retriever...")

result = query_dataset("char buf[10]; strcpy(buf, user_input);", "CWE-120")
print(f"    Query: 'strcpy into small buffer (CWE-120)'")
print(f"    Verdict:    {result['verdict']}")
print(f"    Confidence: {result['confidence']}")
print(f"    Top match:  {result['top_matches'][0]['function_name']} ({result['top_matches'][0]['label']})")

assert result["verdict"] in ("vulnerable", "false_positive", "ambiguous")
assert 0.0 <= result["confidence"] <= 1.0
assert len(result["top_matches"]) > 0
print("    ✅ Retriever working correctly")

print("\n" + "=" * 60)
print("  ALL TESTS PASSED ✅")
print("=" * 60)
