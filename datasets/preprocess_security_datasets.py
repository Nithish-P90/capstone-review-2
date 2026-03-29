# datasets/preprocess_security_datasets.py

import os
import re
import json
import hashlib
import zipfile
from pathlib import Path
from statistics import mean

import requests
from tqdm import tqdm
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer

# ─── Constants ─────────────────────────────────────────────
JULIET_URL = (
    "https://samate.nist.gov/SARD/downloads/test-suites/"
    "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
)
RAW_DIR = Path(__file__).parent / "raw"
JULIET_ZIP = RAW_DIR / "juliet_1.3.zip"
JULIET_DIR = RAW_DIR / "juliet"

COLLECTION_NAME = "security_dataset"
VECTOR_SIZE = 384
BATCH_SIZE = 100

# Same 15 CWEs targeted by the NVD ingestion pipeline
TARGET_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122",
    "CWE-125", "CWE-787", "CWE-416", "CWE-415",
    "CWE-476", "CWE-190", "CWE-191", "CWE-134",
    "CWE-362", "CWE-78",  "CWE-20",
}

# ─── Clients ───────────────────────────────────────────────
client = QdrantClient(host="localhost", port=6333)
model = SentenceTransformer("all-MiniLM-L6-v2")

# ─── Qdrant collection ─────────────────────────────────────
def create_collection():
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION_NAME not in existing:
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )
        print(f"✅ Collection '{COLLECTION_NAME}' created.")
    else:
        print(f"ℹ️  Collection '{COLLECTION_NAME}' already exists.")

# ─── Juliet: download ───────────────────────────────────────
def download_juliet():
    if JULIET_DIR.exists():
        print(f"ℹ️  Juliet already extracted at {JULIET_DIR}. Skipping download.")
        return

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    if not JULIET_ZIP.exists():
        print(f"⬇️  Downloading Juliet Test Suite (~200 MB)...")
        response = requests.get(JULIET_URL, stream=True, timeout=120)
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0))
        with open(JULIET_ZIP, "wb") as f, tqdm(
            total=total, unit="B", unit_scale=True, desc="juliet_1.3.zip"
        ) as bar:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                bar.update(len(chunk))
        print(f"✅ Downloaded to {JULIET_ZIP}")

    print(f"📦 Extracting Juliet...")
    with zipfile.ZipFile(JULIET_ZIP, "r") as zf:
        zf.extractall(JULIET_DIR)
    print(f"✅ Extracted to {JULIET_DIR}")

# ─── Juliet: parse functions ────────────────────────────────
_FUNC_START = re.compile(
    r'^\s*(?:void|int|char\s*\*?|static\s+void)\s+'
    r'(\w*(?:bad|good)\w*)\s*\([^)]*\)\s*$',
    re.MULTILINE | re.IGNORECASE
)

def extract_functions(file_path: Path):
    """
    Extract labeled function bodies from a Juliet C/C++ test file.
    Returns a list of {function_name, code_snippet, label}.
    """
    try:
        text = file_path.read_text(errors="replace")
    except Exception:
        return []

    results = []
    lines = text.splitlines(keepends=True)
    text_flat = "".join(lines)

    for match in _FUNC_START.finditer(text_flat):
        func_name = match.group(1)
        # determine label from function name
        name_lower = func_name.lower()
        if "bad" in name_lower:
            label = "vulnerable"
        elif "good" in name_lower:
            label = "safe"
        else:
            continue

        # walk from the opening brace to find the full body
        start = match.end()
        brace_pos = text_flat.find("{", start)
        if brace_pos == -1:
            continue

        depth = 0
        end = brace_pos
        for i, ch in enumerate(text_flat[brace_pos:], brace_pos):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break

        snippet = text_flat[match.start():end].strip()
        results.append({
            "function_name": func_name,
            "code_snippet": snippet,
            "label": label,
        })

    return results

def parse_cwe_from_path(file_path: Path) -> str:
    for part in file_path.parts:
        m = re.search(r'CWE-?(\d+)', part, re.IGNORECASE)
        if m:
            return f"CWE-{m.group(1)}"
    return "UNKNOWN"

# ─── Juliet: preprocess ─────────────────────────────────────
def preprocess_juliet():
    print("\n=== Processing Juliet Test Suite ===")
    source = "NIST_SARD_Juliet_v1.3"
    all_data = []
    files = list(JULIET_DIR.rglob("*.c")) + list(JULIET_DIR.rglob("*.cpp"))
    print(f"   Found {len(files)} source files")

    for file_path in tqdm(files, desc="Parsing Juliet files"):
        cwe_id = parse_cwe_from_path(file_path)
        if cwe_id not in TARGET_CWES:
            continue

        language = "C++" if file_path.suffix == ".cpp" else "C"
        rel_path = str(file_path.relative_to(JULIET_DIR))

        for func in extract_functions(file_path):
            snippet = truncate_snippet(func["code_snippet"])
            label = func["label"]
            text = (
                f"CWE: {cwe_id} | Language: {language} | Label: {label}\n\n"
                f"{snippet}"
            )
            content_key = f"{source}:{rel_path}:{func['function_name']}"
            stable_id = int(hashlib.md5(content_key.encode()).hexdigest()[:8], 16)
            all_data.append({
                "id": stable_id,
                "text": text,
                "payload": {
                    "code_snippet": snippet,
                    "label": label,
                    "cwe_id": cwe_id,
                    "source": source,
                    "language": language,
                    "function_name": func["function_name"],
                    "file_path": rel_path,
                },
            })

    print(f"   → Extracted {len(all_data)} labeled functions from Juliet")
    return all_data

# ─── BigVul: preprocess ─────────────────────────────────────
def normalize_cwe(raw: str) -> str:
    """Normalize 'CWE-119', 'CWE119', '119' → 'CWE-NNN'."""
    if not raw:
        return "UNKNOWN"
    m = re.search(r'(\d+)', str(raw))
    return f"CWE-{m.group(1)}" if m else "UNKNOWN"

def preprocess_bigvul():
    print("\n=== Processing BigVul (HuggingFace) ===")
    try:
        from datasets import load_dataset  # HuggingFace datasets
    except ImportError:
        print("   ⚠️  'datasets' package not installed. Skipping BigVul.")
        return []

    source = "BigVul"
    all_data = []

    try:
        print("   Loading dataset (may take a few minutes on first run)...")
        ds = load_dataset("MMath/bigvul", split="train", trust_remote_code=True)
    except Exception as e:
        print(f"   ❌ Failed to load BigVul: {e}")
        return []

    print(f"   Loaded {len(ds)} rows. Filtering to target CWEs...")

    for row in tqdm(ds, desc="Parsing BigVul rows"):
        func = row.get("func") or row.get("func_before") or ""
        if not func or not func.strip():
            continue

        cwe_raw = row.get("CWE ID") or row.get("cwe_id") or ""
        cwe_id = normalize_cwe(cwe_raw)
        if cwe_id not in TARGET_CWES:
            continue

        target = row.get("target", -1)
        if target == 1:
            label = "vulnerable"
        elif target == 0:
            label = "safe"
        else:
            continue

        cve_id = str(row.get("CVE ID") or row.get("cve_id") or "unknown")
        snippet = truncate_snippet(func)
        text = f"CWE: {cwe_id} | Language: C | Label: {label}\n\n{snippet}"

        content_key = f"bigvul:{cve_id}:{func[:32]}"
        stable_id = int(hashlib.md5(content_key.encode()).hexdigest()[:8], 16)

        all_data.append({
            "id": stable_id,
            "text": text,
            "payload": {
                "code_snippet": snippet,
                "label": label,
                "cwe_id": cwe_id,
                "source": source,
                "language": "C",
                "function_name": "",
                "file_path": cve_id,
            },
        })

    print(f"   → Extracted {len(all_data)} labeled functions from BigVul")
    return all_data

# ─── Shared helpers ────────────────────────────────────────
def truncate_snippet(text: str, max_chars: int = 512) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."

def deduplicate(data):
    seen = set()
    result = []
    for item in data:
        if item["id"] not in seen:
            seen.add(item["id"])
            result.append(item)
    print(f"\n🧹 Deduplicated → {len(result)} unique entries")
    return result

def store_in_qdrant(data):
    print(f"\n🧠 Embedding {len(data)} entries...")
    texts = [item["text"] for item in data]
    vectors = model.encode(texts, batch_size=32, show_progress_bar=True)

    points = [
        PointStruct(id=item["id"], vector=vectors[i].tolist(), payload=item["payload"])
        for i, item in enumerate(data)
    ]

    for i in range(0, len(points), BATCH_SIZE):
        batch = points[i : i + BATCH_SIZE]
        client.upsert(collection_name=COLLECTION_NAME, points=batch)
        print(f"   Uploaded {min(i + BATCH_SIZE, len(points))}/{len(points)}")

    print("✅ Stored in Qdrant.")

def print_statistics(data):
    from collections import defaultdict
    stats = defaultdict(lambda: {"vulnerable": 0, "safe": 0})
    source_stats = defaultdict(int)

    for item in data:
        p = item["payload"]
        stats[p["cwe_id"]][p["label"]] += 1
        source_stats[p["source"]] += 1

    print("\n📊 Coverage by CWE:")
    print(f"{'CWE':<12} {'Vulnerable':>12} {'Safe':>8} {'Total':>8}")
    print("-" * 44)
    for cwe in sorted(stats):
        v = stats[cwe]["vulnerable"]
        s = stats[cwe]["safe"]
        print(f"{cwe:<12} {v:>12} {s:>8} {v+s:>8}")

    print(f"\n📦 By source:")
    for src, count in source_stats.items():
        print(f"   {src}: {count}")

    print(f"\n✅ Total: {len(data)} labeled code snippets")

# ─── Main ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("🚀 Starting security dataset preprocessing...\n")

    create_collection()

    download_juliet()
    juliet_data = preprocess_juliet()

    bigvul_data = preprocess_bigvul()

    all_data = deduplicate(juliet_data + bigvul_data)

    if not all_data:
        print("\n⚠️  No data to store. Exiting.")
        exit()

    store_in_qdrant(all_data)
    print_statistics(all_data)

    print("\n🎉 Preprocessing complete!")
