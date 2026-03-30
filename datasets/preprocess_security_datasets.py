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

# Python-specific CWEs
PYTHON_TARGET_CWES = {
    "CWE-89",   # SQL Injection
    "CWE-79",   # Cross-site Scripting
    "CWE-22",   # Path Traversal
    "CWE-502",  # Deserialization (pickle, yaml.load)
    "CWE-94",   # Code Injection (eval, exec)
    "CWE-78",   # OS Command Injection
    "CWE-798",  # Hard-coded Credentials
    "CWE-312",  # Cleartext Storage
    "CWE-20",   # Improper Input Validation
    "CWE-918",  # SSRF
}

SARD_PYTHON_URL = (
    "https://samate.nist.gov/SARD/downloads/test-suites/"
    "2022-08-11-python-test-suite-116-v1-0.zip"
)
SARD_PYTHON_ZIP = RAW_DIR / "sard_python_116.zip"
SARD_PYTHON_DIR = RAW_DIR / "sard_python"

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
    r'(\w*(?:bad|good)\w*)\s*\([^)]*\)\s*\{?\s*$',
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

        # walk from the opening brace — search from match.start() to handle
        # { on same line as signature or on the next line
        brace_pos = text_flat.find("{", match.start())
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

# ─── SARD Python: download ─────────────────────────────────
def download_sard_python():
    if SARD_PYTHON_DIR.exists():
        print(f"ℹ️  SARD Python already extracted at {SARD_PYTHON_DIR}. Skipping download.")
        return

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    if not SARD_PYTHON_ZIP.exists():
        print(f"⬇️  Downloading SARD Python Suite 116 (~50 MB)...")
        response = requests.get(SARD_PYTHON_URL, stream=True, timeout=120)
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0))
        with open(SARD_PYTHON_ZIP, "wb") as f, tqdm(
            total=total, unit="B", unit_scale=True, desc="sard_python_116.zip"
        ) as bar:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                bar.update(len(chunk))
        print(f"✅ Downloaded to {SARD_PYTHON_ZIP}")

    print(f"📦 Extracting SARD Python...")
    with zipfile.ZipFile(SARD_PYTHON_ZIP, "r") as zf:
        zf.extractall(SARD_PYTHON_DIR)
    print(f"✅ Extracted to {SARD_PYTHON_DIR}")


# ─── SARD Python: parse functions ──────────────────────────
def extract_python_functions(file_path: Path):
    """
    Extract labeled function bodies from a SARD Python test file.
    Uses stdlib ast module. Returns list of {function_name, code_snippet, label}.
    bad* functions → "vulnerable", good* functions → "safe".
    """
    import ast as _ast
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    try:
        tree = _ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return []

    results = []
    for node in _ast.walk(tree):
        if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue
        name_lower = node.name.lower()
        if "bad" in name_lower:
            label = "vulnerable"
        elif "good" in name_lower:
            label = "safe"
        else:
            continue

        code = _ast.get_source_segment(source, node)
        if code is None:
            lines = source.splitlines()
            end = getattr(node, "end_lineno", node.lineno)
            code = "\n".join(lines[node.lineno - 1:end])
        if not code or len(code) < 10:
            continue
        results.append({
            "function_name": node.name,
            "code_snippet": code,
            "label": label,
        })
    return results


# ─── SARD Python: preprocess ───────────────────────────────
def preprocess_sard_python():
    print("\n=== Processing SARD Python Test Suite 116 ===")
    source = "NIST_SARD_Python_v116"
    all_data = []
    files = list(SARD_PYTHON_DIR.rglob("*.py"))
    print(f"   Found {len(files)} source files")

    for file_path in tqdm(files, desc="Parsing SARD Python files"):
        cwe_id = parse_cwe_from_path(file_path)
        if cwe_id not in PYTHON_TARGET_CWES:
            continue

        rel_path = str(file_path.relative_to(SARD_PYTHON_DIR))

        for func in extract_python_functions(file_path):
            snippet = truncate_snippet(func["code_snippet"])
            label = func["label"]
            text = (
                f"CWE: {cwe_id} | Language: Python | Label: {label}\n\n"
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
                    "language": "Python",
                    "function_name": func["function_name"],
                    "file_path": rel_path,
                },
            })

    print(f"   → Extracted {len(all_data)} labeled functions from SARD Python")
    return all_data


# ─── CVEfixes Python: preprocess ───────────────────────────
def preprocess_cvefixes_python():
    print("\n=== Processing CVEfixes Python (HuggingFace) ===")
    try:
        from datasets import load_dataset
    except ImportError:
        print("   ⚠️  'datasets' package not installed. Skipping CVEfixes.")
        return []

    source = "CVEfixes_Python"
    all_data = []

    try:
        print("   Loading CVEfixes dataset (may take a few minutes on first run)...")
        ds = load_dataset("msr-llm-reliability/CVEFixes", split="train", trust_remote_code=True)
    except Exception as e:
        print(f"   ❌ Failed to load CVEfixes: {e}")
        return []

    print(f"   Loaded {len(ds)} rows. Filtering to Python + target CWEs...")

    for row in tqdm(ds, desc="Parsing CVEfixes rows"):
        if (row.get("language") or "").lower() != "python":
            continue

        cwe_raw = row.get("cwe_id") or row.get("CWE ID") or ""
        cwe_id = normalize_cwe(cwe_raw)
        if cwe_id not in PYTHON_TARGET_CWES:
            continue

        func_before = row.get("func_before") or ""
        func_after  = row.get("func_after")  or ""

        cve_id = str(row.get("cve_id") or row.get("CVE ID") or "unknown")

        for func_code, label in ((func_before, "vulnerable"), (func_after, "safe")):
            if not func_code or not func_code.strip():
                continue
            snippet = truncate_snippet(func_code)
            text = f"CWE: {cwe_id} | Language: Python | Label: {label}\n\n{snippet}"
            content_key = f"cvefixes:{cve_id}:{label}:{func_code[:32]}"
            stable_id = int(hashlib.md5(content_key.encode()).hexdigest()[:8], 16)
            all_data.append({
                "id": stable_id,
                "text": text,
                "payload": {
                    "code_snippet": snippet,
                    "label": label,
                    "cwe_id": cwe_id,
                    "source": source,
                    "language": "Python",
                    "function_name": "",
                    "file_path": cve_id,
                },
            })

    print(f"   → Extracted {len(all_data)} labeled functions from CVEfixes Python")
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

    download_sard_python()
    sard_python_data = preprocess_sard_python()

    cvefixes_data = preprocess_cvefixes_python()

    all_data = deduplicate(juliet_data + bigvul_data + sard_python_data + cvefixes_data)

    if not all_data:
        print("\n⚠️  No data to store. Exiting.")
        exit()

    store_in_qdrant(all_data)
    print_statistics(all_data)

    print("\n🎉 Preprocessing complete!")
