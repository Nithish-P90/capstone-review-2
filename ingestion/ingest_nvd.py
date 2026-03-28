# ingestion/ingest_nvd.py

import nvdlib
import os
import time
import json
import hashlib
from datetime import datetime, timezone
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer

# ─── Load env ──────────────────────────────────────────────
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

# ─── Clients ───────────────────────────────────────────────
client = QdrantClient(host="localhost", port=6333)
model = SentenceTransformer("all-MiniLM-L6-v2")

COLLECTION_NAME = "nvd_threats"
VECTOR_SIZE = 384
TIMESTAMP_FILE = "last_run.json"   # keep simple path

# ─── CWE targets ───────────────────────────────────────────
cwe_targets = [
    "CWE-119", "CWE-120", "CWE-121", "CWE-122",
    "CWE-125", "CWE-787", "CWE-416", "CWE-415",
    "CWE-476", "CWE-190", "CWE-191", "CWE-134",
    "CWE-362", "CWE-78", "CWE-20",
]

# ─── Keyword groups ────────────────────────────────────────
keyword_groups = [
    ("buffer overflow", "CRITICAL"),
    ("use after free", "CRITICAL"),
    ("memory corruption", "CRITICAL"),
    ("command injection", "CRITICAL"),
    ("improper input validation", "HIGH"),
]

# ─── Timestamp helpers ─────────────────────────────────────
def get_last_run_timestamp():
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE) as f:
            return json.load(f).get("last_run")
    return None

def save_last_run_timestamp():
    with open(TIMESTAMP_FILE, "w") as f:
        json.dump({"last_run": datetime.now(timezone.utc).isoformat()}, f)

# ─── Create collection ─────────────────────────────────────
def create_collection():
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION_NAME not in existing:
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )
        print(f"✅ Collection '{COLLECTION_NAME}' created.")
    else:
        print(f"ℹ️ Collection '{COLLECTION_NAME}' already exists.")

# ─── Fetch CVEs ────────────────────────────────────────────
def fetch_cves(params, label):
    print(f"\n🔎 {label}")
    try:
        results = nvdlib.searchCVE(**params)
        print(f"   → Fetched {len(results)} CVEs")
        return results
    except Exception as e:
        print(f"   ❌ Fetch failed: {e}")
        return []

def fetch_cves_by_cwe(cwe_id, last_run=None):
    params = {
        "cweId": cwe_id,
        "key": NVD_API_KEY,
        "limit": 500
    }

    if last_run:
        params["lastModStartDate"] = last_run
        params["lastModEndDate"] = datetime.now(timezone.utc).isoformat()
        label = f"CWE {cwe_id} (incremental)"
    else:
        label = f"CWE {cwe_id} (full)"

    return fetch_cves(params, label)

def fetch_cves_by_keyword(keyword, severity, last_run=None):
    params = {
        "keywordSearch": keyword,
        "cvssV3Severity": severity,
        "key": NVD_API_KEY,
        "limit": 200
    }

    if last_run:
        params["lastModStartDate"] = last_run
        params["lastModEndDate"] = datetime.now(timezone.utc).isoformat()
        label = f"{keyword} ({severity}) incremental"
    else:
        label = f"{keyword} ({severity}) full"

    return fetch_cves(params, label)

# ─── Preprocess CVE ────────────────────────────────────────
def preprocess_cve(cve):
    try:
        description = cve.descriptions[0].value if cve.descriptions else None
        if not description:
            return None

        # Safe score extraction
        cvss_score = None
        severity = "UNKNOWN"
        if hasattr(cve, "score") and cve.score:
            try:
                cvss_score = cve.score[2]
                severity = cve.score[1]
            except:
                pass

        cwe_ids = [c.value for c in getattr(cve, "cwe", [])]
        cpe_list = [c.criteria for c in getattr(cve, "cpe", [])[:5]]

        text = f"{cve.id}: {description}"
        if cwe_ids:
            text += f" Weakness: {', '.join(cwe_ids)}."

        # Stable ID (prevents duplicates on re-run)
        stable_id = int(hashlib.md5(cve.id.encode()).hexdigest()[:8], 16)

        return {
            "id": stable_id,
            "text": text,
            "payload": {
                "cve_id": cve.id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "cwe_ids": cwe_ids,
                "cpe": cpe_list,
                "published": str(getattr(cve, "published", "")),
                "last_modified": str(getattr(cve, "lastModified", "")),
            }
        }

    except Exception as e:
        print(f"⚠️ Skipping {cve.id}: {e}")
        return None

# ─── Store in Qdrant ───────────────────────────────────────
def store_in_qdrant(data):
    print(f"\n🧠 Embedding {len(data)} CVEs...")

    texts = [item["text"] for item in data]
    vectors = model.encode(texts, batch_size=32, show_progress_bar=True)

    points = [
        PointStruct(
            id=item["id"],
            vector=vectors[i].tolist(),
            payload=item["payload"]
        )
        for i, item in enumerate(data)
    ]

    BATCH_SIZE = 100
    for i in range(0, len(points), BATCH_SIZE):
        batch = points[i:i+BATCH_SIZE]
        client.upsert(collection_name=COLLECTION_NAME, points=batch)
        print(f"   Uploaded {min(i+BATCH_SIZE, len(points))}/{len(points)}")

    print("✅ Stored in Qdrant.")

# ─── Deduplicate ───────────────────────────────────────────
def deduplicate(data):
    seen = set()
    result = []

    for item in data:
        cve_id = item["payload"]["cve_id"]
        if cve_id not in seen:
            seen.add(cve_id)
            result.append(item)

    print(f"\n🧹 Deduplicated → {len(result)} unique CVEs")
    return result

# ─── Main ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("🚀 Starting ingestion pipeline...\n")

    create_collection()

    last_run = get_last_run_timestamp()
    print(f"⏱ Last run: {last_run}")

    all_data = []

    # CWE fetch
    print("\n=== CWE Fetch ===")
    for cwe in cwe_targets:
        cves = fetch_cves_by_cwe(cwe, last_run)
        if not cves:
            print("   → No new CVEs")
        for cve in cves:
            processed = preprocess_cve(cve)
            if processed:
                all_data.append(processed)
        time.sleep(1)

    # Keyword fetch
    print("\n=== Keyword Fetch ===")
    for keyword, severity in keyword_groups:
        cves = fetch_cves_by_keyword(keyword, severity, last_run)
        if not cves:
            print("   → No new CVEs")
        for cve in cves:
            processed = preprocess_cve(cve)
            if processed:
                all_data.append(processed)
        time.sleep(1)

    if not all_data:
        print("\n⚠️ No new CVEs found. Exiting.")
        exit()

    deduped = deduplicate(all_data)

    store_in_qdrant(deduped)

    save_last_run_timestamp()

    print("\n🎉 Ingestion complete!")