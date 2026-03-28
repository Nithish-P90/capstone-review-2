# rag/threat_retriever.py

from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

client = QdrantClient(host="localhost", port=6333)
model = SentenceTransformer("all-MiniLM-L6-v2")
COLLECTION_NAME = "nvd_threats"

def query_threat_db(vulnerability_description: str, top_k: int = 5):
    query_vector = model.encode(vulnerability_description).tolist()
    results = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=query_vector,
        limit=top_k,
        with_payload=True
    )
    return results