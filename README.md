# C/C++ AI Vulnerability Scanner — Capstone Team 167

An end-to-end, fully local AI pipeline that scans C/C++ source files for security vulnerabilities, explains them in plain English, and suggests code fixes. No cloud APIs required.

---

## How to Run It on Your Own Code

```bash
python main.py path/to/your/file.c
```

A browser window opens automatically with the full report. That's it.

---

## Setup (One Time)

### 1. Prerequisites
- Python 3.9+
- Docker (for Qdrant vector database)
- [Ollama](https://ollama.com) (for local LLM)

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Start Qdrant (vector database)
```bash
docker run -d --name qdrant -p 6333:6333 qdrant/qdrant
```

### 4. Install and start Ollama
```bash
# macOS
brew install ollama
brew services start ollama

# Pull the code analysis model (~4 GB)
OLLAMA_INSECURE=1 ollama pull deepseek-coder:6.7b
```

### 5. Preprocess the security dataset (one time, ~20–40 min)
This builds the labeled code snippet database the verification agent uses.
```bash
python datasets/preprocess_security_datasets.py
```

> **Skip this step** if your team has already run it and Qdrant has the `security_dataset` collection.

### 6. Ingest NVD threat data (one time, requires NVD API key)
```bash
# Add your key to a .env file:
echo "NVD_API_KEY=your_key_here" > .env

python ingestion/ingest_nvd.py
```

> Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

---

## Usage

```bash
# Scan a single file
python main.py src/mycode.c

# Scan any C/C++ file
python main.py /path/to/any/file.cpp
```

The scanner will:
1. Parse every function in your file
2. Ask the local LLM to identify vulnerable patterns
3. Cross-check against 300k+ labeled code examples (Qdrant)
4. Filter out false positives
5. Explain each real vulnerability in plain English
6. Suggest a minimal code fix
7. Open `scan_report.html` in your browser

---

## Architecture

```
Your C/C++ File
       │
       ▼
┌─────────────────────┐
│  parsing/           │  tree-sitter / regex function extractor
│  ast_parser.py      │  → extracts every function with line numbers
└────────┬────────────┘
         │ List[FunctionInfo]
         ▼
┌─────────────────────┐
│  agents/            │  Local LLM (Ollama / deepseek-coder:6.7b)
│  categorization_    │  → flags suspicious patterns as JSON
│  agent.py           │  → cross-references NVD CVE database (Qdrant)
└────────┬────────────┘
         │ List[Finding]
         ▼
┌─────────────────────┐
│  agents/            │  Semantic search against 300k labeled snippets
│  verification_      │  → confirms true positives, discards false alarms
│  agent.py           │  → confidence scoring (0.0–1.0)
└────────┬────────────┘
         │ List[VerifiedFinding]
         ▼
┌─────────────────────┐
│  agents/            │  Local LLM
│  explainable_ai_    │  → explains WHY code is vulnerable
│  agent.py           │  → references related CVEs for context
└────────┬────────────┘
         │ List[ExplainedFinding]
         ▼
┌─────────────────────┐
│  agents/            │  Local LLM
│  advisory_          │  → generates a minimal, correct code fix
│  refactoring_       │
│  agent.py           │
└────────┬────────────┘
         │ List[AdvisedFinding]
         ▼
┌─────────────────────┐
│  dashboard/         │  Self-contained HTML report
│  report_generator   │  → dark theme, severity badges, CVE references
│  .py                │  → auto-opens in browser
└─────────────────────┘
```

### Two Qdrant Collections

| Collection | Data | Built by |
|---|---|---|
| `nvd_threats` | Real CVEs from NIST NVD | `ingestion/ingest_nvd.py` |
| `security_dataset` | 300k labeled C/C++ snippets (Juliet + BigVul) | `datasets/preprocess_security_datasets.py` |

---

## Project Structure

```
Capstone/
├── main.py                          # CLI entrypoint — run this
│
├── parsing/
│   └── ast_parser.py                # Extracts functions from C/C++ files
│
├── agents/
│   ├── categorization_agent.py      # LLM flags vulnerabilities + fetches CVEs
│   ├── verification_agent.py        # RAG-based false positive filter
│   ├── explainable_ai_agent.py      # LLM explains each vulnerability
│   └── advisory_refactoring_agent.py# LLM suggests code fixes
│
├── rag/
│   ├── threat_retriever.py          # Queries nvd_threats collection
│   └── dataset_retriever.py         # Queries security_dataset collection
│
├── ingestion/
│   └── ingest_nvd.py                # Fetches CVEs from NVD API → Qdrant
│
├── datasets/
│   └── preprocess_security_datasets.py  # Downloads Juliet + BigVul → Qdrant
│
├── dashboard/
│   └── report_generator.py          # Generates scan_report.html
│
├── test_vuln.c                      # Sample file with known vulnerabilities
├── test_pipeline.py                 # Smoke test (no full dataset needed)
└── requirements.txt
```

---

## Target Vulnerabilities

The scanner detects these CWE types:

| CWE | Name |
|---|---|
| CWE-119/120/121/122/125 | Buffer overflow / overread |
| CWE-787 | Out-of-bounds write |
| CWE-416/415 | Use-after-free / double free |
| CWE-476 | Null pointer dereference |
| CWE-190/191 | Integer overflow / underflow |
| CWE-134 | Format string vulnerability |
| CWE-362 | Race condition |
| CWE-78 | OS command injection |
| CWE-20 | Improper input validation |

---

## Tech Stack

| Component | Technology | Why |
|---|---|---|
| LLM inference | Ollama + deepseek-coder:6.7b | Free, local, code-specialized |
| Vector database | Qdrant (Docker) | Fast semantic search |
| Embeddings | all-MiniLM-L6-v2 | Lightweight, 384-dim, runs on CPU |
| Code parsing | Regex + brace walker | No dependency conflicts, reliable |
| CVE data | NIST NVD API | Authoritative, free |
| Training data | NIST Juliet v1.3 + BigVul | Labeled vulnerable/safe C/C++ code |
| Report | Self-contained HTML | No server needed, shareable |

---

## For Contributors / Co-developers

### Data dict shapes (what each agent passes to the next)

```python
# After parsing/ast_parser.py
FunctionInfo = {
    "name":       str,   # function name
    "code":       str,   # full function source text
    "start_line": int,   # 1-indexed
    "end_line":   int,
    "file_path":  str,
}

# After agents/categorization_agent.py  (+= these fields)
Finding = FunctionInfo + {
    "cwe_id":      str,        # e.g. "CWE-120"
    "severity":    str,        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    "description": str,        # LLM one-liner
    "cve_matches": list[dict], # from NVD (cve_id, description, cvss_score, ...)
}

# After agents/verification_agent.py  (+= these fields)
VerifiedFinding = Finding + {
    "verdict":     str,        # "vulnerable" | "ambiguous" | "false_positive"
    "confidence":  float,      # 0.0–1.0
    "top_matches": list[dict], # similar labeled snippets from security_dataset
}

# After agents/explainable_ai_agent.py  (+= this field)
ExplainedFinding = VerifiedFinding + {
    "explanation": str,        # plain English explanation (2-3 sentences)
}

# After agents/advisory_refactoring_agent.py  (+= these fields)
AdvisedFinding = ExplainedFinding + {
    "fixed_code":      str,    # corrected function code
    "fix_description": str,    # one sentence describing what changed
}
```

### Adding a new agent

1. Import `call_ollama` from `agents/categorization_agent.py`
2. Accept the previous stage's list as input
3. Return the enriched list with new keys added
4. Wire it into `main.py` between the appropriate stages

### Changing the LLM model

Edit line 14 in [agents/categorization_agent.py](agents/categorization_agent.py):
```python
OLLAMA_MODEL = "deepseek-coder:6.7b"   # change this
```

Any model available in Ollama works. Pull with:
```bash
ollama pull <model-name>
```

### Adding new CWE targets

Add to `TARGET_CWES` in both:
- `agents/categorization_agent.py`
- `ingestion/ingest_nvd.py`
- `datasets/preprocess_security_datasets.py`

Then re-run ingestion and preprocessing to populate new data.

### Confidence thresholds

Edit in [rag/dataset_retriever.py](rag/dataset_retriever.py):
```python
THRESHOLD_HIGH = 0.75   # above this → definitive verdict
THRESHOLD_LOW  = 0.50   # below this → ambiguous
```

Verification filter in [agents/verification_agent.py](agents/verification_agent.py):
- Keep if `verdict == "vulnerable"`
- Keep if `verdict == "ambiguous"` AND `confidence > 0.6`
- Discard if `verdict == "false_positive"` AND `confidence >= 0.75`

---

## Running Tests

```bash
# Smoke test (fast — no dataset download needed, Qdrant must be running)
python test_pipeline.py

# Full scan on the sample vulnerable file
python main.py test_vuln.c
```

---

## Environment Variables

Create a `.env` file in the project root:

```env
NVD_API_KEY=your_nvd_api_key_here
```

Only needed for `ingestion/ingest_nvd.py`. Everything else works without it.

---

## Known Limitations

- **Parser**: Uses regex-based function extraction. Works well on standard C code; may miss functions with complex macros or preprocessor directives.
- **LLM accuracy**: Depends heavily on model size. `deepseek-coder:6.7b` detects ~60-70% of vulnerabilities. Larger models (13b+) improve recall.
- **Verification**: Requires `security_dataset` collection to be populated. Without it, the verification agent passes all findings through.
- **Language support**: Designed for C/C++. Other languages not tested.
