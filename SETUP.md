# Setup Guide
**threat-intel-pipeline — full setup from scratch**

---

## Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.11+ | |
| Neo4j | 5.x | Community edition is fine |
| Qdrant | 1.7+ | Run via Docker or binary |
| Docker | any | Only needed for PDF parsing step |
| ~50GB disk | — | CVE JSON corpus is large |
| ~8GB RAM | — | embedder.py processes in batches |

---

## Step 0 — Clone and install dependencies

```bash
git clone https://github.com/<your-username>/threat-intel-pipeline.git
cd threat-intel-pipeline

pip install -r requirements.txt
```

**requirements.txt** should include at minimum:
```
fastapi
uvicorn
neo4j
qdrant-client
sentence-transformers
numpy
pdfplumber
nltk
httpx
openai          # used for OpenRouter (OpenAI-compatible)
stix2
python-dotenv
```

---

## Step 1 — Start Neo4j and Qdrant

**Neo4j:**
```bash
# If installed locally (Arch Linux)
sudo systemctl start neo4j

# Or via Docker
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:5
```

**Qdrant:**
```bash
docker run -d \
  --name qdrant \
  -p 6333:6333 \
  -v $(pwd)/qdrant_storage:/qdrant/storage \
  qdrant/qdrant
```

Verify both are running:
```bash
curl http://localhost:7474          # Neo4j browser
curl http://localhost:6333/health   # Qdrant health
```

---

## Step 2 — Environment variables

Create `phase4/.env`:
```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
QDRANT_HOST=localhost
QDRANT_PORT=6333
OPENROUTER_API_KEY=<your-key>
```

Get a free OpenRouter key at https://openrouter.ai — the pipeline uses `meta-llama/llama-3.1-8b-instruct` (free tier).

---

## Step 3 — Download CVE data

```bash
# Clone the CVE List v5 repository (~40GB, be patient)
git clone https://github.com/CVEProject/cvelistV5.git ~/data/json/cvelistV5
```

---

## Step 4 — Ingest ATT&CK STIX data into Neo4j

```bash
# Downloads enterprise-attack.json (~44MB) and loads nodes
python phase3/stix_to_neo4j.py --wipe

# Loads relationships (uses indexed MATCH — fast)
python phase3/fast_attack_rels.py
```

Expected output:
```
Loaded: 691 Techniques, 172 Groups, 784 Software, 44 Mitigations, 14 Tactics
Loaded: 16,102 USES + 1,445 MITIGATES + 475 SUBTECHNIQUE_OF + 887 ENABLES_TACTIC
```

---

## Step 5 — Normalize and embed CVE data

```bash
# Normalize CVE JSON → JSONL (~10 min on 12 cores)
python parse/normalize_cves.py
# Output: phase4/cve_normalized.jsonl (323k records)

# Embed CVE descriptions → .npy + metadata JSONL (~45 min, has checkpoint/resume)
python phase4/embedder.py
# Output: phase4/cve_embeddings.npy + phase4/cve_metadata.jsonl
```

---

## Step 6 — Load CVE embeddings into Qdrant

```bash
python phase4/qdrant_loader.py
# Output: 249k vectors in Qdrant collection 'cve_descriptions'
```

---

## Step 7 — Load CVE graph into Neo4j

```bash
python phase3/pipeline.py structural
# Output: 323k Vulnerability nodes + 174k PATTERN_OF edges
# Links CVEs to CWEs to ATT&CK techniques deterministically
# ~10 min
```

---

## Step 8 — Parse and ingest PDF threat reports

**Parse PDFs** (requires Docker):

> `data/pdfs/` is gitignored. Drop the source PDF files there before running the
> parse step. The directory exists after a fresh clone (via `data/pdfs/.gitkeep`);
> just copy the PDFs in.

```bash
# Place PDFs in data/pdfs/
docker run --rm \
  -v $(pwd)/data/pdfs:/input \
  -v $(pwd)/data/parsed:/output \
  <docling-image> python parse/parse.py
# Output: data/parsed/*.json + data/parsed/*.md
```

> If Docker isn't available, skip this step — the parsed JSONs may already exist in `data/parsed/`.

**Ingest parsed chunks into Qdrant:**
```bash
python phase4/pdf_chunk_loader.py
# Output: pdf_chunks collection in Qdrant
# Uses three-tier chunking: hard-anchored / soft-anchored / narrative
```

**Validate ingestion:**
```bash
python - <<'EOF'
from qdrant_client import QdrantClient
from collections import Counter
c = QdrantClient("localhost", port=6333)
results, _ = c.scroll("pdf_chunks", limit=10000, with_payload=True)
print(Counter(r.payload["entity_confidence"] for r in results))
EOF
# Expected: Counter({'low': ~60%, 'high': ~15%, 'narrative': ~25%})
```

---

## Step 9 — Start the API

```bash
cd phase4
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

Open http://localhost:8000/docs for the interactive API explorer.

**Smoke test:**
```bash
# Should return CVE results
curl "http://localhost:8000/search?q=log4j+remote+code+execution&source=all&limit=3"

# Should return a grounded narrative
curl -X POST http://localhost:8000/investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "Log4Shell exploitation and affected organizations"}'
```

---

## Step 10 — Run the eval suite

Only run this after Step 8 (PDF ingestion) is complete — otherwise PDF hit rate will be 0%.

```bash
bash run_eval.sh
# Outputs: eval_results.json + eval_summary.txt
```

`eval_summary.txt` contains the efficiency multiplier metric for the UNICC demo.

---

## Troubleshooting

**`ImportError: attempted relative import in non-package`**
→ Run uvicorn from inside `phase4/`, not from the repo root: `cd phase4 && uvicorn api:app`

**Neo4j relationship loading times out**
→ Make sure `stix_to_neo4j.py` ran first to create the constraint indexes. Then run `fast_attack_rels.py` (not the relationship step of `stix_to_neo4j.py`).

**embedder.py runs out of memory**
→ Reduce batch size: `python phase4/embedder.py --batch-size 512`

**pdf_chunk_loader.py finds no JSON files**
→ Check `PARSE_DIR` at the top of `pdf_chunk_loader.py` matches where `parse/parse.py` wrote its output.

**OpenRouter returns 402 / quota exceeded**
→ The free tier has rate limits. The pipeline falls back to returning search results without a narrative if the LLM call fails — search still works.

---

## Re-ingestion (if Neo4j or Qdrant data is wiped)

```bash
# Neo4j wipe + reload
python phase3/stix_to_neo4j.py --wipe
python phase3/fast_attack_rels.py
python phase3/pipeline.py structural

# Qdrant wipe + reload
python phase4/qdrant_loader.py --wipe
python phase4/pdf_chunk_loader.py --wipe
```

Both loaders accept a `--wipe` flag that deletes and recreates the collection before loading.
