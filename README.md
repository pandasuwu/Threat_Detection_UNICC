# Threat_Detection_UNICC

> AI-powered cybersecurity threat intelligence pipeline — UNICC × IITGN capstone project (CS 299)

Developed under **Prof. Sameer Kulkarni** at IIT Gandhinagar in collaboration with the **United Nations International Computing Centre (UNICC)**. 
---

## What It Does

Given a natural language query from a security analyst — *"What do we know about Log4Shell exploitation campaigns?"* — the pipeline:

1. Searches 323,647 CVE records and 8 threat landscape reports (ENISA, Microsoft, AT&T) using hybrid vector + graph retrieval
2. Traverses a Neo4j knowledge graph to surface linked ATT&CK techniques, threat actor groups, malware, and mitigations
3. Generates a grounded 5-section narrative via LLM — every claim is anchored to a verified source node

Designed for internal use by security operations teams. All data is local; no external transmission of query content.

---

## Current Status

| Component | Status |
|---|---|
| CVE ingestion (323,647 records from NVD) |  
| MITRE ATT&CK STIX graph (691 techniques, 172 groups, 784 software) | 
| CWE → ATT&CK deterministic mapping (~95% corpus coverage) |
| Qdrant vector search (249k CVE + 691 ATT&CK vectors) | 
| PDF threat report ingestion (8 reports) | 
| Search API (`/search`, `/investigate`, `/cve`, `/technique`) | 
| Grounded LLM narratives (hallucination rate measured by eval suite) | 
| Eval suite + efficiency multiplier (computed, not hardcoded) | 

---

## Architecture

```
Data Sources
├── CVE List v5 (323k JSON files)          ──► normalize_cves.py
├── MITRE ATT&CK STIX 2.1 bundle           ──► stix_to_neo4j.py + fast_attack_rels.py
└── Threat Reports (8 PDFs)                ──► pdf_chunk_loader.py
        │                                          │
        ▼                                          ▼
   Neo4j 5.13                              Qdrant 1.7
   325k nodes · 192k edges                 249k CVE + 691 ATT&CK + pdf_chunks
   CVE → CWE → ATT&CK → Actor/Malware      all-mpnet-base-v2 (768d, cosine)
        │                                          │
        └──────────────────┬───────────────────────┘
                           ▼
                    HybridSearchEngine (search.py)
                    α·vector_score + (1-α)·graph_boost
                           │
                           ▼
                    FastAPI (api.py)
                    /search · /investigate · /cve · /technique
                           │
                           ▼
                    OpenRouter → llama-3.1-8b-instruct
                    Grounded narrative · CONFIDENCE scoring
```

---

## Repository Structure

```
threat-intel-pipeline/
├── ingest/
│   ├── parse.py               # PDF → MD + JSON via docling (Docker)
│   ├── normalize_cves.py      # CVE List v5 → cve_normalized.jsonl
│   ├── embedder.py            # CVE descriptions → embeddings (.npy)
│   ├── qdrant_loader.py       # cve_embeddings.npy → Qdrant (uuid5 IDs, --wipe)
│   └── pdf_chunk_loader.py    # Parsed PDF chunks → Qdrant (three-tier)
│
├── graph/
│   ├── stix_to_neo4j.py       # ATT&CK STIX bundle → Neo4j nodes
│   ├── fast_attack_rels.py    # ATT&CK STIX edges (indexed MATCH, 30s vs 600s)
│   ├── pipeline.py            # CVE → Neo4j orchestrator (structural subcommand)
│   ├── stix_builder.py        # CVE record → STIX2.1 Vulnerability objects
│   ├── cwe_to_attack.py       # CWE → ATT&CK lookup table (100 mappings)
│   └── neo4j_loader.py        # Neo4j loading utilities
│
├── search/
│   └── search.py              # HybridSearchEngine (Qdrant + Neo4j)
│
├── api/
│   ├── api.py                 # FastAPI entrypoint
│   └── narrative.py           # OpenRouter LLM narrative generation
│
├── eval/
│   ├── eval.py                # Eval runner
│   └── eval_queries.py        # 70 ground-truth queries + manual baselines
│
├── data/
│   └── pdfs/                  # Source PDFs — gitignored; see SETUP.md §8
│
├── run_eval.sh                # Runs eval suite (API must be up on :8000)
│
├── archive/
│   └── gliner_ner.py          # Deferred: CUDA NER, not integrated
│
├── SETUP.md                   # Step-by-step setup from scratch
└── README.md                  # This file
```

---

## Setup

See [SETUP.md](./SETUP.md) for the full step-by-step setup from scratch.

**Prerequisites:** Neo4j 5.x, Qdrant 1.7+, Python 3.11+, Docker (for PDF parsing only)

**Quick start** (if Neo4j + Qdrant are already running with data loaded):

```bash
uvicorn api.api:app --host 0.0.0.0 --port 8000
```

Then open `http://localhost:8000/docs` for the interactive API explorer.

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/search` | GET | Hybrid search across CVEs + PDF chunks. `?q=...&source=all\|cve\|pdf` |
| `/investigate` | POST | Full narrative generation for a threat query |
| `/cve/{cve_id}` | GET | Expand a single CVE with graph context |
| `/technique/{attack_id}` | GET | Pivot on an ATT&CK technique → linked CVEs, groups, software |
| `/health` | GET | Service health check |

---

## Evaluation

The eval suite runs 50 ground-truth queries across 5 categories (CVE lookup, technique pivot, actor attribution, analyst free-text, campaign analysis) against a manual analyst baseline of 1,604 minutes (26.7 hours).

```bash
bash run_eval.sh
# Preflight: checks API + Qdrant collections are non-empty
# Outputs:   eval_results.json + eval_summary.txt
```

The efficiency multiplier (analyst hours ÷ system seconds) is computed from actual run timings and printed in `eval_summary.txt`.

---

## Data Sources

| Source | Records | Notes |
|---|---|---|
| CVE List v5 (MITRE) | 323,647 CVEs | Normalized to JSONL, embedded with all-mpnet-base-v2 |
| MITRE ATT&CK Enterprise v14 | 691 techniques, 172 groups, 784 software | STIX 2.1 bundle |
| ENISA Threat Landscape 2022/2023/2024 | 3 reports | Ingested via pdf_chunk_loader.py |
| Microsoft Digital Defense Report 2022/2023 | 2 reports | Ingested via pdf_chunk_loader.py |
| AT&T Cybersecurity Insights Report | 3 reports | Ingested via pdf_chunk_loader.py |

All sources are publicly available. No proprietary or confidential data.


---

## Information

- **Institution:** IIT Gandhinagar 
- **Supervisor:** Prof. Sameer Kulkarni
- **Student:** Suhani
- **Dept:** CSE
