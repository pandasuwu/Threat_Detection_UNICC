"""
Phase 5: FastAPI Investigator API
Thin HTTP wrapper around HybridSearchEngine for the UNICC demo.

Endpoints:
  GET  /search?q=<text>&top_k=20&min_cvss=7.0&severity=HIGH
  GET  /cve/{cve_id}
  GET  /technique/{attack_id}
  GET  /health

Start:
  uvicorn api.api:app --host 0.0.0.0 --port 8000 --reload

Env vars (required):
  NEO4J_URI           bolt://localhost:7687
  NEO4J_USER          neo4j
  NEO4J_PASSWORD      your_password
  QDRANT_HOST         localhost
  QDRANT_PORT         6333
  EMBED_MODEL         sentence-transformers/all-mpnet-base-v2
"""

import os
import logging
from contextlib import asynccontextmanager
from typing import Union, Optional
from pydantic import BaseModel, Field

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .narrative import generate_narrative

from search.search import HybridSearchEngine, CVESearchResult, TechniquePivotResult

logger = logging.getLogger(__name__)

# ── Engine singleton ─────────────────────────────────────────────────────────

_engine: Optional[HybridSearchEngine] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine
    logger.info("Initializing HybridSearchEngine...")
    _engine = HybridSearchEngine(
        neo4j_uri=os.environ["NEO4J_URI"],
        neo4j_user=os.environ.get("NEO4J_USER", "neo4j"),
        neo4j_password=os.environ["NEO4J_PASSWORD"],
        qdrant_host=os.environ.get("QDRANT_HOST", "localhost"),
        qdrant_port=int(os.environ.get("QDRANT_PORT", "6333")),
        model_name=os.environ.get(
            "EMBED_MODEL", "sentence-transformers/all-mpnet-base-v2"
        ),
    )
    logger.info("Engine ready")
    yield
    _engine.close()


app = FastAPI(
    title="UNICC Threat Intelligence API",
    description="Hybrid semantic + graph search over CVE corpus and MITRE ATT&CK",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten for production
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Response models ──────────────────────────────────────────────────────────

class TechniqueRef(BaseModel):
    attack_id: str
    name: Optional[str] = None
    cwe: Optional[str] = None
    tactic: Optional[str] = None


class CVEResult(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: Optional[str]
    cwe_ids: list[str]
    published: Optional[str]
    vector_score: float
    final_score: float
    techniques: list[dict]


class CVEDetail(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: Optional[str]
    techniques: list[dict]
    threat_groups: list[dict]
    related_malware: list[dict]
    similar_cves: list[dict]


class TechniqueDetail(BaseModel):
    attack_id: str
    name: str
    tactics: list[str]
    related_groups: list[dict]
    related_software: list[dict]
    similar_cves: list[dict]
    n_cves_total: int


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/search", response_model=list[Union[CVEResult, PDFResult]])
def search(
    q: str = Query(..., description="Free-form query text"),
    top_k: int = Query(default=20, ge=1, le=100),
    min_cvss: Optional[float] = Query(default=None, ge=0.0, le=10.0),
    severity: Optional[str] = Query(default=None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$"),
    after_date: Optional[str] = Query(default=None, description="ISO date, e.g. 2020-01-01"),
    alpha: Optional[float] = Query(default=None, ge=0.0, le=1.0),
    # NEW: Hybrid search parameters
    source: str = Query(default="all", description="'cve', 'pdf', or 'all'"),
    pdf_source: Optional[str] = Query(default=None, description="Filter for specific PDF report"),
):
    """
    Hybrid semantic search over CVE corpus and PDF threat reports.
    """
    if _engine is None:
        raise HTTPException(503, "Engine not initialized")
        
    # Call the new hybrid search method, passing down all filters
    results = _engine.hybrid_search(
        query=q, 
        top_k=top_k, 
        min_cvss=min_cvss,
        severity_filter=severity, 
        after_date=after_date, 
        alpha=alpha,
        source=source,
        pdf_source_filter=pdf_source
    )
    
    # The engine now returns pre-formatted dictionaries that match 
    # either CVEResult or PDFResult schemas.
    return results


@app.get("/cve/{cve_id}", response_model=CVEDetail)
def get_cve(cve_id: str):
    """
    Full context expansion for a CVE:
    ATT&CK techniques, threat groups (2-hop), related malware, similar CVEs.
    """
    if _engine is None:
        raise HTTPException(503, "Engine not initialized")
    result = _engine.expand_cve(cve_id.upper())
    if not result:
        raise HTTPException(404, f"CVE {cve_id} not found")
    return CVEDetail(**result)


@app.get("/technique/{attack_id}", response_model=TechniqueDetail)
def get_technique(attack_id: str):
    """
    Context pivot on an ATT&CK technique:
    Groups using it, software using it, semantically similar CVEs.
    """
    if _engine is None:
        raise HTTPException(503, "Engine not initialized")
    result = _engine.pivot_on_technique(attack_id.upper())
    if not result:
        raise HTTPException(404, f"Technique {attack_id} not found")
    return TechniqueDetail(
        attack_id=result.attack_id, name=result.name, tactics=result.tactics,
        related_groups=result.related_groups, related_software=result.related_software,
        similar_cves=result.similar_cves, n_cves_total=result.n_cves_total,
    )

# =====================================================================
# Paste the contents of investigate_endpoint.py below this line
# =====================================================================

# ═══════════════════════════════════════════════════════════════════════
# ADD TO api.py — Phase 5 /investigate endpoint
# ═══════════════════════════════════════════════════════════════════════
#
# Step 1: Add this import at the top of api.py (with your other imports):
#
#   from api.narrative import generate_narrative
#
# Step 2: Add GEMINI_API_KEY to your env vars. In your shell:
#
#   export GEMINI_API_KEY=your_key_here
#
# Step 3: Change allow_methods in CORSMiddleware from ["GET"] to ["GET", "POST"]
#
# Step 4: pip install google-generativeai
#
# Step 5: Paste the code below into api.py after your existing endpoints.
# ═══════════════════════════════════════════════════════════════════════

import re

# ── Request / Response models ─────────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    query: str                          # free-text or CVE ID
    top_k: int = 10                     # CVEs to retrieve for context
    min_cvss: Optional[float] = None
    alpha: Optional[float] = None       # vector/graph weight override


class InvestigateResponse(BaseModel):
    query: str
    narrative: str
    confidence: str                     # HIGH / MEDIUM / LOW
    sources: list[str]                  # CVE IDs used in narrative
    n_cves_retrieved: int
    graph_context_used: bool
    top_cves: list[CVEResult]           # the raw results, so UI can show them


class PDFResult(BaseModel):
    result_type: str = "pdf_chunk"
    score: float
    text: str
    source: str
    source_type: str
    page: Optional[int] = None
    chunk_index: Optional[int] = None
    doc_id: Optional[str] = None

# ── CVE ID detection ──────────────────────────────────────────────────────────

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ── /investigate ──────────────────────────────────────────────────────────────

@app.post("/investigate", response_model=InvestigateResponse)
def investigate(req: InvestigateRequest):
    """
    Core SOW deliverable: given a free-text query or CVE ID, return an
    investigative narrative with ATT&CK context and confidence rating.

    Examples:
      {"query": "CVE-2021-44228"}
      {"query": "ransomware targeting healthcare via RDP brute force", "min_cvss": 7.0}
      {"query": "T1190 exploitation of public-facing application 2023"}
    """
    if _engine is None:
        raise HTTPException(503, "Engine not initialized")

    query = req.query.strip()

    # 1. Hybrid search — always run this
    search_results = _engine.search_similar_cves(
        query=query,
        top_k=req.top_k,
        min_cvss=req.min_cvss,
        alpha=req.alpha,
    )

    # 2. If query looks like a CVE ID, also do full context expansion
    cve_details = None
    cve_match = CVE_RE.match(query)
    if cve_match:
        cve_details = _engine.expand_cve(query.upper())

    if not search_results and not cve_details:
        raise HTTPException(404, "No relevant threat intelligence found for this query.")

    # 3. Generate narrative
    try:
        result = generate_narrative(
            query=query,
            search_results=search_results,
            cve_details=cve_details,
        )
    except RuntimeError as e:
        raise HTTPException(502, str(e))

    # 4. Attach top CVEs to response for UI rendering
    top_cves = [
        CVEResult(
            cve_id=r.cve_id,
            description=r.description,
            cvss_score=r.cvss_score,
            severity=r.severity,
            cwe_ids=r.cwe_ids,
            published=r.published,
            vector_score=round(r.vector_score, 4),
            final_score=round(r.final_score, 4),
            techniques=r.techniques,
        )
        for r in search_results[:5]
    ]

    return InvestigateResponse(
        query=result["query"],
        narrative=result["narrative"],
        confidence=result["confidence"],
        sources=result["sources"],
        n_cves_retrieved=result["n_cves_retrieved"],
        graph_context_used=result["graph_context_used"],
        top_cves=top_cves,
    )
