"""
Threat Intelligence API — FastAPI entrypoint.

Endpoints:
  GET  /search?q=<text>&top_k=20&min_cvss=7.0&severity=HIGH&source=all|cve|pdf
  POST /investigate
  GET  /cve/{cve_id}
  GET  /technique/{attack_id}
  GET  /health

Start (from repo root):
  uvicorn api.api:app --host 0.0.0.0 --port 8000 --reload

Env vars (required):
  NEO4J_URI           bolt://localhost:7687
  NEO4J_USER          neo4j
  NEO4J_PASSWORD      your_password
  QDRANT_HOST         localhost
  QDRANT_PORT         6333
  EMBED_MODEL         sentence-transformers/all-mpnet-base-v2
"""

# Import strategy: absolute imports throughout.
# Run from repo root (uvicorn api.api:app). The repo root is on sys.path so
# all top-level packages (api/, search/) resolve without any sys.path surgery.

import os
import re
import logging
from contextlib import asynccontextmanager
from typing import Union, Optional
from pydantic import BaseModel, Field

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from api.narrative import generate_narrative
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


class PDFResult(BaseModel):
    """PDF chunk result — Issue #4 payload schema."""
    result_type: str = "pdf_chunk"
    text: str
    source: str
    score: float
    year: Optional[int] = None
    page: Optional[int] = None
    section_path: Optional[str] = None
    categories: list[str] = Field(default_factory=list)
    mentions: list[str] = Field(default_factory=list)


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


class InvestigateRequest(BaseModel):
    query: str
    top_k: int = 10
    min_cvss: Optional[float] = None
    alpha: Optional[float] = None


class InvestigateResponse(BaseModel):
    query: str
    narrative: str
    confidence: str
    sources: list[str]
    n_cves_retrieved: int
    graph_context_used: bool
    top_cves: list[CVEResult]


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Probe Neo4j and Qdrant connectivity; return per-service status."""
    if _engine is None:
        return {"status": "not_ready", "neo4j": "not_initialized", "qdrant": "not_initialized"}

    checks: dict[str, str] = {}

    try:
        with _engine.neo4j_driver.session() as session:
            session.run("RETURN 1").single()
        checks["neo4j"] = "ok"
    except Exception as e:
        checks["neo4j"] = f"error: {e}"

    try:
        _engine.qdrant.get_collections()
        checks["qdrant"] = "ok"
    except Exception as e:
        checks["qdrant"] = f"error: {e}"

    ok = all(v == "ok" for v in checks.values())
    return {"status": "ok" if ok else "degraded", **checks}


@app.get("/search", response_model=list[Union[CVEResult, PDFResult]])
def search(
    q: str = Query(..., description="Free-form query text"),
    top_k: int = Query(default=20, ge=1, le=100),
    min_cvss: Optional[float] = Query(default=None, ge=0.0, le=10.0),
    severity: Optional[str] = Query(default=None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$"),
    after_date: Optional[str] = Query(default=None, description="ISO date, e.g. 2020-01-01"),
    alpha: Optional[float] = Query(default=None, ge=0.0, le=1.0),
    source: str = Query(default="all", description="'cve', 'pdf', or 'all'"),
    pdf_source: Optional[str] = Query(default=None, description="Filter for specific PDF report"),
):
    """Hybrid semantic search over CVE corpus and PDF threat reports."""
    if _engine is None:
        raise HTTPException(503, "Engine not initialized")

    results = _engine.hybrid_search(
        query=q,
        top_k=top_k,
        min_cvss=min_cvss,
        severity_filter=severity,
        after_date=after_date,
        alpha=alpha,
        source=source,
        pdf_source_filter=pdf_source,
    )
    return results


@app.get("/cve/{cve_id}", response_model=CVEDetail)
def get_cve(cve_id: str):
    """Full context expansion for a CVE: ATT&CK techniques, threat groups, malware, similar CVEs."""
    if _engine is None:
        raise HTTPException(503, "Engine not initialized")
    result = _engine.expand_cve(cve_id.upper())
    if not result:
        raise HTTPException(404, f"CVE {cve_id} not found")
    return CVEDetail(**result)


@app.get("/technique/{attack_id}", response_model=TechniqueDetail)
def get_technique(attack_id: str):
    """Context pivot on an ATT&CK technique: groups, software, similar CVEs."""
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


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@app.post("/investigate", response_model=InvestigateResponse)
def investigate(req: InvestigateRequest):
    """
    Core deliverable: given a free-text query or CVE ID, return an investigative
    narrative grounded in CVE + ATT&CK + PDF threat report context.
    """
    if _engine is None:
        raise HTTPException(503, "Engine not initialized")

    query = req.query.strip()

    # Hybrid search — source=all so PDF chunks reach the narrative context
    all_results = _engine.hybrid_search(
        query=query,
        top_k=req.top_k,
        min_cvss=req.min_cvss,
        alpha=req.alpha,
        source="all",
    )
    # Separate CVE results for narrative and top_cves construction
    cve_results = [r for r in all_results if r.get("result_type") == "cve"]

    # Optional full CVE expansion when query is a bare CVE ID
    cve_details = None
    if CVE_RE.match(query):
        cve_details = _engine.expand_cve(query.upper())

    if not all_results and not cve_details:
        raise HTTPException(404, "No relevant threat intelligence found for this query.")

    try:
        result = generate_narrative(
            query=query,
            search_results=cve_results,
            cve_details=cve_details,
        )
    except RuntimeError as e:
        raise HTTPException(502, str(e))

    top_cves = [
        CVEResult(
            cve_id=r["cve_id"],
            description=r.get("description", ""),
            cvss_score=r.get("cvss_score"),
            severity=r.get("severity"),
            cwe_ids=r.get("cwe_ids", []),
            published=r.get("published"),
            vector_score=round(r.get("vector_score", 0.0), 4),
            final_score=round(r.get("final_score", 0.0), 4),
            techniques=r.get("techniques", []),
        )
        for r in cve_results[:5]
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
