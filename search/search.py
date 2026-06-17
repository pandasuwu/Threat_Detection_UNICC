"""
Phase 4: Hybrid Search Engine
Combines Qdrant vector similarity with Neo4j graph traversal for investigative queries.

Two query modes:

1. CVE SIMILARITY SEARCH
   "Find CVEs similar to this description / IOC / incident"
   - Embed query → Qdrant ANN on cve_descriptions → top-k by cosine similarity
   - For each result: expand via Neo4j PATTERN_OF → ATT&CK techniques
   - Optionally filter by severity, CVSS threshold, date range

2. TECHNIQUE PIVOT
   "Given a CVE or ATT&CK technique ID, what else is connected?"
   - Graph traversal: CVE → PATTERN_OF → Technique → USES → Group/Software
   - Returns: related threat actors, related malware, similar CVEs via Qdrant

Hybrid scoring:
   final_score = α * vector_score + (1-α) * graph_boost
   - vector_score: Qdrant cosine similarity (0..1, higher=more similar)
   - graph_boost: 1.0 if connected to a high-degree ATT&CK technique, else 0.5
   - α default: 0.7 (vector-dominant; adjust per query type)

This is the query layer that the FastAPI backend (Phase 5) calls directly.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from neo4j import GraphDatabase
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue, Range

logger = logging.getLogger(__name__)

COLLECTION_CVE    = "cve_descriptions"
COLLECTION_ATTACK = "attack_techniques"


@dataclass
class CVESearchResult:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: Optional[str]
    cwe_ids: list[str]
    published: Optional[str]
    vector_score: float
    techniques: list[dict] = field(default_factory=list)   # ATT&CK techniques via Neo4j
    final_score: float = 0.0


@dataclass
class TechniquePivotResult:
    attack_id: str
    name: str
    tactics: list[str]
    related_groups: list[dict]    # [{name, attack_id}]
    related_software: list[dict]  # [{name, attack_id}]
    similar_cves: list[dict]      # top CVEs via Qdrant
    n_cves_total: int             # total CVEs mapped to this technique in graph


class HybridSearchEngine:

    def __init__(
        self,
        neo4j_uri: str,
        neo4j_user: str,
        neo4j_password: str,
        qdrant_host: str = "localhost",
        qdrant_port: int = 6333,
        model_name: str = "sentence-transformers/all-mpnet-base-v2",
        alpha: float = 0.7,
    ):
        self.neo4j_driver = GraphDatabase.driver(
            neo4j_uri, auth=(neo4j_user, neo4j_password)
        )
        self.qdrant = QdrantClient(host=qdrant_host, port=qdrant_port)
        self.alpha = alpha
        self._model = None
        self._model_name = model_name
        self.pdf_collection = "pdf_chunks" 

    def close(self):
        self.neo4j_driver.close()

    def __enter__(self): return self
    def __exit__(self, *a): self.close()

    def _embed(self, text: str) -> list[float]:
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self._model_name)
        vec = self._model.encode(text, normalize_embeddings=True)
        return vec.tolist()

    # ── CVE Similarity Search ────────────────────────────────────────────────

    def search_similar_cves(
        self,
        query: str,
        top_k: int = 20,
        min_cvss: Optional[float] = None,
        severity_filter: Optional[str] = None,
        after_date: Optional[str] = None,
        alpha: Optional[float] = None,
    ) -> list[CVESearchResult]:
        """
        Find CVEs semantically similar to query text.

        Args:
            query:          Free-form query ("remote code execution via buffer overflow
                            in web server", "CVE-2021-44228", "JNDI injection Log4j")
            top_k:          Number of results to return
            min_cvss:       Minimum CVSS score filter (e.g. 7.0 for High+)
            severity_filter: "CRITICAL", "HIGH", "MEDIUM", "LOW"
            after_date:     ISO date string "2020-01-01" — exclude older CVEs
            alpha:          Override instance alpha for this query

        Returns:
            Ranked list of CVESearchResult with Neo4j-expanded technique context
        """
        _alpha = alpha if alpha is not None else self.alpha

        # Build Qdrant filter
        conditions = []
        if min_cvss is not None:
            conditions.append(
                FieldCondition(key="cvss_score", range=Range(gte=min_cvss))
            )
        if severity_filter:
            conditions.append(
                FieldCondition(key="severity", match=MatchValue(value=severity_filter.upper()))
            )
        # Note: date filtering needs a numeric representation in Qdrant payload
        # We store published as string; filter post-hoc if needed (Qdrant doesn't
        # natively support string-date range without a keyword index)

        qdrant_filter = Filter(must=conditions) if conditions else None

        # Vector search
        query_vec = self._embed(query)
        qdrant_response = self.qdrant.query_points(
            collection_name=COLLECTION_CVE,
            query=query_vec,
            query_filter=qdrant_filter,
            limit=top_k * 2,
            with_payload=True,
        )
        qdrant_results = qdrant_response.points

        # Build initial results
        results = []
        cve_ids = []
        for hit in qdrant_results:
            p = hit.payload
            # Post-hoc date filter
            if after_date and (p.get("published") or "0") < after_date:
                continue
            r = CVESearchResult(
                cve_id=p["cve_id"],
                description="",  # will fill from Neo4j
                cvss_score=p.get("cvss_score"),
                severity=p.get("severity"),
                cwe_ids=p.get("cwe_ids", []),
                published=p.get("published"),
                vector_score=hit.score,
            )
            results.append(r)
            cve_ids.append(p["cve_id"])
            if len(results) >= top_k:
                break

        if not results:
            return []

        # Enrich from Neo4j: description + ATT&CK techniques
        with self.neo4j_driver.session() as session:
            enrichment = session.run(
                """
                UNWIND $cve_ids AS cid
                MATCH (v:Vulnerability {cve_id: cid})
                OPTIONAL MATCH (v)-[r:PATTERN_OF]->(t:Technique)
                RETURN v.cve_id AS cve_id,
                       v.description AS description,
                       collect({
                           attack_id: t.attack_id,
                           name:      t.name,
                           cwe:       r.cwe_id
                       }) AS techniques
                """,
                cve_ids=cve_ids,
            ).data()

        neo4j_map = {row["cve_id"]: row for row in enrichment}

        for r in results:
            neo4j_row = neo4j_map.get(r.cve_id, {})
            r.description = neo4j_row.get("description") or ""
            r.techniques  = [
                t for t in (neo4j_row.get("techniques") or [])
                if t.get("attack_id")
            ]
            # Graph boost: connected to ATT&CK = 1.0, not = 0.5
            graph_boost = 1.0 if r.techniques else 0.5
            r.final_score = _alpha * r.vector_score + (1 - _alpha) * graph_boost

        # Re-rank by final score
        results.sort(key=lambda x: x.final_score, reverse=True)
        return results[:top_k]

    # ── Technique Pivot ──────────────────────────────────────────────────────

    def pivot_on_technique(
        self,
        attack_id: str,
        max_similar_cves: int = 10,
    ) -> Optional[TechniquePivotResult]:
        """
        Given an ATT&CK technique ID, return the full context graph:
        - Which threat groups use this technique
        - Which malware uses it
        - How many CVEs are mapped to it
        - Semantically similar CVEs (via Qdrant on technique embedding)
        """
        with self.neo4j_driver.session() as session:
            # Core technique context
            tech_row = session.run(
                """
                MATCH (t:Technique {attack_id: $aid})
                OPTIONAL MATCH (t)-[:ENABLES_TACTIC]->(tac:Tactic)
                RETURN t.stix_id AS stix_id, t.name AS name,
                       collect(DISTINCT tac.name) AS tactics
                """,
                aid=attack_id,
            ).single()

            if not tech_row:
                logger.warning(f"Technique {attack_id} not found in Neo4j")
                return None

            # Related groups
            groups = session.run(
                """
                MATCH (g:Group)-[:USES]->(t:Technique {attack_id: $aid})
                RETURN g.name AS name, g.attack_id AS attack_id
                ORDER BY g.name LIMIT 20
                """,
                aid=attack_id,
            ).data()

            # Related software
            software = session.run(
                """
                MATCH (s:Software)-[:USES]->(t:Technique {attack_id: $aid})
                RETURN s.name AS name, s.attack_id AS attack_id
                ORDER BY s.name LIMIT 20
                """,
                aid=attack_id,
            ).data()

            # CVE count
            n_cves = session.run(
                "MATCH (v:Vulnerability)-[:PATTERN_OF]->(t:Technique {attack_id: $aid}) "
                "RETURN count(v) AS n",
                aid=attack_id,
            ).single()["n"]

        # Similar CVEs via Qdrant — search using technique name as query
        tech_query = f"{attack_id} {tech_row['name']}"
        similar_hits = self.qdrant.query_points(
            collection_name=COLLECTION_CVE,
            query=self._embed(tech_query),
            limit=max_similar_cves,
            with_payload=True,
        ).points
        similar_cves = [
            {
                "cve_id":     h.payload["cve_id"],
                "cvss_score": h.payload.get("cvss_score"),
                "severity":   h.payload.get("severity"),
                "score":      h.score,
            }
            for h in similar_hits
        ]

        return TechniquePivotResult(
            attack_id=attack_id,
            name=tech_row["name"],
            tactics=tech_row["tactics"] or [],
            related_groups=groups,
            related_software=software,
            similar_cves=similar_cves,
            n_cves_total=n_cves,
        )

    # ── CVE Context Expansion ────────────────────────────────────────────────

    def expand_cve(self, cve_id: str) -> Optional[dict]:
        """
        Full context expansion for a single CVE:
        - ATT&CK techniques (via PATTERN_OF)
        - Threat groups known to use those techniques (2-hop)
        - Related software (2-hop)
        - Semantically similar CVEs (Qdrant)
        """
        with self.neo4j_driver.session() as session:
            # Core CVE + techniques
            row = session.run(
                """
                MATCH (v:Vulnerability {cve_id: $cid})
                OPTIONAL MATCH (v)-[r:PATTERN_OF]->(t:Technique)
                OPTIONAL MATCH (t)-[:ENABLES_TACTIC]->(tac:Tactic)
                RETURN v.cve_id AS cve_id, v.description AS description,
                       v.cvss_score AS cvss_score, v.severity AS severity,
                       collect(DISTINCT {
                           attack_id: t.attack_id, name: t.name,
                           cwe: r.cwe_id, tactic: tac.name
                       }) AS techniques
                """,
                cid=cve_id,
            ).single()

            if not row:
                return None

            attack_ids = [t["attack_id"] for t in (row["techniques"] or []) if t.get("attack_id")]

            # 2-hop: groups and software using these techniques
            groups = []
            malware = []
            if attack_ids:
                hop2 = session.run(
                    """
                    UNWIND $aids AS aid
                    MATCH (t:Technique {attack_id: aid})
                    OPTIONAL MATCH (g:Group)-[:USES]->(t)
                    OPTIONAL MATCH (s:Software)-[:USES]->(t)
                    RETURN collect(DISTINCT {name: g.name, attack_id: g.attack_id}) AS groups,
                           collect(DISTINCT {name: s.name, attack_id: s.attack_id}) AS software
                    """,
                    aids=attack_ids,
                ).single()
                groups  = [g for g in (hop2["groups"]   or []) if g.get("name")]
                malware = [s for s in (hop2["software"] or []) if s.get("name")]

        # Similar CVEs via Qdrant
        desc = row["description"] or cve_id
        similar_hits = self.qdrant.query_points(
            collection_name=COLLECTION_CVE,
            query=self._embed(desc),
            limit=11,  # +1 because the CVE itself will appear
            with_payload=True,
        ).points
        similar_cves = [
            {"cve_id": h.payload["cve_id"], "score": h.score}
            for h in similar_hits
            if h.payload["cve_id"] != cve_id
        ][:10]

        return {
            "cve_id":          row["cve_id"],
            "description":     row["description"],
            "cvss_score":      row["cvss_score"],
            "severity":        row["severity"],
            "techniques":      [t for t in (row["techniques"] or []) if t.get("attack_id")],
            "threat_groups":   groups,
            "related_malware": malware,
            "similar_cves":    similar_cves,
        }
    
    # ── PDF Search & Merging ─────────────────────────────────────────────────

    def _search_pdf_chunks(
        self,
        query: str,
        top_k: int = 5,
        source_filter: Optional[str] = None,
    ) -> list[dict]:
        """
        Vector search over pdf_chunks collection.
        source_filter: if provided, restrict to that report (payload.source == value).
        Always restricts to source_type == "pdf".
        """
        query_vec = self._embed(query) # Fixed to use your existing embedder

        qdrant_filter = Filter(
            must=[
                FieldCondition(key="source_type", match=MatchValue(value="pdf")),
            ]
        )
        if source_filter:
            qdrant_filter.must.append(
                FieldCondition(key="source", match=MatchValue(value=source_filter))
            )

        try:
            hits = self.qdrant.query_points(
                collection_name=self.pdf_collection,
                query=query_vec,
                query_filter=qdrant_filter,
                limit=top_k,
                with_payload=True,
            ).points
        except Exception as e:
            logger.error(f"[pdf_chunks search error] {e}")
            return []

        results = []
        for h in hits:
            p = h.payload
            results.append(
                {
                    "result_type":  "pdf_chunk",
                    "score":        round(h.score, 4),
                    "text":         p.get("text", ""),
                    "source":       p.get("source", ""),
                    "source_type":  "pdf",
                    "page":         p.get("page"),
                    "chunk_index":  p.get("chunk_index"),
                    "doc_id":       p.get("doc_id"),
                }
            )
        return results

    def _merge_results(
        self,
        cve_results: list[dict],
        pdf_results: list[dict],
        source: str = "all",
        top_k: int = 10,
    ) -> list[dict]:
        """
        Merge CVE and PDF chunk results into a single ranked list.
        source param controls which streams are included.
        """
        merged = []
        if source in ("cve", "all"):
            merged.extend(cve_results)
        if source in ("pdf", "all"):
            merged.extend(pdf_results)
        
        # Sort by the 'score' key
        merged.sort(key=lambda x: x.get("score", 0.0), reverse=True)
        return merged[:top_k]
    

    def hybrid_search(
        self, 
        query: str, 
        top_k: int = 10, 
        min_cvss: Optional[float] = None,
        severity_filter: Optional[str] = None,
        after_date: Optional[str] = None,
        alpha: Optional[float] = None,
        source: str = "all",
        pdf_source_filter: Optional[str] = None
    ) -> list[dict]:
        """
        Master search method that queries both CVEs and PDF chunks,
        formatting and merging them based on the requested source.
        """
        cve_results = []
        if source in ("cve", "all"):
            # Fetch CVEs using your existing filters
            cve_raw = self.search_similar_cves(
                query, 
                top_k=top_k, 
                min_cvss=min_cvss, 
                severity_filter=severity_filter, 
                after_date=after_date, 
                alpha=alpha
            )
            cve_results = [
                {
                    "result_type": "cve",
                    "score": round(r.final_score, 4), 
                    "cve_id": r.cve_id,
                    "description": r.description,
                    "cvss_score": r.cvss_score,
                    "severity": r.severity,
                    "cwe_ids": r.cwe_ids,
                    "published": r.published,
                    "vector_score": round(r.vector_score, 4),
                    "final_score": round(r.final_score, 4),
                    "techniques": r.techniques
                }
                for r in cve_raw
            ]

        pdf_results = []
        if source in ("pdf", "all"):
            pdf_results = self._search_pdf_chunks(
                query, 
                top_k=top_k, 
                source_filter=pdf_source_filter
            )

        return self._merge_results(cve_results, pdf_results, source=source, top_k=top_k)
