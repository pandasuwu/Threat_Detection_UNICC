"""
Phase 3: Neo4j Batch Loader
Ingests STIX 2.1 objects into the existing ATT&CK-anchored Neo4j graph.

Existing graph (Phase 1):
  - Technique, Software, Group, Mitigation, Tactic nodes
  - USES, MITIGATES, SUBTECHNIQUE_OF, ENABLES_TACTIC edges
  - Indexes on attack_id and name for all node types

New nodes:
  - Vulnerability  (stix_id, cve_id, cvss_score, severity, description, published_date)
  - ExtractedSW    (stix_id, name)  — Gemini-extracted software products

New edges:
  - (Vulnerability)-[:PATTERN_OF {cwe_id, attack_id}]->(Technique)
  - (Vulnerability)-[:EXPLOITS {confidence}]->(ExtractedSW)  — Gemini output
  - (Vulnerability)-[:AFFECTS  {confidence}]->(ExtractedSW)  — Gemini output

Design:
  - MERGE on stix_id -> idempotent re-runs
  - execute_write for automatic retry on transient errors (Neo4j driver handles this)
  - Batch size 500 — safe for community edition heap
  - No APOC dependency
"""

import logging
from typing import Generator

from neo4j import GraphDatabase
import stix2

logger = logging.getLogger(__name__)

BATCH_SIZE = 500


class Neo4jSTIXLoader:

    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self._ensure_indexes()

    def close(self):
        self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _ensure_indexes(self):
        cmds = [
            "CREATE INDEX vuln_stix_id IF NOT EXISTS FOR (n:Vulnerability) ON (n.stix_id)",
            "CREATE INDEX vuln_cve_id  IF NOT EXISTS FOR (n:Vulnerability) ON (n.cve_id)",
            "CREATE INDEX extsw_stix_id IF NOT EXISTS FOR (n:ExtractedSW)  ON (n.stix_id)",
            "CREATE INDEX extsw_name   IF NOT EXISTS FOR (n:ExtractedSW)  ON (n.name)",
        ]
        with self.driver.session() as session:
            for cmd in cmds:
                session.run(cmd)
        logger.info("Indexes verified")

    def fetch_technique_stix_ids(self) -> dict[str, str]:
        """Pre-fetch {attack_id -> stix_id} for all Technique nodes (~691 rows)."""
        with self.driver.session() as session:
            rows = session.run(
                "MATCH (t:Technique) RETURN t.attack_id AS aid, t.stix_id AS sid"
            ).data()
        mapping = {r["aid"]: r["sid"] for r in rows if r["aid"]}
        logger.info(f"Fetched {len(mapping)} technique IDs from Neo4j")
        return mapping

    def load_vulnerabilities(self, vulns: list) -> int:
        """MERGE Vulnerability nodes. Returns count loaded."""
        loaded = 0
        for batch in _chunks(vulns, BATCH_SIZE):
            rows = [
                {
                    "stix_id":        v.id,
                    "cve_id":         v.name,
                    "description":    v.description or "",
                    "cvss_score":     v.get("x_cvss_score"),
                    "severity":       v.get("x_severity"),
                    "cwe_ids":        v.get("x_cwe_ids", []),
                    "published_date": v.get("x_published_date"),
                }
                for v in batch
            ]
            with self.driver.session() as session:
                session.execute_write(_upsert_vulns, rows)
            loaded += len(batch)
            if loaded % 20_000 == 0:
                logger.info(f"  Vulnerability nodes: {loaded}")
        logger.info(f"Total Vulnerability nodes loaded: {loaded}")
        return loaded

    def load_pattern_of(self, rels: list) -> int:
        """MERGE Vulnerability->Technique PATTERN_OF edges."""
        loaded = 0
        for batch in _chunks(rels, BATCH_SIZE):
            rows = [
                {
                    "vsid": r.source_ref,
                    "tsid": r.target_ref,
                    "cwe":  r.get("x_cwe_id", ""),
                    "aid":  r.get("x_attack_technique_id", ""),
                    "desc": r.description or "",
                }
                for r in batch
            ]
            with self.driver.session() as session:
                session.execute_write(_upsert_pattern_of, rows)
            loaded += len(batch)
        logger.info(f"Total PATTERN_OF edges loaded: {loaded}")
        return loaded

    def load_extracted_software(self, sw_nodes: list) -> int:
        loaded = 0
        for batch in _chunks(sw_nodes, BATCH_SIZE):
            rows = [
                {
                    "stix_id": s.id,
                    "name":    s.name,
                    "source":  s.get("x_extracted_from", ""),
                }
                for s in batch
            ]
            with self.driver.session() as session:
                session.execute_write(_upsert_extracted_sw, rows)
            loaded += len(batch)
        logger.info(f"Total ExtractedSW nodes loaded: {loaded}")
        return loaded

    def load_gemini_relationships(self, rels: list, rel_type: str) -> int:
        """
        Load Gemini-extracted relationships of a single type.
        rel_type must be one of: EXPLOITS, AFFECTS, TARGETS, USES, RELATED_TO
        """
        ALLOWED = {"EXPLOITS", "AFFECTS", "TARGETS", "USES", "RELATED_TO"}
        if rel_type not in ALLOWED:
            raise ValueError(f"Disallowed relationship type: {rel_type}")

        loaded = 0
        for batch in _chunks(rels, BATCH_SIZE):
            rows = [
                {
                    "src":  r.source_ref,
                    "tgt":  r.target_ref,
                    "desc": r.description or "",
                    "conf": r.get("x_confidence", 0.0),
                    "doc":  r.get("x_source_doc", ""),
                }
                for r in batch
            ]
            fn = _make_gemini_rel_fn(rel_type)
            with self.driver.session() as session:
                session.execute_write(fn, rows)
            loaded += len(batch)
        logger.info(f"Total {rel_type} edges loaded: {loaded}")
        return loaded

    def graph_stats(self) -> dict:
        with self.driver.session() as session:
            nodes = session.run(
                "MATCH (n) RETURN labels(n)[0] AS lbl, count(n) AS cnt ORDER BY cnt DESC"
            ).data()
            edges = session.run(
                "MATCH ()-[r]->() RETURN type(r) AS t, count(r) AS cnt ORDER BY cnt DESC"
            ).data()
        return {"nodes": nodes, "edges": edges}


# Top-level transaction functions

def _upsert_vulns(tx, rows):
    tx.run(
        """
        UNWIND $rows AS r
        MERGE (v:Vulnerability {stix_id: r.stix_id})
        SET v.cve_id         = r.cve_id,
            v.description    = r.description,
            v.cvss_score     = r.cvss_score,
            v.severity       = r.severity,
            v.cwe_ids        = r.cwe_ids,
            v.published_date = r.published_date
        """,
        rows=rows,
    )


def _upsert_pattern_of(tx, rows):
    tx.run(
        """
        UNWIND $rows AS r
        MATCH (v:Vulnerability {stix_id: r.vsid})
        MATCH (t:Technique     {stix_id: r.tsid})
        MERGE (v)-[rel:PATTERN_OF {cwe_id: r.cwe}]->(t)
        SET rel.attack_id   = r.aid,
            rel.description = r.desc
        """,
        rows=rows,
    )


def _upsert_extracted_sw(tx, rows):
    tx.run(
        """
        UNWIND $rows AS r
        MERGE (s:ExtractedSW {stix_id: r.stix_id})
        SET s.name   = r.name,
            s.source = r.source
        """,
        rows=rows,
    )


def _make_gemini_rel_fn(rel_type: str):
    """Return a transaction function for a specific (whitelisted) relationship type."""
    query = f"""
        UNWIND $rows AS r
        MATCH (src {{stix_id: r.src}})
        MATCH (tgt {{stix_id: r.tgt}})
        MERGE (src)-[rel:{rel_type} {{source_doc: r.doc}}]->(tgt)
        SET rel.description = r.desc,
            rel.confidence  = r.conf
    """

    def _fn(tx, rows):
        tx.run(query, rows=rows)

    return _fn


def _chunks(lst: list, size: int) -> Generator:
    for i in range(0, len(lst), size):
        yield lst[i : i + size]
