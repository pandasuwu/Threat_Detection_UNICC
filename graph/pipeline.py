"""
Phase 3 Pipeline Orchestrator
Builds STIX 2.1 graph from CVE corpus and loads into Neo4j.

Usage:
  # Step 1: CVE structural load (CWE → ATT&CK edges). No API needed. ~10min for 323k records.
  python pipeline.py structural \
      --input /path/to/cve_entities_all.jsonl \
      --neo4j-uri bolt://localhost:7687 \
      --neo4j-user neo4j \
      --neo4j-password your_password

  # Step 2 (optional): Gemini relation extraction on high-quality subset.
  # Requires GEMINI_API_KEY. Free tier: slow. Paid tier: ~2hrs for 80k records.
  python pipeline.py gemini \
      --input /path/to/cve_entities_all.jsonl \
      --output /path/to/gemini_relations.jsonl \
      --neo4j-uri bolt://localhost:7687 \
      --neo4j-user neo4j \
      --neo4j-password your_password \
      --batch-size 20 \
      --rate-limit-delay 0.5

  # Step 3: Load Gemini output into Neo4j (if step 2 run separately)
  python pipeline.py load-gemini \
      --input /path/to/gemini_relations.jsonl \
      --neo4j-uri bolt://localhost:7687 \
      --neo4j-user neo4j \
      --neo4j-password your_password

  # Stats only
  python pipeline.py stats \
      --neo4j-uri bolt://localhost:7687 \
      --neo4j-user neo4j \
      --neo4j-password your_password
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Local imports
sys.path.insert(0, str(Path(__file__).parent))
from cwe_to_attack import get_techniques_for_cwe, coverage_report
from stix_builder import (
    cve_to_vulnerability,
    cve_to_attack_relationships,
    gemini_software_to_stix,
    gemini_relation_to_stix,
    PRODUCER_IDENTITY,
)
from neo4j_loader import Neo4jSTIXLoader
from relation_extractor import (
    CVERelationExtractor,
    setup_gemini,
    is_high_quality,
    run_extraction_batch,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pipeline")


# ── Structural load ──────────────────────────────────────────────────────────

def run_structural(args):
    """
    Load all CVEs as Vulnerability nodes + CWE→ATT&CK PATTERN_OF edges.
    No API calls. Fully deterministic. Safe to re-run (MERGE).
    """
    logger.info("=== Phase 3 Structural Load ===")
    logger.info(f"Input: {args.input}")

    with Neo4jSTIXLoader(args.neo4j_uri, args.neo4j_user, args.neo4j_password) as loader:
        # Pre-fetch ATT&CK technique STIX IDs — needed for relationship construction
        technique_map = loader.fetch_technique_stix_ids()
        logger.info(f"ATT&CK techniques available: {len(technique_map)}")

        # --- Pass 1: CWE coverage profiling ---
        cwe_all = []
        total_records = 0
        with open(args.input, encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                cwe_all.extend(r.get("cwe_ids") or [])
                total_records += 1

        cov = coverage_report(cwe_all)
        logger.info(
            f"CWE coverage: {cov['covered']}/{cov['total']} "
            f"({cov['coverage_pct']:.1f}%) mapped to ATT&CK"
        )
        if cov["uncovered"]:
            logger.info(f"Top uncovered CWEs: {sorted(cov['uncovered'])[:10]}")

        # --- Pass 2: Build and load Vulnerability nodes ---
        logger.info("Loading Vulnerability nodes...")
        VULN_BATCH = 5_000
        vuln_buffer = []
        total_vulns = 0

        with open(args.input, encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                try:
                    vuln = cve_to_vulnerability(record)
                    vuln_buffer.append(vuln)
                except Exception as e:
                    logger.warning(f"Skipping {record.get('cve_id')}: {e}")
                    continue

                if len(vuln_buffer) >= VULN_BATCH:
                    loaded = loader.load_vulnerabilities(vuln_buffer)
                    total_vulns += loaded
                    vuln_buffer = []

        if vuln_buffer:
            total_vulns += loader.load_vulnerabilities(vuln_buffer)

        logger.info(f"Vulnerability nodes loaded: {total_vulns}")

        # --- Pass 3: Build and load PATTERN_OF edges ---
        logger.info("Loading PATTERN_OF edges (CWE -> ATT&CK)...")
        REL_BATCH = 5_000
        rel_buffer = []
        total_rels = 0

        with open(args.input, encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                if not record.get("cwe_ids"):
                    continue
                try:
                    rels = cve_to_attack_relationships(record, technique_map)
                    rel_buffer.extend(rels)
                except Exception as e:
                    logger.warning(f"Rel error for {record.get('cve_id')}: {e}")

                if len(rel_buffer) >= REL_BATCH:
                    total_rels += loader.load_pattern_of(rel_buffer)
                    rel_buffer = []

        if rel_buffer:
            total_rels += loader.load_pattern_of(rel_buffer)

        logger.info(f"PATTERN_OF edges loaded: {total_rels}")

    logger.info("=== Structural load complete ===")
    logger.info(f"  Vulnerability nodes: {total_vulns}")
    logger.info(f"  PATTERN_OF edges:    {total_rels}")
    logger.info(
        f"  ATT&CK technique coverage via CWE: {total_rels} CVE→Technique connections"
    )


# ── Gemini extraction ────────────────────────────────────────────────────────

def run_gemini(args):
    """
    Run Gemini Flash relation extraction on high-quality CVE subset.
    Writes results to JSONL. Does NOT load to Neo4j — use load-gemini step for that.
    """
    logger.info("=== Phase 3 Gemini Relation Extraction ===")

    api_key = os.environ.get("GEMINI_API_KEY") or getattr(args, "gemini_api_key", None)
    setup_gemini(api_key=api_key)
    extractor = CVERelationExtractor()

    # Filter to high-quality subset
    hq_records = []
    with open(args.input, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if is_high_quality(r):
                hq_records.append(r)

    logger.info(f"High-quality records for Gemini: {len(hq_records)} / total")

    # Check for existing output (resume support)
    already_done = set()
    output_path = args.output
    if Path(output_path).exists():
        with open(output_path, encoding="utf-8") as f:
            for line in f:
                try:
                    done = json.loads(line)
                    already_done.add(done["cve_id"])
                except Exception:
                    pass
        logger.info(f"Resuming — already processed: {len(already_done)}")

    pending = [r for r in hq_records if r["cve_id"] not in already_done]
    logger.info(f"Pending: {len(pending)}")

    # Run in batches
    BATCH = getattr(args, "batch_size", 20)
    DELAY = getattr(args, "rate_limit_delay", 0.5)
    total_stats = {"processed": 0, "with_triples": 0, "total_triples": 0, "errors": 0}

    for i in range(0, len(pending), BATCH):
        batch = pending[i : i + BATCH]
        stats = run_extraction_batch(batch, extractor, output_path, rate_limit_delay=DELAY)
        for k in total_stats:
            total_stats[k] += stats[k]
        logger.info(
            f"Batch {i//BATCH + 1}: {stats['processed']} processed, "
            f"{stats['with_triples']} with triples, {stats['errors']} errors"
        )

    logger.info(f"=== Gemini extraction complete: {total_stats} ===")


# ── Load Gemini output into Neo4j ────────────────────────────────────────────

def run_load_gemini(args):
    """Load gemini_relations.jsonl into Neo4j as ExtractedSW nodes + AFFECTS edges."""
    logger.info("=== Loading Gemini Relations into Neo4j ===")

    sw_nodes = {}   # name_lower -> stix2.Software
    affects_rels = []  # stix2.Relationship objects

    from stix_builder import gemini_software_to_stix, gemini_relation_to_stix, _vuln_id

    with open(args.input, encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue

            cve_id = rec.get("cve_id", "")
            vuln_stix_id = _vuln_id(cve_id)

            for triple in rec.get("triples") or []:
                sw_name = triple.get("software", "").strip()
                if not sw_name:
                    continue

                # Deduplicate software nodes
                key = sw_name.lower()
                if key not in sw_nodes:
                    sw_nodes[key] = gemini_software_to_stix(sw_name, cve_id)

                sw_stix_id = sw_nodes[key].id
                evidence = triple.get("evidence", "")
                attack_class = triple.get("attack_class", "")
                desc = f"{evidence} [{attack_class}]".strip(" []")

                rel = gemini_relation_to_stix(
                    source_ref=vuln_stix_id,
                    target_ref=sw_stix_id,
                    relation_type="affects",
                    evidence=desc,
                    source_cve_id=cve_id,
                    confidence=0.85,  # Gemini-extracted, flagged high-confidence
                )
                if rel:
                    affects_rels.append(rel)

    logger.info(f"ExtractedSW nodes to load: {len(sw_nodes)}")
    logger.info(f"AFFECTS edges to load:     {len(affects_rels)}")

    with Neo4jSTIXLoader(args.neo4j_uri, args.neo4j_user, args.neo4j_password) as loader:
        loader.load_extracted_software(list(sw_nodes.values()))
        loader.load_gemini_relationships(affects_rels, "AFFECTS")

    logger.info("=== Gemini load complete ===")


# ── Stats ─────────────────────────────────────────────────────────────────────

def run_stats(args):
    with Neo4jSTIXLoader(args.neo4j_uri, args.neo4j_user, args.neo4j_password) as loader:
        stats = loader.graph_stats()

    print("\n=== Graph Statistics ===")
    print("\nNode counts:")
    for row in stats["nodes"]:
        print(f"  {row['lbl']:25s} {row['cnt']:>8,}")

    print("\nEdge counts:")
    for row in stats["edges"]:
        print(f"  {row['t']:25s} {row['cnt']:>8,}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(description="Phase 3 STIX graph pipeline")
    sub = p.add_subparsers(dest="command", required=True)

    # Shared Neo4j args
    def add_neo4j(sp):
        sp.add_argument("--neo4j-uri",      default="bolt://localhost:7687")
        sp.add_argument("--neo4j-user",     default="neo4j")
        sp.add_argument("--neo4j-password", required=True)

    # structural
    sp = sub.add_parser("structural", help="Load CVE Vulnerability nodes + CWE→ATT&CK edges")
    sp.add_argument("--input", required=True, help="Path to cve_entities_all.jsonl")
    add_neo4j(sp)

    # gemini
    sp = sub.add_parser("gemini", help="Run Gemini relation extraction on high-quality subset")
    sp.add_argument("--input",             required=True, help="Path to cve_entities_all.jsonl")
    sp.add_argument("--output",            required=True, help="Output JSONL for Gemini results")
    sp.add_argument("--gemini-api-key",    default=None,  help="Gemini API key (or set GEMINI_API_KEY)")
    sp.add_argument("--batch-size",        type=int, default=20)
    sp.add_argument("--rate-limit-delay",  type=float, default=0.5)
    add_neo4j(sp)

    # load-gemini
    sp = sub.add_parser("load-gemini", help="Load Gemini JSONL output into Neo4j")
    sp.add_argument("--input", required=True, help="Path to Gemini JSONL output")
    add_neo4j(sp)

    # stats
    sp = sub.add_parser("stats", help="Print graph statistics")
    add_neo4j(sp)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "structural":  run_structural,
        "gemini":      run_gemini,
        "load-gemini": run_load_gemini,
        "stats":       run_stats,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
