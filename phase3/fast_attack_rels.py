"""
Fast ATT&CK Relationship Loader
Loads only relationships from enterprise-attack.json into Neo4j.
Assumes nodes (Technique, Group, Software, Mitigation, Tactic) are already loaded.

Speed fix: uses labeled MATCH (e.g. MATCH (a:Technique {stix_id:...})) instead of
label-free MATCH ({stix_id:...}). Label-free causes full graph scans on every lookup.
With 323k+ Vulnerability nodes now in the graph, that's catastrophic for performance.

Expected runtime: ~30 seconds for all 18k edges.

Usage:
  python fast_attack_rels.py \
      --stix-file data/enterprise-attack.json \
      --neo4j-password password
"""

import json
import argparse
import time
import logging
from collections import defaultdict

from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s — %(message)s")
logger = logging.getLogger(__name__)

BATCH_SIZE = 500

# Maps STIX type → Neo4j label (for labeled MATCH)
STIX_TYPE_TO_LABEL = {
    "attack-pattern":       "Technique",
    "intrusion-set":        "Group",
    "malware":              "Software",
    "tool":                 "Software",
    "course-of-action":     "Mitigation",
    "x-mitre-tactic":       "Tactic",
}

# Maps (src_type, rel_type, tgt_type) → Cypher relationship type
REL_MAP = {
    ("intrusion-set",   "uses", "attack-pattern"):  "USES",
    ("intrusion-set",   "uses", "malware"):         "USES",
    ("intrusion-set",   "uses", "tool"):            "USES",
    ("malware",         "uses", "attack-pattern"):  "USES",
    ("tool",            "uses", "attack-pattern"):  "USES",
    ("course-of-action","mitigates","attack-pattern"): "MITIGATES",
    ("attack-pattern",  "subtechnique-of", "attack-pattern"): "SUBTECHNIQUE_OF",
}

# ENABLES_TACTIC is handled separately (not a STIX relationship object)


def load_stix(path: str) -> dict:
    logger.info(f"Loading {path}...")
    with open(path, encoding="utf-8") as f:
        bundle = json.load(f)
    objects = {obj["id"]: obj for obj in bundle.get("objects", []) if "id" in obj}
    logger.info(f"Loaded {len(objects)} STIX objects")
    return objects


def extract_relationships(objects: dict) -> dict[str, list[dict]]:
    """
    Returns dict: {cypher_rel_type: [{src_stix_id, src_label, tgt_stix_id, tgt_label}, ...]}
    Skips revoked/deprecated objects.
    """
    rels: dict[str, list] = defaultdict(list)

    for obj in objects.values():
        if obj.get("type") != "relationship":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        src_id = obj.get("source_ref", "")
        tgt_id = obj.get("target_ref", "")
        rel_type = obj.get("relationship_type", "")

        src = objects.get(src_id)
        tgt = objects.get(tgt_id)
        if not src or not tgt:
            continue
        if src.get("revoked") or tgt.get("revoked"):
            continue

        src_type = src.get("type", "")
        tgt_type = tgt.get("type", "")

        cypher_type = REL_MAP.get((src_type, rel_type, tgt_type))
        if not cypher_type:
            continue

        src_label = STIX_TYPE_TO_LABEL.get(src_type)
        tgt_label = STIX_TYPE_TO_LABEL.get(tgt_type)
        if not src_label or not tgt_label:
            continue

        rels[cypher_type].append({
            "src_id":    src_id,
            "src_label": src_label,
            "tgt_id":    tgt_id,
            "tgt_label": tgt_label,
        })

    return dict(rels)


def extract_enables_tactic(objects: dict) -> list[dict]:
    """
    ENABLES_TACTIC: attack-pattern → x-mitre-tactic
    Extracted from kill_chain_phases on Technique objects, matched to Tactic by shortname.
    """
    # Build shortname → tactic stix_id map
    tactic_by_shortname = {}
    for obj in objects.values():
        if obj.get("type") == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname", "")
            if shortname:
                tactic_by_shortname[shortname] = obj["id"]

    edges = []
    for obj in objects.values():
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for kcp in obj.get("kill_chain_phases", []):
            if kcp.get("kill_chain_name") != "mitre-attack":
                continue
            phase = kcp.get("phase_name", "")
            tactic_id = tactic_by_shortname.get(phase)
            if tactic_id:
                edges.append({
                    "src_id":    obj["id"],
                    "src_label": "Technique",
                    "tgt_id":    tactic_id,
                    "tgt_label": "Tactic",
                })

    return edges


def load_rels_batch(driver, cypher_type: str, rows: list[dict]) -> int:
    """
    Load a batch of relationships using labeled MATCH for index efficiency.
    Since src and tgt can have different labels, we group by (src_label, tgt_label).
    """
    # Group by label pair to use typed MATCH
    by_labels: dict[tuple, list] = defaultdict(list)
    for row in rows:
        key = (row["src_label"], row["tgt_label"])
        by_labels[key].append({"src": row["src_id"], "tgt": row["tgt_id"]})

    total = 0
    for (src_label, tgt_label), batch in by_labels.items():
        # Cypher type is whitelisted — safe to interpolate
        query = f"""
            UNWIND $batch AS row
            MATCH (a:{src_label} {{stix_id: row.src}})
            MATCH (b:{tgt_label} {{stix_id: row.tgt}})
            MERGE (a)-[:{cypher_type}]->(b)
        """
        for i in range(0, len(batch), BATCH_SIZE):
            chunk = batch[i:i + BATCH_SIZE]
            with driver.session() as session:
                session.run(query, batch=chunk)
            total += len(chunk)

    return total


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--stix-file",       required=True)
    p.add_argument("--neo4j-uri",       default="bolt://localhost:7687")
    p.add_argument("--neo4j-user",      default="neo4j")
    p.add_argument("--neo4j-password",  required=True)
    args = p.parse_args()

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))

    # Verify nodes exist
    with driver.session() as session:
        counts = session.run(
            "MATCH (n) WHERE n:Technique OR n:Group OR n:Software OR n:Mitigation OR n:Tactic "
            "RETURN labels(n)[0] AS lbl, count(n) AS cnt"
        ).data()
    logger.info(f"Node counts: {counts}")
    if not counts:
        logger.error("No ATT&CK nodes found. Run stix_to_neo4j.py node loading first.")
        return

    # Verify stix_id index exists — critical for performance
    with driver.session() as session:
        indexes = session.run("SHOW INDEXES").data()
    stix_indexed = any(
        "stix_id" in str(idx.get("properties", "")) for idx in indexes
    )
    if not stix_indexed:
        logger.warning("No stix_id index found — creating on Technique and Group...")
        with driver.session() as session:
            for label in ("Technique", "Group", "Software", "Mitigation", "Tactic"):
                session.run(
                    f"CREATE INDEX {label.lower()}_stix_id IF NOT EXISTS "
                    f"FOR (n:{label}) ON (n.stix_id)"
                )
        logger.info("Indexes created")

    # Load STIX bundle
    objects = load_stix(args.stix_file)

    # Extract relationships
    rels = extract_relationships(objects)
    enables_tactic = extract_enables_tactic(objects)
    rels["ENABLES_TACTIC"] = enables_tactic

    # Load each relationship type
    total_edges = 0
    for cypher_type, rows in sorted(rels.items()):
        logger.info(f"Loading {cypher_type}: {len(rows)} edges...")
        t0 = time.time()
        n = load_rels_batch(driver, cypher_type, rows)
        elapsed = time.time() - t0
        logger.info(f"  ✓ {cypher_type}: {n} edges in {elapsed:.1f}s")
        total_edges += n

    logger.info(f"\nDone. Total edges loaded: {total_edges}")

    # Quick verify
    with driver.session() as session:
        edge_counts = session.run(
            "MATCH ()-[r]->() WHERE type(r) IN ['USES','MITIGATES','SUBTECHNIQUE_OF','ENABLES_TACTIC'] "
            "RETURN type(r) AS t, count(r) AS cnt"
        ).data()
    logger.info("Edge counts in graph:")
    for row in edge_counts:
        logger.info(f"  {row['t']}: {row['cnt']}")

    driver.close()


if __name__ == "__main__":
    main()
