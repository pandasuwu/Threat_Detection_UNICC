"""
stix_to_neo4j.py  —  MITRE ATT&CK STIX 2.0 → Neo4j loader
============================================================
Downloads enterprise-attack.json (or loads from local cache),
parses with stix2.MemoryStore, and loads into Neo4j as:

NODE LABELS
  :Technique      attack-pattern          (T1059, T1059.001, …)
  :Group          intrusion-set           (G0016 APT29, …)
  :Software       tool | malware          (S0002 Mimikatz, …)
  :Mitigation     course-of-action        (M1026, …)
  :Tactic         x-mitre-tactic          (TA0001 Initial Access, …)

RELATIONSHIP TYPES  (all carry .description, .stix_rel_id)
  (:Group)    -[:USES]->          (:Technique)
  (:Group)    -[:USES]->          (:Software)
  (:Software) -[:USES]->          (:Technique)
  (:Mitigation)-[:MITIGATES]->   (:Technique)
  (:Technique) -[:SUBTECHNIQUE_OF]-> (:Technique)   # T1059.001 → T1059
  (:Technique) -[:ENABLES_TACTIC]->  (:Tactic)      # via kill_chain_phases

All nodes carry .stix_id for round-trip traceability.
Revoked and deprecated objects are SKIPPED by default.

Usage:
    python stix_to_neo4j.py
    python stix_to_neo4j.py --stix-file ~/data/enterprise-attack.json
    python stix_to_neo4j.py --neo4j-uri bolt://localhost:7687 \\
                             --neo4j-user neo4j --neo4j-password yourpassword
    python stix_to_neo4j.py --wipe   # clear ATT&CK nodes before loading

Requirements:
    pip install stix2 neo4j requests
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Optional

import requests
import stix2
from neo4j import GraphDatabase

# ── Defaults ──────────────────────────────────────────────────────────────────
STIX_URL   = ("https://raw.githubusercontent.com/mitre/cti/master/"
              "enterprise-attack/enterprise-attack.json")
CACHE_PATH = Path.home() / "data" / "enterprise-attack.json"

NEO4J_URI  = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "password"

BATCH_SIZE = 500   # nodes per transaction

# ── STIX type → Neo4j label mapping ──────────────────────────────────────────
TYPE_LABEL = {
    "attack-pattern":    "Technique",
    "intrusion-set":     "Group",
    "tool":              "Software",
    "malware":           "Software",
    "course-of-action":  "Mitigation",
    "x-mitre-tactic":    "Tactic",
}

# ── Relationship type mapping ─────────────────────────────────────────────────
# (stix relationship_type) → Neo4j rel type
REL_TYPE_MAP = {
    "uses":      "USES",
    "mitigates": "MITIGATES",
    "subtechnique-of": "SUBTECHNIQUE_OF",
    # attribution kept for future use
    "attributed-to": "ATTRIBUTED_TO",
    "revoked-by":    "REVOKED_BY",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _attr(obj, key: str, default=None):
    """
    Unified getter — works on both stix2 objects and raw dicts.
    x-mitre-tactic is a custom type; stix2 returns it as a plain dict.
    """
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _get_attack_id(obj) -> Optional[str]:
    """Extract ATT&CK ID (e.g. T1059.001) from external_references."""
    refs = _attr(obj, "external_references") or []
    for ref in refs:
        src = ref.get("source_name", "") if isinstance(ref, dict) else getattr(ref, "source_name", "")
        eid = ref.get("external_id",  "") if isinstance(ref, dict) else getattr(ref, "external_id",  "")
        if src == "mitre-attack":
            return eid or None
    return None


def _clean_description(text: Optional[str]) -> str:
    """Strip STIX citation markers like (Citation: ...) from descriptions."""
    if not text:
        return ""
    return re.sub(r"\(Citation:[^)]+\)", "", text).strip()


def _is_revoked_deprecated(obj) -> bool:
    return bool(_attr(obj, "revoked", False) or _attr(obj, "x_mitre_deprecated", False))


def _node_props(obj, label: str) -> dict:
    """Build the property dict for a node. Handles both dict and stix2 objects."""
    attack_id = _get_attack_id(obj)
    props = {
        "stix_id":     _attr(obj, "id", ""),
        "attack_id":   attack_id or "",
        "name":        _attr(obj, "name", "") or "",
        "description": _clean_description(_attr(obj, "description", "")),
        "created":     str(_attr(obj, "created", "") or ""),
        "modified":    str(_attr(obj, "modified", "") or ""),
        "version":     str(_attr(obj, "x_mitre_version", "") or ""),
    }

    if label == "Technique":
        kc_phases   = _attr(obj, "kill_chain_phases") or []
        tactic_refs = []
        for p in kc_phases:
            kc_name = p.get("kill_chain_name", "") if isinstance(p, dict) else getattr(p, "kill_chain_name", "")
            phase   = p.get("phase_name",       "") if isinstance(p, dict) else getattr(p, "phase_name",       "")
            if kc_name == "mitre-attack" and phase:
                tactic_refs.append(phase)
        props["is_subtechnique"] = bool(_attr(obj, "x_mitre_is_subtechnique", False))
        props["platforms"]       = list(_attr(obj, "x_mitre_platforms", []) or [])
        props["detection"]       = _clean_description(_attr(obj, "x_mitre_detection", ""))
        props["tactic_refs"]     = tactic_refs

    elif label == "Software":
        props["software_type"] = _attr(obj, "type", "")
        aliases = _attr(obj, "aliases") or _attr(obj, "x_mitre_aliases") or []
        props["aliases"]   = list(aliases)
        props["platforms"] = list(_attr(obj, "x_mitre_platforms", []) or [])

    elif label == "Group":
        aliases = _attr(obj, "aliases") or _attr(obj, "x_mitre_aliases") or []
        props["aliases"] = list(aliases)
        props["country"] = ""

    elif label == "Tactic":
        props["shortname"] = _attr(obj, "x_mitre_shortname", "") or ""

    return props


# ── Neo4j writer ──────────────────────────────────────────────────────────────

class Neo4jWriter:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self._verify()

    def _verify(self):
        with self.driver.session() as s:
            s.run("RETURN 1")
        print("[Neo4j] Connected")

    def close(self):
        self.driver.close()

    def wipe_attack_nodes(self):
        """Delete all ATT&CK nodes and relationships (clean slate)."""
        labels = list(TYPE_LABEL.values()) + ["Technique", "Tactic"]
        with self.driver.session() as s:
            for label in set(labels):
                result = s.run(
                    f"MATCH (n:{label}) DETACH DELETE n RETURN count(n) AS c"
                )
                n = result.single()["c"]
                print(f"  Deleted {n:,} :{label} nodes")

    def create_constraints(self):
        """Unique constraints on stix_id for each node label."""
        with self.driver.session() as s:
            for label in set(TYPE_LABEL.values()):
                try:
                    s.run(f"""
                        CREATE CONSTRAINT IF NOT EXISTS
                        FOR (n:{label}) REQUIRE n.stix_id IS UNIQUE
                    """)
                except Exception:
                    pass   # constraint may already exist
            # Index attack_id for fast NER lookup
            for label in ["Technique", "Group", "Software", "Mitigation"]:
                try:
                    s.run(f"""
                        CREATE INDEX IF NOT EXISTS
                        FOR (n:{label}) ON (n.attack_id)
                    """)
                    s.run(f"""
                        CREATE INDEX IF NOT EXISTS
                        FOR (n:{label}) ON (n.name)
                    """)
                except Exception:
                    pass
        print("[Neo4j] Constraints and indexes ready")

    def upsert_nodes_batch(self, label: str, nodes: list[dict]):
        """MERGE nodes in batches using UNWIND."""
        if not nodes:
            return
        query = f"""
            UNWIND $batch AS props
            MERGE (n:{label} {{stix_id: props.stix_id}})
            SET n += props
        """
        with self.driver.session() as s:
            for i in range(0, len(nodes), BATCH_SIZE):
                s.run(query, batch=nodes[i:i + BATCH_SIZE])

    def upsert_relationships_batch(self, rels: list[dict]):
        """
        Each rel dict: {src_stix_id, dst_stix_id, rel_type, props}
        Uses MERGE so re-runs are idempotent.
        """
        if not rels:
            return
        # Group by rel_type for cleaner Cypher
        by_type: dict[str, list] = {}
        for r in rels:
            by_type.setdefault(r["rel_type"], []).append(r)

        with self.driver.session() as s:
            for rel_type, batch in by_type.items():
                query = f"""
                    UNWIND $batch AS r
                    MATCH (src {{stix_id: r.src}})
                    MATCH (dst {{stix_id: r.dst}})
                    MERGE (src)-[rel:{rel_type}]->(dst)
                    SET rel += r.props
                """
                for i in range(0, len(batch), BATCH_SIZE):
                    chunk = [
                        {"src": b["src_stix_id"],
                         "dst": b["dst_stix_id"],
                         "props": b["props"]}
                        for b in batch[i:i + BATCH_SIZE]
                    ]
                    s.run(query, batch=chunk)

    def upsert_tactic_edges(self, tech_stix_id: str, tactic_shortnames: list[str]):
        """Link Technique → Tactic via ENABLES_TACTIC."""
        if not tactic_shortnames:
            return
        with self.driver.session() as s:
            for shortname in tactic_shortnames:
                s.run("""
                    MATCH (t:Technique {stix_id: $tid})
                    MATCH (tac:Tactic {shortname: $shortname})
                    MERGE (t)-[:ENABLES_TACTIC]->(tac)
                """, tid=tech_stix_id, shortname=shortname)


# ── Download / load STIX ──────────────────────────────────────────────────────

def load_stix(stix_file: Optional[Path]) -> stix2.MemoryStore:
    if stix_file and stix_file.exists():
        print(f"[STIX] Loading from {stix_file} …")
        ms = stix2.MemoryStore()
        ms.load_from_file(str(stix_file))
        return ms

    # Try cache
    if CACHE_PATH.exists():
        print(f"[STIX] Loading from cache {CACHE_PATH} …")
        ms = stix2.MemoryStore()
        ms.load_from_file(str(CACHE_PATH))
        return ms

    # Download
    print(f"[STIX] Downloading from {STIX_URL} …")
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    resp = requests.get(STIX_URL, timeout=120)
    resp.raise_for_status()
    CACHE_PATH.write_bytes(resp.content)
    print(f"[STIX] Saved to cache {CACHE_PATH}  ({len(resp.content)//1024:,} KB)")
    ms = stix2.MemoryStore()
    ms.load_from_file(str(CACHE_PATH))
    return ms


# ── Main loader ───────────────────────────────────────────────────────────────

def load_attack(ms: stix2.MemoryStore, writer: Neo4jWriter):
    t0 = time.time()

    # ── 1. Load all nodes by type ────────────────────────────────────────────
    node_counts = {}
    stix_id_map: dict[str, str] = {}   # stix_id → label (for rel filtering)

    for stix_type, label in TYPE_LABEL.items():
        objects = ms.query([stix2.Filter("type", "=", stix_type)])
        # filter revoked/deprecated
        objects = [o for o in objects if not _is_revoked_deprecated(o)]

        nodes = []
        for obj in objects:
            props = _node_props(obj, label)
            nodes.append(props)
            stix_id_map[_attr(obj, "id")] = label   # works for dict and object

        writer.upsert_nodes_batch(label, nodes)
        # Software has two stix types (tool + malware) — accumulate rather than overwrite
        node_counts[label] = node_counts.get(label, 0) + len(nodes)

    # Print node summary once per label (after all types processed)
    for label, n in node_counts.items():
        print(f"  ✓ {label:<12}  {n:>5,} nodes")

    # ── 2. Technique → Tactic edges (via kill_chain_phases) ──────────────────
    techniques = ms.query([stix2.Filter("type", "=", "attack-pattern")])
    tech_tactic_count = 0
    for obj in techniques:
        if _is_revoked_deprecated(obj):
            continue
        kc_phases = _attr(obj, "kill_chain_phases") or []
        tactic_refs = []
        for p in kc_phases:
            kc_name = p.get("kill_chain_name", "") if isinstance(p, dict) else getattr(p, "kill_chain_name", "")
            phase   = p.get("phase_name",       "") if isinstance(p, dict) else getattr(p, "phase_name",       "")
            if kc_name == "mitre-attack" and phase:
                tactic_refs.append(phase)
        if tactic_refs:
            writer.upsert_tactic_edges(_attr(obj, "id"), tactic_refs)
            tech_tactic_count += len(tactic_refs)

    print(f"  ✓ ENABLES_TACTIC  {tech_tactic_count:>5,} edges")

    # ── 3. All STIX relationships ────────────────────────────────────────────
    relationships = ms.query([stix2.Filter("type", "=", "relationship")])

    rel_batches: list[dict] = []
    rel_counts: dict[str, int] = {}
    skipped_rels = 0

    for rel in relationships:
        src_id = str(_attr(rel, "source_ref") or "")
        dst_id = str(_attr(rel, "target_ref") or "")

        # Only load rels where both ends were loaded as nodes
        if src_id not in stix_id_map or dst_id not in stix_id_map:
            skipped_rels += 1
            continue

        rel_type = REL_TYPE_MAP.get(_attr(rel, "relationship_type", ""))
        if not rel_type:
            skipped_rels += 1
            continue

        props = {
            "stix_rel_id": _attr(rel, "id", ""),
            "description": _clean_description(_attr(rel, "description", "")),
        }
        rel_batches.append({
            "src_stix_id": src_id,
            "dst_stix_id": dst_id,
            "rel_type":    rel_type,
            "props":       props,
        })
        rel_counts[rel_type] = rel_counts.get(rel_type, 0) + 1

    writer.upsert_relationships_batch(rel_batches)

    for rt, n in sorted(rel_counts.items()):
        print(f"  ✓ :{rt:<22}  {n:>5,} edges")
    print(f"  ↷ skipped          {skipped_rels:>5,} rels (revoked/unmapped ends)")

    elapsed = time.time() - t0
    print()
    print("=" * 56)
    print("LOAD COMPLETE")
    print("=" * 56)
    for label, n in node_counts.items():
        print(f"  {label:<14} {n:>5,} nodes")
    print(f"  {'Relationships':<14} {sum(rel_counts.values()):>5,} edges")
    print(f"  Time: {elapsed:.1f}s")


# ── Verification queries ──────────────────────────────────────────────────────

def verify(writer: Neo4jWriter):
    """Run a few sanity-check queries and print results."""
    print("\n[Verify] Spot checks …")
    checks = [
        # Technique by ATT&CK ID
        ("T1059 exists",
         "MATCH (t:Technique {attack_id:'T1059'}) RETURN t.name AS name"),
        # Group APT29
        ("APT29 exists",
         "MATCH (g:Group {attack_id:'G0016'}) RETURN g.name AS name"),
        # APT29 techniques count
        ("APT29 technique count",
         "MATCH (g:Group {attack_id:'G0016'})-[:USES]->(t:Technique) "
         "RETURN count(t) AS n"),
        # Mimikatz techniques
        ("Mimikatz used-by count",
         "MATCH (s:Software {attack_id:'S0002'})<-[:USES]-() RETURN count(*) AS n"),
        # Subtechniques
        ("Subtechnique count",
         "MATCH ()-[:SUBTECHNIQUE_OF]->() RETURN count(*) AS n"),
        # Tactic coverage
        ("Tactic node count",
         "MATCH (t:Tactic) RETURN count(t) AS n"),
        # NER resolution example: name lookup
        ("Name index check",
         "MATCH (n) WHERE n.name CONTAINS 'PowerShell' "
         "RETURN labels(n)[0] AS label, n.attack_id AS id, n.name AS name LIMIT 3"),
    ]
    with writer.driver.session() as s:
        for label, query in checks:
            try:
                result = s.run(query)
                rows = result.data()
                print(f"  {label}: {rows}")
            except Exception as e:
                print(f"  {label}: ERROR — {e}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Load MITRE ATT&CK STIX into Neo4j"
    )
    parser.add_argument("--stix-file", type=Path, default=None,
                        help=f"Local STIX JSON path (default: {CACHE_PATH})")
    parser.add_argument("--neo4j-uri",      default=NEO4J_URI)
    parser.add_argument("--neo4j-user",     default=NEO4J_USER)
    parser.add_argument("--neo4j-password", default=NEO4J_PASS)
    parser.add_argument("--wipe",  action="store_true",
                        help="DELETE all ATT&CK nodes before loading (idempotent re-run)")
    parser.add_argument("--verify", action="store_true", default=True,
                        help="Run spot-check queries after load (default: on)")
    parser.add_argument("--no-verify", dest="verify", action="store_false")
    args = parser.parse_args()

    # ── Connect ──────────────────────────────────────────────────────────────
    writer = Neo4jWriter(args.neo4j_uri, args.neo4j_user, args.neo4j_password)

    try:
        if args.wipe:
            print("[Neo4j] Wiping existing ATT&CK nodes …")
            writer.wipe_attack_nodes()

        writer.create_constraints()

        # ── Load STIX ────────────────────────────────────────────────────────
        ms = load_stix(args.stix_file)

        print("\n[Load] Writing nodes and relationships …")
        load_attack(ms, writer)

        if args.verify:
            verify(writer)

    finally:
        writer.close()


if __name__ == "__main__":
    main()
