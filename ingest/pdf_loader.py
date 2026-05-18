"""
PDF chunk loader — Issue #4 Part B.
Supersedes ingest/pdf_chunk_loader.py (which used random uuid4 IDs).

Reads  data/chunks_categorized/*.jsonl
Embeds text with sentence-transformers/all-mpnet-base-v2
Upserts to Qdrant collection 'pdf_chunks' — uuid5(NAMESPACE_URL, f"pdf:{source}:{chunk_index}")
Runs entity matching (Group/Software) and writes aggregated edges to Neo4j:
  (:Report {source, year, chunk_count})
  (:Group|Software)-[:MENTIONED_IN {contexts, chunk_count}]->(:Report)
  One relationship per entity+report pair; contexts list capped at 10.

Idempotency:
  Qdrant — deterministic uuid5 IDs; upsert is idempotent by definition
  Neo4j  — MERGE + SET; second run overwrites with identical values

Note: if data/pdf_chunks collection has points from the old pdf_chunk_loader.py
(random uuid4 IDs), run with --wipe once to remove them before using pdf_loader.py.

Usage:
  python -m ingest.pdf_loader                   # full load
  python -m ingest.pdf_loader --dry-run         # count chunks, no writes
  python -m ingest.pdf_loader --wipe            # delete + recreate collection first
"""

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PayloadSchemaType, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

from ingest.entity_matcher import _build_entity_patterns, _context

load_dotenv()

# ── Constants ────────────────────────────────────────────────────────────────

COLLECTION  = "pdf_chunks"
VECTOR_DIM  = 768
EMBED_MODEL = "sentence-transformers/all-mpnet-base-v2"
BATCH_SIZE  = 64
_NS         = uuid.NAMESPACE_URL


# ── Chunk helpers ────────────────────────────────────────────────────────────

def _point_id(source: str, chunk_index: int) -> str:
    return str(uuid.uuid5(_NS, f"pdf:{source}:{chunk_index}"))


def _load_chunks(chunks_dir: Path) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    for path in sorted(chunks_dir.glob("*.jsonl")):
        source = path.stem
        chunks = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        result[source] = chunks
    return result


# ── Entity scan ──────────────────────────────────────────────────────────────

def _scan_entities(
    chunks_by_source: dict[str, list[dict]],
    ep_list: list[dict],
) -> dict[tuple[str, str], dict]:
    """
    Scan all chunks for entity mentions.
    Returns mentions[(source, attack_id)] = {canonical, entity_type, chunk_count, contexts}.
    contexts is capped at 10 snippets.
    """
    mentions: dict[tuple[str, str], dict] = {}
    for source, chunks in chunks_by_source.items():
        for chunk in chunks:
            text = chunk.get("text", "")
            for ep in ep_list:
                cs_m = ep["cs_re"].search(text) if ep["cs_re"] else None
                ci_m = ep["ci_re"].search(text) if ep["ci_re"] else None
                first = cs_m or ci_m
                if first is None:
                    continue
                key = (source, ep["attack_id"])
                if key not in mentions:
                    mentions[key] = {
                        "canonical":   ep["canonical"],
                        "entity_type": ep["type"],
                        "chunk_count": 0,
                        "contexts":    [],
                    }
                m = mentions[key]
                m["chunk_count"] += 1
                if len(m["contexts"]) < 10:
                    m["contexts"].append(_context(text, first))
    return mentions


# ── Qdrant ───────────────────────────────────────────────────────────────────

def _ensure_collection(client: QdrantClient, wipe: bool) -> None:
    existing = {c.name for c in client.get_collections().collections}
    if wipe and COLLECTION in existing:
        print(f"--wipe: deleting collection '{COLLECTION}'")
        client.delete_collection(COLLECTION)
        existing.discard(COLLECTION)
    if COLLECTION not in existing:
        print(f"Creating collection '{COLLECTION}' (dim={VECTOR_DIM}, cosine)")
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )
        client.create_payload_index(COLLECTION, "source",      PayloadSchemaType.KEYWORD)
        client.create_payload_index(COLLECTION, "source_type", PayloadSchemaType.KEYWORD)
    else:
        print(f"Collection '{COLLECTION}' exists — upserting")


def _upsert_chunks(
    client: QdrantClient,
    model: SentenceTransformer,
    chunks_by_source: dict[str, list[dict]],
    batch_size: int,
) -> int:
    flat: list[tuple[str, dict]] = [
        (source, chunk)
        for source, chunks in chunks_by_source.items()
        for chunk in chunks
    ]
    total = len(flat)
    print(f"Embedding {total} chunks (batch_size={batch_size})…")

    t0 = time.time()
    points: list[PointStruct] = []
    for start in range(0, total, batch_size):
        batch = flat[start: start + batch_size]
        vectors = model.encode(
            [c["text"] for _, c in batch], show_progress_bar=False
        ).tolist()
        for (source, chunk), vec in zip(batch, vectors):
            points.append(
                PointStruct(
                    id=_point_id(source, chunk["chunk_index"]),
                    vector=vec,
                    payload={
                        "text":         chunk["text"],
                        "source":       source,
                        "source_type":  "pdf",
                        "page":         chunk.get("page"),
                        "chunk_index":  chunk["chunk_index"],
                        "section_path": chunk.get("section_path", []),
                        "categories":   chunk.get("categories", []),
                    },
                )
            )
        done = min(start + batch_size, total)
        print(f"  Embedded {done:5d}/{total}", end="\r")
    print()

    for start in range(0, len(points), 256):
        client.upsert(COLLECTION, points=points[start: start + 256])

    elapsed = time.time() - t0
    print(f"Upserted {len(points)} points in {elapsed:.1f}s")
    return len(points)


# ── Neo4j ────────────────────────────────────────────────────────────────────

_UPSERT_REPORT = """
MERGE (r:Report {source: $source})
SET r.year = $year, r.chunk_count = $chunk_count
"""

_UPSERT_GROUP_EDGE = """
MATCH (e:Group {attack_id: $attack_id})
MATCH (r:Report {source: $source})
MERGE (e)-[rel:MENTIONED_IN]->(r)
SET rel.contexts = $contexts, rel.chunk_count = $chunk_count
RETURN count(rel) AS n
"""

_UPSERT_SOFTWARE_EDGE = """
MATCH (e:Software {attack_id: $attack_id})
MATCH (r:Report {source: $source})
MERGE (e)-[rel:MENTIONED_IN]->(r)
SET rel.contexts = $contexts, rel.chunk_count = $chunk_count
RETURN count(rel) AS n
"""


def _write_neo4j(
    driver,
    chunks_by_source: dict[str, list[dict]],
    mentions: dict[tuple[str, str], dict],
) -> tuple[int, int]:
    n_reports = 0
    n_edges = 0
    with driver.session() as session:
        for source, chunks in chunks_by_source.items():
            year = chunks[0].get("year") if chunks else None
            session.run(_UPSERT_REPORT, source=source, year=year, chunk_count=len(chunks))
            n_reports += 1

        for (source, attack_id), m in mentions.items():
            cypher = (
                _UPSERT_GROUP_EDGE
                if m["entity_type"] == "group"
                else _UPSERT_SOFTWARE_EDGE
            )
            result = session.run(
                cypher,
                attack_id=attack_id,
                source=source,
                contexts=m["contexts"],
                chunk_count=m["chunk_count"],
            )
            rec = result.single()
            if rec and rec["n"] > 0:
                n_edges += 1

    return n_reports, n_edges


# ── Entry point ──────────────────────────────────────────────────────────────

def run(
    chunks_dir: Path,
    alias_dict_path: Path,
    dry_run: bool,
    wipe: bool,
    batch_size: int,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    qdrant_host: str,
    qdrant_port: int,
) -> None:
    if not chunks_dir.exists():
        sys.exit(f"ERROR: {chunks_dir} not found")
    if not alias_dict_path.exists():
        sys.exit(f"ERROR: {alias_dict_path} not found")

    chunks_by_source = _load_chunks(chunks_dir)
    if not chunks_by_source:
        sys.exit(f"ERROR: no JSONL files in {chunks_dir}")

    total_chunks = sum(len(c) for c in chunks_by_source.values())
    print(f"Sources: {len(chunks_by_source)}, total chunks: {total_chunks}")
    for src, chunks in chunks_by_source.items():
        print(f"  {src}: {len(chunks)}")

    if dry_run:
        print("\n--dry-run: stopping before any writes.")
        return

    with open(alias_dict_path, encoding="utf-8") as f:
        alias_data = json.load(f)
    ep_list = _build_entity_patterns(alias_data["entities"])
    print(f"\nEntity patterns: {len(ep_list)} entities ({alias_data.get('version', '?')})")

    print("Scanning for entity mentions…")
    mentions = _scan_entities(chunks_by_source, ep_list)
    unique_entities = len({aid for _, aid in mentions})
    print(
        f"Found {len(mentions)} (source, entity) pairs "
        f"across {unique_entities} unique entities"
    )

    print("\n── Qdrant ─────────────────────────────────────────────────────────")
    model = SentenceTransformer(EMBED_MODEL)
    q_client = QdrantClient(host=qdrant_host, port=qdrant_port)
    _ensure_collection(q_client, wipe=wipe)
    _upsert_chunks(q_client, model, chunks_by_source, batch_size)
    q_info = q_client.get_collection(COLLECTION)
    q_count = q_info.points_count
    print(f"Collection '{COLLECTION}': {q_count} points total")

    print("\n── Neo4j ──────────────────────────────────────────────────────────")
    if not neo4j_password:
        sys.exit("ERROR: NEO4J_PASSWORD not set (env var or --neo4j-password)")
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    try:
        driver.verify_connectivity()
        n_reports, n_edges = _write_neo4j(driver, chunks_by_source, mentions)
    finally:
        driver.close()
    print(f"(:Report) nodes upserted: {n_reports}")
    print(f"MENTIONED_IN edges upserted: {n_edges}")

    print("\n── Summary ────────────────────────────────────────────────────────")
    print(f"Qdrant  '{COLLECTION}': {q_count} points")
    print(f"Neo4j   (:Report):      {n_reports} nodes")
    print(f"Neo4j   MENTIONED_IN:   {n_edges} edges")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chunks-dir",     default="data/chunks_categorized")
    parser.add_argument("--alias-dict",     default="data/alias_dictionary.json")
    parser.add_argument("--dry-run",        action="store_true",
                        help="Count chunks only; skip embedding and all DB writes")
    parser.add_argument("--wipe",           action="store_true",
                        help="Delete and recreate the Qdrant collection before loading")
    parser.add_argument("--batch-size",     type=int, default=BATCH_SIZE)
    parser.add_argument("--neo4j-uri",      default=os.getenv("NEO4J_URI",      "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user",     default=os.getenv("NEO4J_USER",     "neo4j"))
    parser.add_argument("--neo4j-password", default=os.getenv("NEO4J_PASSWORD", ""))
    parser.add_argument("--qdrant-host",    default=os.getenv("QDRANT_HOST",    "localhost"))
    parser.add_argument("--qdrant-port",    type=int, default=int(os.getenv("QDRANT_PORT", "6333")))
    args = parser.parse_args()

    run(
        chunks_dir=Path(args.chunks_dir),
        alias_dict_path=Path(args.alias_dict),
        dry_run=args.dry_run,
        wipe=args.wipe,
        batch_size=args.batch_size,
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        qdrant_host=args.qdrant_host,
        qdrant_port=args.qdrant_port,
    )


if __name__ == "__main__":
    main()
