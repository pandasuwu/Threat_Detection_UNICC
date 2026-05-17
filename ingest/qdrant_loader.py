"""
qdrant_loader.py — Load CVE embeddings into Qdrant collection `cve_descriptions`

Reads the two files produced by embedder.py and upserts them into Qdrant:

  cve_embeddings.npy   — float32 array (N, 768), memory-mapped (never fully loaded)
  cve_metadata.jsonl   — one JSON object per line, in the same row order as the .npy

Metadata schema (as written by embedder.py)
-------------------------------------------
  idx        : int    — row index in the .npy (used internally; not stored in payload)
  cve_id     : str    — e.g. "CVE-2021-44228"
  cvss_score : float  — CVSS v3 base score, or null
  severity   : str    — "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null
  cwe_ids    : list   — e.g. ["CWE-79", "CWE-352"], may be empty
  published  : str    — ISO date string "YYYY-MM-DD", or null

Note: `description` is intentionally absent from the metadata JSONL; search.py fills
it at query time from the Neo4j Vulnerability node (description="" in Qdrant payload).

Collection spec
---------------
  Name      : cve_descriptions
  Dimension : 768 (all-mpnet-base-v2 / SecBERT)
  Distance  : Cosine
  Point IDs : uuid5(NAMESPACE_URL, cve_id) — deterministic, idempotent re-runs
  Payload   : cve_id, cvss_score, severity, cwe_ids, published
  Index     : keyword payload index on cve_id

Usage
-----
  # First run (create collection)
  python ingest/qdrant_loader.py --embeddings ingest/cve_embeddings.npy \\
                                  --metadata   ingest/cve_metadata.jsonl

  # Re-ingestion (wipe and reload)
  python ingest/qdrant_loader.py --embeddings ingest/cve_embeddings.npy \\
                                  --metadata   ingest/cve_metadata.jsonl \\
                                  --wipe
"""

import argparse
import json
import logging
import uuid
from pathlib import Path

import numpy as np
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct,
    PayloadSchemaType,
)

logger = logging.getLogger(__name__)

COLLECTION     = "cve_descriptions"
VECTOR_DIM     = 768
BATCH_SIZE     = 512
PROGRESS_EVERY = 10_000
_NS            = uuid.NAMESPACE_URL


def _point_id(cve_id: str) -> str:
    return str(uuid.uuid5(_NS, cve_id))


def _collection_exists(client: QdrantClient) -> bool:
    return any(c.name == COLLECTION for c in client.get_collections().collections)


def _ensure_collection(client: QdrantClient, wipe: bool) -> None:
    exists = _collection_exists(client)
    if exists and wipe:
        logger.info("--wipe: deleting existing collection '%s'", COLLECTION)
        client.delete_collection(COLLECTION)
        exists = False
    if not exists:
        logger.info("Creating collection '%s' (dim=%d, cosine)", COLLECTION, VECTOR_DIM)
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )
        client.create_payload_index(
            collection_name=COLLECTION,
            field_name="cve_id",
            field_schema=PayloadSchemaType.KEYWORD,
        )
        logger.info("Payload index created on 'cve_id'")
    else:
        logger.info("Collection '%s' already exists — upserting (idempotent)", COLLECTION)


def load(
    embeddings_path: str,
    metadata_path: str,
    qdrant_host: str = "localhost",
    qdrant_port: int = 6333,
    wipe: bool = False,
) -> int:
    emb_path  = Path(embeddings_path)
    meta_path = Path(metadata_path)

    # Memory-map the embeddings — never loads the full array into RAM
    embeddings = np.load(emb_path, mmap_mode="r")
    n_emb = embeddings.shape[0]
    logger.info("Memory-mapped %s: shape=%s dtype=%s", emb_path.name, embeddings.shape, embeddings.dtype)

    # Stream metadata and assert row count matches
    with open(meta_path, encoding="utf-8") as f:
        metadata = [json.loads(line) for line in f]
    n_meta = len(metadata)

    if n_emb != n_meta:
        raise ValueError(
            f"Length mismatch: {emb_path.name} has {n_emb} rows "
            f"but {meta_path.name} has {n_meta} lines — aborting"
        )
    logger.info("Lengths match: %d records", n_emb)

    client = QdrantClient(host=qdrant_host, port=qdrant_port)
    _ensure_collection(client, wipe)

    # Batched upsert
    batch: list[PointStruct] = []
    total_upserted = 0

    for i, meta in enumerate(metadata):
        cve_id = meta["cve_id"]
        vector = embeddings[i].tolist()

        batch.append(PointStruct(
            id=_point_id(cve_id),
            vector=vector,
            payload={
                "cve_id":     cve_id,
                "cvss_score": meta.get("cvss_score"),
                "severity":   meta.get("severity"),
                "cwe_ids":    meta.get("cwe_ids") or [],
                "published":  meta.get("published"),
            },
        ))

        if len(batch) >= BATCH_SIZE:
            client.upsert(collection_name=COLLECTION, points=batch)
            total_upserted += len(batch)
            batch.clear()
            if total_upserted % PROGRESS_EVERY == 0:
                logger.info("  Upserted %d / %d", total_upserted, n_emb)

    if batch:
        client.upsert(collection_name=COLLECTION, points=batch)
        total_upserted += len(batch)

    final_count = client.count(COLLECTION).count
    logger.info(
        "Done. Upserted %d points. Collection '%s' count: %d",
        total_upserted, COLLECTION, final_count,
    )
    return final_count


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s — %(message)s")

    p = argparse.ArgumentParser(description="Load CVE embeddings into Qdrant")
    p.add_argument("--embeddings",   default="ingest/cve_embeddings.npy",   help="Path to cve_embeddings.npy")
    p.add_argument("--metadata",     default="ingest/cve_metadata.jsonl",   help="Path to cve_metadata.jsonl")
    p.add_argument("--qdrant-host",  default="localhost")
    p.add_argument("--qdrant-port",  type=int, default=6333)
    p.add_argument("--wipe",         action="store_true", help="Delete and recreate collection before loading")
    args = p.parse_args()

    count = load(
        embeddings_path=args.embeddings,
        metadata_path=args.metadata,
        qdrant_host=args.qdrant_host,
        qdrant_port=args.qdrant_port,
        wipe=args.wipe,
    )
    print(f"Final collection count: {count}")
