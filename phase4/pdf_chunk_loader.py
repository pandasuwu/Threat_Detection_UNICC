"""
pdf_chunk_loader.py
-------------------
Loads Docling-parsed PDF chunks into Qdrant collection `pdf_chunks`.

Usage:
    python3 pdf_chunk_loader.py [--dry-run] [--batch-size 64]

Expects:
    ~/Workspace/parse/parse/  — double-nested dir from handoff doc
    Each PDF produces two files:
        <name>.json   — Docling structured output  (primary)
        <name>.md     — fallback if .json missing

Qdrant payload schema per point:
    {
        "text":        str,        # chunk text
        "source":      str,        # report name e.g. "ENISA_2024"
        "source_type": "pdf",      # for /search filter
        "page":        int | None,
        "chunk_index": int,
        "doc_id":      str,        # sha1 of source filename
    }
"""

import argparse
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
    PayloadSchemaType,
)
from sentence_transformers import SentenceTransformer

# ── Config ────────────────────────────────────────────────────────────────────

PARSE_DIR = Path.home() / "Workspace" / "parse" 
QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", 6333))
EMBED_MODEL = os.getenv("EMBED_MODEL", "sentence-transformers/all-mpnet-base-v2")
COLLECTION = "pdf_chunks"
VECTOR_DIM = 768          # all-mpnet-base-v2 output dimension
BATCH_SIZE = 64
MIN_CHUNK_CHARS = 80      # discard boilerplate / page-number fragments

# Known report names → canonical source label (extend as needed)
SOURCE_MAP = {
    "att_v5":              "ATT_CSRIC_v5",
    "att_v6":              "ATT_CSRIC_v6",
    "att_v8":              "ATT_CSRIC_v8",
    "enisa_2023":          "ENISA_2023",
    "enisa_2024":          "ENISA_2024",
    "enisa_2025":          "ENISA_2025",
    "microsoft_ddfr_2023": "Microsoft_DDFR_2023",
    "microsoft_ddfr_2025": "Microsoft_DDFR_2025",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _doc_id(filename: str) -> str:
    return hashlib.sha1(filename.encode()).hexdigest()[:12]


def _canonical_source(stem: str) -> str:
    s = stem.lower()
    for key, label in SOURCE_MAP.items():
        if key in s:
            return label
    return stem  # fallback: raw filename stem


def _extract_chunks_from_docling_json(path: Path) -> list[dict[str, Any]]:
    """
    Docling JSON schema (HybridChunker output):
        {
          "chunks": [
            {
              "text": "...",
              "meta": {"page_no": 3, ...},
              ...
            }
          ]
        }
    Falls back to top-level keys if schema differs.
    """
    with open(path) as f:
        data = json.load(f)

    raw_chunks: list[dict] = []

    # HybridChunker canonical format
    if "chunks" in data:
        raw_chunks = data["chunks"]
    # Some Docling versions wrap under "body" or "content"
    elif "body" in data:
        raw_chunks = data["body"] if isinstance(data["body"], list) else []
    elif "content" in data:
        raw_chunks = data["content"] if isinstance(data["content"], list) else []
    else:
        # Flat list at root
        if isinstance(data, list):
            raw_chunks = data

    chunks = []
    for i, c in enumerate(raw_chunks):
        if isinstance(c, str):
            text = c
            page = None
        elif isinstance(c, dict):
            # Try common text field names
            text = (
                c.get("text")
                or c.get("content")
                or c.get("body")
                or ""
            )
            meta = c.get("meta") or c.get("metadata") or {}
            page = meta.get("page_no") or meta.get("page") or c.get("page_no")
        else:
            continue

        text = text.strip()
        if len(text) < MIN_CHUNK_CHARS:
            continue

        chunks.append({"text": text, "page": page, "chunk_index": i})

    return chunks


def _extract_chunks_from_md(path: Path) -> list[dict[str, Any]]:
    """
    Markdown fallback: split on double newlines, keep ≥ MIN_CHUNK_CHARS segments.
    Page info not available from .md — set to None.
    """
    text = path.read_text(errors="replace")
    raw = [p.strip() for p in text.split("\n\n")]
    return [
        {"text": p, "page": None, "chunk_index": i}
        for i, p in enumerate(raw)
        if len(p) >= MIN_CHUNK_CHARS
    ]


def discover_documents(parse_dir: Path) -> list[dict[str, Any]]:
    """
    Walk parse_dir, pair .json + .md for each PDF.
    Returns list of {stem, source_label, doc_id, json_path, md_path}.
    """
    docs = {}
    for p in sorted(parse_dir.rglob("*")):
        if p.suffix not in (".json", ".md"):
            continue
        # Skip summary/metadata files
        if p.name.startswith("_") or "parse_summary" in p.name:
            continue
        stem = p.stem
        if stem not in docs:
            docs[stem] = {"stem": stem, "json_path": None, "md_path": None}
        if p.suffix == ".json":
            docs[stem]["json_path"] = p
        else:
            docs[stem]["md_path"] = p

    result = []
    for stem, d in docs.items():
        result.append(
            {
                **d,
                "source_label": _canonical_source(stem),
                "doc_id": _doc_id(stem),
            }
        )
    return result


def load_chunks(doc: dict[str, Any]) -> list[dict[str, Any]]:
    chunks = []
    if doc["json_path"]:
        try:
            chunks = _extract_chunks_from_docling_json(doc["json_path"])
        except Exception as e:
            print(f"  ⚠  JSON parse failed for {doc['stem']}: {e}")

    if not chunks and doc["md_path"]:
        print(f"  ↩  Falling back to .md for {doc['stem']}")
        chunks = _extract_chunks_from_md(doc["md_path"])

    return chunks


# ── Qdrant setup ──────────────────────────────────────────────────────────────

def ensure_collection(client: QdrantClient) -> None:
    existing = {c.name for c in client.get_collections().collections}
    if COLLECTION not in existing:
        print(f"Creating collection '{COLLECTION}' (dim={VECTOR_DIM}, cosine)…")
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )
        # Payload index for source_type filter — mirrors cve collection pattern
        client.create_payload_index(
            collection_name=COLLECTION,
            field_name="source_type",
            field_schema=PayloadSchemaType.KEYWORD,
        )
        client.create_payload_index(
            collection_name=COLLECTION,
            field_name="source",
            field_schema=PayloadSchemaType.KEYWORD,
        )
    else:
        print(f"Collection '{COLLECTION}' already exists — upserting into it.")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(dry_run: bool = False, batch_size: int = BATCH_SIZE) -> None:
    print(f"Scanning: {PARSE_DIR}")
    docs = discover_documents(PARSE_DIR)
    if not docs:
        print("No documents found. Check PARSE_DIR path.")
        return
    print(f"Found {len(docs)} document(s): {[d['source_label'] for d in docs]}")

    # Collect all chunks first to report counts before embedding
    all_chunks: list[dict[str, Any]] = []
    for doc in docs:
        chunks = load_chunks(doc)
        print(f"  {doc['source_label']:30s} → {len(chunks):4d} chunks")
        for c in chunks:
            c["source"] = doc["source_label"]
            c["source_type"] = "pdf"
            c["doc_id"] = doc["doc_id"]
        all_chunks.extend(chunks)

    print(f"\nTotal chunks to embed: {len(all_chunks)}")
    if dry_run:
        print("Dry-run mode — stopping before embed/upsert.")
        return

    print(f"Loading embedding model: {EMBED_MODEL}")
    model = SentenceTransformer(EMBED_MODEL)

    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    ensure_collection(client)

    texts = [c["text"] for c in all_chunks]
    total = len(texts)
    points: list[PointStruct] = []

    t0 = time.time()
    for start in range(0, total, batch_size):
        batch_texts = texts[start : start + batch_size]
        batch_meta = all_chunks[start : start + batch_size]

        vectors = model.encode(batch_texts, show_progress_bar=False).tolist()

        for vec, meta in zip(vectors, batch_meta):
            points.append(
                PointStruct(
                    id=str(uuid.uuid4()),
                    vector=vec,
                    payload={
                        "text":        meta["text"],
                        "source":      meta["source"],
                        "source_type": meta["source_type"],
                        "page":        meta["page"],
                        "chunk_index": meta["chunk_index"],
                        "doc_id":      meta["doc_id"],
                    },
                )
            )

        done = min(start + batch_size, total)
        elapsed = time.time() - t0
        rate = done / elapsed if elapsed > 0 else 0
        print(f"  Embedded {done:5d}/{total} ({rate:.0f} chunks/s)", end="\r")

    print(f"\nUpserting {len(points)} points into '{COLLECTION}'…")
    # Upsert in batches to avoid gRPC message size limits
    for start in range(0, len(points), 256):
        client.upsert(
            collection_name=COLLECTION,
            points=points[start : start + 256],
        )

    elapsed = time.time() - t0
    info = client.get_collection(COLLECTION)
    print(f"\n✅ Done in {elapsed:.1f}s")
    print(f"   Collection '{COLLECTION}' now has {info.points_count} points.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Discover and count chunks without embedding or uploading")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    args = parser.parse_args()
    run(dry_run=args.dry_run, batch_size=args.batch_size)
