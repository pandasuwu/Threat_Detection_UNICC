"""
Phase 4: Batch Embedder
Embeds CVE descriptions and ATT&CK technique text using a local sentence-transformer model.

Model choice:
  Primary:  sentence-transformers/all-mpnet-base-v2  (768-dim, general semantic similarity)
  Domain:   AI-Growth-Lab/SecBERT                     (768-dim, cybersecurity domain)

SecBERT is the better choice for domain relevance but requires more RAM.
all-mpnet-base-v2 is faster and works fine for CVE descriptions.
Switch via --model flag.

Scale:
  323,647 CVE descriptions @ median 37 words = ~40s on GPU, ~12min on CPU (batch 256)
  691 ATT&CK techniques = seconds

Output:
  cve_embeddings.npy       — float32 array (N, 768)
  cve_metadata.jsonl       — {cve_id, stix_id, cvss_score, severity, cwe_ids, idx} per row
  attack_embeddings.npy    — float32 array (691, 768)
  attack_metadata.jsonl    — {attack_id, stix_id, name, tactic_ids, idx} per row

Paramananta note:
  This is a candidate for HPC if CPU-only and time-constrained.
  SLURM array job: shard cve_metadata.jsonl into N slices, embed each, merge .npy arrays.
  But local GPU (if available) is likely faster than the SLURM queue overhead for this scale.
"""

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Iterator

import numpy as np

logger = logging.getLogger(__name__)

# Lazy import — not available in all environments
_model = None


def get_model(model_name: str):
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        logger.info(f"Loading embedding model: {model_name}")
        t0 = time.time()
        _model = SentenceTransformer(model_name)
        logger.info(f"Model loaded in {time.time()-t0:.1f}s")
    return _model


# ── CVE embedding ────────────────────────────────────────────────────────────

def build_cve_text(record: dict) -> str:
    """
    Construct the text to embed for a CVE record.
    We prepend key metadata tokens to bias the embedding toward security-relevant dimensions.

    Format: "<severity> <cwe_ids>: <description>"
    Example: "HIGH CWE-79 CWE-352: Cross-site scripting in Apache Struts 2..."
    """
    parts = []
    severity = record.get("severity")
    if severity:
        parts.append(severity.upper())
    cwes = record.get("cwe_ids") or []
    if cwes:
        parts.append(" ".join(cwes))
    desc = (record.get("description") or "").strip()
    if parts:
        return ": ".join([" ".join(parts), desc]) if desc else " ".join(parts)
    return desc


def embed_cves(
    input_path: str,
    output_dir: str,
    model_name: str,
    batch_size: int = 256,
    min_desc_len: int = 5,
) -> dict:
    """
    Embed all CVE descriptions and write:
      - <output_dir>/cve_embeddings.npy
      - <output_dir>/cve_metadata.jsonl

    Returns stats dict.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    meta_path = output_dir / "cve_metadata.jsonl"
    emb_path  = output_dir / "cve_embeddings.npy"

    # ── Check for existing progress (resume support) ──────────────────────
    done_cve_ids: set[str] = set()
    start_idx = 0
    if meta_path.exists():
        with open(meta_path, encoding="utf-8") as f:
            for line in f:
                m = json.loads(line)
                done_cve_ids.add(m["cve_id"])
        start_idx = len(done_cve_ids)
        logger.info(f"Resuming from {start_idx:,} already embedded CVEs")

    # ── Load model ────────────────────────────────────────────────────────
    model = get_model(model_name)

    # ── Stream and batch ──────────────────────────────────────────────────
    texts_buf: list[str]  = []
    meta_buf:  list[dict] = []
    idx = start_idx
    skipped = 0
    all_embeddings: list[np.ndarray] = []

    # Load existing embeddings if resuming
    if emb_path.exists() and start_idx > 0:
        logger.info(f"Loading {start_idx} existing embeddings from {emb_path}")
        existing = np.load(emb_path)
        all_embeddings.append(existing)

    def flush_batch():
        nonlocal idx
        if not texts_buf:
            return
        embeddings = model.encode(
            texts_buf, batch_size=min(batch_size, len(texts_buf)),
            show_progress_bar=False, normalize_embeddings=True
        )
        all_embeddings.append(embeddings.astype(np.float32))
        with open(meta_path, "a", encoding="utf-8") as mf:
            for i, meta in enumerate(meta_buf):
                mf.write(json.dumps(meta) + "\n")
        idx += len(texts_buf)
        if idx % 20_000 == 0:
            # Checkpoint: save .npy periodically
            np.save(emb_path, np.vstack(all_embeddings))
            logger.info(f"  Checkpoint at {idx:,} embeddings saved")
        texts_buf.clear()
        meta_buf.clear()

    with open(input_path, encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            cve_id = record["cve_id"]

            if cve_id in done_cve_ids:
                continue

            text = build_cve_text(record)
            if len(text.split()) < min_desc_len:
                skipped += 1
                # Still add a zero vector placeholder so indexing stays consistent
                # Actually: skip entirely and don't index — short CVEs aren't useful for search
                continue

            texts_buf.append(text)
            meta_buf.append({
                "idx":        idx + len(texts_buf) - 1,
                "cve_id":     cve_id,
                "cvss_score": record.get("cvss_score"),
                "severity":   record.get("severity"),
                "cwe_ids":    record.get("cwe_ids") or [],
                "published":  record.get("published_date"),
            })

            if len(texts_buf) >= batch_size:
                flush_batch()

    flush_batch()  # final partial batch

    # Final save
    if all_embeddings:
        final = np.vstack(all_embeddings)
        np.save(emb_path, final)
        logger.info(f"Saved {final.shape[0]:,} embeddings → {emb_path} ({final.nbytes/1e9:.2f} GB)")

    return {
        "embedded": idx,
        "skipped_too_short": skipped,
        "embedding_shape": list(final.shape) if all_embeddings else [0, 0],
        "output_dir": str(output_dir),
    }


# ── ATT&CK technique embedding ───────────────────────────────────────────────

def embed_attack_techniques(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    output_dir: str,
    model_name: str,
) -> dict:
    """
    Embed all ATT&CK Technique nodes from Neo4j.
    Text = "<tactic_names> | <technique_name>: <description>"
    """
    from neo4j import GraphDatabase

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    with driver.session() as session:
        rows = session.run(
            """
            MATCH (t:Technique)
            OPTIONAL MATCH (t)-[:ENABLES_TACTIC]->(tac:Tactic)
            RETURN t.stix_id    AS stix_id,
                   t.attack_id  AS attack_id,
                   t.name       AS name,
                   t.description AS description,
                   collect(tac.name) AS tactics
            """
        ).data()
    driver.close()

    logger.info(f"Fetched {len(rows)} ATT&CK techniques from Neo4j")

    def tech_text(row: dict) -> str:
        tactic_str = " | ".join(row.get("tactics") or [])
        name = row.get("name") or ""
        desc = (row.get("description") or "")[:500]  # cap at 500 chars
        return f"{tactic_str} | {name}: {desc}" if tactic_str else f"{name}: {desc}"

    model = get_model(model_name)
    texts = [tech_text(r) for r in rows]
    embeddings = model.encode(texts, batch_size=64, show_progress_bar=True, normalize_embeddings=True)

    meta_path = output_dir / "attack_metadata.jsonl"
    emb_path  = output_dir / "attack_embeddings.npy"

    np.save(emb_path, embeddings.astype(np.float32))
    with open(meta_path, "w", encoding="utf-8") as f:
        for i, row in enumerate(rows):
            f.write(json.dumps({
                "idx":       i,
                "stix_id":   row["stix_id"],
                "attack_id": row["attack_id"],
                "name":      row["name"],
                "tactics":   row.get("tactics") or [],
            }) + "\n")

    logger.info(f"ATT&CK embeddings: {embeddings.shape} → {emb_path}")
    return {"n_techniques": len(rows), "shape": list(embeddings.shape)}


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s — %(message)s")

    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    # cves
    sp = sub.add_parser("cves")
    sp.add_argument("--input",      required=True)
    sp.add_argument("--output-dir", required=True)
    sp.add_argument("--model",      default="sentence-transformers/all-mpnet-base-v2")
    sp.add_argument("--batch-size", type=int, default=256)

    # attack
    sp = sub.add_parser("attack")
    sp.add_argument("--output-dir",      required=True)
    sp.add_argument("--model",           default="sentence-transformers/all-mpnet-base-v2")
    sp.add_argument("--neo4j-uri",       default="bolt://localhost:7687")
    sp.add_argument("--neo4j-user",      default="neo4j")
    sp.add_argument("--neo4j-password",  required=True)

    args = p.parse_args()

    if args.cmd == "cves":
        stats = embed_cves(args.input, args.output_dir, args.model, args.batch_size)
        print(stats)
    elif args.cmd == "attack":
        stats = embed_attack_techniques(
            args.neo4j_uri, args.neo4j_user, args.neo4j_password,
            args.output_dir, args.model
        )
        print(stats)
