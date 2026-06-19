"""
Daily CVE auto-update orchestrator — Issue #5.

Pipeline (each step is idempotent):
  1. git pull on CVELIST_DIR to advance to the latest commit
  2. git diff from last_successful_commit → list of changed CVE JSON files
  3. normalize_file() each changed file (reuses ingest/normalize_cves.py)
  4. Embed descriptions with all-mpnet-base-v2 in batches
  5. Upsert to Qdrant 'cve_descriptions' — uuid5(cve_id) point IDs
  6. Upsert to Neo4j (:Vulnerability) nodes — MERGE on cve_id
  7. Update state file and log

State file:  data/cve_sync_state.json
Log file:    data/cve_sync.log

Idempotency guarantee:
  Qdrant uses uuid5(cve_id) IDs — upsert is a no-op for already-loaded CVEs.
  Neo4j uses MERGE on cve_id — idempotent by definition.
  State records source_commit_hash only on SUCCESSFUL completion.
  If killed mid-run, source_commit_hash stays at the previous successful commit,
  so resume reprocesses the same diff (all upserts are no-ops for done work).

SIGTERM / SIGINT:
  A signal sets the shutdown flag. After the current batch completes, the
  loop exits WITHOUT updating source_commit_hash or last_successful_completion.
  Resume will reprocess the same diff cleanly.

Usage:
  python -m ingest.cve_sync                # full sync
  python -m ingest.cve_sync --dry-run      # print diff only, no writes
  python -m ingest.cve_sync --limit 500    # process at most 500 files (testing)
  python -m ingest.cve_sync --force-full   # ignore last commit, reprocess all
"""

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PayloadSchemaType, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

from ingest.normalize_cves import normalize_file
from ingest.embedder import build_cve_text

load_dotenv()

# ── Config ───────────────────────────────────────────────────────────────────

STATE_FILE   = Path("data/cve_sync_state.json")
LOG_FILE     = Path("data/cve_sync.log")
COLLECTION   = "cve_descriptions"
VECTOR_DIM   = 768
EMBED_MODEL  = "sentence-transformers/all-mpnet-base-v2"
BATCH_SIZE   = 256
_NS          = uuid.NAMESPACE_URL

# Neo4j Cypher — MERGE on cve_id (index exists from graph/neo4j_loader.py)
_MERGE_VULN = """
UNWIND $rows AS r
MERGE (v:Vulnerability {cve_id: r.cve_id})
SET v.description    = r.description,
    v.cvss_score     = r.cvss_score,
    v.severity       = r.severity,
    v.cwe_ids        = r.cwe_ids,
    v.published_date = r.published_date
"""

# ── Shutdown flag (set by SIGTERM / SIGINT) ───────────────────────────────────

_SHUTDOWN = False


def _handle_signal(signum, frame):
    global _SHUTDOWN
    _SHUTDOWN = True
    logging.getLogger(__name__).warning(
        "Signal %s received — will stop after current batch", signum
    )


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)


# ── Logging ───────────────────────────────────────────────────────────────────

def _setup_logging() -> logging.Logger:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt = "%(asctime)s %(levelname)s — %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stderr),
        ],
    )
    return logging.getLogger(__name__)


# ── State file ────────────────────────────────────────────────────────────────

_EMPTY_STATE = {
    "last_run_timestamp":       None,
    "last_processed_cve_count": 0,
    "source_commit_hash":       None,
    "last_successful_completion": None,
}


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return dict(_EMPTY_STATE)


def _save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, STATE_FILE)  # atomic on POSIX


# ── Git helpers ───────────────────────────────────────────────────────────────

def _git(cvelist_dir: Path, *args) -> str:
    result = subprocess.run(
        ["git", "-C", str(cvelist_dir), *args],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def _git_pull(cvelist_dir: Path) -> str:
    """Fast-forward pull. Returns new HEAD commit hash."""
    _git(cvelist_dir, "fetch", "origin", "--quiet")
    _git(cvelist_dir, "merge", "--ff-only", "FETCH_HEAD")
    return _git(cvelist_dir, "rev-parse", "HEAD")


def _changed_files(
    cvelist_dir: Path,
    from_commit: str | None,
    to_commit: str,
) -> list[Path]:
    """
    Return CVE JSON files that changed between two commits.
    If from_commit is None (initial load), return all CVE JSON files.
    """
    cves_dir = cvelist_dir / "cves"
    if from_commit is None:
        return sorted(cves_dir.rglob("CVE-*.json"))

    raw = _git(cvelist_dir, "diff", "--name-only", from_commit, to_commit, "--", "cves/")
    files = []
    for line in raw.splitlines():
        if not line.endswith(".json"):
            continue
        p = cvelist_dir / line
        if p.exists():
            files.append(p)
    return files


# ── Field bridge ─────────────────────────────────────────────────────────────

def _flatten(record: dict) -> dict:
    """
    normalize_cves.py stores CVSS as cvss_v3: {score, severity, ...}.
    Qdrant payload and Neo4j nodes expect flat cvss_score + severity fields.
    build_cve_text() from embedder.py also expects the flat form.
    """
    cvss = record.get("cvss_v3") or {}
    return {
        **record,
        "cvss_score": cvss.get("score"),
        "severity":   cvss.get("severity"),
    }


# ── Qdrant helpers ────────────────────────────────────────────────────────────

def _point_id(cve_id: str) -> str:
    return str(uuid.uuid5(_NS, cve_id))


def _ensure_collection(client: QdrantClient) -> None:
    exists = any(c.name == COLLECTION for c in client.get_collections().collections)
    if not exists:
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )
        client.create_payload_index(COLLECTION, "cve_id", PayloadSchemaType.KEYWORD)


# ── Core sync loop ────────────────────────────────────────────────────────────

def _process_batch(
    batch: list[dict],
    model: SentenceTransformer,
    q_client: QdrantClient,
    neo4j_session,
    log: logging.Logger,
) -> int:
    """Embed, upsert to Qdrant, and upsert to Neo4j. Returns count processed."""
    flat_records = [_flatten(r) for r in batch]

    texts = [build_cve_text(r) for r in flat_records]
    vectors = model.encode(
        texts, batch_size=BATCH_SIZE, show_progress_bar=False, normalize_embeddings=True
    ).tolist()

    # Qdrant upsert
    points = [
        PointStruct(
            id=_point_id(r["cve_id"]),
            vector=vec,
            payload={
                "cve_id":     r["cve_id"],
                "cvss_score": r.get("cvss_score"),
                "severity":   r.get("severity"),
                "cwe_ids":    r.get("cwe_ids") or [],
                "published":  r.get("published_date"),
            },
        )
        for r, vec in zip(flat_records, vectors)
    ]
    q_client.upsert(COLLECTION, points=points)

    # Neo4j upsert
    neo4j_rows = [
        {
            "cve_id":        r["cve_id"],
            "description":   r.get("description") or "",
            "cvss_score":    r.get("cvss_score"),
            "severity":      r.get("severity"),
            "cwe_ids":       r.get("cwe_ids") or [],
            "published_date": r.get("published_date"),
        }
        for r in flat_records
    ]
    neo4j_session.run(_MERGE_VULN, rows=neo4j_rows)

    return len(batch)


def sync(
    cvelist_dir: Path,
    dry_run: bool,
    limit: int,
    force_full: bool,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    qdrant_host: str,
    qdrant_port: int,
) -> None:
    log = _setup_logging()
    log.info("=== cve_sync starting ===")

    state = _load_state()
    state["last_run_timestamp"] = datetime.now(timezone.utc).isoformat()
    _save_state(state)

    # ── Git pull ──────────────────────────────────────────────────────────────
    log.info("git pull: %s", cvelist_dir)
    try:
        new_commit = _git_pull(cvelist_dir)
    except subprocess.CalledProcessError as e:
        log.error("git pull failed: %s", e.stderr)
        sys.exit(1)
    log.info("HEAD: %s", new_commit)

    last_commit = None if force_full else state.get("source_commit_hash")

    if last_commit and last_commit == new_commit:
        log.info("Already up to date (%s). Nothing to do.", new_commit[:12])
        state["last_run_timestamp"] = datetime.now(timezone.utc).isoformat()
        _save_state(state)
        return

    # ── Determine file set ────────────────────────────────────────────────────
    log.info(
        "Computing diff: %s..%s",
        (last_commit or "initial")[:12],
        new_commit[:12],
    )
    try:
        cve_files = _changed_files(cvelist_dir, last_commit, new_commit)
    except subprocess.CalledProcessError as e:
        log.error("git diff failed: %s", e.stderr)
        sys.exit(1)

    if limit:
        cve_files = cve_files[:limit]

    total_files = len(cve_files)
    log.info("Files to process: %d", total_files)

    if total_files == 0:
        log.info("No CVE files in diff. State unchanged.")
        return

    if dry_run:
        print(f"--dry-run: {total_files} CVE files would be processed")
        print(f"  from: {(last_commit or 'all')[:12]}")
        print(f"  to:   {new_commit[:12]}")
        for f in cve_files[:20]:
            print(f"  {f.name}")
        if total_files > 20:
            print(f"  ... and {total_files - 20} more")
        return

    # ── Normalize all files first (fast, no GPU) ──────────────────────────────
    cve_root = cvelist_dir / "cves"
    records: list[dict] = []
    skipped = 0
    for path in cve_files:
        rec = normalize_file(path, cve_root)
        if rec is None:
            skipped += 1
        else:
            records.append(rec)
    log.info("Normalized %d records (%d skipped/rejected)", len(records), skipped)

    if not records:
        log.info("No valid records after normalization.")
        return

    # ── Connect to backends ───────────────────────────────────────────────────
    # Force CPU: daily CVE syncs are small (100-2000 records); CPU avoids the
    # CUDA context corruption that SIGTERM causes mid-GPU-kernel when the GPU
    # is also shared with the PDF-chunk loader or other processes.
    log.info("Loading embedding model: %s (device=cpu)", EMBED_MODEL)
    model = SentenceTransformer(EMBED_MODEL, device="cpu")

    q_client = QdrantClient(host=qdrant_host, port=qdrant_port)
    _ensure_collection(q_client)

    if not neo4j_password:
        log.error("NEO4J_PASSWORD not set")
        sys.exit(1)
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    driver.verify_connectivity()

    # ── Batch process ─────────────────────────────────────────────────────────
    processed = 0
    interrupted = False

    with driver.session() as session:
        for start in range(0, len(records), BATCH_SIZE):
            if _SHUTDOWN:
                log.warning("Shutdown flag set — stopping before batch %d", start)
                interrupted = True
                break

            batch = records[start: start + BATCH_SIZE]
            try:
                n = _process_batch(batch, model, q_client, session, log)
            except (RuntimeError, SystemExit, KeyboardInterrupt) as exc:
                # SIGTERM mid-CUDA-kernel raises RuntimeError (PyTorch CUDA assert)
                # or KeyboardInterrupt. Treat as a clean interrupt when flag is set.
                if _SHUTDOWN:
                    log.warning(
                        "Interrupted during batch %d (%s) — treating as clean stop",
                        start, type(exc).__name__,
                    )
                    interrupted = True
                    break
                raise
            processed += n

            pct = 100 * processed / len(records)
            log.info(
                "Progress: %d / %d (%.1f%%)  — Qdrant+Neo4j upserted",
                processed, len(records), pct,
            )

    driver.close()

    q_count = q_client.count(COLLECTION).count
    log.info("Qdrant '%s' total points: %d", COLLECTION, q_count)

    if interrupted:
        log.warning(
            "Run interrupted after %d / %d records. "
            "State NOT updated — resume will reprocess the same diff.",
            processed, len(records),
        )
        return

    # ── Update state only on successful completion ────────────────────────────
    now = datetime.now(timezone.utc).isoformat()
    state.update({
        "last_run_timestamp":        now,
        "last_processed_cve_count":  q_count,
        "source_commit_hash":        new_commit,
        "last_successful_completion": now,
    })
    _save_state(state)
    log.info(
        "=== cve_sync complete: %d processed, %d in collection, commit %s ===",
        processed, q_count, new_commit[:12],
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cvelist-dir",
        default=os.getenv("CVELIST_DIR", ""),
        help="Path to cloned cvelistV5 repo (default: $CVELIST_DIR)",
    )
    parser.add_argument("--dry-run",    action="store_true",
                        help="Print diff only; skip all writes and state update")
    parser.add_argument("--force-full", action="store_true",
                        help="Ignore last commit; reprocess all CVE files")
    parser.add_argument("--limit",      type=int, default=0,
                        help="Cap number of CVE files to process (0 = all; for testing)")
    parser.add_argument("--neo4j-uri",      default=os.getenv("NEO4J_URI",      "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user",     default=os.getenv("NEO4J_USER",     "neo4j"))
    parser.add_argument("--neo4j-password", default=os.getenv("NEO4J_PASSWORD", ""))
    parser.add_argument("--qdrant-host",    default=os.getenv("QDRANT_HOST",    "localhost"))
    parser.add_argument("--qdrant-port",    type=int, default=int(os.getenv("QDRANT_PORT", "6333")))
    args = parser.parse_args()

    if not args.cvelist_dir:
        sys.exit(
            "ERROR: CVELIST_DIR not set. "
            "Set it in .env or pass --cvelist-dir <path to cvelistV5 clone>."
        )

    cvelist_dir = Path(args.cvelist_dir)
    if not cvelist_dir.exists():
        sys.exit(f"ERROR: {cvelist_dir} does not exist.")
    if not (cvelist_dir / ".git").exists():
        sys.exit(f"ERROR: {cvelist_dir} is not a git repository.")

    sync(
        cvelist_dir=cvelist_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        force_full=args.force_full,
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        qdrant_host=args.qdrant_host,
        qdrant_port=args.qdrant_port,
    )


if __name__ == "__main__":
    main()
