"""
normalize_cves.py — CVE JSON 5.x → flat schema normalizer
============================================================
Walks ~/data/json/cvelistV5/cves/**/*.json and outputs a single
normalized JSONL file (one CVE per line) with this flat schema:

  {
    "cve_id":            "CVE-2024-1212",
    "description":       "...",          # English, from cna (preferred) or adp
    "cvss_v3":           {               # best score found across cna + adp
      "score":           9.8,
      "severity":        "CRITICAL",
      "vector":          "CVSS:3.1/AV:N/...",
      "version":         "3.1"           # "3.0" or "3.1"
    },
    "cwe_ids":           ["CWE-78"],     # deduplicated, from cna + adp
    "affected_products": [               # from cna.affected[]
      {
        "vendor":  "Progress Software",
        "product": "LoadMaster",
        "versions": [
          {"version": "7.2.48.1", "lessThan": "7.2.48.10", "status": "affected"}
        ]
      }
    ],
    "published_date":    "2024-02-21",   # ISO date only (no time)
    "state":             "PUBLISHED",
    "source_file":       "cves/2024/1xxx/CVE-2024-1212.json"
  }

CVSS priority: if multiple scores exist across containers, the highest
baseScore wins (gives you worst-case severity — appropriate for ground truth).

Skips REJECTED records by default (set INCLUDE_REJECTED=true to keep them).

Usage:
    python normalize_cves.py                          # defaults
    python normalize_cves.py --input ~/data/json/cvelistV5/cves \\
                             --output ./cve_normalized.jsonl \\
                             --workers 8
"""

import argparse
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Constants ────────────────────────────────────────────────────────────────
DEFAULT_INPUT  = Path.home() / "data" / "json" / "cvelistV5" / "cves"
DEFAULT_OUTPUT = Path("cve_normalized.jsonl")
DEFAULT_WORKERS = max(1, (os.cpu_count() or 4) - 1)
INCLUDE_REJECTED = os.getenv("INCLUDE_REJECTED", "false").lower() == "true"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _iso_date(ts: Optional[str]) -> Optional[str]:
    """'2024-02-21T17:39:12.599Z' → '2024-02-21'.  Returns None if blank."""
    if not ts:
        return None
    return ts[:10]   # always safe — schema guarantees ISO 8601


def _get_english_description(descriptions: list) -> Optional[str]:
    """
    Pick the English description from a descriptions[] array.
    Prefers lang='en', falls back to first entry.
    """
    if not descriptions:
        return None
    for d in descriptions:
        if isinstance(d, dict) and d.get("lang", "").startswith("en"):
            return d.get("value", "").strip() or None
    # fallback: first entry regardless of language
    first = descriptions[0]
    return first.get("value", "").strip() if isinstance(first, dict) else None


def _extract_cvss_v3(metrics: list) -> Optional[dict]:
    """
    Find the best (highest baseScore) CVSS v3.x entry from a metrics[] array.
    Handles both cvssV3_1 and cvssV3_0 keys.
    Returns None if no v3 score present.
    """
    best = None
    best_score = -1.0

    for m in (metrics or []):
        if not isinstance(m, dict):
            continue
        for key in ("cvssV3_1", "cvssV3_0"):
            cvss = m.get(key)
            if not isinstance(cvss, dict):
                continue
            score = cvss.get("baseScore")
            if score is None:
                continue
            try:
                score = float(score)
            except (TypeError, ValueError):
                continue
            if score > best_score:
                best_score = score
                version = "3.1" if key == "cvssV3_1" else "3.0"
                best = {
                    "score":    score,
                    "severity": cvss.get("baseSeverity", "").upper() or _score_to_severity(score),
                    "vector":   cvss.get("vectorString", ""),
                    "version":  version,
                }
    return best


def _score_to_severity(score: float) -> str:
    """Derive severity label from numeric score when baseSeverity is missing."""
    if score == 0.0:   return "NONE"
    if score < 4.0:    return "LOW"
    if score < 7.0:    return "MEDIUM"
    if score < 9.0:    return "HIGH"
    return "CRITICAL"


def _extract_cwes(problem_types: list) -> list[str]:
    """
    Pull all CWE IDs from problemTypes[].descriptions[].
    Returns a deduplicated sorted list like ["CWE-78", "CWE-89"].
    """
    seen = set()
    for pt in (problem_types or []):
        if not isinstance(pt, dict):
            continue
        for desc in pt.get("descriptions", []):
            if not isinstance(desc, dict):
                continue
            cwe = desc.get("cweId", "").strip()
            if cwe and cwe.upper().startswith("CWE-"):
                seen.add(cwe.upper())
    return sorted(seen)


def _extract_affected(affected: list) -> list[dict]:
    """
    Normalise cna.affected[] into a clean list of
    {vendor, product, versions: [{version, lessThan?, status}]}.
    """
    results = []
    for entry in (affected or []):
        if not isinstance(entry, dict):
            continue
        vendor  = entry.get("vendor",  "").strip()
        product = entry.get("product", "").strip()
        if not product:
            continue

        versions = []
        for v in entry.get("versions", []):
            if not isinstance(v, dict):
                continue
            ver_entry: dict = {}
            if v.get("version"):
                ver_entry["version"] = v["version"]
            if v.get("lessThan"):
                ver_entry["lessThan"] = v["lessThan"]
            if v.get("lessThanOrEqual"):
                ver_entry["lessThanOrEqual"] = v["lessThanOrEqual"]
            if v.get("status"):
                ver_entry["status"] = v["status"]
            if ver_entry:
                versions.append(ver_entry)

        results.append({
            "vendor":   vendor,
            "product":  product,
            "versions": versions,
        })
    return results


# ── Per-file normalizer ───────────────────────────────────────────────────────

def normalize_file(json_path: Path, root: Path) -> Optional[dict]:
    """
    Parse one CVE JSON 5.x file and return the flat record.
    Returns None for REJECTED records (unless INCLUDE_REJECTED).
    Returns None on any parse error (caller logs).
    """
    try:
        raw = json.loads(json_path.read_bytes())
    except Exception:
        return None

    meta = raw.get("cveMetadata", {})
    state = meta.get("state", "")

    if state == "REJECTED" and not INCLUDE_REJECTED:
        return None

    containers = raw.get("containers", {})
    cna = containers.get("cna", {})

    # ── ADP containers (CISA Vulnrichment etc.) ───────────────────────────
    # adp is a list; we merge metrics + problemTypes from all of them
    adp_list = containers.get("adp", [])
    if isinstance(adp_list, dict):
        adp_list = [adp_list]   # some older records have a single object

    # ── Description: cna first, then adp ─────────────────────────────────
    description = _get_english_description(cna.get("descriptions", []))
    if not description:
        for adp in adp_list:
            description = _get_english_description(adp.get("descriptions", []))
            if description:
                break

    # ── CVSS v3: best score across cna + all adp ─────────────────────────
    all_metrics = list(cna.get("metrics", []))
    for adp in adp_list:
        all_metrics.extend(adp.get("metrics", []))
    cvss_v3 = _extract_cvss_v3(all_metrics)

    # ── CWEs: union of cna + all adp ─────────────────────────────────────
    all_problem_types = list(cna.get("problemTypes", []))
    for adp in adp_list:
        all_problem_types.extend(adp.get("problemTypes", []))
    cwe_ids = _extract_cwes(all_problem_types)

    # ── Affected products: cna only (authoritative) ───────────────────────
    affected_products = _extract_affected(cna.get("affected", []))

    # ── Dates ─────────────────────────────────────────────────────────────
    published_date = _iso_date(meta.get("datePublished"))

    return {
        "cve_id":            meta.get("cveId", ""),
        "description":       description,
        "cvss_v3":           cvss_v3,
        "cwe_ids":           cwe_ids,
        "affected_products": affected_products,
        "published_date":    published_date,
        "state":             state,
        "source_file":       str(json_path.relative_to(root.parent)),
    }


# ── Worker (top-level so ProcessPoolExecutor can pickle it) ──────────────────

def _worker(args: tuple) -> tuple[str, Optional[dict], Optional[str]]:
    """Returns (path_str, record_or_None, error_or_None)."""
    path_str, root_str = args
    path = Path(path_str)
    root = Path(root_str)
    try:
        record = normalize_file(path, root)
        return (path_str, record, None)
    except Exception as exc:
        return (path_str, None, str(exc))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Normalize CVE JSON 5.x → flat JSONL")
    parser.add_argument("--input",   type=Path, default=DEFAULT_INPUT,
                        help=f"Path to cvelistV5/cves directory (default: {DEFAULT_INPUT})")
    parser.add_argument("--output",  type=Path, default=DEFAULT_OUTPUT,
                        help=f"Output .jsonl file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--workers", type=int,  default=DEFAULT_WORKERS,
                        help=f"Parallel workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--limit",   type=int,  default=0,
                        help="Only process first N files (0 = all, for testing)")
    args = parser.parse_args()

    cve_root: Path = args.input
    if not cve_root.exists():
        print(f"[ERROR] Input path not found: {cve_root}", file=sys.stderr)
        print("  Expected: ~/data/json/cvelistV5/cves", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Scanning {cve_root} …")
    all_files = sorted(cve_root.rglob("CVE-*.json"))
    if args.limit:
        all_files = all_files[:args.limit]
    total = len(all_files)
    print(f"[INFO] Found {total:,} CVE JSON files  |  workers={args.workers}")

    args.output.parent.mkdir(parents=True, exist_ok=True)

    written  = 0
    skipped  = 0   # REJECTED or missing data
    errors   = 0
    no_desc  = 0
    no_cvss  = 0
    no_cwe   = 0

    t0 = datetime.now(timezone.utc)

    task_args = [(str(f), str(cve_root)) for f in all_files]

    with open(args.output, "w", encoding="utf-8") as out_fh:
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(_worker, a): a[0] for a in task_args}

            done = 0
            for fut in as_completed(futures):
                done += 1
                path_str, record, err = fut.result()

                if err:
                    errors += 1
                    print(f"[WARN] Error processing {Path(path_str).name}: {err}",
                          file=sys.stderr)
                    continue

                if record is None:
                    skipped += 1
                    continue

                # Track coverage gaps (useful for downstream validation)
                if not record["description"]:
                    no_desc += 1
                if not record["cvss_v3"]:
                    no_cvss += 1
                if not record["cwe_ids"]:
                    no_cwe += 1

                out_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                written += 1

                if done % 10_000 == 0:
                    elapsed = (datetime.now(timezone.utc) - t0).seconds
                    rate = done / elapsed if elapsed else 0
                    print(f"  [{done:>7,}/{total:,}]  written={written:,}  "
                          f"skipped={skipped:,}  errors={errors}  "
                          f"({rate:.0f} files/s)")

    elapsed = (datetime.now(timezone.utc) - t0).total_seconds()
    print()
    print("=" * 60)
    print("NORMALIZATION COMPLETE")
    print("=" * 60)
    print(f"  Output file : {args.output}")
    print(f"  Total files : {total:,}")
    print(f"  Written     : {written:,}")
    print(f"  Skipped     : {skipped:,}  (REJECTED or non-CVE)")
    print(f"  Errors      : {errors}")
    print(f"  Time        : {elapsed:.1f}s  ({total/elapsed:.0f} files/s)")
    print()
    print("Coverage gaps (fields missing in output records):")
    print(f"  No description : {no_desc:,}  ({100*no_desc/max(written,1):.1f}%)")
    print(f"  No CVSS v3     : {no_cvss:,}  ({100*no_cvss/max(written,1):.1f}%)")
    print(f"  No CWE         : {no_cwe:,}  ({100*no_cwe/max(written,1):.1f}%)")


if __name__ == "__main__":
    main()
