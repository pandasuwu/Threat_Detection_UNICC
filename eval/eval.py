"""
eval.py — UNICC Pipeline Evaluation
=====================================
Runs 50 ground-truth queries across 5 categories against the live API and
measures retrieval quality + investigative efficiency.

Categories (10 queries each)
  A — Named CVE lookups        → /cve/{id}
  B — ATT&CK technique pivots  → /technique/{id}
  C — Threat actor attribution → /investigate
  D — Realistic analyst queries → /search or /investigate (per query)
  E — Campaign / multi-technique → /investigate

Metrics per query
  latency_s         : wall-clock seconds for the API call
  technique_recall  : fraction of expected ATT&CK IDs found in response
  technique_hit     : bool — at least one expected technique found (hit-rate@k)
  actor_recall      : fraction of expected threat groups found
  actor_hit         : bool — at least one expected actor found (hit-rate@k)
  cve_hit           : bool — at least one expected CVE found in response
  pdf_hit           : bool — at least one pdf_chunk result returned

Aggregate + per-category metrics written to eval_results.json.
Human-readable summary + efficiency multiplier written to eval_summary.txt.

Efficiency multiplier (computed, never hardcoded)
  = total manual analyst minutes × 60 / total system seconds

Usage
  # API must be running on port 8000
  python3 eval/eval.py [--api http://localhost:8000] \\
                       [--out eval_results.json] \\
                       [--summary eval_summary.txt]
"""

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

# eval_queries.py lives alongside this file; importable when run as a script
# (Python adds the script's directory to sys.path automatically).
from eval_queries import TEST_QUERIES

# ── Category definitions ─────────────────────────────────────────────────────

CATEGORIES: dict[str, dict] = {
    "A": {"label": "CVE lookups",          "ids": range(0,  10)},
    "B": {"label": "Technique pivots",     "ids": range(10, 20)},
    "C": {"label": "Actor attribution",    "ids": range(20, 30)},
    "D": {"label": "Analyst queries",      "ids": range(30, 40)},
    "E": {"label": "Campaign queries",     "ids": range(40, 50)},
}

TOTAL_MANUAL_MINUTES: int = sum(q["manual_minutes"] for q in TEST_QUERIES)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _blob(obj: Any) -> str:
    """Flatten any JSON-serialisable object to a single searchable string."""
    return json.dumps(obj, default=str).lower()


def _recall(expected: list[str], blob: str) -> float:
    """Fraction of expected tokens found (case-insensitive). Vacuous → 1.0."""
    if not expected:
        return 1.0
    return sum(1 for e in expected if e.lower() in blob) / len(expected)


def _hit(expected: list[str], blob: str) -> bool:
    """True if at least one expected token appears in blob."""
    return any(e.lower() in blob for e in expected) if expected else True


def _pdf_hit(results: list[dict]) -> bool:
    return any(
        r.get("result_type") == "pdf_chunk" or r.get("source_type") == "pdf"
        for r in results
    )


# ── Per-query runner ─────────────────────────────────────────────────────────

def _run_query(client: httpx.Client, q: dict) -> dict:
    endpoint = q["hit_endpoint"]
    query    = q["query"]
    t0       = time.perf_counter()

    try:
        if endpoint == "cve":
            resp = client.get(f"/cve/{query.upper()}", timeout=20.0)
            resp.raise_for_status()
            data = resp.json()
            results = []   # /cve returns a single object, not a list

        elif endpoint == "technique":
            resp = client.get(f"/technique/{query.upper()}", timeout=20.0)
            resp.raise_for_status()
            data = resp.json()
            results = []

        elif endpoint == "search":
            resp = client.get(
                "/search",
                params={"q": query, "top_k": 10, "source": "all"},
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data if isinstance(data, list) else []

        elif endpoint == "investigate":
            resp = client.post(
                "/investigate",
                json={"query": query, "top_k": 10},
                timeout=60.0,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("top_cves", [])

        else:
            raise ValueError(f"Unknown hit_endpoint: {endpoint!r}")

    except Exception as exc:
        latency = time.perf_counter() - t0
        return {
            "id":               q["id"],
            "label":            q.get("label", ""),
            "query":            query,
            "hit_endpoint":     endpoint,
            "latency_s":        round(latency, 3),
            "error":            str(exc),
            "technique_recall": 0.0,
            "technique_hit":    False,
            "actor_recall":     0.0,
            "actor_hit":        False,
            "cve_hit":          False,
            "pdf_hit":          False,
            "n_results":        0,
            "manual_minutes":   q["manual_minutes"],
        }

    latency = time.perf_counter() - t0
    full    = _blob(data)

    t_recall = _recall(q["expected_techniques"], full)
    t_hit    = _hit(q["expected_techniques"],    full)
    a_recall = _recall(q["expected_groups"],     full)
    a_hit    = _hit(q["expected_groups"],        full)
    c_hit    = _hit(q["expected_cves"],          full)
    p_hit    = _pdf_hit(results)

    return {
        "id":               q["id"],
        "label":            q.get("label", ""),
        "query":            query,
        "hit_endpoint":     endpoint,
        "latency_s":        round(latency, 3),
        "technique_recall": round(t_recall, 3),
        "technique_hit":    t_hit,
        "actor_recall":     round(a_recall, 3),
        "actor_hit":        a_hit,
        "cve_hit":          c_hit,
        "pdf_hit":          p_hit,
        "n_results":        len(results),
        "manual_minutes":   q["manual_minutes"],
        "expected_techniques": q["expected_techniques"],
        "expected_groups":  q["expected_groups"],
        "expected_cves":    q["expected_cves"],
        "notes":            q.get("notes", ""),
    }


# ── Aggregation helpers ──────────────────────────────────────────────────────

def _agg(rows: list[dict]) -> dict:
    valid = [r for r in rows if "error" not in r]
    if not valid:
        return {"n": len(rows), "n_ok": 0}

    lats     = [r["latency_s"]        for r in valid]
    t_rec    = [r["technique_recall"] for r in valid]
    a_rec    = [r["actor_recall"]     for r in valid]

    def rate(key: str) -> float:
        return round(sum(1 for r in valid if r[key]) / len(valid) * 100, 1)

    return {
        "n":                    len(rows),
        "n_ok":                 len(valid),
        "n_errors":             len(rows) - len(valid),
        "avg_latency_s":        round(statistics.mean(lats), 3),
        "p95_latency_s":        round(sorted(lats)[max(0, int(len(lats) * 0.95) - 1)], 3),
        "avg_technique_recall": round(statistics.mean(t_rec), 3),
        "avg_actor_recall":     round(statistics.mean(a_rec), 3),
        "technique_hit_rate_pct": rate("technique_hit"),
        "actor_hit_rate_pct":     rate("actor_hit"),
        "cve_hit_rate_pct":       rate("cve_hit"),
        "pdf_hit_rate_pct":       rate("pdf_hit"),
    }


# ── Main evaluation loop ─────────────────────────────────────────────────────

def run_eval(api_base: str, out_path: str, summary_path: str) -> None:
    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    per_query: list[dict] = []

    with httpx.Client(base_url=api_base, timeout=60.0) as client:
        for q in TEST_QUERIES:
            cat = next(
                k for k, v in CATEGORIES.items() if q["id"] in v["ids"]
            )
            print(f"  [{cat}{q['id']:02d}] {q.get('label','')[:55]:<55}", end=" ", flush=True)

            row = _run_query(client, q)
            per_query.append(row)

            if "error" in row:
                print(f"ERROR: {row['error'][:60]}")
            else:
                print(
                    f"lat={row['latency_s']:.2f}s  "
                    f"tech={row['technique_recall']:.2f}  "
                    f"actor={row['actor_recall']:.2f}  "
                    f"pdf={'✓' if row['pdf_hit'] else '✗'}"
                )

    # ── Per-category aggregates ────────────────────────────────────────────
    cat_agg: dict[str, dict] = {}
    for key, cat in CATEGORIES.items():
        rows = [r for r in per_query if r["id"] in cat["ids"]]
        cat_agg[key] = {"label": cat["label"], **_agg(rows)}

    # ── Overall aggregate ──────────────────────────────────────────────────
    overall = _agg(per_query)

    # ── Efficiency multiplier (computed from actual timings) ───────────────
    valid_latencies = [r["latency_s"] for r in per_query if "error" not in r]
    total_system_s  = sum(valid_latencies)
    total_manual_s  = TOTAL_MANUAL_MINUTES * 60
    efficiency_x    = round(total_manual_s / total_system_s, 1) if total_system_s > 0 else None

    overall["total_manual_minutes"] = TOTAL_MANUAL_MINUTES
    overall["total_system_s"]       = round(total_system_s, 2)
    overall["efficiency_multiplier"] = efficiency_x

    output = {
        "meta": {
            "run_timestamp": run_ts,
            "api_base": api_base,
            "n_queries": len(TEST_QUERIES),
            "total_manual_minutes": TOTAL_MANUAL_MINUTES,
        },
        "overall": overall,
        "by_category": cat_agg,
        "per_query": per_query,
    }

    Path(out_path).write_text(json.dumps(output, indent=2))

    # ── Console + file summary ─────────────────────────────────────────────
    lines = [
        "UNICC Threat Intelligence Pipeline — Eval Summary",
        "=" * 52,
        f"Run:      {run_ts}",
        f"API:      {api_base}",
        "",
        "Overall",
        f"  Queries:               {overall['n_ok']}/{overall['n']} successful",
        f"  Avg latency:           {overall['avg_latency_s']} s",
        f"  p95 latency:           {overall['p95_latency_s']} s",
        f"  Technique hit-rate@10: {overall['technique_hit_rate_pct']}%",
        f"  Actor hit-rate@10:     {overall['actor_hit_rate_pct']}%",
        f"  CVE hit-rate:          {overall['cve_hit_rate_pct']}%",
        f"  PDF hit-rate:          {overall['pdf_hit_rate_pct']}%",
        f"  Avg technique recall:  {overall['avg_technique_recall']}",
        f"  Avg actor recall:      {overall['avg_actor_recall']}",
        "",
        f"  Manual baseline:       {TOTAL_MANUAL_MINUTES} min ({TOTAL_MANUAL_MINUTES/60:.1f} h)",
        f"  Total system time:     {overall['total_system_s']} s",
        f"  Efficiency multiplier: {efficiency_x}×",
        "",
        "Per-category breakdown",
        f"  {'Cat':<4}  {'Label':<22}  {'N':>3}  {'TechHit':>7}  {'ActHit':>6}  {'CVEHit':>6}  {'Lat':>6}",
        "  " + "-" * 64,
    ]
    for key, agg in cat_agg.items():
        lines.append(
            f"  {key:<4}  {agg['label']:<22}  {agg['n_ok']:>3}  "
            f"{agg['technique_hit_rate_pct']:>6}%  "
            f"{agg['actor_hit_rate_pct']:>5}%  "
            f"{agg['cve_hit_rate_pct']:>5}%  "
            f"{agg['avg_latency_s']:>5}s"
        )

    failed = [r for r in per_query if "error" in r]
    if failed:
        lines += ["", f"  ⚠  {len(failed)} failed queries:"]
        for r in failed:
            lines.append(f"     [{r['id']:02d}] {r.get('label','')[:45]}  error={r['error'][:50]}")

    lines += ["", f"Full results: {out_path}"]

    summary_text = "\n".join(lines)
    print("\n" + summary_text)
    Path(summary_path).write_text(summary_text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UNICC pipeline evaluation")
    parser.add_argument("--api",     default="http://localhost:8000", help="API base URL")
    parser.add_argument("--out",     default="eval_results.json",     help="JSON results output path")
    parser.add_argument("--summary", default="eval_summary.txt",      help="Text summary output path")
    args = parser.parse_args()

    print(f"\nRunning {len(TEST_QUERIES)} queries "
          f"(manual baseline: {TOTAL_MANUAL_MINUTES} min = {TOTAL_MANUAL_MINUTES/60:.1f} h):\n")
    run_eval(api_base=args.api, out_path=args.out, summary_path=args.summary)
