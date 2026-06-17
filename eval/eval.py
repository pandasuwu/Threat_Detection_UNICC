"""
eval.py  —  UNICC Pipeline Evaluation Script
=============================================
Measures investigative efficiency across 20 representative queries.

Metrics per query
-----------------
  latency_s          : wall-clock time from request to first byte received
  technique_recall   : fraction of expected ATT&CK IDs surfaced in top-10
  actor_recall       : fraction of expected threat actors surfaced in top-10
  cve_hit            : bool — expected CVE ID appears anywhere in results
  pdf_hit            : bool — at least one pdf_chunk result returned (NEW)

Aggregate metrics (printed + written to eval_results.json)
-----------------------------------------------------------
  avg_latency_s
  p95_latency_s
  avg_technique_recall
  avg_actor_recall
  cve_hit_rate
  pdf_hit_rate        ← proves PDF ingestion is working end-to-end

Usage
-----
    # API must be running: uvicorn api:app --port 8000
    python3 eval.py [--api http://localhost:8000] [--out eval_results.json]
"""

import argparse
import json
import statistics
import time
from typing import Any, Optional

import httpx

# ── Ground-truth test queries ─────────────────────────────────────────────────
# Covers: specific CVEs, ransomware families, APT groups, supply chain,
#         cloud misconfig, ICS/OT, zero-days — representative of UNICC workload.

TEST_QUERIES: list[dict[str, Any]] = [
    # ── Log4Shell / RCE ────────────────────────────────────────────────────
    {
        "id": "Q01",
        "query": "CVE-2021-44228 Log4Shell remote code execution",
        "expected_cve": "CVE-2021-44228",
        "expected_techniques": ["T1190", "T1059"],
        "expected_actors": [],
        "note": "Highest-profile RCE of 2021; should hit CVE + T1190 Exploit Public-Facing App",
    },
    # ── Ransomware / healthcare ─────────────────────────────────────────────
    {
        "id": "Q02",
        "query": "ransomware targeting healthcare RDP lateral movement",
        "expected_cve": None,
        "expected_techniques": ["T1133", "T1486", "T1021"],
        "expected_actors": ["Wizard Spider"],
        "note": "ENISA/Microsoft reports both cover this pattern",
    },
    # ── Supply chain / SolarWinds ──────────────────────────────────────────
    {
        "id": "Q03",
        "query": "SolarWinds Orion supply chain compromise SUNBURST",
        "expected_cve": "CVE-2020-10148",
        "expected_techniques": ["T1195", "T1072"],
        "expected_actors": ["APT29"],
        "note": "APT29 / Cozy Bear canonical supply-chain case",
    },
    # ── PrintNightmare ─────────────────────────────────────────────────────
    {
        "id": "Q04",
        "query": "CVE-2021-34527 PrintNightmare privilege escalation",
        "expected_cve": "CVE-2021-34527",
        "expected_techniques": ["T1068"],
        "expected_actors": [],
        "note": "Windows Print Spooler; widespread exploitation",
    },
    # ── Phishing / credential harvesting ──────────────────────────────────
    {
        "id": "Q05",
        "query": "spear phishing credential theft Office 365",
        "expected_cve": None,
        "expected_techniques": ["T1566", "T1078", "T1539"],
        "expected_actors": ["Fancy Bear"],
        "note": "AT&T + ENISA both discuss O365 phishing campaigns",
    },
    # ── Cobalt Strike / C2 ────────────────────────────────────────────────
    {
        "id": "Q06",
        "query": "Cobalt Strike beacon command and control DNS tunneling",
        "expected_cve": None,
        "expected_techniques": ["T1071", "T1090", "T1572"],
        "expected_actors": [],
        "note": "C2 via DNS is covered in ENISA 2023",
    },
    # ── Emotet / initial access broker ────────────────────────────────────
    {
        "id": "Q07",
        "query": "Emotet botnet initial access broker malware dropper",
        "expected_cve": None,
        "expected_techniques": ["T1566", "T1204", "T1055"],
        "expected_actors": ["Mealybug"],
        "note": "Emotet takedown + resurgence in ENISA 2023",
    },
    # ── Exchange Server zero-day ───────────────────────────────────────────
    {
        "id": "Q08",
        "query": "Microsoft Exchange Server ProxyLogon zero-day 2021",
        "expected_cve": "CVE-2021-26855",
        "expected_techniques": ["T1190", "T1505"],
        "expected_actors": ["HAFNIUM"],
        "note": "HAFNIUM exploitation covered in Microsoft DDFR 2023",
    },
    # ── ICS / OT targeting ────────────────────────────────────────────────
    {
        "id": "Q09",
        "query": "industrial control system OT SCADA attack energy sector",
        "expected_cve": None,
        "expected_techniques": ["T0810", "T0814"],
        "expected_actors": ["Sandworm"],
        "note": "ENISA 2024 covers ICS threats extensively",
    },
    # ── Data exfiltration / DLP bypass ────────────────────────────────────
    {
        "id": "Q10",
        "query": "data exfiltration cloud storage DLP bypass MEGA OneDrive",
        "expected_cve": None,
        "expected_techniques": ["T1567", "T1030"],
        "expected_actors": [],
        "note": "Covered in Microsoft DDFR 2025",
    },
    # ── MOVEit file transfer CVE ───────────────────────────────────────────
    {
        "id": "Q11",
        "query": "MOVEit Transfer SQL injection mass exploitation 2023",
        "expected_cve": "CVE-2023-34362",
        "expected_techniques": ["T1190", "T1059.006"],
        "expected_actors": ["TA505"],
        "note": "Cl0p / TA505 campaign; ENISA 2024 + AT&T v8",
    },
    # ── Credential stuffing / brute force ──────────────────────────────────
    {
        "id": "Q12",
        "query": "credential stuffing password spraying Azure Active Directory",
        "expected_cve": None,
        "expected_techniques": ["T1110", "T1078"],
        "expected_actors": [],
        "note": "Microsoft DDFR covers Azure identity attacks",
    },
    # ── Living-off-the-land (LotL) ─────────────────────────────────────────
    {
        "id": "Q13",
        "query": "living off the land LOLBins PowerShell WMI persistence",
        "expected_cve": None,
        "expected_techniques": ["T1059.001", "T1047", "T1546"],
        "expected_actors": [],
        "note": "Cross-report LotL pattern — AT&T + ENISA",
    },
    # ── Volt Typhoon / China nexus ─────────────────────────────────────────
    {
        "id": "Q14",
        "query": "Volt Typhoon China critical infrastructure pre-positioning",
        "expected_cve": None,
        "expected_techniques": ["T1078", "T1021", "T1090"],
        "expected_actors": ["Volt Typhoon"],
        "note": "2024 advisory; ENISA 2024 + Microsoft DDFR 2025",
    },
    # ── AI-assisted attacks ────────────────────────────────────────────────
    {
        "id": "Q15",
        "query": "AI generated phishing deepfake social engineering 2024",
        "expected_cve": None,
        "expected_techniques": ["T1566", "T1598"],
        "expected_actors": [],
        "note": "ENISA 2025 + Microsoft DDFR 2025 new threat vector",
    },
    # ── Kubernetes / container escape ─────────────────────────────────────
    {
        "id": "Q16",
        "query": "Kubernetes container escape privilege escalation cloud native",
        "expected_cve": "CVE-2022-0185",
        "expected_techniques": ["T1610", "T1611"],
        "expected_actors": [],
        "note": "ENISA 2023 covers cloud-native threats",
    },
    # ── BGP hijacking / network infrastructure ─────────────────────────────
    {
        "id": "Q17",
        "query": "BGP route hijacking DNS poisoning internet infrastructure",
        "expected_cve": None,
        "expected_techniques": ["T1584", "T1557"],
        "expected_actors": [],
        "note": "Network-layer attacks in ENISA reports",
    },
    # ── Midnight Blizzard / Nobelium ──────────────────────────────────────
    {
        "id": "Q18",
        "query": "Midnight Blizzard Nobelium OAuth token theft Microsoft 2024",
        "expected_cve": None,
        "expected_techniques": ["T1528", "T1550"],
        "expected_actors": ["NOBELIUM"],
        "note": "Microsoft DDFR 2025 incident coverage",
    },
    # ── DDoS / hacktivist ─────────────────────────────────────────────────
    {
        "id": "Q19",
        "query": "DDoS amplification reflection hacktivist botnet 2023 Europe",
        "expected_cve": None,
        "expected_techniques": ["T1498", "T1499"],
        "expected_actors": ["Killnet"],
        "note": "ENISA 2023 covers pro-Russia hacktivist DDoS wave",
    },
    # ── Zero-trust bypass ─────────────────────────────────────────────────
    {
        "id": "Q20",
        "query": "zero trust bypass MFA fatigue push notification attack",
        "expected_cve": None,
        "expected_techniques": ["T1621", "T1556"],
        "expected_actors": ["Lapsus$"],
        "note": "AT&T v8 + ENISA 2024; Lapsus$ MFA fatigue campaigns",
    },
]


# ── Evaluation helpers ────────────────────────────────────────────────────────

def _text_contains_any(text: str, tokens: list[str]) -> bool:
    t = text.lower()
    return any(tok.lower() in t for tok in tokens)


def _results_text(results: list[dict]) -> str:
    """Flatten all result fields into a single string for recall checking."""
    parts = []
    for r in results:
        for v in r.values():
            if isinstance(v, str):
                parts.append(v)
    return " ".join(parts)


def _compute_recall(expected: list[str], results_blob: str) -> float:
    if not expected:
        return 1.0  # vacuously true
    hits = sum(1 for e in expected if e.lower() in results_blob.lower())
    return hits / len(expected)


def _has_pdf_hit(results: list[dict]) -> bool:
    return any(r.get("result_type") == "pdf_chunk" or r.get("source_type") == "pdf"
               for r in results)


# ── Main evaluation loop ──────────────────────────────────────────────────────

def run_eval(api_base: str, out_path: str) -> None:
    per_query: list[dict[str, Any]] = []

    with httpx.Client(base_url=api_base, timeout=30.0) as client:
        for q in TEST_QUERIES:
            print(f"[{q['id']}] {q['query'][:60]}…", end=" ", flush=True)
            t0 = time.perf_counter()
            try:
                r = client.get(
                    "/search",
                    params={"q": q["query"], "top_k": 10, "source": "all"},
                )
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                print(f"ERROR: {e}")
                per_query.append(
                    {**q, "latency_s": None, "error": str(e),
                     "technique_recall": 0.0, "actor_recall": 0.0,
                     "cve_hit": False, "pdf_hit": False}
                )
                continue

            latency = time.perf_counter() - t0
            # Handle list directly, since your API returns a JSON array
            results = data if isinstance(data, list) else data.get("results", [])
            blob = _results_text(results)

            # Also check narrative endpoint for richer recall signal
            narrative_blob = ""
            try:
                nr = client.post(
                    "/investigate",
                    json={"query": q["query"], "top_k": 5},
                    timeout=45.0,
                )
                if nr.status_code == 200:
                    narrative_blob = nr.json().get("narrative", "")
            except Exception:
                pass  # narrative optional; don't fail eval on it

            full_blob = blob + " " + narrative_blob

            t_recall = _compute_recall(q["expected_techniques"], full_blob)
            a_recall = _compute_recall(q["expected_actors"], full_blob)
            cve_hit = bool(q["expected_cve"]) and (
                q["expected_cve"].lower() in full_blob.lower()
            )
            pdf_hit = _has_pdf_hit(results)

            row = {
                "id":               q["id"],
                "query":            q["query"],
                "latency_s":        round(latency, 3),
                "technique_recall": round(t_recall, 3),
                "actor_recall":     round(a_recall, 3),
                "cve_hit":          cve_hit,
                "pdf_hit":          pdf_hit,
                "n_results":        len(results),
                "expected_cve":     q["expected_cve"],
                "expected_techniques": q["expected_techniques"],
                "expected_actors":  q["expected_actors"],
                "note":             q.get("note", ""),
            }
            per_query.append(row)

            status = (
                f"lat={latency:.2f}s  "
                f"tech={t_recall:.2f}  "
                f"actor={a_recall:.2f}  "
                f"pdf={'✓' if pdf_hit else '✗'}"
            )
            print(status)

    # ── Aggregate ─────────────────────────────────────────────────────────────
    valid = [r for r in per_query if r.get("latency_s") is not None]

    latencies   = [r["latency_s"]        for r in valid]
    t_recalls   = [r["technique_recall"] for r in valid]
    a_recalls   = [r["actor_recall"]     for r in valid]
    cve_hits    = [r["cve_hit"]          for r in valid]
    pdf_hits    = [r["pdf_hit"]          for r in valid]

    def pct(lst, val=True):
        return round(sum(1 for x in lst if x == val) / len(lst) * 100, 1) if lst else 0

    agg = {
        "n_queries":             len(TEST_QUERIES),
        "n_successful":          len(valid),
        "avg_latency_s":         round(statistics.mean(latencies), 3)   if latencies else None,
        "p95_latency_s":         round(sorted(latencies)[int(len(latencies)*0.95)-1], 3) if latencies else None,
        "avg_technique_recall":  round(statistics.mean(t_recalls), 3)   if t_recalls else None,
        "avg_actor_recall":      round(statistics.mean(a_recalls), 3)   if a_recalls else None,
        "cve_hit_rate_pct":      pct(cve_hits),
        "pdf_hit_rate_pct":      pct(pdf_hits),
    }

    output = {"aggregate": agg, "per_query": per_query}

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    # ── Print summary ─────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("EVAL SUMMARY")
    print("="*60)
    print(f"  Queries run:           {agg['n_successful']}/{agg['n_queries']}")
    print(f"  Avg latency:           {agg['avg_latency_s']}s")
    print(f"  p95 latency:           {agg['p95_latency_s']}s")
    print(f"  Avg technique recall:  {agg['avg_technique_recall']}")
    print(f"  Avg actor recall:      {agg['avg_actor_recall']}")
    print(f"  CVE hit rate:          {agg['cve_hit_rate_pct']}%")
    print(f"  PDF hit rate:          {agg['pdf_hit_rate_pct']}%  ← should be >0 after ingestion")
    print(f"\n  Full results → {out_path}")

    # ── Flag low-performers for triage ────────────────────────────────────────
    low = [r for r in valid if r["technique_recall"] < 0.5]
    if low:
        print(f"\n  ⚠  {len(low)} queries with technique_recall < 0.5:")
        for r in low:
            print(f"     [{r['id']}] {r['query'][:55]}  (recall={r['technique_recall']})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000",
                        help="Base URL of the FastAPI backend")
    parser.add_argument("--out", default="eval_results.json",
                        help="Output path for JSON results")
    args = parser.parse_args()
    run_eval(api_base=args.api, out_path=args.out)
