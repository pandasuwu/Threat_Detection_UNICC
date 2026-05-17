#!/usr/bin/env bash
# run_eval.sh — UNICC pipeline evaluation runner
# Runs preflight checks then executes eval/eval.py.
# Outputs: eval_results.json + eval_summary.txt (both at repo root)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
API_BASE="${API_BASE:-http://localhost:8000}"
QDRANT_BASE="${QDRANT_BASE:-http://localhost:6333}"
OUT_JSON="$SCRIPT_DIR/eval_results.json"
OUT_TXT="$SCRIPT_DIR/eval_summary.txt"

# ── Preflight: API ────────────────────────────────────────────────────────────
echo "[preflight] Checking API at $API_BASE ..."
if ! curl -sf --max-time 5 "$API_BASE/health" > /dev/null 2>&1; then
    echo "ERROR: API not reachable at $API_BASE"
    echo "  Start it with:  uvicorn api.api:app --host 0.0.0.0 --port 8000"
    exit 1
fi
echo "[preflight] API OK"

# ── Preflight: Qdrant CVE collection non-empty ────────────────────────────────
echo "[preflight] Checking Qdrant CVE collection ..."
CVE_COUNT=$(
    curl -sf --max-time 5 \
        -X POST "$QDRANT_BASE/collections/cve_descriptions/points/count" \
        -H "Content-Type: application/json" \
        -d '{}' 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('count',0))" \
    2>/dev/null \
    || echo "0"
)
if [ "$CVE_COUNT" = "0" ]; then
    echo "WARNING: cve_descriptions collection is empty or unreachable."
    echo "  CVE search results will be missing. Run:"
    echo "    python ingest/qdrant_loader.py --embeddings ingest/cve_embeddings.npy \\"
    echo "                                   --metadata   ingest/cve_metadata.jsonl"
    echo "  Continuing anyway (PDF chunks may still produce results) ..."
else
    echo "[preflight] cve_descriptions: $CVE_COUNT points — OK"
fi

# ── Preflight: Qdrant PDF collection ─────────────────────────────────────────
PDF_COUNT=$(
    curl -sf --max-time 5 \
        -X POST "$QDRANT_BASE/collections/pdf_chunks/points/count" \
        -H "Content-Type: application/json" \
        -d '{}' 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('count',0))" \
    2>/dev/null \
    || echo "0"
)
if [ "$PDF_COUNT" = "0" ]; then
    echo "WARNING: pdf_chunks collection is empty — PDF hit-rate will be 0%."
    echo "  Run: python ingest/pdf_chunk_loader.py"
else
    echo "[preflight] pdf_chunks: $PDF_COUNT points — OK"
fi

echo ""
echo "[eval] Starting evaluation against $API_BASE ..."
echo ""

cd "$SCRIPT_DIR"
python3 eval/eval.py \
    --api     "$API_BASE" \
    --out     "$OUT_JSON" \
    --summary "$OUT_TXT" \
    "$@"

echo ""
echo "Done."
echo "  Results:  $OUT_JSON"
echo "  Summary:  $OUT_TXT"
