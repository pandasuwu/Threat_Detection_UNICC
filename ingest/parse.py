"""
parse.py — Layout-aware PDF parsing pipeline
  1. Try docling (layout-aware: tables, headings, captions preserved)
  2. If docling fails → fallback to marker-pdf for that file

Input:  /input/*.pdf   (mounted from raw_pdfs)
Output: /output/<filename>.md   + /output/<filename>.json  (metadata/chunks)
"""

import os
import json
import traceback
from pathlib import Path
from datetime import datetime

# ── Config from env ──────────────────────────────────────────────────────────
INPUT_DIR    = Path(os.getenv("INPUT_DIR",  "/input"))
OUTPUT_DIR   = Path(os.getenv("OUTPUT_DIR", "/output"))
FORCE_MARKER = os.getenv("FORCE_MARKER", "false").lower() == "true"
TEST_LIMIT   = int(os.getenv("TEST_LIMIT", "0"))   # 0 = all files

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Logging helper ───────────────────────────────────────────────────────────
def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


# ── Docling parser ───────────────────────────────────────────────────────────
def parse_with_docling(pdf_path: Path) -> dict:
    """
    Uses docling's DocumentConverter for layout-aware extraction.
    Docling preserves headings hierarchy, tables, figure captions, lists.

    FIX: newer docling (>=2.x) returns headings/captions as plain strings,
         not objects — so we check isinstance before calling .text
    """
    from docling.document_converter import DocumentConverter
    from docling.chunking import HybridChunker

    converter = DocumentConverter()
    result    = converter.convert(str(pdf_path))
    doc       = result.document

    # Full markdown with layout preserved
    markdown = doc.export_to_markdown()

    # HybridChunker: splits at heading/table boundaries, max 512 tokens
    chunker = HybridChunker(
        tokenizer="sentence-transformers/all-MiniLM-L6-v2",
        max_tokens=512,
        merge_peers=True,
    )

    def _to_str(item):
        """Handle both plain-string and object-with-.text headings/captions."""
        return item if isinstance(item, str) else getattr(item, "text", str(item))

    chunks = []
    for i, chunk in enumerate(chunker.chunk(doc)):
        headings = [_to_str(h) for h in chunk.meta.headings] if chunk.meta.headings else []
        captions = [_to_str(c) for c in chunk.meta.captions] if chunk.meta.captions else []

        # Page range — prov can be missing or empty, guard everything
        page_start = page_end = None
        try:
            items = chunk.meta.doc_items or []
            if items:
                first_prov = items[0].prov
                last_prov  = items[-1].prov
                if first_prov:
                    page_start = first_prov[0].page_no
                if last_prov:
                    page_end = last_prov[-1].page_no
        except (IndexError, AttributeError):
            pass

        chunks.append({
            "chunk_id":   i,
            "text":       chunk.text,
            "meta":       {"headings": headings, "captions": captions},
            "page_range": [page_start, page_end],
        })

    return {"markdown": markdown, "chunks": chunks, "parser": "docling"}


# ── Marker fallback ──────────────────────────────────────────────────────────
def parse_with_marker(pdf_path: Path) -> dict:
    """
    Fallback: marker-pdf.
    Supports both marker-pdf v0.2+ (new API) and <=0.1.x (old API).

    v0.2+ API:  marker.converters.pdf.PdfConverter
    v0.1.x API: marker.convert.convert_single_pdf
    """
    full_text = None

    # ── Try new marker API (v0.2+) ───────────────────────────────────────
    try:
        from marker.converters.pdf import PdfConverter
        from marker.models import create_model_dict
        from marker.output import text_from_rendered

        log("    [marker] using v0.2+ API")
        models    = create_model_dict()
        converter = PdfConverter(artifact_dict=models)
        rendered  = converter(str(pdf_path))
        full_text, _, _ = text_from_rendered(rendered)

    except ImportError:
        # ── Fall back to old marker API (<=0.1.x) ───────────────────────
        log("    [marker] v0.2+ not found, trying legacy API")
        from marker.convert import convert_single_pdf   # type: ignore
        from marker.models import load_all_models       # type: ignore

        models    = load_all_models()
        full_text, _, _ = convert_single_pdf(
            str(pdf_path), models,
            max_pages=None, langs=["English"], batch_multiplier=1,
        )

    # Chunk on paragraph boundaries (double newline)
    raw_chunks = [c.strip() for c in full_text.split("\n\n") if c.strip()]
    chunks = [
        {"chunk_id": i, "text": c, "meta": {}, "page_range": [None, None]}
        for i, c in enumerate(raw_chunks)
    ]

    return {"markdown": full_text, "chunks": chunks, "parser": "marker"}


# ── Save outputs ─────────────────────────────────────────────────────────────
def save_outputs(stem: str, result: dict, source_path: Path):
    md_path = OUTPUT_DIR / f"{stem}.md"
    md_path.write_text(result["markdown"], encoding="utf-8")

    meta = {
        "source_file": source_path.name,
        "parser_used": result["parser"],
        "chunk_count": len(result["chunks"]),
        "parsed_at":   datetime.utcnow().isoformat() + "Z",
        "chunks":      result["chunks"],
    }
    json_path = OUTPUT_DIR / f"{stem}.json"
    json_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    return md_path, json_path


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    pdf_files = sorted(INPUT_DIR.glob("*.pdf"))
    if not pdf_files:
        log(f"No PDFs found in {INPUT_DIR}", "WARN")
        return

    if TEST_LIMIT > 0:
        pdf_files = pdf_files[:TEST_LIMIT]
        log(f"TEST_LIMIT={TEST_LIMIT}: processing {len(pdf_files)} file(s)")

    log(f"Found {len(pdf_files)} PDF(s) to parse")

    summary = []

    for pdf_path in pdf_files:
        stem = pdf_path.stem
        log(f"── Processing: {pdf_path.name}")

        result    = None
        error_msg = None

        # ── Step 1: Try docling ───────────────────────────────────────────
        if not FORCE_MARKER:
            try:
                log("  → Trying docling…")
                result = parse_with_docling(pdf_path)
                log(f"  ✓ docling OK ({len(result['chunks'])} chunks)")
            except Exception as e:
                error_msg = str(e)
                log(f"  ✗ docling failed: {error_msg}", "WARN")
                traceback.print_exc()

        # ── Step 2: Fallback to marker ───────────────────────────────────
        if result is None:
            try:
                log("  → Falling back to marker…")
                result = parse_with_marker(pdf_path)
                log(f"  ✓ marker OK ({len(result['chunks'])} chunks)")
            except Exception as e:
                log(f"  ✗ marker also failed: {e}", "ERROR")
                traceback.print_exc()
                summary.append({"file": pdf_path.name, "status": "FAILED", "error": str(e)})
                continue

        # ── Save ──────────────────────────────────────────────────────────
        md_path, json_path = save_outputs(stem, result, pdf_path)
        log(f"  Saved → {md_path.name}  |  {json_path.name}")

        summary.append({
            "file":        pdf_path.name,
            "status":      "OK",
            "parser":      result["parser"],
            "chunks":      len(result["chunks"]),
            "docling_err": error_msg,
        })

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("PARSE SUMMARY")
    print("="*60)
    for s in summary:
        ok = s["status"] == "OK"
        mark = "✓" if ok else "✗"
        if ok:
            fb = f"  [docling err: {s['docling_err']}]" if s.get("docling_err") else ""
            print(f"  {mark} {s['file']}  →  {s['parser']} ({s['chunks']} chunks){fb}")
        else:
            print(f"  {mark} {s['file']}  →  FAILED: {s['error']}")

    summary_path = OUTPUT_DIR / "_parse_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log(f"Summary saved to {summary_path}")


if __name__ == "__main__":
    main()
