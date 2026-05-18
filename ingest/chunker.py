"""
Heading-aware PDF chunker for UNICC threat intelligence reports.

Transforms a Docling export_to_dict() document into heading-aware JSONL chunks,
preserving section_path and reliable page numbers for downstream category tagging
(Issue #3) and entity matching (Issue #4).

DOCLING STRUCTURE (confirmed via exploration — 2026-06-18):
  body.children  — flat ordered list of {"$ref": "#/texts/N"} etc.; IS reading order
  texts[]        — all text items; headings have label="section_header", level=N
  groups[]       — list/unspecified containers; their children are NOT in body.children
  prov[0].page_no — page number; 0% null rate across all tested reports

NOTE on heading levels: Docling reports ALL headings as level=1 for these threat
landscape PDFs (tested: ENISA 2023/2024/2025, MDDR 2023/2025, Microsoft DDFR 2024).
The level-based stack is the correct implementation — it degenerates gracefully to
a flat single-element section_path for level-1-only documents.  This is expected
behaviour given Docling's heading detection on styled (non-semantic) PDF headings.

Operates on 7 source PDFs in data/pdfs/. SOURCE_MAP retains historical 8-report labels from pdf_chunk_loader.py for backward compatibility.

Usage:
  # Single file
  python -m ingest.chunker --input data/parsed/ENISA_2025.json --source ENISA_2025
  python -m ingest.chunker --input data/parsed/ENISA_2025.json --source ENISA_2025 --stats

  # Batch: parse all PDFs in data/pdfs/ and chunk them
  python -m ingest.chunker --batch [--stats]
"""

import argparse
import hashlib
import json
import logging
import re
import sys
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

TOKENIZER_MODEL = "sentence-transformers/all-mpnet-base-v2"
TARGET_MAX_TOKENS = 500   # hard ceiling; sections above this are split
MIN_CHUNK_CHARS = 80      # discard boilerplate / heading-only fragments

# Text labels to skip entirely (furniture items that land in body.children)
_SKIP_LABELS = {"page_header", "page_footer"}

# Text labels treated as body content
_CONTENT_LABELS = {"text", "list_item", "caption"}
# footnote excluded: these are almost always citation numbers / URLs in CTI reports

# Noise detection
_TOC_DOT_RE = re.compile(r"\.{4,}")          # dot-leaders:  "Introduction ........... 3"
_DIGIT_NOISE_MAX_LEN = 250                   # only check short strings
_HIGH_DIGIT_RATIO = 0.40                     # >40% digits = likely TOC/page-number line

# ── Source map for batch mode ─────────────────────────────────────────────────
# Maps lowercased filename stem substrings → canonical source label.
# More-specific patterns must appear before shorter ones.
SOURCE_MAP: list[tuple[str, str]] = [
    ("enisa threat landscape 2025",    "ENISA_2025"),
    ("enisa threat landscape 2024",    "ENISA_2024"),
    ("enisa threat landscape 2023",    "ENISA_2023"),
    ("enisa threat landscape 2022",    "ENISA_2022"),
    ("mddr-2025",                      "Microsoft_DDFR_2025"),
    ("mddr-executivesummary-oct2023",  "Microsoft_DDFR_2023"),
    ("microsoft digital defense report 2024", "Microsoft_DDFR_2024"),
    ("microsoft digital defense report 2023", "Microsoft_DDFR_2023"),
    ("cybersecurity-report-v8",        "ATT_CSRIC_v8"),
    ("cybersecurity-report-v6",        "ATT_CSRIC_v6"),
    ("cybersecurity-report-v5",        "ATT_CSRIC_v5"),
]

_YEAR_RE = re.compile(r"(\d{4})")

# Year lookup for source labels that use version numbers instead of years.
# AT&T Cybersecurity Insights Reports: v5=2018, v6=2019, v8=2022.
_YEAR_OVERRIDES: dict[str, int] = {
    "ATT_CSRIC_v5": 2018,
    "ATT_CSRIC_v6": 2019,
    "ATT_CSRIC_v8": 2022,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _doc_id(filename: str) -> str:
    return hashlib.sha1(filename.encode()).hexdigest()[:12]


def _year_from_source(source: str) -> int:
    if source in _YEAR_OVERRIDES:
        return _YEAR_OVERRIDES[source]
    m = _YEAR_RE.search(source)
    if not m:
        raise ValueError(
            f"Cannot extract year from source label {source!r}. "
            "Add it to _YEAR_OVERRIDES in chunker.py or use a label with a 4-digit year."
        )
    return int(m.group(1))


def _canonical_source(pdf_stem: str) -> str:
    low = pdf_stem.lower()
    for pattern, label in SOURCE_MAP:
        if pattern in low:
            return label
    # Fallback: clean the stem
    return re.sub(r"[^A-Za-z0-9_]", "_", pdf_stem)


def _is_noise(text: str) -> bool:
    """True if text looks like a TOC line, page-number fragment, or dot-leader."""
    if _TOC_DOT_RE.search(text):
        return True
    if len(text) <= _DIGIT_NOISE_MAX_LEN:
        digits  = sum(1 for c in text if c.isdigit())
        letters = sum(1 for c in text if c.isalpha())
        if letters > 0 and digits / (digits + letters) > _HIGH_DIGIT_RATIO:
            return True
    return False


# ── Tokenizer (lazy singleton) ────────────────────────────────────────────────

_tokenizer = None


def _get_tokenizer():
    global _tokenizer
    if _tokenizer is None:
        from transformers import AutoTokenizer
        logger.info(f"Loading tokenizer: {TOKENIZER_MODEL}")
        _tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_MODEL)
    return _tokenizer


def _token_count(text: str) -> int:
    return len(_get_tokenizer().encode(text, add_special_tokens=False))


# ── Docling document walker ───────────────────────────────────────────────────

def _resolve(ref: str, doc: dict) -> tuple[str, dict] | None:
    """Resolve a $ref string into (collection_name, item_dict)."""
    parts = ref.lstrip("#/").split("/")
    if len(parts) != 2:
        return None
    collection, idx_str = parts
    try:
        idx = int(idx_str)
    except ValueError:
        return None
    items = doc.get(collection)
    if not items or idx >= len(items):
        return None
    return (collection, items[idx])


def _walk_children(children: list[dict], doc: dict) -> Iterator[tuple[str, dict]]:
    """
    Recursively yield (collection, item) for a children list.
    Groups are descended into so their content items are not missed.
    """
    for child_ref in children:
        ref = child_ref.get("$ref", "")
        resolved = _resolve(ref, doc)
        if resolved is None:
            continue
        collection, item = resolved
        if collection == "groups":
            # Recurse: a list/unspecified group's children are not in body.children
            yield from _walk_children(item.get("children", []), doc)
        else:
            yield (collection, item)


def _body_items(doc: dict) -> Iterator[tuple[str, dict]]:
    """Yield (collection, item) for every item in body, in reading order."""
    yield from _walk_children(doc["body"]["children"], doc)


def _page_of(item: dict) -> int | None:
    prov = item.get("prov") or []
    if prov:
        return prov[0].get("page_no")
    return None


# ── Core chunking logic ───────────────────────────────────────────────────────

def _emit_chunks(
    section_path: list[str],
    items: list[tuple[str, int | None]],   # (text, page_no)
    source: str,
    year: int,
    doc_id: str,
    chunk_index_start: int,
) -> tuple[list[dict], int]:
    """
    Turn a list of (text, page) content items collected under one section into
    one or more chunks. Returns (chunks, next_chunk_index).

    If the whole section fits in TARGET_MAX_TOKENS → one chunk.
    If not → split at paragraph boundaries; each piece keeps the full section_path.
    """
    if not items:
        return [], chunk_index_start

    combined = "\n\n".join(t for t, _ in items)
    primary_page = next((pg for _, pg in items if pg is not None), None)
    total_tokens = _token_count(combined)
    idx = chunk_index_start
    result: list[dict] = []

    def _make_chunk(text: str, page: int | None) -> dict | None:
        text = text.strip()
        if len(text) < MIN_CHUNK_CHARS:
            return None
        if _is_noise(text):
            return None
        return {
            "text":         text,
            "source":       source,
            "year":         year,
            "page":         page,
            "section_path": section_path[:],
            "chunk_index":  idx,
            "doc_id":       doc_id,
            "token_count":  _token_count(text),
        }

    if total_tokens <= TARGET_MAX_TOKENS:
        chunk = _make_chunk(combined, primary_page)
        if chunk:
            result.append(chunk)
            idx += 1
        return result, idx

    # Over 500 tokens — split at paragraph boundaries
    paragraphs: list[tuple[str, int | None]] = []
    for raw_text, pg in items:
        for para in re.split(r"\n\n+", raw_text):
            para = para.strip()
            if para:
                paragraphs.append((para, pg))

    buf_paras: list[tuple[str, int | None]] = []
    buf_tokens = 0

    for para, pg in paragraphs:
        para_tokens = _token_count(para)
        if buf_tokens + para_tokens > TARGET_MAX_TOKENS and buf_paras:
            buf_text = "\n\n".join(t for t, _ in buf_paras)
            buf_page = next((p for _, p in buf_paras if p is not None), primary_page)
            chunk = _make_chunk(buf_text, buf_page)
            if chunk:
                chunk["chunk_index"] = idx
                result.append(chunk)
                idx += 1
            buf_paras = [(para, pg)]
            buf_tokens = para_tokens
        else:
            buf_paras.append((para, pg))
            buf_tokens += para_tokens

    if buf_paras:
        buf_text = "\n\n".join(t for t, _ in buf_paras)
        buf_page = next((p for _, p in buf_paras if p is not None), primary_page)
        chunk = _make_chunk(buf_text, buf_page)
        if chunk:
            chunk["chunk_index"] = idx
            result.append(chunk)
            idx += 1

    return result, idx


def chunk_document(doc: dict, source: str, doc_id: str) -> list[dict]:
    """
    Pure transformation: Docling export_to_dict() → list of chunk dicts.

    Walks body.children in reading order, maintains a level-based heading stack,
    groups consecutive content items under the same section, then emits chunks of
    ≤TARGET_MAX_TOKENS tokens each.
    """
    year = _year_from_source(source)

    heading_stack: list[tuple[int, str]] = []   # [(level, heading_text), ...]
    acc_items: list[tuple[str, int | None]] = [] # (text, page_no)
    current_path: list[str] = []
    all_chunks: list[dict] = []
    chunk_idx = 0

    for collection, item in _body_items(doc):
        if collection != "texts":
            # tables / pictures: skip (out of scope for Issue #2)
            continue

        label = item.get("label", "")

        if label in _SKIP_LABELS:
            continue

        if label == "section_header":
            # Flush accumulator before switching sections
            new_chunks, chunk_idx = _emit_chunks(
                current_path, acc_items, source, year, doc_id, chunk_idx
            )
            all_chunks.extend(new_chunks)
            acc_items = []

            level = item.get("level", 1)
            text = item.get("text", "").strip()
            if not text:
                continue
            # Pop stack to entries strictly shallower than this level
            heading_stack = [(l, t) for l, t in heading_stack if l < level]
            heading_stack.append((level, text))
            current_path = [t for _, t in heading_stack]

        elif label in _CONTENT_LABELS:
            text = item.get("text", "").strip()
            if text:
                acc_items.append((text, _page_of(item)))

    # Flush final section
    new_chunks, _ = _emit_chunks(
        current_path, acc_items, source, year, doc_id, chunk_idx
    )
    all_chunks.extend(new_chunks)

    return all_chunks


# ── Parsing helper ────────────────────────────────────────────────────────────

def parse_pdf_to_dict(pdf_path: Path) -> dict:
    """Parse a PDF with Docling (no OCR) and return export_to_dict() output."""
    from docling.document_converter import DocumentConverter, PdfFormatOption
    from docling.datamodel.pipeline_options import PdfPipelineOptions
    from docling.datamodel.base_models import InputFormat

    opts = PdfPipelineOptions()
    opts.do_ocr = False
    opts.do_table_structure = False  # not needed for chunking

    converter = DocumentConverter(
        format_options={InputFormat.PDF: PdfFormatOption(pipeline_options=opts)}
    )
    logger.info(f"Parsing {pdf_path.name} with Docling ...")
    result = converter.convert(str(pdf_path))
    return result.document.export_to_dict()


# ── Stats printer ─────────────────────────────────────────────────────────────

def print_stats(source: str, chunks: list[dict], total_pages: int | None = None) -> None:
    import statistics

    n = len(chunks)
    if n == 0:
        print(f"  {source}: 0 chunks")
        return

    tokens = [c["token_count"] for c in chunks]
    empty_path = sum(1 for c in chunks if not c["section_path"])
    pages_with_chunks = {c["page"] for c in chunks if c["page"] is not None}

    p95_idx = max(0, int(0.95 * n) - 1)
    tokens_sorted = sorted(tokens)

    print(f"\n{'='*60}")
    print(f"  {source}  ({n} chunks)")
    print(f"{'='*60}")
    print(f"  tokens:              min={tokens_sorted[0]}  "
          f"median={int(statistics.median(tokens))}  "
          f"p95={tokens_sorted[p95_idx]}  "
          f"max={tokens_sorted[-1]}")
    print(f"  empty section_path:  {empty_path}/{n} "
          f"({100*empty_path/n:.1f}%)")
    if total_pages is not None:
        print(f"  pages covered:       {len(pages_with_chunks)}/{total_pages}")
    else:
        print(f"  pages covered:       {len(pages_with_chunks)} (total unknown)")
    # Token histogram buckets
    buckets = [(0,100),(100,200),(200,300),(300,400),(400,500),(500,9999)]
    print("  token distribution:")
    for lo, hi in buckets:
        count = sum(1 for t in tokens if lo <= t < hi)
        bar = "█" * (count * 30 // max(n, 1))
        label = f"{lo}-{hi}" if hi < 9999 else f"{lo}+"
        print(f"    {label:>8}:  {bar} {count}")


# ── Single-file and batch runners ─────────────────────────────────────────────

def run_single(
    input_path: Path,
    source: str,
    output_path: Path,
    stats: bool,
) -> list[dict]:
    """Load one Docling JSON, chunk it, write JSONL."""
    logger.info(f"Loading {input_path}")
    with open(input_path, encoding="utf-8") as f:
        doc = json.load(f)

    doc_id = _doc_id(input_path.stem)
    chunks = chunk_document(doc, source, doc_id)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")

    total_pages = len(doc.get("pages", {})) or None
    print(f"Wrote {len(chunks)} chunks → {output_path}")
    if stats:
        print_stats(source, chunks, total_pages)

    return chunks


def run_batch(
    pdf_dir: Path,
    parsed_dir: Path,
    output_dir: Path,
    stats: bool,
) -> None:
    """Parse all PDFs in pdf_dir, chunk each, write one JSONL per report."""
    pdfs = sorted(pdf_dir.glob("*.pdf"))
    if not pdfs:
        sys.exit(f"No PDFs found in {pdf_dir}")

    parsed_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_stats: list[tuple[str, list[dict], int | None]] = []

    for pdf_path in pdfs:
        source = _canonical_source(pdf_path.stem)
        parsed_json = parsed_dir / f"{source}.json"

        # Parse PDF → Docling dict (cache to disk)
        if not parsed_json.exists():
            doc = parse_pdf_to_dict(pdf_path)
            parsed_json.write_text(
                json.dumps(doc, ensure_ascii=False), encoding="utf-8"
            )
            logger.info(f"Cached parse output → {parsed_json}")
        else:
            logger.info(f"Using cached parse: {parsed_json}")
            with open(parsed_json, encoding="utf-8") as f:
                doc = json.load(f)

        doc_id = _doc_id(pdf_path.name)
        chunks = chunk_document(doc, source, doc_id)
        total_pages = len(doc.get("pages", {})) or None

        out_path = output_dir / f"{source}.jsonl"
        with open(out_path, "w", encoding="utf-8") as f:
            for chunk in chunks:
                f.write(json.dumps(chunk, ensure_ascii=False) + "\n")

        print(f"  {source:<35} {len(chunks):>4} chunks → {out_path.name}")
        all_stats.append((source, chunks, total_pages))

    if stats:
        for source, chunks, total_pages in all_stats:
            print_stats(source, chunks, total_pages)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input",  metavar="JSON",
                      help="Path to a Docling export_to_dict() JSON file")
    mode.add_argument("--batch",  action="store_true",
                      help="Parse + chunk all PDFs in --pdf-dir")

    parser.add_argument("--source",  metavar="LABEL",
                        help="Canonical source label, e.g. ENISA_2025 (required with --input)")
    parser.add_argument("--output",  metavar="JSONL",
                        help="Output JSONL path (default: data/chunks/<source>.jsonl)")
    parser.add_argument("--pdf-dir",    default="data/pdfs",
                        help="Directory containing source PDFs (batch mode)")
    parser.add_argument("--parsed-dir", default="data/parsed",
                        help="Directory to cache/read Docling parse output (batch mode)")
    parser.add_argument("--output-dir", default="data/chunks",
                        help="Directory for output JSONL files (batch mode)")
    parser.add_argument("--stats", action="store_true",
                        help="Print token histogram and coverage stats after chunking")
    args = parser.parse_args()

    if args.input:
        if not args.source:
            sys.exit("--source is required with --input")
        input_path = Path(args.input)
        if not input_path.exists():
            sys.exit(f"Input not found: {input_path}")
        output_path = Path(args.output) if args.output \
            else Path("data/chunks") / f"{args.source}.jsonl"
        run_single(input_path, args.source, output_path, args.stats)

    else:  # batch
        run_batch(
            pdf_dir=Path(args.pdf_dir),
            parsed_dir=Path(args.parsed_dir),
            output_dir=Path(args.output_dir),
            stats=args.stats,
        )


if __name__ == "__main__":
    main()
