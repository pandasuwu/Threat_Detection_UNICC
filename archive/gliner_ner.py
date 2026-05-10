#!/usr/bin/env python3
"""
GLiNER-based NER for UNICC pipeline.
Processes CVE JSONL and PDF parsed text.
Usage:
    python3 gliner_ner.py --mode cve
    python3 gliner_ner.py --mode pdf
"""

import json
import argparse
from pathlib import Path
from tqdm import tqdm
from gliner import GLiNER

# ── Config ──────────────────────────────────────────────────────────────────
CVE_INPUT   = Path.home() / "Workspace/output/cve_entities_all.jsonl"
CVE_OUTPUT  = Path.home() / "Workspace/output/cve_gliner_entities.jsonl"
PDF_INPUT   = Path.home() / "Workspace/Reports"   # folder with parsed .json/.md files
PDF_OUTPUT  = Path.home() / "Workspace/output/pdf_gliner_entities.jsonl"

LABELS = [
    "Malware",
    "Threat Actor",
    "Vulnerability",
    "Attack Pattern",
    "Tool",
    "Operating System",
    "Software",
    "Organization",
    "Campaign",
]

THRESHOLD   = 0.35   # lower = more recall; raise to 0.50 for higher precision
BATCH_SIZE  = 32     # reduce to 16 if you hit OOM

# ────────────────────────────────────────────────────────────────────────────

def load_model():
    print("Loading GLiNER model...")
    model = GLiNER.from_pretrained("urchade/gliner_medium-v2.1").to("cuda")
    print("Model ready.")
    return model


def extract(model, texts: list[str]) -> list[list[dict]]:
    """Run GLiNER on a batch of texts. Returns list of entity lists."""
    results = model.inference(
        texts, LABELS, threshold=THRESHOLD, flat_ner=True
    )
    output = []
    for entities in results:
        output.append([
            {"text": e["text"], "label": e["label"], "confidence": round(e["score"], 4)}
            for e in entities
        ])
    return output


def run_cve(model):
    print(f"Reading {CVE_INPUT}")
    lines = CVE_INPUT.read_text().strip().splitlines()
    print(f"Total records: {len(lines)}")

    CVE_OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    batch_records, batch_texts = [], []
    written, with_entities = 0, 0

    with open(CVE_OUTPUT, "w") as out:
        for line in tqdm(lines, desc="CVE NER"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                    # If the line is corrupted, ignore it and move to the next one
                continue
            desc = record.get("description", "").strip()

            batch_records.append(record)
            batch_texts.append(desc if desc else " ")

            if len(batch_texts) >= BATCH_SIZE:
                entity_batches = extract(model, batch_texts)
                for rec, ents in zip(batch_records, entity_batches):
                    rec["entities"] = ents
                    if ents:
                        with_entities += 1
                    out.write(json.dumps(rec) + "\n")
                    written += 1
                batch_records, batch_texts = [], []

        # flush remainder
        if batch_texts:
            entity_batches = extract(model, batch_texts)
            for rec, ents in zip(batch_records, entity_batches):
                rec["entities"] = ents
                if ents:
                    with_entities += 1
                out.write(json.dumps(rec) + "\n")
                written += 1

    print(f"\nDone. Written: {written}")
    print(f"Records with entities: {with_entities} ({with_entities/written*100:.1f}%)")
    print(f"Output: {CVE_OUTPUT}")


def run_pdf(model):
    """Process parsed PDF JSONs from Docling output."""
    PDF_OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # Docling outputs: look for .json files with 'chunks' or raw .md files
    json_files = list(PDF_INPUT.glob("**/*.json"))
    md_files   = list(PDF_INPUT.glob("**/*.md"))

    print(f"Found {len(json_files)} JSON + {len(md_files)} MD files in {PDF_INPUT}")

    with open(PDF_OUTPUT, "w") as out:
        # ── JSON (Docling structured output) ──
        for jf in json_files:
            try:
                data = json.loads(jf.read_text())
            except Exception:
                continue

            # Docling JSON has a 'chunks' key or 'texts' key — handle both
            chunks = []
            if isinstance(data, list):
                chunks = [c.get("text", c.get("content", "")) for c in data if isinstance(c, dict)]
            elif isinstance(data, dict):
                chunks = [c.get("text", c.get("content", ""))
                          for c in data.get("chunks", data.get("texts", []))]

            chunks = [c.strip() for c in chunks if len(c.strip()) > 30]
            if not chunks:
                print(f"  No chunks found in {jf.name} — skipping")
                continue

            print(f"  {jf.name}: {len(chunks)} chunks")
            for i in range(0, len(chunks), BATCH_SIZE):
                batch = chunks[i:i+BATCH_SIZE]
                entity_batches = extract(model, batch)
                for chunk_text, ents in zip(batch, entity_batches):
                    out.write(json.dumps({
                        "source": jf.stem,
                        "chunk": chunk_text[:300],
                        "entities": ents
                    }) + "\n")

        # ── MD (plain markdown fallback) ──
        for mf in md_files:
            text = mf.read_text()
            # Split on double newlines → paragraphs
            paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 30]
            if not paragraphs:
                continue

            print(f"  {mf.name}: {len(paragraphs)} paragraphs")
            for i in range(0, len(paragraphs), BATCH_SIZE):
                batch = paragraphs[i:i+BATCH_SIZE]
                entity_batches = extract(model, batch)
                for para, ents in zip(batch, entity_batches):
                    out.write(json.dumps({
                        "source": mf.stem,
                        "chunk": para[:300],
                        "entities": ents
                    }) + "\n")

    print(f"\nDone. Output: {PDF_OUTPUT}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["cve", "pdf", "both"], default="both")
    args = parser.parse_args()

    model = load_model()

    if args.mode in ("cve", "both"):
        run_cve(model)
    if args.mode in ("pdf", "both"):
        run_pdf(model)
