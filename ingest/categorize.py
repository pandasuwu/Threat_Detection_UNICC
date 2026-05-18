"""
Categorize PDF report chunks using a hand-curated section-path keyword map.

Reads  data/chunks/*.jsonl + data/category_map.yaml
Writes data/chunks_categorized/<source>.jsonl  (all original fields + "categories")

Matching: case-insensitive substring match against the joined section_path string.
Multi-category: all matching categories are recorded.
Exclude fallback: if ONLY exclude patterns match (no category hit), categories=[]
and the chunk is counted as excluded (not toward the uncategorized bar).

Usage:
  python -m ingest.categorize               # write categorized JSONL
  python -m ingest.categorize --stats       # also print per-report stats table
"""

import argparse
import json
import sys
from pathlib import Path

import yaml


# Sentinel so we can tell apart "excluded front-matter" from "no match at all"
_EXCLUDED = object()


def _load_map(map_path: Path) -> tuple[dict[str, list[str]], list[str]]:
    with open(map_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    categories = {k: [p.lower() for p in v] for k, v in data["categories"].items()}
    exclude = [p.lower() for p in data.get("exclude", [])]
    return categories, exclude


def _classify(
    section_path: list[str],
    categories: dict[str, list[str]],
    exclude: list[str],
):
    """
    Returns:
      list[str]  — matched category names (may be multi)
      []         — only exclude patterns matched (front-matter)
      _EXCLUDED  — sentinel for excluded (same outcome, tracked separately)
    """
    if not section_path:
        return _EXCLUDED
    # Pad with spaces so leading/trailing space in patterns act as word boundaries.
    text = " " + " ".join(section_path).lower() + " "
    matched = [cat for cat, patterns in categories.items() if any(p in text for p in patterns)]
    if matched:
        return matched
    if any(p in text for p in exclude):
        return _EXCLUDED
    return []  # truly uncategorized content


def _run(chunks_dir: Path, output_dir: Path, categories: dict, exclude: list) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    stats = {}
    for src_file in sorted(chunks_dir.glob("*.jsonl")):
        source = src_file.stem
        cat_counts: dict[str, int] = {cat: 0 for cat in categories}
        n_uncategorized = 0
        n_excluded = 0
        out_lines = []
        for line in src_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            chunk = json.loads(line)
            result = _classify(chunk["section_path"], categories, exclude)
            if result is _EXCLUDED:
                chunk["categories"] = []
                n_excluded += 1
            elif result:
                chunk["categories"] = result
                for cat in result:
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
            else:
                chunk["categories"] = []
                n_uncategorized += 1
            out_lines.append(json.dumps(chunk, ensure_ascii=False))
        (output_dir / src_file.name).write_text(
            "\n".join(out_lines) + "\n", encoding="utf-8"
        )
        stats[source] = {
            "cat_counts": cat_counts,
            "uncategorized": n_uncategorized,
            "excluded": n_excluded,
            "total": len(out_lines),
        }
    return stats


def _print_stats(stats: dict, categories: dict) -> None:
    cat_names = list(categories.keys())
    src_w = max(len(s) for s in stats) + 2
    col_w = 7

    print(f"\n{'Source':<{src_w}}", end="")
    for c in cat_names:
        print(f"{c[:col_w-1]:>{col_w}}", end="")
    print(f"{'uncat':>8}{'excl':>7}{'total':>7}{'uncat%':>8}")
    print("-" * (src_w + len(cat_names) * col_w + 30))

    for source, s in stats.items():
        print(f"{source:<{src_w}}", end="")
        for c in cat_names:
            print(f"{s['cat_counts'].get(c, 0):>{col_w}}", end="")
        content = s["total"] - s["excluded"]
        pct = s["uncategorized"] / content * 100 if content else 0
        flag = " !" if pct > 15 else ""
        print(f"{s['uncategorized']:>8}{s['excluded']:>7}{s['total']:>7}{pct:>7.1f}%{flag}")

    print()
    for source, s in stats.items():
        content = s["total"] - s["excluded"]
        pct = s["uncategorized"] / content * 100 if content else 0
        if pct > 15:
            print(f"WARNING: {source} {pct:.1f}% uncategorized (threshold 15%)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stats", action="store_true", help="Print per-report stats table")
    parser.add_argument("--chunks-dir", default="data/chunks")
    parser.add_argument("--output-dir", default="data/chunks_categorized")
    parser.add_argument("--map", default="data/category_map.yaml")
    args = parser.parse_args()

    map_path = Path(args.map)
    if not map_path.exists():
        sys.exit(f"ERROR: category map not found: {map_path}")
    categories, exclude = _load_map(map_path)

    chunks_dir = Path(args.chunks_dir)
    if not any(chunks_dir.glob("*.jsonl")):
        sys.exit(f"ERROR: no JSONL files in {chunks_dir}")

    output_dir = Path(args.output_dir)
    stats = _run(chunks_dir, output_dir, categories, exclude)

    if args.stats:
        _print_stats(stats, categories)

    total = sum(s["total"] for s in stats.values())
    total_uncat = sum(s["uncategorized"] for s in stats.values())
    total_excl = sum(s["excluded"] for s in stats.values())
    print(f"Wrote {len(stats)} files → {output_dir}/")
    print(f"  Total: {total}  Uncategorized: {total_uncat}  Excluded: {total_excl}")
    for source, s in stats.items():
        content = s["total"] - s["excluded"]
        pct = s["uncategorized"] / content * 100 if content else 0
        flag = "  *** OVER 15% ***" if pct > 15 else ""
        print(f"  {source}: {pct:.1f}% uncategorized{flag}")


if __name__ == "__main__":
    main()
