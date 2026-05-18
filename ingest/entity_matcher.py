"""
Scan PDF chunk corpus for ATT&CK entity mentions, CVE-IDs, and ATT&CK technique IDs.

Reads:
  data/alias_dictionary.json       — entity aliases (Groups + Software)
  data/chunks_categorized/*.jsonl  — annotated chunk corpus

Match strategies:
  • Case-sensitive regex for codenames (all-caps or CamelCase, ≥4 chars, single-word)
      e.g. APT28, STRONTIUM, LockBit, PlugX, ALPHV
  • Case-insensitive regex for natural-language phrases (multi-word or title-case)
      e.g. Fancy Bear, Cobalt Strike, Forest Blizzard
  • CVE-ID:   \\bCVE-\\d{4}-\\d{4,7}\\b
  • T-ID:     \\bT\\d{4}(?:\\.\\d{3})?\\b

Usage:
  python -m ingest.entity_matcher --report   # scan corpus, write report, STOP
"""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ingest.stoplist import STOPLIST_KEYS


# ── Patterns ──────────────────────────────────────────────────────────────────

CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b')
TID_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')


def _is_codename(alias: str) -> bool:
    """
    True  → match case-sensitively (all-caps or CamelCase single-word aliases).
    False → match case-insensitively (multi-word phrases or plain-capitalised words).
    """
    if ' ' in alias:
        return False
    # All-caps with optional digits / hyphens: APT28, STRONTIUM, ALPHV, CL0P
    if re.fullmatch(r'[A-Z][A-Z0-9\-_\.]+', alias):
        return True
    # CamelCase: has an uppercase letter somewhere after position 0: LockBit, PlugX, WannaCry
    if alias and re.search(r'[A-Z]', alias[1:]):
        return True
    return False


def _build_entity_patterns(entities: list[dict]) -> list[dict]:
    """
    For each entity build up to two compiled regexes:
      cs_re — case-sensitive  (codenames)
      ci_re — case-insensitive (phrases + plain-capitalised single words)

    STOPLIST_KEYS is applied here at match-time to BOTH canonical names and
    aliases. An entity whose canonical is stoplisted contributes zero matches
    via that string; stoplisted aliases are simply dropped from the pattern.
    If filtering leaves no matchable names the entity is skipped entirely.
    """
    result = []
    for e in entities:
        # Union of canonical + all aliases; enforce ≥4-char floor
        all_names = ({e['canonical']} | set(e.get('aliases') or [])) - {''}
        all_names = {n for n in all_names if len(n) >= 4}
        # Drop anything in the shared STOPLIST (case-insensitive key comparison)
        all_names = {n for n in all_names if n.lower() not in STOPLIST_KEYS}
        if not all_names:
            continue

        codenames = sorted([n for n in all_names if _is_codename(n)], key=len, reverse=True)
        phrases   = sorted([n for n in all_names if not _is_codename(n)], key=len, reverse=True)

        cs_re = (
            re.compile(r'\b(?:' + '|'.join(re.escape(n) for n in codenames) + r')\b')
            if codenames else None
        )
        ci_re = (
            re.compile(
                r'\b(?:' + '|'.join(re.escape(n) for n in phrases) + r')\b',
                re.IGNORECASE,
            )
            if phrases else None
        )

        result.append({
            'canonical': e['canonical'],
            'attack_id': e['attack_id'],
            'type':      e['type'],
            'cs_re':     cs_re,
            'ci_re':     ci_re,
        })
    return result


def _context(text: str, match: re.Match, window: int = 100) -> str:
    """Return ≤200-char snippet centred on a regex match."""
    s = max(0, match.start() - window)
    e = min(len(text), match.end() + window)
    snippet = text[s:e].replace('\n', ' ').strip()
    if s > 0:
        snippet = '…' + snippet
    if e < len(text):
        snippet = snippet + '…'
    return snippet


# ── Report mode ───────────────────────────────────────────────────────────────

def run_report(
    alias_dict_path: Path,
    chunks_dir: Path,
    output_path: Path,
) -> None:
    with open(alias_dict_path, encoding='utf-8') as f:
        alias_data = json.load(f)
    entities = alias_data['entities']
    print(f"Loaded {len(entities)} entities ({alias_data.get('version','?')})", file=sys.stderr)

    ep_list = _build_entity_patterns(entities)
    print(f"Built regexes for {len(ep_list)} entities", file=sys.stderr)

    # entity_hits[canonical] → {count, chunks, attack_id, type, strategy, sample, source, section}
    entity_hits: dict[str, dict] = {}
    cve_counter: Counter = Counter()
    tid_counter: Counter = Counter()

    chunk_files = sorted(chunks_dir.glob('*.jsonl'))
    total_chunks = 0

    for chunk_file in chunk_files:
        source = chunk_file.stem
        for line in chunk_file.read_text(encoding='utf-8').splitlines():
            if not line.strip():
                continue
            chunk = json.loads(line)
            text = chunk.get('text', '')
            total_chunks += 1

            for m in CVE_RE.finditer(text):
                cve_counter[m.group()] += 1
            for m in TID_RE.finditer(text):
                tid_counter[m.group()] += 1

            for ep in ep_list:
                canonical = ep['canonical']
                first_match = None
                strategy   = None
                occ        = 0

                if ep['cs_re']:
                    hits = ep['cs_re'].findall(text)
                    if hits:
                        occ += len(hits)
                        if first_match is None:
                            first_match = ep['cs_re'].search(text)
                            strategy = 'case-sensitive'

                if ep['ci_re']:
                    hits = ep['ci_re'].findall(text)
                    if hits:
                        occ += len(hits)
                        if first_match is None:
                            first_match = ep['ci_re'].search(text)
                            strategy = 'case-insensitive'

                if first_match is None:
                    continue

                if canonical not in entity_hits:
                    entity_hits[canonical] = {
                        'count':    0,
                        'chunks':   0,
                        'attack_id': ep['attack_id'],
                        'type':     ep['type'],
                        'strategy': strategy,
                        'sample':   None,
                        'source':   None,
                        'section':  None,
                    }
                h = entity_hits[canonical]
                h['count']  += occ
                h['chunks'] += 1
                if h['sample'] is None:
                    h['sample']  = _context(text, first_match)
                    h['source']  = source
                    h['section'] = ' > '.join(chunk.get('section_path', []))

    print(
        f"Scanned {total_chunks} chunks · "
        f"{len(entity_hits)} entities matched · "
        f"{len(cve_counter)} CVE-IDs · "
        f"{len(tid_counter)} T-IDs",
        file=sys.stderr,
    )

    _write_report(output_path, entity_hits, cve_counter, tid_counter,
                  total_chunks, alias_data.get('version', '?'))
    print(f"\nFull report → {output_path}", file=sys.stderr)

    # Print condensed summary to stdout for quick review
    print("\n=== TOP 50 ENTITY MATCHES ===")
    print(f"{'Rank':<5} {'Canonical':<30} {'ID':<8} {'Type':<9} {'Strat':<16} {'Occ':>6} {'Chunks':>7}")
    print('-' * 82)
    top50 = sorted(entity_hits.items(), key=lambda x: -x[1]['count'])[:50]
    for rank, (canon, h) in enumerate(top50, 1):
        strat = 'cs' if h['strategy'] == 'case-sensitive' else 'ci'
        print(f"{rank:<5} {canon:<30} {h['attack_id']:<8} {h['type']:<9} {strat:<16} {h['count']:>6} {h['chunks']:>7}")

    print("\n=== TOP 20 CVE-IDs ===")
    for rank, (cve, cnt) in enumerate(cve_counter.most_common(20), 1):
        print(f"  {rank:>2}. {cve:<22} {cnt:>4}")

    print("\n=== TOP 20 T-IDs ===")
    for rank, (tid, cnt) in enumerate(tid_counter.most_common(20), 1):
        print(f"  {rank:>2}. {tid:<12} {cnt:>4}")


def _write_report(
    output_path: Path,
    entity_hits: dict,
    cve_counter: Counter,
    tid_counter: Counter,
    total_chunks: int,
    alias_version: str,
) -> None:
    top50  = sorted(entity_hits.items(), key=lambda x: -x[1]['count'])[:50]
    top_cv = cve_counter.most_common(20)
    top_ti = tid_counter.most_common(20)

    lines = [
        "# Issue #4 Entity Match Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"ATT&CK version: {alias_version}  ",
        f"Corpus: {total_chunks} chunks  ",
        f"Unique entities matched: {len(entity_hits)}  ",
        f"Unique CVE-IDs: {len(cve_counter)}  ",
        f"Unique T-IDs: {len(tid_counter)}  ",
        "",
        "---",
        "",
        "## Top 50 Entity Matches",
        "",
        "| Rank | Canonical | ATT&CK ID | Type | Strategy | Occurrences | Chunks |",
        "|------|-----------|-----------|------|----------|-------------|--------|",
    ]
    for rank, (canon, h) in enumerate(top50, 1):
        lines.append(
            f"| {rank} | {canon} | {h['attack_id']} | {h['type']}"
            f" | {h['strategy']} | {h['count']} | {h['chunks']} |"
        )

    lines += ["", "### Sample Contexts", ""]
    for rank, (canon, h) in enumerate(top50, 1):
        lines.append(
            f"**{rank}. {canon}** "
            f"({h['attack_id']}, {h['type']}, {h['count']} occurrences, {h['chunks']} chunks)"
        )
        lines.append(f"> Source: `{h['source']}` · Section: `{h['section']}`")
        snippet = h['sample'].replace('`', "'")
        lines.append(f"> {snippet}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Top 20 CVE-IDs",
        "",
        "| Rank | CVE-ID | Occurrences |",
        "|------|--------|-------------|",
    ]
    for rank, (cve, cnt) in enumerate(top_cv, 1):
        lines.append(f"| {rank} | {cve} | {cnt} |")

    lines += [
        "",
        "---",
        "",
        "## Top 20 ATT&CK Technique IDs",
        "",
        "| Rank | T-ID | Occurrences |",
        "|------|------|-------------|",
    ]
    for rank, (tid, cnt) in enumerate(top_ti, 1):
        lines.append(f"| {rank} | {tid} | {cnt} |")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        '--report', action='store_true',
        help='Scan corpus and write match report; no DB writes (Part A)',
    )
    parser.add_argument('--alias-dict',  default='data/alias_dictionary.json')
    parser.add_argument('--chunks-dir',  default='data/chunks_categorized')
    parser.add_argument('--output',      default='data/_issue4_match_report.md')
    args = parser.parse_args()

    if args.report:
        run_report(
            alias_dict_path=Path(args.alias_dict),
            chunks_dir=Path(args.chunks_dir),
            output_path=Path(args.output),
        )


if __name__ == '__main__':
    main()
