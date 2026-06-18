"""
Build entity alias dictionary from Neo4j ATT&CK data.

Produces data/alias_dictionary.json: one entry per entity (Group/Software),
with all known aliases, for downstream entity matching in PDF chunks.

Usage:
  python -m ingest.alias_dictionary --audit      # review ambiguous aliases, propose STOPLIST
  python -m ingest.alias_dictionary --generate   # write data/alias_dictionary.json
"""

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

logger = logging.getLogger(__name__)

# ── STOPLIST ──────────────────────────────────────────────────────────────────
# Hand-curated aliases to drop from the dictionary.
# Reviewed and approved 2026-06-18. Format: lowercase alias → reason.
STOPLIST: dict[str, str] = {
    "net":    "Generic .NET/networking; ubiquitous in every report sentence",
    "empire": "Geopolitical/figurative false positives ('criminal empire', historical)",
    "carbon": "VMware Carbon Black + common chemistry term",
    "anchor": "HTML anchors, nautical, journalism",
    "rover":  "Vehicle brand + common English noun",
    "agent":  "Ubiquitous in LLM/monitoring/general prose",
    "play":   "'Google Play', sentence-initial, verb form; case-sensitive match insufficient",
    "page":   "Too generic: web pages, document pages, proper names",
    "ping":   "Networking verb; appears in every operational sentence",
    "spark":  "Apache Spark confusion",
    "meek":   "Common adjective; Tor transport context too rare to justify noise",
    # Considered and rejected — kept in dictionary:
    # regin:          case-sensitive match sufficient; Regin is an unambiguous codename
    # flame:          same; 'Flame' capitalised is unambiguous in CTI prose
    # maze:           same; 'Maze' capitalised is unambiguous in CTI prose
    # gold/wing/iron/bronze/silver: only appear as parts of multi-word aliases
    #                 (e.g. "IRON TWILIGHT") — standalone form not present in data
}

_TRUE_STOPLIST: frozenset[str] = frozenset(STOPLIST)

# ── Inline English word set for audit ─────────────────────────────────────────
# Common single English words that are risky as entity matchers.
# Used only by --audit mode; not used during generation.
_ENGLISH_WORDS: frozenset[str] = frozenset("""
about above across after again against agent anchor angle apple arm army
arrow back ball band base bear before below bird black blade blue bomb bone
book born break bridge bright brown build burn button camp carbon carry
catch cause chain change chase check chip circle claim class clean clear
click close cloud coal code cold color come cool core cover crane cross
crowd crown cut dark data dawn dead deal deep delta demon dense dirt disk
dog dome door down draw dream drive drop drum dust dust earth east edge
eight elder elite empire end enter equal error event every exit face fall
false fame fast fate feel field file fill final find fire first fish five
fixed flag flame flash flat flesh float flow foam fold folk follow food
force forge form found four frame free fresh front fuel full fund fuse gain
game gate gear give glad glow glue goal gold gone good grab grade grand
grant gray great green grew grid grin grip grow guard guide hard harm hash
have hawk head heal heap heat heavy help hero high hill hold home hood hook
hope horn host hour hunt info iron jade join jump just keep kill king know
lack lake land lane last late lead leak left lend less life lift light like
lime line link lion list live load lock loft long look loop lord lore lose
loud love luck main make many mark mass mate maze mean meet mesh mind mine
mist mode moon more most move much nail name near need nest next nine node
none norm note null object once open over page pair palm park pass peak
pick pipe plan plate play plus poll pool port post pull push rain rank raw
read real rear reef rest rice ride ring rise road rock role roll root rule
rush rust safe sail sand save scan seat seed self send set seven shed ship
side sign silk site size skip sky slab slim slip slow snap snow soft soil
some sort soul span spark speed spin spoke spring square stamp stand star
stark start stay steam steep step stick still stone stop storm strap stream
string strip suit sung swap swim sync tail take task team tear tell test
time tiny trap trim true trust tube turn type unit upon user vary view vim
void wait walk wall want warm wave weak well west wide wild will wind wing
wire word work wrap yard year zero zone
""".split())


# ── Neo4j queries ─────────────────────────────────────────────────────────────

_GROUP_QUERY = """
MATCH (g:Group)
RETURN g.name       AS name,
       g.attack_id  AS attack_id,
       g.aliases    AS aliases
ORDER BY g.attack_id
"""

_SOFTWARE_QUERY = """
MATCH (s:Software)
RETURN s.name       AS name,
       s.attack_id  AS attack_id,
       s.aliases    AS aliases
ORDER BY s.attack_id
"""


def _connect(uri: str, user: str, password: str):
    driver = GraphDatabase.driver(uri, auth=(user, password))
    driver.verify_connectivity()
    return driver


def _normalize_aliases(raw_aliases: list, stoplist: frozenset[str]) -> list[str]:
    """
    Deduplicate case-insensitively (preserve first-seen casing), strip whitespace,
    drop entries shorter than 4 chars, drop STOPLIST entries.
    Returns list ordered: first occurrence wins.
    """
    seen_lower: set[str] = set()
    result: list[str] = []
    for alias in raw_aliases:
        alias = alias.strip()
        if len(alias) < 4:
            continue
        lo = alias.lower()
        if lo in stoplist:
            continue
        if lo in seen_lower:
            continue
        seen_lower.add(lo)
        result.append(alias)
    return result


def _fetch_entities(driver) -> tuple[list[dict], list[dict]]:
    with driver.session() as session:
        groups = session.run(_GROUP_QUERY).data()
        software = session.run(_SOFTWARE_QUERY).data()
    return groups, software


def _build_entities(
    groups: list[dict],
    software: list[dict],
    stoplist: frozenset[str],
) -> list[dict]:
    entities = []
    for row in groups:
        aliases = _normalize_aliases(row["aliases"] or [], stoplist)
        entities.append({
            "canonical":  row["name"],
            "attack_id":  row["attack_id"],
            "type":       "group",
            "aliases":    aliases,
        })
    for row in software:
        aliases = _normalize_aliases(row["aliases"] or [], stoplist)
        entities.append({
            "canonical":  row["name"],
            "attack_id":  row["attack_id"],
            "type":       "software",
            "aliases":    aliases,
        })
    return entities


def _get_attack_version() -> str:
    """Best-effort: read x_mitre_attack_spec_version from the STIX bundle."""
    bundle_path = os.getenv("STIX_BUNDLE_PATH", "")
    if bundle_path and Path(bundle_path).exists():
        try:
            with open(bundle_path, encoding="utf-8") as f:
                bundle = json.load(f)
            for obj in bundle.get("objects", []):
                v = obj.get("x_mitre_attack_spec_version")
                if v:
                    return f"attack-spec-{v}"
        except Exception:
            pass
    return "unknown"


# ── Audit mode ────────────────────────────────────────────────────────────────

def run_audit(driver) -> None:
    groups, software = _fetch_entities(driver)
    # Collect all raw aliases pre-stoplist (audit is pre-generation)
    all_aliases: list[tuple[str, str, str]] = []  # (alias, entity_name, type)
    for row in groups:
        for alias in (row["aliases"] or []):
            alias = alias.strip()
            if len(alias) >= 4:
                all_aliases.append((alias, row["name"], "group"))
    for row in software:
        for alias in (row["aliases"] or []):
            alias = alias.strip()
            if len(alias) >= 4:
                all_aliases.append((alias, row["name"], "software"))

    # ── Short aliases (≤5 chars) ──────────────────────────────────────────
    short = [(a, e, t) for a, e, t in all_aliases if len(a) <= 5]
    short.sort(key=lambda x: (len(x[0]), x[0].lower()))

    print("\n" + "=" * 70)
    print(f"AUDIT: Aliases ≤5 characters ({len(short)} entries)")
    print("=" * 70)
    print(f"  {'ALIAS':<10}  {'LEN':>3}  {'ENTITY':<35}  TYPE")
    print(f"  {'-'*10}  {'-'*3}  {'-'*35}  {'-'*8}")
    for alias, entity, etype in short:
        print(f"  {alias:<10}  {len(alias):>3}  {entity:<35}  {etype}")

    # ── Single common English words ───────────────────────────────────────
    dict_matches = [
        (a, e, t) for a, e, t in all_aliases
        if re.fullmatch(r"[A-Za-z]+", a) and a.lower() in _ENGLISH_WORDS
    ]
    dict_matches.sort(key=lambda x: x[0].lower())

    print("\n" + "=" * 70)
    print(f"AUDIT: Aliases that are single common English words ({len(dict_matches)} entries)")
    print("=" * 70)
    print(f"  {'ALIAS':<25}  {'ENTITY':<35}  TYPE")
    print(f"  {'-'*25}  {'-'*35}  {'-'*8}")
    for alias, entity, etype in dict_matches:
        print(f"  {alias:<25}  {entity:<35}  {etype}")

    # ── Proposed STOPLIST ─────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("PROPOSED STOPLIST (from STOPLIST constant in script)")
    print("=" * 70)
    for alias, reason in STOPLIST.items():
        marker = "[DROP]  " if alias in _TRUE_STOPLIST else "[NOTE]  "
        print(f"  {marker}{alias:<20}  {reason}")

    print("\n" + "=" * 70)
    print("Counts before stoplist/length filter:")
    print(f"  Groups:   {len(groups)}")
    print(f"  Software: {len(software)}")
    total_raw = sum(len(r['aliases'] or []) for r in groups + software)
    print(f"  Total raw aliases: {total_raw}")
    print("=" * 70)
    print("\nReview the lists above, update STOPLIST in script, then run --generate.\n")


# ── Generate mode ─────────────────────────────────────────────────────────────

def run_generate(driver, output_path: Path) -> None:
    groups, software = _fetch_entities(driver)
    entities = _build_entities(groups, software, _TRUE_STOPLIST)

    version = _get_attack_version()
    payload = {
        "version":      version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entities":     entities,
        "_stats": {
            "n_groups":   sum(1 for e in entities if e["type"] == "group"),
            "n_software": sum(1 for e in entities if e["type"] == "software"),
            "n_aliases_total": sum(len(e["aliases"]) for e in entities),
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")

    stats = payload["_stats"]
    logger.info(
        f"Wrote {output_path}  "
        f"(groups={stats['n_groups']}, software={stats['n_software']}, "
        f"total_aliases={stats['n_aliases_total']})"
    )
    print(f"\nWrote: {output_path}")
    print(f"  Groups:          {stats['n_groups']}")
    print(f"  Software:        {stats['n_software']}")
    print(f"  Total aliases:   {stats['n_aliases_total']}")
    print(f"  ATT&CK version:  {version}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")

    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--audit",    action="store_true",
                      help="Print ambiguous aliases for STOPLIST review; do not write JSON")
    mode.add_argument("--generate", action="store_true",
                      help="Write data/alias_dictionary.json")
    parser.add_argument("--output", default="data/alias_dictionary.json",
                        help="Output path (default: data/alias_dictionary.json)")
    parser.add_argument("--neo4j-uri",      default=os.getenv("NEO4J_URI",      "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user",     default=os.getenv("NEO4J_USER",     "neo4j"))
    parser.add_argument("--neo4j-password", default=os.getenv("NEO4J_PASSWORD", ""))
    args = parser.parse_args()

    if not args.neo4j_password:
        sys.exit("ERROR: NEO4J_PASSWORD not set (env var or --neo4j-password)")

    driver = _connect(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
    try:
        if args.audit:
            run_audit(driver)
        else:
            run_generate(driver, Path(args.output))
    finally:
        driver.close()


if __name__ == "__main__":
    main()
