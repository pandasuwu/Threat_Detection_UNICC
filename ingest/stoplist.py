"""
Shared STOPLIST for ATT&CK entity alias matching.

Design: matching-time filter, not an ontology filter.
data/alias_dictionary.json is generated once from the STIX bundle and is
ground truth for what entities exist. STOPLIST is applied at query/match
time to suppress false-positive matches in free text. Keeping these two
concerns separate means the JSON does not need to be regenerated when the
STOPLIST changes.

History:
  Issue #1 (2026-06-18): 11-entry list applied to alias *generation* in
      alias_dictionary.py (aliases only — canonical names were not filtered).
  Issue #4 (2026-06-19): Centralised here; entity_matcher.py now applies
      this list to BOTH canonical names AND aliases at match time, so
      entities like Play (G1040) and Anchor (S0504) no longer fire on
      generic English prose.
"""

STOPLIST: dict[str, str] = {
    # ── Issue #1 (2026-06-18) ─────────────────────────────────────────────────
    "net":    "Generic .NET/networking; ubiquitous in every report sentence",
    "empire": "Geopolitical/figurative false positives ('criminal empire', historical)",
    "carbon": "VMware Carbon Black + common chemistry term",
    "anchor": "HTML anchors, nautical, journalism; canonical fires on general prose",
    "rover":  "Vehicle brand + common English noun",
    "agent":  "Ubiquitous in LLM/monitoring/general prose",
    "play":   "'Google Play', sentence-initial, verb form; canonical fires on 'orgs play a role'",
    "page":   "Too generic: web pages, document pages, proper names",
    "ping":   "Networking verb; appears in every operational sentence",
    "spark":  "Apache Spark confusion",
    "meek":   "Common adjective; Tor transport context too rare to justify noise",
    # ── Issue #4 additions (2026-06-19) ──────────────────────────────────────
    "expand": "Common English verb; S0361 canonical fires on 'expand risk assessment' etc.",
    "route":  "Common English noun/verb; S0103 canonical fires on BGP/routing prose",
    "cuba":   "Matches Cuba the country in internet-shutdown/censorship sections (S0625)",
    "donut":  "Common word; S0695 fires on chart/diagram text, not shellcode-loader mentions",
    "wiper":  "Used generically for wiper-malware class, not specifically S0041 artifact",
    "royal":  "Fires on 'Royal Canadian Mounted Police' and similar proper nouns (S1073)",
    # ── Considered and rejected (unchanged from Issue #1) ────────────────────
    # regin:          case-sensitive match sufficient; unambiguous codename
    # flame:          same
    # maze:           same
    # gold, wing, iron, bronze, silver: only appear as parts of multi-word aliases
    #                 (e.g. "IRON TWILIGHT") — standalone form not present in corpus
}

STOPLIST_KEYS: frozenset[str] = frozenset(STOPLIST)
