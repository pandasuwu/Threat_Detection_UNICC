# Corpus Notes

Shared reference for Issues #3–#5. Update in place as observations accumulate.

---

## Corpus version

**7 reports** in `data/chunks/` as of Issue #2 (2026-06-19).

| Source label | File | Coverage |
|---|---|---|
| `ENISA_2023` | ENISA Threat Landscape 2023 | full report — 224 chunks |
| `ENISA_2024` | ENISA Threat Landscape 2024 | full report — 166 chunks |
| `ENISA_2025` | ENISA Threat Landscape 2025 Booklet | booklet only (6 pp) — 8 chunks |
| `Microsoft_DDFR_2023` | MDDR Executive Summary Oct 2023 | exec summary only (13 pp) — 28 chunks |
| `Microsoft_DDFR_2024` | Microsoft Digital Defense Report 2024 | full report — 232 chunks |
| `Microsoft_DDFR_2025` | MDDR Government Executive Summary 2025 | gov. exec. summary — 29 chunks |
| `ATT_CSRIC_v6` | AT&T Cybersecurity Insights Report v6 | full report — 22 chunks |

**Known gaps:**
- `ENISA_2025` and `Microsoft_DDFR_2023` are exec-summary/booklet versions — full versions not available at time of build. Affects coverage and recall on 2025 events and pre-2024 Microsoft data.
- No ENISA 2022 or Microsoft DDFR 2022 available.

---

## Alias matching caveats (from Issue #1)

- **Play ransomware** excluded from alias matching (STOPLIST entry in `ingest/alias_dictionary.py`); the group's only alias is the generic word "Play". May affect 1–2 eval queries that mention the Play group by name.
- See `ingest/alias_dictionary.py` STOPLIST for the full list of 11 excluded aliases with rationale.

---

## Heading structure (from Issue #2)

All 7 source PDFs produce **flat level-1 section paths** — Docling does not detect H2/H3 in styled-PDF CTI layouts. `section_path` is always a single-element list (e.g. `["Ransomware remains the most impactful threat in the EU"]`). Issue #3 category mapping should key on substring/keyword patterns within `section_path[0]`, not on path depth.

---

## Trend observations

*To be filled in during Issue #3 hand-mapping of section paths to threat categories.*

<!-- Example format:
- "DDoS" appears as a heading keyword in ENISA_2023 (3 sections), ENISA_2024 (2 sections), MDDR_2024 (1 section).
- "Ransomware" is the most frequent heading keyword across all 7 reports.
-->
