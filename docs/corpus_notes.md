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

1. **ENISA 2023→2024 taxonomy stability with growing AI integration.** ENISA reports show a consistent threat taxonomy across 2023 and 2024 (ransomware, malware, social engineering, supply chain, availability, data, information manipulation), making year-over-year comparison reliable. AI-related sub-sections grow noticeably from 2023 to 2024 — from one scattered sub-section to multiple dedicated sub-sections under social engineering, malware, and information manipulation. ENISA 2025 is booklet-only (8 chunks); the full 2025 report is not available and should be acquired before drawing 2025 trend conclusions.

2. **Microsoft DDFR pivots from technical landscape (2024) to policy/regulation lens (2025).** MDDR 2024 is the full technical report (232 chunks), covering AI defense, nation-state targeting by sector, OT/ICS security, identity attacks, and cloud threats. MDDR 2025 is a government executive summary (29 chunks) focused on deterrence, ransomware geopolitics, quantum, cyber mercenaries, and multistakeholder regulation — a different lens entirely. MDDR 2023 is an exec-summary only (28 chunks); neither 2023 nor 2025 full versions are available, limiting longitudinal technical analysis.

4. **CVE-ID and ATT&CK Technique-ID coverage is minimal.** Only 4 unique CVE-IDs and 1 ATT&CK Technique-ID (T0068, an ICS tactic) were found across all 7 reports. Landscape reports use descriptive language rather than identifier citations. Consequence: PDF-side MENTIONED_IN edges to specific CVEs/T-IDs will be sparse; CVE retrieval will lean on the Qdrant CVE collection (description-based) rather than PDF entity matches.

3. **ATT_CSRIC_v6 is a workforce/management survey, not a threat-content report.** Almost all chunks categorize under `security_management` (15 of 22); zero chunks land in ransomware, malware, DDoS, supply chain, or AI threats. Content centers on staffing shortages, cyberinsurance, awareness training, and risk investment rather than attack techniques or actor activity. Retrieval recall for threat-vector queries against this source will be near zero by design. Consider excluding ATT_CSRIC_v6 from threat-vector search results if eval relevance confirms low signal.
