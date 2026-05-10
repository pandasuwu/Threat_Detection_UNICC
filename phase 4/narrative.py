"""
Phase 5: Narrative Generation via OpenRouter
Drop-in replacement for the Gemini direct API version.

Install: pip install openai   (OpenRouter uses OpenAI-compatible API)
Env:     OPENROUTER_API_KEY=your_key

Model: google/gemini-2.0-flash-001  (change to any OpenRouter model string)
"""

import os
import logging
from typing import Optional
from openai import OpenAI

logger = logging.getLogger(__name__)

_MODEL = os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct")
_client = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY env var not set")
        _client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
        )
    return _client


SYSTEM_PROMPT = """You are a cybersecurity threat intelligence analyst assistant working for UNICC (United Nations International Computing Centre).

Your job: given a query and retrieved threat intelligence context, produce a concise investigative narrative.

Rules:
- Be factual. Only assert what is evidenced in the provided context.
- Use ATT&CK technique IDs where available (e.g. T1190, T1059.001).
- Structure: Threat Summary → Attack Pattern → Affected Scope → Historical Precedent → Recommended Action.
- Target length: 150-250 words. Investigators are busy.
- Do NOT speculate. If uncertain, say "Evidence is limited — further investigation recommended."
- Flag confidence: HIGH (multiple corroborating sources), MEDIUM (single source), LOW (inferred only).
- Never invent CVE IDs, technique IDs, or group names not present in the context."""

USER_TEMPLATE = """Query: {query}

Retrieved CVE Context ({n_cves} matches):
{cve_context}

ATT&CK Graph Context:
{graph_context}

Generate an investigative narrative following the rules above.
End with a line: CONFIDENCE: HIGH|MEDIUM|LOW — <one sentence reason>"""


def build_context(search_results: list, cve_details: Optional[dict]) -> tuple[str, str]:
    cve_lines = []
    for r in search_results[:5]:
        techs = ", ".join(t["attack_id"] for t in r.techniques if t.get("attack_id")) or "none mapped"
        score_str = f"CVSS {r.cvss_score:.1f}" if r.cvss_score else "CVSS N/A"
        cve_lines.append(
            f"- {r.cve_id} [{r.severity or 'UNKNOWN'}, {score_str}]: {r.description[:200]}...\n"
            f"  ATT&CK: {techs}"
        )
    cve_context = "\n".join(cve_lines) if cve_lines else "No CVE matches found."

    graph_lines = []
    if cve_details:
        if cve_details.get("techniques"):
            techs = [f"{t['attack_id']} ({t.get('name', '')})" for t in cve_details["techniques"] if t.get("attack_id")]
            graph_lines.append(f"Techniques: {', '.join(techs)}")
        if cve_details.get("threat_groups"):
            groups = [g["name"] for g in cve_details["threat_groups"] if g.get("name")]
            graph_lines.append(f"Threat Groups: {', '.join(groups[:10])}")
        if cve_details.get("related_malware"):
            malware = [m["name"] for m in cve_details["related_malware"] if m.get("name")]
            graph_lines.append(f"Related Malware/Tools: {', '.join(malware[:10])}")
    else:
        all_techs = {}
        for r in search_results[:5]:
            for t in r.techniques:
                if t.get("attack_id"):
                    all_techs[t["attack_id"]] = t.get("name", "")
        if all_techs:
            graph_lines.append(
                f"Techniques across results: "
                f"{', '.join(f'{k} ({v})' for k, v in list(all_techs.items())[:8])}"
            )

    graph_context = "\n".join(graph_lines) if graph_lines else "No graph context available."
    return cve_context, graph_context


def generate_narrative(
    query: str,
    search_results: list,
    cve_details: Optional[dict] = None,
) -> dict:
    cve_context, graph_context = build_context(search_results, cve_details)
    prompt = USER_TEMPLATE.format(
        query=query,
        n_cves=len(search_results),
        cve_context=cve_context,
        graph_context=graph_context,
    )

    try:
        client = _get_client()
        response = client.chat.completions.create(
            model=_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.2,
            max_tokens=512,
        )
        full_text = response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"OpenRouter API error: {e}")
        raise RuntimeError(f"Narrative generation failed: {e}")

    # Parse confidence line
    confidence = "MEDIUM"
    narrative = full_text
    for line in reversed(full_text.splitlines()):
        if line.startswith("CONFIDENCE:"):
            confidence_raw = line.replace("CONFIDENCE:", "").strip()
            for level in ("HIGH", "MEDIUM", "LOW"):
                if confidence_raw.startswith(level):
                    confidence = level
                    break
            narrative = full_text[:full_text.rfind(line)].strip()
            break

    return {
        "query": query,
        "narrative": narrative,
        "confidence": confidence,
        "sources": list({r.cve_id for r in search_results[:5]}),
        "n_cves_retrieved": len(search_results),
        "graph_context_used": graph_context != "No graph context available.",
    }
