"""
Phase 3: STIX 2.1 Object Builder
Converts CVE records from cve_entities_all.jsonl to STIX 2.1 objects.

Produces:
  - stix2.Vulnerability per CVE record
  - stix2.Relationship PATTERN_OF linking Vulnerability → AttackPattern (via CWE→ATT&CK)

Deterministic IDs: uuid5(NAMESPACE_DNS, identifier) ensures same entity always gets same STIX ID.
This is the deduplication mechanism — re-runs are idempotent.
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

import stix2

from cwe_to_attack import get_techniques_for_cwe

logger = logging.getLogger(__name__)

# Stable namespace for deterministic STIX IDs
_NS = uuid.UUID("4f6e8b2a-1c3d-5e7f-9a0b-2c4d6e8f1a3b")

# UNICC as the producer identity (created once, referenced everywhere)
PRODUCER_IDENTITY = stix2.Identity(
    id=f"identity--{uuid.uuid5(_NS, 'UNICC-IITGN-Pipeline')}",
    name="UNICC-IITGN Threat Intelligence Pipeline",
    identity_class="system",
    description="Automated extraction pipeline — IITGN B.Tech Capstone / UNICC SOW 2025",
    created=datetime(2025, 11, 21, tzinfo=timezone.utc),
    modified=datetime(2025, 11, 21, tzinfo=timezone.utc),
)


def _vuln_id(cve_id: str) -> str:
    return f"vulnerability--{uuid.uuid5(_NS, cve_id)}"


def _rel_id(source_ref: str, target_ref: str, rel_type: str) -> str:
    return f"relationship--{uuid.uuid5(_NS, f'{source_ref}:{rel_type}:{target_ref}')}"


def cve_to_vulnerability(record: dict) -> stix2.Vulnerability:
    """
    Convert a CVE record dict to a stix2.Vulnerability.

    Input record schema (from cve_entities_all.jsonl / cve_normalized.jsonl):
        cve_id, description, cvss_score, severity, published_date, cwe_ids

    Custom properties (x_ prefix per STIX spec):
        x_cvss_score, x_severity, x_cwe_ids, x_source_pipeline
    """
    cve_id = record["cve_id"]
    published = record.get("published_date")
    if published:
        try:
            published_dt = datetime.fromisoformat(published).replace(tzinfo=timezone.utc)
        except ValueError:
            published_dt = None
    else:
        published_dt = None

    ext_refs = [
        stix2.ExternalReference(
            source_name="cve",
            external_id=cve_id,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )
    ]

    # Add CWE external references
    for cwe in record.get("cwe_ids") or []:
        ext_refs.append(
            stix2.ExternalReference(
                source_name="cwe",
                external_id=cwe,
                url=f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html",
            )
        )

    now = datetime.now(timezone.utc)
    vuln = stix2.Vulnerability(
        id=_vuln_id(cve_id),
        name=cve_id,
        description=record.get("description") or "",
        created=published_dt or now,
        modified=now,
        created_by_ref=PRODUCER_IDENTITY.id,
        external_references=ext_refs,
        custom_properties={
            "x_cvss_score": record.get("cvss_score"),
            "x_severity": record.get("severity"),
            "x_cwe_ids": record.get("cwe_ids") or [],
            "x_published_date": record.get("published_date"),
            "x_source_pipeline": "unicc-iitgn-phase3",
        },
    )
    return vuln


def cve_to_attack_relationships(
    record: dict,
    attack_technique_stix_ids: dict[str, str],
) -> list[stix2.Relationship]:
    """
    Generate STIX Relationships: Vulnerability -[PATTERN_OF]-> AttackPattern

    Args:
        record: CVE record dict
        attack_technique_stix_ids: mapping from ATT&CK technique ID (T1059 etc.)
                                   to STIX ID (attack-pattern--...) from Neo4j.
                                   Pre-fetched once, passed in for performance.

    Returns:
        List of stix2.Relationship objects (may be empty if no CWE mapping).
    """
    cve_id = record["cve_id"]
    vuln_stix_id = _vuln_id(cve_id)
    cwes = record.get("cwe_ids") or []
    now = datetime.now(timezone.utc)

    relationships = []
    seen_technique_ids = set()  # dedup: one relationship per technique per CVE

    for cwe in cwes:
        for attack_id in get_techniques_for_cwe(cwe):
            if attack_id in seen_technique_ids:
                continue
            ap_stix_id = attack_technique_stix_ids.get(attack_id)
            if not ap_stix_id:
                logger.debug(f"ATT&CK technique {attack_id} not found in Neo4j for {cve_id}")
                continue
            seen_technique_ids.add(attack_id)

            rel = stix2.Relationship(
                id=_rel_id(vuln_stix_id, ap_stix_id, "pattern-of"),
                relationship_type="pattern-of",
                source_ref=vuln_stix_id,
                target_ref=ap_stix_id,
                created=now,
                modified=now,
                created_by_ref=PRODUCER_IDENTITY.id,
                description=f"{cve_id} ({cwe}) maps to ATT&CK {attack_id}",
                custom_properties={
                    "x_cwe_id": cwe,
                    "x_attack_technique_id": attack_id,
                    "x_source_pipeline": "unicc-iitgn-phase3",
                },
            )
            relationships.append(rel)

    return relationships


def gemini_software_to_stix(
    software_name: str,
    source_cve_id: str,
) -> stix2.Software:
    """
    Convert a Gemini-extracted software name to a STIX 2.1 Software object.
    Used for Phase 3 relation extraction results.
    """
    now = datetime.now(timezone.utc)
    return stix2.Software(
        id=f"software--{uuid.uuid5(_NS, software_name.lower().strip())}",
        name=software_name,
        created=now,
        modified=now,
        created_by_ref=PRODUCER_IDENTITY.id,
        custom_properties={
            "x_extracted_from": source_cve_id,
            "x_source_pipeline": "unicc-iitgn-phase3-gemini",
        },
    )


def gemini_relation_to_stix(
    source_ref: str,
    target_ref: str,
    relation_type: str,
    evidence: str,
    source_cve_id: str,
    confidence: float,
) -> Optional[stix2.Relationship]:
    """
    Convert a Gemini-extracted relation triple to a STIX Relationship.
    Returns None if relation_type is not in the allowed set.
    """
    VALID_RELATION_TYPES = {
        "exploits", "targets", "uses", "mitigates",
        "delivers", "attributed-to", "indicates", "related-to",
        "affects",
    }
    if relation_type not in VALID_RELATION_TYPES:
        logger.warning(f"Rejected invalid relation type: {relation_type}")
        return None

    now = datetime.now(timezone.utc)
    return stix2.Relationship(
        id=_rel_id(source_ref, target_ref, relation_type),
        relationship_type=relation_type,
        source_ref=source_ref,
        target_ref=target_ref,
        description=evidence,
        created=now,
        modified=now,
        created_by_ref=PRODUCER_IDENTITY.id,
        custom_properties={
            "x_source_doc": source_cve_id,
            "x_confidence": confidence,
            "x_source_pipeline": "unicc-iitgn-phase3-gemini",
        },
    )
