"""Attach evidence from the multi-source knowledge registry to PHASE 3 steps."""
from __future__ import annotations

import json
from collections import Counter
from typing import Any

from knowledge_base import get_knowledge_base
from structured_attack import validate_structured_incident


CONTEXT_SOURCES = (
    "sigma",
    "yara",
    "threat_intelligence",
    "nist_cis",
    "playbooks",
    "enterprise_assets",
)


def enrich_with_knowledge(
    structured: dict[str, Any],
    *,
    knowledge_base=None,
    limit_per_step: int = 6,
) -> dict[str, Any]:
    """Search real indexed sources and attach compact, provenance-rich matches."""
    result = json.loads(json.dumps(validate_structured_incident(structured)))
    kb = knowledge_base or get_knowledge_base()
    status = kb.status()
    ready_sources = [
        source
        for source in CONTEXT_SOURCES
        if status["sources"].get(source, {}).get("ready")
    ]
    if not ready_sources:
        result["metadata"]["knowledge"] = {
            "ready": False,
            "search_engine": status["search_engine"],
            "sources": [],
            "matches": 0,
        }
        return result

    source_counts: Counter[str] = Counter()
    total_matches = 0
    for step in result["steps"]:
        query = _step_query(step)
        response = kb.search(
            query,
            sources=ready_sources,
            limit=max(1, min(20, int(limit_per_step))),
        )
        matches = [_compact_match(item) for item in response["results"]]
        for match in matches:
            source_counts[match["source"]] += 1
        total_matches += len(matches)
        step["knowledge"] = {"query": query, "matches": matches}

    pipeline = result["metadata"].setdefault("pipeline", [])
    if "phase_4_multisource_knowledge" not in pipeline:
        pipeline.append("phase_4_multisource_knowledge")
    result["metadata"]["knowledge"] = {
        "ready": True,
        "search_engine": status["search_engine"],
        "sources": ready_sources,
        "source_counts": dict(source_counts),
        "matches": total_matches,
        "indexed_documents": status["totals"]["documents"],
        "indexed_assets": status["totals"]["assets"],
    }
    return result


def _step_query(step: dict[str, Any]) -> str:
    values = [
        step.get("action"),
        step.get("actor"),
        step.get("target"),
        step.get("asset"),
        step.get("mitre", {}).get("technique_id"),
        step.get("mitre", {}).get("tactic"),
    ]
    return " ".join(
        str(value).strip()
        for value in values
        if value and str(value).strip().lower() != "unknown"
    )


def _compact_match(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata") or {}
    return {
        "id": item.get("id"),
        "source": item.get("source"),
        "document_type": item.get("document_type"),
        "title": item.get("title"),
        "snippet": item.get("snippet") or str(item.get("text", ""))[:360],
        "origin": item.get("origin"),
        "score": item.get("score", 0),
        "metadata": {
            key: metadata[key]
            for key in (
                "external_id",
                "level",
                "status",
                "tags",
                "criticality",
                "hostname",
                "ip_address",
                "framework",
            )
            if key in metadata
        },
    }
