import json
from pathlib import Path

from knowledge_base import KnowledgeBase, KnowledgeBaseConfig
from knowledge_enrichment import CONTEXT_SOURCES, enrich_with_knowledge
from structured_attack import build_structured_incident


def _temporary_kb(tmp_path: Path) -> KnowledgeBase:
    config = KnowledgeBaseConfig(
        root=tmp_path / "knowledge",
        mitre_path=tmp_path / "mitre" / "enterprise-attack.json",
        database_path=tmp_path / "knowledge.sqlite3",
    )
    return KnowledgeBase(config=config)


def _write(kb: KnowledgeBase, source: str, filename: str, text: str) -> None:
    destination = kb.source_path(source) / "manual" / filename
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


def _incident():
    return build_structured_incident(
        "Attacker dùng PowerShell tải malware vào máy chủ tài chính.",
        [{
            "step": 1,
            "actor": "Attacker",
            "action": "PowerShell download malware",
            "target": "Finance Server",
            "asset": "fin-app-01",
            "severity": "High",
            "mitre_tactic": "Execution",
            "technique_id": "T1059.001",
        }],
        model="fixture-llm",
        provider="offline-test",
    )


def _index_multisource_fixtures(kb: KnowledgeBase) -> None:
    _write(kb, "sigma", "powershell.yml", """
title: Fixture PowerShell Download
id: 10000000-0000-0000-0000-000000000001
description: Detects PowerShell download activity on a finance server.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
""")
    _write(kb, "yara", "powershell.yar", """
rule Fixture_PowerShell_Malware {
    meta:
        description = "Detects a PowerShell malware fixture"
    strings:
        $command = "PowerShell download malware"
    condition:
        $command
}
""")
    _write(kb, "threat_intelligence", "fixture.json", json.dumps({
        "indicators": [{
            "id": "indicator--powershell-fixture",
            "type": "indicator",
            "name": "PowerShell malware infrastructure",
            "description": "PowerShell payload targeting finance servers.",
            "pattern": "[domain-name:value = 'offline.invalid']",
        }],
    }))
    _write(
        kb,
        "nist_cis",
        "fixture-nist.txt",
        "NIST fixture guidance\nMonitor and restrict PowerShell execution.",
    )
    _write(
        kb,
        "playbooks",
        "powershell-response.md",
        "# PowerShell malware response\nIsolate the finance server and preserve logs.",
    )
    for source in (
        "sigma",
        "yara",
        "threat_intelligence",
        "nist_cis",
        "playbooks",
    ):
        kb.ingest_source(source)
    kb.import_assets(
        [{
            "asset_id": "asset-fin-app-01",
            "name": "PowerShell Finance Server",
            "hostname": "fin-app-01",
            "asset_type": "server",
            "criticality": "Critical",
            "environment": "Production",
        }],
        filename="fixture-assets.json",
    )


def test_enrichment_attaches_real_multisource_evidence_from_temporary_sqlite(
    tmp_path,
):
    kb = _temporary_kb(tmp_path)
    _index_multisource_fixtures(kb)
    incident = _incident()

    enriched = enrich_with_knowledge(
        incident,
        knowledge_base=kb,
        limit_per_step=20,
    )

    # The input contract is not mutated by enrichment.
    assert "knowledge" not in incident["steps"][0]

    evidence = enriched["steps"][0]["knowledge"]
    sources = {match["source"] for match in evidence["matches"]}
    assert sources == set(CONTEXT_SOURCES)
    assert evidence["query"].startswith("PowerShell download malware")
    assert all(match["origin"] for match in evidence["matches"])
    assert all(isinstance(match["score"], (int, float)) for match in evidence["matches"])

    metadata = enriched["metadata"]["knowledge"]
    assert metadata["ready"] is True
    assert metadata["search_engine"] in {"sqlite-fts5", "sqlite-lexical"}
    assert metadata["matches"] == len(evidence["matches"])
    assert metadata["indexed_documents"] == 6
    assert metadata["indexed_assets"] == 1
    assert set(metadata["source_counts"]) == set(CONTEXT_SOURCES)
    assert (
        enriched["metadata"]["pipeline"].count("phase_4_multisource_knowledge")
        == 1
    )


def test_enrichment_reports_empty_registry_without_fabricating_evidence(tmp_path):
    kb = _temporary_kb(tmp_path)

    enriched = enrich_with_knowledge(_incident(), knowledge_base=kb)

    assert enriched["metadata"]["knowledge"] == {
        "ready": False,
        "search_engine": kb.status()["search_engine"],
        "sources": [],
        "matches": 0,
    }
    assert "knowledge" not in enriched["steps"][0]
