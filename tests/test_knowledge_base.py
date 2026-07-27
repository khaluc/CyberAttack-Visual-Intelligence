import json
from pathlib import Path

from knowledge_base import (
    DownloadTarget,
    KnowledgeBase,
    KnowledgeBaseConfig,
    SourceSpec,
)


def _kb(tmp_path: Path) -> KnowledgeBase:
    mitre = tmp_path / "mitre" / "enterprise-attack.json"
    mitre.parent.mkdir(parents=True)
    mitre.write_text(json.dumps({
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Phishing",
                "description": "Adversaries send malicious email attachments.",
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": "T1566",
                }],
                "kill_chain_phases": [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access",
                }],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--1",
                "name": "Fixture Group",
                "description": "Threat actor used spearphishing.",
            },
        ],
    }), encoding="utf-8")
    config = KnowledgeBaseConfig(
        root=tmp_path / "kb",
        mitre_path=mitre,
        database_path=tmp_path / "kb.sqlite3",
    )
    return KnowledgeBase(config=config)


def _write_source(kb: KnowledgeBase, source: str, name: str, content: str) -> Path:
    path = kb.source_path(source) / "manual" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_multisource_ingestion_and_dynamic_status(tmp_path):
    kb = _kb(tmp_path)
    _write_source(kb, "sigma", "powershell.yml", """
title: Suspicious PowerShell Download
id: 11111111-1111-1111-1111-111111111111
description: Detects PowerShell downloading a payload.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: 'DownloadString'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
""")
    _write_source(kb, "yara", "malware.yar", """
rule Fixture_Malware : trojan test {
    meta:
        description = "Detects the fixture RAT payload"
        author = "SOC"
    strings:
        $c2 = "evil.example"
    condition:
        $c2
}
""")
    _write_source(kb, "threat_intelligence", "kev.json", json.dumps({
        "catalogVersion": "fixture",
        "vulnerabilities": [{
            "cveID": "CVE-2025-0001",
            "vendorProject": "Fixture",
            "product": "Gateway",
            "vulnerabilityName": "Fixture Gateway Command Injection",
            "shortDescription": "Exploited command injection.",
            "requiredAction": "Apply mitigations.",
            "dueDate": "2026-01-01",
        }],
    }))
    _write_source(
        kb,
        "nist_cis",
        "nist-incident-response.txt",
        "NIST Incident Response Guidance\nContain incidents and recover services.",
    )
    _write_source(
        kb,
        "playbooks",
        "ransomware.md",
        "# Ransomware playbook\nIsolate endpoints, preserve evidence, and reset credentials.",
    )

    results = {source: kb.ingest_source(source) for source in (
        "mitre_attack", "sigma", "yara", "threat_intelligence",
        "nist_cis", "playbooks",
    )}
    assert results["mitre_attack"]["documents"] == 2
    assert results["sigma"]["documents"] == 1
    assert results["yara"]["documents"] == 1
    assert results["threat_intelligence"]["documents"] == 1
    assert results["nist_cis"]["documents"] == 1
    assert results["playbooks"]["documents"] == 1

    status = kb.status()
    assert status["sources"]["sigma"]["files"] == 1
    assert status["sources"]["sigma"]["documents"] == 1
    assert status["sources"]["yara"]["ready"] is True
    assert status["totals"]["documents"] == 7

    sigma = kb.search("PowerShell DownloadString", sources=["sigma"], limit=5)
    assert sigma["count"] == 1
    assert sigma["results"][0]["metadata"]["level"] == "high"
    threat = kb.search("CVE-2025-0001", sources="threat_intelligence")
    assert threat["results"][0]["document_type"] == "known_exploited_vulnerability"
    playbook = kb.search("isolate endpoints", sources="playbooks")
    assert "Ransomware" in playbook["results"][0]["title"]


def test_enterprise_asset_import_merge_replace_and_query(tmp_path):
    kb = _kb(tmp_path)
    csv_payload = """asset_id,name,type,hostname,ip,criticality,environment,owner,tags
srv-001,Finance Database,database,fin-db-01,10.0.0.10,Critical,Production,Finance,"pci;customer-data"
vpn-001,VPN Gateway,network,vpn-01,10.0.0.1,High,Production,IT,internet-facing
"""
    result = kb.import_assets(csv_payload, filename="assets.csv")
    assert result["imported"] == 2
    assert result["assets"] == 2
    assert kb.status()["sources"]["enterprise_assets"]["assets"] == 2

    match = kb.query_assets("Finance")
    assert match["count"] == 1
    assert match["assets"][0]["asset_id"] == "srv-001"
    assert match["assets"][0]["tags"] == ["pci", "customer-data"]
    search = kb.search("Finance Database", sources=["enterprise_assets"])
    assert search["results"][0]["metadata"]["criticality"] == "Critical"

    update = kb.import_assets(
        [{"asset_id": "srv-001", "name": "Finance DB", "criticality": "High"}],
        filename="assets.json",
        mode="merge",
    )
    assert update["assets"] == 2
    assert kb.query_assets("Finance DB")["assets"][0]["criticality"] == "High"

    replaced = kb.import_assets(
        {"assets": [{"id": "ws-01", "name": "SOC Workstation", "type": "endpoint"}]},
        filename="assets.json",
        mode="replace",
    )
    assert replaced["assets"] == 1
    assert kb.query_assets()["assets"][0]["asset_id"] == "ws-01"


def test_offline_file_sync_uses_manifest_and_indexes(tmp_path):
    kb = _kb(tmp_path)
    fixture = tmp_path / "feed.json"
    fixture.write_text(json.dumps({
        "indicators": [{
            "id": "indicator--fixture",
            "name": "Fixture C2",
            "type": "indicator",
            "pattern": "[domain-name:value = 'c2.example']",
        }],
    }), encoding="utf-8")
    kb.manifest["threat_intelligence"] = SourceSpec(
        key="threat_intelligence",
        label="Threat Intelligence",
        downloads=(DownloadTarget(
            url=fixture.resolve().as_uri(),
            filename="fixture-feed.json",
        ),),
    )
    result = kb.sync("threat_intelligence")
    assert result["ok"] is True
    assert result["results"]["threat_intelligence"]["index"]["documents"] == 1
    source_status = result["status"]["sources"]["threat_intelligence"]
    assert source_status["files"] == 1
    assert source_status["documents"] == 1
    assert source_status["last_sync_at"]


def test_offline_mitre_sync_replaces_configured_stix_file(tmp_path):
    kb = _kb(tmp_path)
    fixture = tmp_path / "new-enterprise-attack.json"
    fixture.write_text(json.dumps({
        "type": "bundle",
        "objects": [{
            "type": "attack-pattern",
            "id": "attack-pattern--new",
            "name": "Input Capture",
            "description": "Capture credentials from user input.",
            "external_references": [{"external_id": "T1056"}],
        }],
    }), encoding="utf-8")
    kb.manifest["mitre_attack"] = SourceSpec(
        key="mitre_attack",
        label="MITRE ATT&CK",
        downloads=(DownloadTarget(
            url=fixture.resolve().as_uri(),
            filename="enterprise-attack.json",
        ),),
    )
    result = kb.sync("mitre_attack")
    assert result["ok"] is True
    assert result["results"]["mitre_attack"]["index"]["documents"] == 1
    assert kb.search("Input Capture", sources="mitre")["results"][0][
        "metadata"
    ]["external_id"] == "T1056"


def test_yara_parser_handles_braces_inside_strings(tmp_path):
    kb = _kb(tmp_path)
    _write_source(kb, "yara", "braces.yara", r'''
rule Has_Braces {
    strings:
        $a = "{not a block}"
        $b = /a{2,4}/
    condition:
        any of them
}
rule Second_Rule {
    condition:
        true
}
''')
    result = kb.ingest_source("yara")
    assert result["documents"] == 2
    names = {item["title"] for item in kb.iter_documents(["yara"])}
    assert names == {"Has_Braces", "Second_Rule"}


def test_yara_repository_tree_metadata_is_searchable(tmp_path):
    kb = _kb(tmp_path)
    _write_source(
        kb,
        "yara",
        "yara-rules-tree.json",
        json.dumps(
            {
                "sha": "tree-sha",
                "truncated": False,
                "tree": [
                    {
                        "path": "malware/APT_CobaltStrike.yar",
                        "mode": "100644",
                        "type": "blob",
                        "sha": "blob-sha",
                        "size": 2048,
                        "url": "https://api.github.test/blob-sha",
                    },
                    {
                        "path": "README.md",
                        "mode": "100644",
                        "type": "blob",
                        "sha": "readme-sha",
                    },
                ],
            }
        ),
    )

    result = kb.ingest_source("yara")
    assert result["documents"] == 1
    match = kb.search("CobaltStrike", sources="yara")
    assert match["count"] == 1
    assert match["results"][0]["metadata"]["blob_sha"] == "blob-sha"
    assert (
        match["results"][0]["metadata"]["content_mode"]
        == "safe_repository_metadata"
    )
