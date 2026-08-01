from copy import deepcopy
from types import SimpleNamespace

from structured_attack import build_structured_incident
from llm_service import validate_phase2
from vietnamese_localization import (
    SEVERITY_VI,
    TACTIC_VI,
    localize_structured_incident,
)


class FixtureTranslator:
    """Offline translator supporting scalar and batch-style adapters."""

    def __init__(self, translations):
        self.translations = translations
        self.calls = []

    def __call__(self, value, *args, **kwargs):
        self.calls.append(deepcopy(value))
        if isinstance(value, dict):
            return {
                token: self.translations.get(str(text), str(text))
                for token, text in value.items()
            }
        if isinstance(value, list):
            return [self(item, *args, **kwargs) for item in value]
        return self.translations.get(str(value), str(value))

    def translate(self, value, *args, **kwargs):
        return self(value, *args, **kwargs)

    def translate_many(self, values, *args, **kwargs):
        return [self(value, *args, **kwargs) for value in values]


class FailingTranslator:
    def __call__(self, value, *args, **kwargs):
        raise RuntimeError("offline translation fixture")

    translate = __call__

    def translate_many(self, values, *args, **kwargs):
        raise RuntimeError("offline translation fixture")


def _incident():
    incident = build_structured_incident(
        "A PowerShell command downloaded ransomware to a production web server.",
        [
            {
                "step": 1,
                "actor": "Attacker",
                "action": "Execute PowerShell to download ransomware",
                "target": "Web server",
                "asset": "Production server",
                "severity": "Critical",
                "mitre_tactic": "Execution",
                "technique_id": "T1059.001",
                "evidence": "PowerShell downloaded ransomware.",
                "detection": "Monitor PowerShell telemetry.",
            }
        ],
        model="glm-5.2-fixture",
        provider="offline-fixture",
    )
    incident["incident_name"] = "PowerShell ransomware incident"
    incident["summary"] = "An attacker used PowerShell to deploy ransomware."
    step = incident["steps"][0]
    step["mitigation"] = "Restrict PowerShell and isolate the server."
    step["procedure"] = "The threat actor downloaded a ransomware payload."
    step["retrieval"] = {
        "query_en": "execute PowerShell ransomware attacker web server"
    }
    step["rag_confidence"] = 0.4321
    step["rag"] = {
        "query": "Execute PowerShell ransomware | Attacker | Web server | Execution",
        "matches": [
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactics": "Execution",
                "score": 0.4321,
                "retrieval_score": 0.6821,
                "rerank_score": 0.8321,
                "description": "Adversaries may abuse PowerShell commands.",
                "detection": ["Monitor PowerShell script-block logging."],
                "mitigation": ["Disable or restrict PowerShell where appropriate."],
                "procedure": ["An adversary downloaded a payload with PowerShell."],
            }
        ],
    }
    step["knowledge"] = {
        "query": "PowerShell ransomware T1059.001 Execution",
        "matches": [
            {
                "id": "sigma:powershell-fixture",
                "source": "sigma",
                "document_type": "detection_rule",
                "title": "Suspicious PowerShell Download",
                "snippet": "Detects PowerShell downloading an executable payload.",
                "origin": "rules/windows/powershell_download.yml",
                "score": 0.91,
                "metadata": {"level": "high"},
            }
        ],
    }
    return incident


TRANSLATIONS = {
    "PowerShell ransomware incident": "Sự cố ransomware qua PowerShell",
    "An attacker used PowerShell to deploy ransomware.": (
        "Kẻ tấn công sử dụng PowerShell để triển khai ransomware."
    ),
    "Attacker": "Kẻ tấn công",
    "Execute PowerShell to download ransomware": (
        "Thực thi PowerShell để tải ransomware"
    ),
    "Web server": "Máy chủ web",
    "Production server": "Máy chủ sản xuất",
    "PowerShell downloaded ransomware.": "PowerShell đã tải ransomware.",
    "Monitor PowerShell telemetry.": "Giám sát telemetry của PowerShell.",
    "Restrict PowerShell and isolate the server.": (
        "Hạn chế PowerShell và cô lập máy chủ."
    ),
    "The threat actor downloaded a ransomware payload.": (
        "Đối tượng đe dọa đã tải payload ransomware."
    ),
    "PowerShell": "PowerShell",
    "Adversaries may abuse PowerShell commands.": (
        "Đối tượng tấn công có thể lạm dụng lệnh PowerShell."
    ),
    "Monitor PowerShell script-block logging.": (
        "Giám sát nhật ký khối lệnh PowerShell."
    ),
    "Disable or restrict PowerShell where appropriate.": (
        "Vô hiệu hóa hoặc hạn chế PowerShell khi phù hợp."
    ),
    "An adversary downloaded a payload with PowerShell.": (
        "Đối tượng tấn công đã tải payload bằng PowerShell."
    ),
    "Suspicious PowerShell Download": "Hoạt động tải xuống PowerShell đáng ngờ",
    "Detects PowerShell downloading an executable payload.": (
        "Phát hiện PowerShell tải xuống payload thực thi."
    ),
}


def _offline_config():
    return SimpleNamespace(
        enabled=False,
        provider="offline-fixture",
        model="glm-5.2-fixture",
        api_key="",
    )


def test_standard_security_labels_have_vietnamese_display_values():
    assert TACTIC_VI["Execution"] == "Thực thi"
    assert TACTIC_VI["Initial Access"] == "Truy cập ban đầu"
    assert TACTIC_VI["Command and Control"] == "Chỉ huy và điều khiển"
    assert SEVERITY_VI["Critical"] == "Nghiêm trọng"
    assert SEVERITY_VI["High"] == "Cao"
    assert SEVERITY_VI["Unknown"] == "Chưa xác định"


def test_localization_adds_vietnamese_display_without_mutating_raw_evidence():
    source = _incident()
    source_before = deepcopy(source)
    translator = FixtureTranslator(TRANSLATIONS)

    localized = localize_structured_incident(
        source,
        _offline_config(),
        translator=translator,
    )

    # Localization is a presentation enrichment. The caller-owned canonical
    # document and its English semantic fields must remain untouched.
    assert source == source_before
    assert localized["incident_name"] == source_before["incident_name"]
    assert localized["summary"] == source_before["summary"]
    assert localized["severity"] == "Critical"
    assert localized["display_vi"] == {
        "incident_name": "Sự cố ransomware qua PowerShell",
        "summary": "Kẻ tấn công sử dụng PowerShell để triển khai ransomware.",
        "severity": "Nghiêm trọng",
        "entities": {
            "actors": ["Kẻ tấn công"],
            "targets": ["Máy chủ web"],
            "assets": ["Máy chủ sản xuất"],
        },
    }

    raw_step = source_before["steps"][0]
    step = localized["steps"][0]
    for field in (
        "order",
        "actor",
        "action",
        "target",
        "asset",
        "severity",
        "evidence",
        "detection",
        "mitigation",
        "procedure",
        "rag_confidence",
    ):
        assert step[field] == raw_step[field]
    assert step["mitre"] == raw_step["mitre"]
    assert step["retrieval"] == raw_step["retrieval"]
    assert step["display_vi"] == {
        "actor": "Kẻ tấn công",
        "action": "Thực thi PowerShell để tải ransomware",
        "target": "Máy chủ web",
        "asset": "Máy chủ sản xuất",
        "severity": "Nghiêm trọng",
        "tactic": "Thực thi",
        "technique_name": "Thực thi PowerShell",
        "description": "PowerShell đã tải ransomware.",
        "detection": "Giám sát telemetry của PowerShell.",
        "mitigation": "Hạn chế PowerShell và cô lập máy chủ.",
        "procedure": "Đối tượng đe dọa đã tải payload ransomware.",
    }

    # Raw query, official ATT&CK identity and ranking values are export and
    # retrieval evidence; translating them would corrupt provenance.
    assert step["rag"]["query"] == raw_step["rag"]["query"]
    raw_match = raw_step["rag"]["matches"][0]
    match = step["rag"]["matches"][0]
    for field in (
        "technique_id",
        "technique_name",
        "tactics",
        "score",
        "retrieval_score",
        "rerank_score",
        "description",
        "detection",
        "mitigation",
        "procedure",
    ):
        assert match[field] == raw_match[field]
    assert match["display_vi"]["technique_name"] == "Thực thi PowerShell"
    assert match["display_vi"]["tactics"] == "Thực thi"
    assert match["display_vi"]["description"] == (
        "Đối tượng tấn công có thể lạm dụng lệnh PowerShell."
    )
    assert match["display_vi"]["detection"] == (
        "Giám sát nhật ký khối lệnh PowerShell."
    )
    assert match["display_vi"]["mitigation"] == (
        "Vô hiệu hóa hoặc hạn chế PowerShell khi phù hợp."
    )
    assert match["display_vi"]["procedure"] == (
        "Đối tượng tấn công đã tải payload bằng PowerShell."
    )

    raw_knowledge = raw_step["knowledge"]["matches"][0]
    knowledge = step["knowledge"]["matches"][0]
    assert knowledge["id"] == raw_knowledge["id"]
    assert knowledge["source"] == raw_knowledge["source"]
    assert knowledge["score"] == raw_knowledge["score"]
    assert knowledge["title"] == raw_knowledge["title"]
    assert knowledge["snippet"] == raw_knowledge["snippet"]
    assert knowledge["display_vi"] == {
        "title": "Hoạt động tải xuống PowerShell đáng ngờ",
        "snippet": "Phát hiện PowerShell tải xuống payload thực thi.",
    }
    assert translator.calls


def test_translation_failure_keeps_pipeline_usable_and_records_fallback():
    source = _incident()

    localized = localize_structured_incident(
        source,
        _offline_config(),
        translator=FailingTranslator(),
    )

    assert localized["incident_name"] == source["incident_name"]
    assert localized["steps"][0]["order"] == 1
    assert localized["steps"][0]["mitre"]["technique_id"] == "T1059.001"
    assert localized["steps"][0]["rag_confidence"] == 0.4321
    assert localized["steps"][0]["rag"]["matches"][0]["score"] == 0.4321
    assert localized["steps"][0]["knowledge"]["matches"][0]["score"] == 0.91
    assert localized["steps"][0]["retrieval"] == source["steps"][0]["retrieval"]

    display = localized["steps"][0]["display_vi"]
    assert display["actor"] == "Kẻ tấn công"
    assert display["action"] == "Thực thi PowerShell"
    assert display["description"] != source["steps"][0]["evidence"]
    assert display["detection"] != source["steps"][0]["detection"]
    assert localized["display_vi"]["incident_name"] != source["incident_name"]

    metadata = localized["metadata"]["localization"]
    assert metadata["status"] == "fallback"
    assert metadata["language"] == "vi"
    assert metadata["raw_preserved"] is True
    assert metadata.get("error")


def test_phase2_replaces_vietnamese_retrieval_query_with_english_query():
    for supplied in (
        "chạy PowerShell để tải ransomware",
        "chay PowerShell tai ransomware",
    ):
        step = validate_phase2({
            "steps": [{
                "actor": "Kẻ tấn công",
                "action": "Chạy PowerShell để tải ransomware",
                "target": "Máy chủ web",
                "asset": "Máy chủ sản xuất",
                "severity": "High",
                "mitre_tactic": "Execution",
                "technique_id": "T1059.001",
                # A model/custom prompt can violate the requested output
                # language; validation must not let it become the query.
                "retrieval_query_en": supplied,
            }]
        })[0]

        query = step["retrieval_query_en"]
        assert "T1059.001" in query
        assert "Execution" in query
        assert "execute PowerShell" in query
        assert "chạy" not in query.lower()
        assert "để" not in query.lower()
        assert "tải" not in query.lower()
        assert "chay" not in query.lower()
        assert " tai " not in f" {query.lower()} "


def test_malformed_translator_payload_uses_fallback_instead_of_crashing():
    source = _incident()

    localized = localize_structured_incident(
        source,
        _offline_config(),
        translator=lambda texts: "not-a-translation-object",
    )

    assert localized["steps"][0]["mitre"]["technique_id"] == "T1059.001"
    assert localized["steps"][0]["rag"]["matches"][0]["score"] == 0.4321
    assert localized["metadata"]["localization"]["status"] == "fallback"
    assert "không trả về object" in localized["metadata"]["localization"]["error"]


def test_phase2_canonicalizes_mitre_identity_without_translating_valid_ids():
    steps = validate_phase2({
        "steps": [
            {
                "action": "Chạy PowerShell",
                "severity": "High",
                "mitre_tactic": "Thực thi",
                "technique_id": "T1059.001",
            },
            {
                "action": "Hành vi chưa xác định",
                "severity": "Medium",
                "mitre_tactic": "Chiến thuật tự suy đoán",
                "technique_id": "Kỹ thuật T9999",
            },
        ]
    })

    assert steps[0]["mitre_tactic"] == "Execution"
    assert steps[0]["technique_id"] == "T1059.001"
    assert steps[1]["mitre_tactic"] == "Unknown"
    assert steps[1]["technique_id"] == "Unknown"
