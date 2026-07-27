import importlib.util
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from pipeline_orchestrator import IncidentPipeline, OrchestratorConfig


PHASES = [
    "phase_2_understand",
    "phase_3_structure",
    "phase_4_mitre_rag",
    "phase_5_graph_model",
]


class OfflineRAG:
    def __init__(self):
        self.config = SimpleNamespace(enabled=True)
        self.calls = 0

    def enrich(self, structured):
        self.calls += 1
        result = deepcopy(structured)
        result["steps"][0]["rag"] = {
            "query": "Phishing T1566",
            "matches": [{
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "score": 0.97,
            }],
        }
        result["metadata"]["offline_rag"] = True
        return result


def _phase2_fixture(description, config):
    assert "email" in description.lower()
    assert config.model == "glm-5.2-fixture"
    return [
        {
            "step": 1,
            "actor": "Attacker",
            "action": "Send phishing email",
            "target": "Employee",
            "asset": "Corporate email",
            "severity": "High",
            "mitre_tactic": "Initial Access",
            "technique_id": "T1566",
        },
        {
            "step": 2,
            "actor": "Employee",
            "action": "Open malicious attachment",
            "target": "Workstation",
            "asset": "Endpoint",
            "severity": "High",
            "mitre_tactic": "Execution",
            "technique_id": "T1204.002",
        },
    ]


def _offline_knowledge(structured):
    result = deepcopy(structured)
    result["steps"][0]["knowledge"] = {
        "query": "phishing email",
        "matches": [{
            "source": "sigma",
            "title": "Fixture phishing attachment rule",
            "origin": "offline-fixture.yml",
            "score": 1.0,
        }],
    }
    result["metadata"]["knowledge"] = {
        "ready": True,
        "sources": ["sigma"],
        "matches": 1,
    }
    return result


def _package_for_engine(engine):
    return {
        "langchain": "langchain_core",
        "llamaindex": "llama_index.core",
    }.get(engine)


def _package_available(package):
    try:
        return importlib.util.find_spec(package) is not None
    except ModuleNotFoundError:
        return False


@pytest.mark.parametrize("engine", ["native", "langchain", "llamaindex"])
def test_all_orchestrators_run_offline_with_trace_and_evidence(engine):
    package = _package_for_engine(engine)
    if package and not _package_available(package):
        pytest.skip(f"{engine} dependency is not installed")

    rag = OfflineRAG()
    local_engine = Mock(side_effect=AssertionError("local fallback must not run"))
    config = SimpleNamespace(
        enabled=True,
        model="glm-5.2-fixture",
        provider="offline-dashscope-fixture",
        rag_enabled=True,
    )
    pipeline = IncidentPipeline(
        OrchestratorConfig(engine=engine),
        phase2_fn=_phase2_fixture,
        local_fn=local_engine,
        rag_factory=lambda: rag,
    )

    # Replacing only the knowledge lookup ensures no default on-disk KB,
    # network client, or embedding model can be reached by this test.
    with patch(
        "pipeline_orchestrator.enrich_with_knowledge",
        side_effect=_offline_knowledge,
    ) as knowledge:
        result = pipeline.run(
            "Email giả mạo được gửi đến nhân viên và chứa tệp độc hại.",
            config,
        )

    assert result["fallback"] is False
    assert result["engine"] == "glm-5.2-fixture"
    assert rag.calls == 1
    assert knowledge.call_count == 1
    local_engine.assert_not_called()

    structured = result["structured_json"]
    assert structured["metadata"]["offline_rag"] is True
    assert structured["metadata"]["knowledge"]["sources"] == ["sigma"]
    assert structured["steps"][0]["rag"]["matches"][0]["technique_id"] == "T1566"
    assert structured["steps"][0]["knowledge"]["matches"][0]["source"] == "sigma"
    assert structured["metadata"]["graph"] == {
        "nodes": 2,
        "edges": 1,
        "model": "canonical-directed-attack-graph",
    }

    trace = structured["metadata"]["orchestration"]
    assert trace["engine"] == engine
    assert trace["library_version"] != "unavailable"
    assert [stage["stage"] for stage in trace["stages"]] == PHASES
    assert all(stage["duration_ms"] >= 0 for stage in trace["stages"])
    assert trace["duration_ms"] >= 0
    assert result["orchestration"] == trace


def test_phase2_projection_is_not_rewritten_by_phase4_mapping():
    class MappingRAG(OfflineRAG):
        def enrich(self, structured):
            result = super().enrich(structured)
            result["steps"][0]["mitre"]["tactic"] = "Credential Access"
            result["steps"][0]["mitre"]["technique_id"] = "T1056"
            return result

    config = SimpleNamespace(
        enabled=True,
        model="glm-5.2-fixture",
        provider="offline-dashscope-fixture",
        rag_enabled=True,
    )
    pipeline = IncidentPipeline(
        OrchestratorConfig(engine="native"),
        phase2_fn=_phase2_fixture,
        local_fn=Mock(side_effect=AssertionError("local fallback must not run")),
        rag_factory=MappingRAG,
    )

    with patch(
        "pipeline_orchestrator.enrich_with_knowledge",
        side_effect=lambda value: value,
    ):
        result = pipeline.run(
            "Email giả mạo được gửi đến nhân viên và chứa tệp độc hại.",
            config,
        )

    assert result["phase2"][0]["mitre_tactic"] == "Initial Access"
    assert (
        result["structured_json"]["steps"][0]["mitre"]["tactic"]
        == "Credential Access"
    )


def test_native_orchestrator_records_explicit_phase2_degradation_offline():
    rag_factory = Mock(side_effect=AssertionError("RAG must be disabled"))
    local_result = {
        "phase2": [{
            "step": 1,
            "actor": "Local analyst",
            "action": "Inspect suspicious email",
            "target": "Mailbox",
            "asset": "Email",
            "severity": "Medium",
            "mitre_tactic": "Initial Access",
        }],
    }
    local_engine = Mock(return_value=local_result)
    config = SimpleNamespace(
        enabled=False,
        model="unused",
        provider="offline",
        rag_enabled=False,
    )
    pipeline = IncidentPipeline(
        OrchestratorConfig(engine="native"),
        phase2_fn=Mock(side_effect=AssertionError("LLM must not run")),
        local_fn=local_engine,
        rag_factory=rag_factory,
    )

    with patch(
        "pipeline_orchestrator.enrich_with_knowledge",
        side_effect=lambda value: value,
    ):
        result = pipeline.run(
            "Email đáng ngờ được chuyển đến đội SOC để phân tích.",
            config,
        )

    assert result["fallback"] is True
    assert result["engine"] == "local-engine"
    assert result["structured_json"]["metadata"]["fallback"] is True
    assert result["structured_json"]["metadata"]["rag_disabled"] is True
    assert "rag_error" not in result["structured_json"]["metadata"]
    assert [item["stage"] for item in result["orchestration"]["stages"]] == PHASES
    local_engine.assert_called_once()
    rag_factory.assert_not_called()
