from app import app
from unittest.mock import patch
from io import BytesIO
from pathlib import Path
from llm_service import LLMConfig, _provider_call, analyze_with_llm, phase2_to_attack_result, understand_phase2
from document_parser import parse_document
from structured_attack import build_structured_incident, validate_structured_incident
from mitre_rag import get_rag
from graph_generation import build_graph_model, render_png, render_svg, to_dot, to_mermaid, to_networkx_json
import config_store


def test_health():
    client = app.test_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_homepage_bootstraps_before_optional_api_status_calls():
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b'id="app"' in response.data
    assert b"/static/app.js" in response.data

    assets = (
        "styles.css", "settings.css", "phase1.css", "phase2.css",
        "phase3.css", "phase4.css", "phase5.css", "confidence.css", "app.js",
    )
    for filename in assets:
        asset = client.get(f"/static/{filename}")
        assert asset.status_code == 200, filename
        assert asset.data, filename

    script = (Path(__file__).parents[1] / "static" / "app.js").read_text(encoding="utf-8")
    bootstrap = "render();\nvoid loadConfig();\nvoid loadVectorBackends();"
    assert bootstrap in script
    assert "Promise.all([loadConfig(),loadVectorBackends()]).finally(render)" not in script


def test_parser_capabilities_endpoint_reports_real_engines():
    response = app.test_client().get("/api/parsers/status")
    assert response.status_code == 200
    assert response.json["ready"] is True
    assert response.json["engines"]["pymupdf"] is True
    assert response.json["engines"]["pdfplumber"] is True
    assert response.json["engines"]["python_docx"] is True
    assert response.json["engines"]["textract"] is True
    assert response.json["engines"]["python_evtx"] is True
    assert ".msg" in response.json["extensions"]


def test_analysis_maps_attack():
    client = app.test_client()
    with patch("app.get_config", return_value=LLMConfig(enabled=False)):
        response = client.post("/api/analyze", json={
            "description": "Email phishing chạy PowerShell, kết nối C2 và gửi dữ liệu ra ngoài."
        })
    assert response.status_code == 200
    assert response.json["severity"] == "critical"
    assert len(response.json["steps"]) >= 3


def test_analysis_validates_input():
    response = app.test_client().post("/api/analyze", json={"description": "ngắn"})
    assert response.status_code == 400


def test_local_fallback_does_not_invent_an_attack_chain_without_evidence():
    from analysis_engine import analyze_incident

    result = analyze_incident(
        "Người dùng báo cáo một hiện tượng chưa xác định và chưa có telemetry."
    )
    assert len(result["steps"]) == 1
    assert result["steps"][0]["techniqueId"] == "Unknown"
    assert result["phase2"][0]["mitre_tactic"] == "Unknown"


def test_config_is_masked_and_can_be_updated():
    client = app.test_client()
    response = client.put("/api/config", json={
        "enabled": True, "provider": "compatible", "api_key": "secret-test-key",
        "base_url": "http://localhost:8000/v1", "model": "test-model",
        "temperature": 0.2, "timeout": 20, "rag_enabled": True
    })
    assert response.status_code == 200
    assert "api_key" not in response.json
    assert response.json["has_api_key"] is True


def test_persisted_config_includes_custom_system_prompt(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text('LLM_ENABLED="false"\n', encoding="utf-8")
    config = LLMConfig(
        enabled=True,
        provider="dashscope",
        api_key="test-key",
        model="glm-5.2",
        system_prompt="Custom phase 2 prompt",
    )
    with patch.object(config_store, "ENV_PATH", env_path):
        config_store._write_env(config)
    content = env_path.read_text(encoding="utf-8")
    assert 'LLM_SYSTEM_PROMPT="Custom phase 2 prompt"' in content


def test_connection_preview_does_not_mutate_live_config():
    before = config_store.get_config()
    with patch(
        "app.test_connection",
        return_value={"ok": True, "provider": "compatible", "model": "preview"},
    ):
        response = app.test_client().post(
            "/api/config/test",
            json={
                "enabled": True,
                "provider": "compatible",
                "base_url": "http://127.0.0.1:9999/v1",
                "model": "preview",
                "api_key": "temporary-key",
            },
        )
    assert response.status_code == 200
    assert response.json["ok"] is True
    assert config_store.get_config() is before


def test_switching_provider_does_not_reuse_another_provider_api_key():
    current = LLMConfig(
        enabled=True,
        provider="dashscope",
        api_key="dashscope-secret",
        model="glm-5.2",
    )
    with patch.object(config_store, "_runtime", current):
        same_provider = config_store.preview_config({"provider": "dashscope"})
        other_provider = config_store.preview_config({"provider": "anthropic"})

    assert same_provider.api_key == "dashscope-secret"
    assert other_provider.api_key == ""


def test_config_rejects_unknown_provider():
    response = app.test_client().put(
        "/api/config",
        json={"provider": "unknown-provider"},
    )
    assert response.status_code == 400
    assert "Provider không được hỗ trợ" in response.json["error"]


def test_llm_failure_falls_back_to_local_engine():
    client = app.test_client()
    client.put("/api/config", json={
        "enabled": True, "provider": "compatible",
        "base_url": "http://localhost:1/v1", "model": "offline", "timeout": 5
    })
    with patch("app.understand_phase2", side_effect=RuntimeError("offline")):
        response = client.post("/api/analyze", json={
            "description": "Email phishing chạy PowerShell và kết nối C2."
        })
    assert response.status_code == 200
    assert response.json["fallback"] is True
    assert response.json["engine"] == "local-engine"


def test_text_document_extraction():
    response = app.test_client().post("/api/extract", data={
        "file": (BytesIO("Email phishing và PowerShell".encode()), "incident.txt")
    }, content_type="multipart/form-data")
    assert response.status_code == 200
    assert "PowerShell" in response.json["text"]


def test_structured_llm_output_is_validated():
    fake = """```json
    {"incidentName":"Test","severity":"high","confidence":91,"entities":["Email"],
    "steps":[{"action":"Phishing","tactic":"Initial Access","techniqueId":"T1566.001",
    "description":"Email độc hại","source":"Actor","target":"User","detection":"Gateway","icon":"✉"}],
    "executiveSummary":"Sự cố thử nghiệm","recommendations":["Cô lập máy"]}
    ```"""
    with patch("llm_service._provider_call", return_value=fake):
        result = analyze_with_llm("Một mô tả sự cố đủ dài.", LLMConfig(enabled=True))
    assert result["engine"] == "llm"
    assert result["techniques"][0]["id"] == "T1566.001"


def test_email_parser_extracts_headers_body_and_attachments():
    raw = (b"From: attacker@example.com\r\nTo: accounting@example.com\r\n"
           b"Subject: Urgent invoice\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
           b"Open the attached invoice and enable macro.")
    result = parse_document("phishing.eml", raw)
    assert result.source_type == "Email"
    assert result.parser == "email.parser"
    assert "Urgent invoice" in result.text


def test_outlook_msg_parser_uses_textract():
    with patch(
        "document_parser._textract_fallback",
        return_value="From: attacker@example.test\nSubject: Invoice\nMalicious link",
    ):
        result = parse_document("phishing.msg", b"outlook-msg-placeholder")
    assert result.source_type == "Email"
    assert result.parser == "textract"
    assert "Malicious link" in result.text


def test_security_log_type_detection():
    result = parse_document("firewall.log", b"CEF:0|Vendor|Firewall|1|deny|blocked|src=10.0.0.5 dst=8.8.8.8")
    assert result.source_type == "Firewall"
    assert "src=10.0.0.5" in result.text


def test_docx_parser():
    from docx import Document
    buffer = BytesIO()
    document = Document()
    document.add_paragraph("PowerShell tai malware va ket noi C2")
    document.save(buffer)
    result = parse_document("incident.docx", buffer.getvalue())
    assert result.parser == "python-docx"
    assert "PowerShell" in result.text


def test_pdf_parser_uses_pymupdf():
    import fitz
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Phishing email executed PowerShell")
    result = parse_document("report.pdf", document.tobytes())
    assert result.parser == "PyMuPDF"
    assert "PowerShell" in result.text


def test_phase2_glm_schema_and_adapter():
    fake = """{"steps":[
      {"step":1,"actor":"Attacker","action":"Send phishing email",
       "target":"Employee","asset":"Corporate email","severity":"High",
       "mitre_tactic":"Initial Access"},
      {"step":2,"actor":"Employee","action":"Open malicious file",
       "target":"Workstation","asset":"Endpoint","severity":"Medium",
       "mitre_tactic":"Execution"}
    ]}"""
    config = LLMConfig(enabled=True, provider="zhipu", model="glm-5.2")
    with patch("llm_service._provider_call", return_value=fake):
        steps = understand_phase2("Email giả mạo được gửi đến nhân viên.", config)
    result = phase2_to_attack_result(steps)
    assert len(steps) == 2
    assert steps[0]["actor"] == "Attacker"
    assert result["engine"] == "glm-5.2"
    assert result["phase2"][1]["mitre_tactic"] == "Execution"
    assert result["confidence"] == 96
    assert (
        result["confidence_breakdown"]["methodology"]
        == "weighted_pipeline_quality_v1"
    )


def test_dashscope_glm_uses_openai_compatible_endpoint():
    config = LLMConfig(
        enabled=True, provider="dashscope", api_key="test-dashscope-key",
        base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        model="glm-5.2",
    )
    response = {"choices": [{"message": {"content": '{"steps":[]}'}}]}
    with patch("llm_service._request", return_value=response) as mocked:
        content = _provider_call(config, [{"role": "user", "content": "test"}])
    url, headers, payload, _ = mocked.call_args.args
    assert url == "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions"
    assert headers["Authorization"] == "Bearer test-dashscope-key"
    assert payload["model"] == "glm-5.2"
    assert content == '{"steps":[]}'


def test_phase3_is_canonical_backbone():
    phase2 = [{
        "step": 1, "actor": "Attacker", "action": "Send phishing email",
        "target": "Employee", "asset": "Corporate email", "severity": "High",
        "mitre_tactic": "Initial Access",
    }, {
        "step": 2, "actor": "Malware", "action": "Credential theft",
        "target": "Browser", "asset": "Credentials", "severity": "Critical",
        "mitre_tactic": "Credential Access",
    }]
    result = build_structured_incident(
        "Email giả mạo dẫn đến đánh cắp thông tin đăng nhập.",
        phase2, model="glm-5.2", provider="dashscope",
    )
    assert result["schema_version"] == "1.0"
    assert result["severity"] == "Critical"
    assert result["steps"][0]["order"] == 1
    assert result["steps"][1]["mitre"]["tactic"] == "Credential Access"
    assert result["metadata"]["pipeline"][-1] == "phase_3_structure"


def test_phase3_validator_rejects_broken_order():
    phase2 = [{
        "step": 1, "actor": "Attacker", "action": "Phishing",
        "target": "Employee", "asset": "Email", "severity": "High",
        "mitre_tactic": "Initial Access",
    }]
    result = build_structured_incident("Mô tả sự cố đủ dài.", phase2, model="test", provider="test")
    result["steps"][0]["order"] = 2
    try:
        validate_structured_incident(result)
        assert False, "validator must reject broken order"
    except ValueError as exc:
        assert "order" in str(exc)


def test_schema_endpoints():
    client = app.test_client()
    schema = client.get("/api/schema/incident")
    assert schema.status_code == 200
    assert "incident_name" in schema.json["required"]


def test_phase4_retrieves_input_capture_for_credential_theft():
    results = get_rag().retrieve("Credential Theft steal credentials input capture", top_k=5)
    ids = [item["technique_id"] for item in results]
    assert "T1056" in ids
    match = next(item for item in results if item["technique_id"] == "T1056")
    assert match["technique_name"] == "Input Capture"
    assert match["description"]


def test_rag_status_endpoint():
    response = app.test_client().get("/api/rag/status")
    assert response.status_code == 200
    assert response.json["ready"] is True
    assert response.json["chunks"] > 5000


def _graph_incident():
    phase2 = [
        {"step": 1, "actor": "Attacker", "action": "Phishing", "target": "Employee",
         "asset": "Email", "severity": "High", "mitre_tactic": "Initial Access"},
        {"step": 2, "actor": "Malware", "action": "Credential Theft", "target": "Browser",
         "asset": "Credentials", "severity": "Critical", "mitre_tactic": "Credential Access"},
        {"step": 3, "actor": "Attacker", "action": "VPN Login", "target": "VPN",
         "asset": "Gateway", "severity": "High", "mitre_tactic": "Initial Access"},
    ]
    return build_structured_incident("Graph generation incident.", phase2, model="test", provider="test")


def test_phase5_graph_sources_and_object():
    graph = build_graph_model(_graph_incident())
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2
    dot = to_dot(graph)
    assert "digraph CyberVisionAttack" in dot
    assert "\\n" in dot
    assert "\\\\n" not in dot
    assert "flowchart LR" in to_mermaid(graph)
    network = to_networkx_json(graph)
    assert network["directed"] is True
    assert network["links"][0]["weight"] > 0


def test_phase5_svg_and_png_artifacts():
    graph = build_graph_model(_graph_incident())
    assert render_svg(graph).lstrip().startswith(b"<svg")
    assert render_png(graph, "networkx").startswith(b"\x89PNG")


def test_graph_api_downloads():
    client = app.test_client()
    incident = _graph_incident()
    generated = client.post("/api/graph/generate", json={"structured_json": incident})
    assert generated.status_code == 200
    assert len(generated.json["graph"]["nodes"]) == 3
    svg = client.post("/api/graph/render", json={
        "structured_json": incident, "engine": "mermaid", "format": "svg"
    })
    assert svg.status_code == 200
    assert svg.content_type.startswith("image/svg+xml")


def test_confidence_is_derived_from_structure_quality():
    strong = [{
        "step": 1, "actor": "Attacker", "action": "Send phishing email",
        "target": "Employee", "asset": "Corporate email", "severity": "High",
        "mitre_tactic": "Initial Access",
    }]
    weak = [{
        "step": 1, "actor": "Unknown", "action": "Suspicious activity",
        "target": "Unknown", "asset": "Unknown", "severity": "Unknown",
        "mitre_tactic": "Unknown",
    }]
    strong_result = build_structured_incident("Strong evidence.", strong, model="glm-5.2", provider="dashscope")
    weak_result = build_structured_incident("Weak evidence.", weak, model="glm-5.2", provider="dashscope")
    fallback_result = build_structured_incident(
        "Strong local evidence.", strong, model="local-engine", provider="local", fallback=True
    )
    assert strong_result["confidence"] > weak_result["confidence"]
    assert strong_result["confidence"] > fallback_result["confidence"]
    assert strong_result["confidence"] != 90
    assert strong_result["confidence_breakdown"]["structure_completeness"] == 1.0


def test_rag_recalculates_confidence_with_breakdown():
    incident = _graph_incident()
    before = incident["confidence"]
    enriched = get_rag().enrich(incident)
    breakdown = enriched["confidence_breakdown"]
    assert breakdown["stage"] == "phase_4_mitre_rag"
    assert breakdown["pre_rag_confidence"] == before
    assert 0 <= breakdown["rag_mean_score"] <= 1
    assert 0 <= enriched["confidence"] <= 100
    assert breakdown["final_confidence"] == enriched["confidence"]


def test_vector_backend_status_endpoint():
    payload = {
        "selected": "chroma",
        "embedding_provider": "sentence-transformers",
        "embedding_model": "BAAI/bge-m3",
        "backends": {
            name: {"available": True, "ready": True, "chunks": 5375}
            for name in ("chroma", "qdrant", "faiss")
        },
    }
    with patch("app.backend_statuses", return_value=payload):
        response = app.test_client().get("/api/rag/backends")
    assert response.status_code == 200
    assert response.json["embedding_model"] == "BAAI/bge-m3"
    assert response.json["backends"]["faiss"]["ready"] is True


def test_vector_backend_migration_endpoint():
    payload = {
        "ok": True,
        "source": {"backend": "chroma", "documents": 5375, "dimension": 1024},
        "targets": {
            "qdrant": {"ok": True},
            "faiss": {"ok": True},
        },
    }
    with patch("app.migrate_from_chroma", return_value=payload) as mocked:
        response = app.test_client().post(
            "/api/rag/migrate",
            json={"targets": ["qdrant", "faiss"], "batch_size": 256},
        )
    assert response.status_code == 200
    assert response.json["targets"]["qdrant"]["ok"] is True
    mocked.assert_called_once_with(["qdrant", "faiss"], batch_size=256)


def test_vector_backend_migration_validates_targets():
    response = app.test_client().post(
        "/api/rag/migrate",
        json={"targets": {"backend": "faiss"}},
    )
    assert response.status_code == 400
