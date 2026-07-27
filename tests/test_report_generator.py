import json
from io import BytesIO
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from app import _report_graph_png, app
from report_generator import (
    PPTX_SCRIPT,
    ReportGenerationError,
    generate_docx,
    generate_pdf,
    generate_pptx,
    generate_report,
    report_capabilities,
)
from structured_attack import build_structured_incident


def _incident():
    phase2 = [
        {
            "step": 1,
            "actor": "Attacker",
            "action": "Send phishing email",
            "target": "Employee",
            "asset": "Corporate email",
            "severity": "High",
            "mitre_tactic": "Initial Access",
        },
        {
            "step": 2,
            "actor": "Malware",
            "action": "Steal browser credentials",
            "target": "Browser",
            "asset": "Credentials",
            "severity": "Critical",
            "mitre_tactic": "Credential Access",
        },
    ]
    result = build_structured_incident(
        "A phishing email leads to browser credential theft.",
        phase2,
        model="glm-5.2",
        provider="dashscope",
    )
    result["steps"][0]["mitre"]["technique_id"] = "T1566.001"
    result["steps"][0]["detection"] = "Inspect email gateway telemetry."
    result["steps"][0]["mitigation"] = "Block malicious attachments."
    result["steps"][1]["mitre"]["technique_id"] = "T1555.003"
    result["steps"][1]["detection"] = "Monitor browser credential-store access."
    result["steps"][1]["mitigation"] = "Use phishing-resistant MFA."
    return result


def test_generate_server_side_pdf(tmp_path):
    destination = generate_pdf(_incident(), tmp_path / "incident.pdf")
    assert destination.read_bytes().startswith(b"%PDF")
    from pypdf import PdfReader

    reader = PdfReader(str(destination))
    assert len(reader.pages) >= 1
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    assert "CYBERSECURITY INCIDENT REPORT" in text
    assert "T1566.001" in text


def test_generate_docx_uses_explicit_business_brief_geometry(tmp_path):
    destination = generate_docx(_incident(), tmp_path / "incident.docx")
    assert zipfile.is_zipfile(destination)
    with zipfile.ZipFile(destination) as archive:
        document_xml = archive.read("word/document.xml").decode("utf-8")
        styles_xml = archive.read("word/styles.xml").decode("utf-8")
        section_xml = document_xml
    assert "CYBERSECURITY INCIDENT REPORT" in document_xml
    assert "T1566.001" in document_xml
    assert 'w:w="9360"' in document_xml
    assert 'w:w="120"' in document_xml
    assert '<w:pgSz w:w="12240" w:h="15840"' in section_xml
    assert '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"' in section_xml
    assert "CVI Title" in styles_xml
    assert "CVI Metadata" in styles_xml


def test_report_dispatcher_rejects_unknown_format(tmp_path):
    with pytest.raises(ValueError):
        generate_report("xlsx", _incident(), tmp_path / "incident.xlsx")


def test_pptx_script_is_artifact_tool_only():
    source = PPTX_SCRIPT.read_text(encoding="utf-8")
    assert '@oai/artifact-tool' in source
    assert "PresentationFile.exportPptx" in source
    assert "python-pptx" not in source
    assert "pptxgenjs" not in source
    assert "deck.export({ slide, format: \"png\"" in source


def test_pptx_generator_builds_artifact_tool_command(tmp_path):
    fake_node = tmp_path / "node.exe"
    fake_node.write_bytes(b"node")
    module_root = tmp_path / "node_modules"
    package_dir = module_root / "@oai" / "artifact-tool"
    package_dir.mkdir(parents=True)
    (package_dir / "package.json").write_text(
        json.dumps({"name": "@oai/artifact-tool"}), encoding="utf-8"
    )
    output = tmp_path / "incident.pptx"
    qa_dir = tmp_path / "qa"

    def fake_run(command, **kwargs):
        assert command[0] == str(fake_node.resolve())
        assert command[1] == str(PPTX_SCRIPT)
        assert command[3] == str(output.resolve())
        assert command[4] == str(module_root.resolve())
        Path(command[3]).write_bytes(b"P" * 1200)

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()

    with patch("report_generator.subprocess.run", side_effect=fake_run):
        result = generate_pptx(
            _incident(),
            output,
            node_binary=fake_node,
            artifact_tool_node_modules=module_root,
            qa_directory=qa_dir,
        )
    assert result == output.resolve()
    assert result.stat().st_size == 1200


def test_pptx_generator_reports_missing_runtime(tmp_path):
    with patch("report_generator._find_node_binary", return_value=None):
        with pytest.raises(ReportGenerationError, match="Node.js"):
            generate_pptx(_incident(), tmp_path / "incident.pptx")


def test_capabilities_never_claim_pptx_without_both_dependencies():
    with patch("report_generator._find_node_binary", return_value=Path("node.exe")):
        with patch("report_generator._find_artifact_tool_modules", return_value=None):
            assert report_capabilities()["pptx"]["ready"] is False


def test_report_capabilities_api_is_truthful():
    response = app.test_client().get("/api/report/capabilities")
    assert response.status_code == 200
    assert response.json["pdf"]["engine"] == "reportlab"
    assert response.json["docx"]["engine"] == "python-docx"
    assert response.json["pptx"]["engine"] == "@oai/artifact-tool"
    assert isinstance(response.json["pdf"]["ready"], bool)
    assert isinstance(response.json["docx"]["ready"], bool)
    assert isinstance(response.json["pptx"]["ready"], bool)


def test_report_pdf_api_returns_server_generated_pdf(tmp_path, monkeypatch):
    import report_generator

    monkeypatch.setattr(report_generator, "DEFAULT_REPORT_DIR", tmp_path)
    with patch("app.render_png", return_value=None):
        response = app.test_client().post(
            "/api/report/pdf",
            json={"structured_json": _incident()},
        )
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF")
    assert response.content_type.startswith("application/pdf")
    assert "attachment;" in response.headers["Content-Disposition"]
    assert response.headers["Content-Disposition"].endswith("-report.pdf")


def test_report_docx_api_returns_server_generated_docx(tmp_path, monkeypatch):
    import report_generator

    monkeypatch.setattr(report_generator, "DEFAULT_REPORT_DIR", tmp_path)
    with patch("app.render_png", return_value=None):
        response = app.test_client().post(
            "/api/report/docx",
            json={"structured_json": _incident()},
        )
    assert response.status_code == 200
    assert response.content_type.startswith(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert zipfile.is_zipfile(BytesIO(response.data))
    with zipfile.ZipFile(BytesIO(response.data)) as archive:
        document_xml = archive.read("word/document.xml").decode("utf-8")
    assert "CYBERSECURITY INCIDENT REPORT" in document_xml
    assert "T1566.001" in document_xml


def test_report_pptx_api_exports_or_returns_clear_runtime_503(
    tmp_path,
    monkeypatch,
):
    import report_generator

    monkeypatch.setattr(report_generator, "DEFAULT_REPORT_DIR", tmp_path)
    client = app.test_client()
    capabilities = client.get("/api/report/capabilities").json
    with patch("app.render_png", return_value=None):
        response = client.post(
            "/api/report/pptx",
            json={"structured_json": _incident()},
        )

    if capabilities["pptx"]["ready"]:
        assert response.status_code == 200
        assert response.content_type.startswith(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        )
        assert zipfile.is_zipfile(BytesIO(response.data))
    else:
        assert response.status_code == 503
        assert response.is_json
        assert "@oai/artifact-tool" in response.json["error"]
        assert response.json["capabilities"]["pptx"]["ready"] is False


def test_report_api_rejects_invalid_structured_json():
    with patch("app.render_png", return_value=None):
        response = app.test_client().post(
            "/api/report/pdf",
            json={"structured_json": {"incident_name": "broken"}},
        )
    assert response.status_code == 400
    assert response.is_json
    assert "error" in response.json


def test_report_graph_falls_back_to_graphviz_when_networkx_is_unavailable():
    with patch(
        "app.render_png",
        side_effect=[RuntimeError("matplotlib missing"), b"\x89PNG\r\n\x1a\nfallback"],
    ) as mocked:
        result = _report_graph_png({"nodes": [], "edges": []})
    assert result.startswith(b"\x89PNG")
    assert [call.args[1] for call in mocked.call_args_list] == [
        "networkx",
        "graphviz",
    ]
