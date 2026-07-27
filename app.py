import subprocess

from flask import Flask, Response, jsonify, render_template, request, send_file
from document_parser import parse_document, parser_capabilities
from analysis_engine import SAMPLE, analyze_incident
from config_store import get_config, preview_config, update_config
from llm_service import test_connection, understand_phase2
from structured_attack import (
    INCIDENT_JSON_SCHEMA, build_structured_incident, to_ui_result,
    validate_structured_incident,
)
from mitre_rag import get_rag
from vector_management import backend_statuses, migrate_from_chroma
from graph_generation import (
    build_graph_model, render_png, render_svg, to_dot, to_mermaid,
    to_networkx_json, renderer_status,
)
from knowledge_base import (
    get_knowledge_base,
    import_assets as import_enterprise_assets,
    query_assets as query_enterprise_assets,
)
from pipeline_orchestrator import orchestration_status, run_pipeline
from report_generator import (
    ReportGenerationError,
    generate_report,
    report_capabilities,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


@app.get("/")
def index():
    return render_template("index.html", sample=SAMPLE)


@app.get("/api/health")
def health():
    return jsonify(
        status="ok",
        engine="cybervision-pipeline",
        version="2.0",
        orchestration=orchestration_status(),
        renderers=renderer_status(),
        reports=report_capabilities(),
        parsers=parser_capabilities(),
    )


@app.post("/api/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    description = str(payload.get("description", "")).strip()
    if len(description) < 10:
        return jsonify(error="Mô tả sự cố phải có ít nhất 10 ký tự."), 400
    config = get_config()
    try:
        return jsonify(
            run_pipeline(
                description,
                config,
                phase2_fn=understand_phase2,
                local_fn=analyze_incident,
                rag_factory=get_rag,
            )
        )
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        return jsonify(error=f"Pipeline phân tích thất bại: {exc}"), 500


def _apply_phase4(structured):
    try:
        rag = get_rag()
        if rag.config.enabled:
            return rag.enrich(structured)
    except Exception as exc:
        structured["metadata"]["rag_error"] = str(exc)
    return structured


@app.get("/api/rag/status")
def rag_status():
    try:
        rag = get_rag()
        return jsonify({**rag.status(), "enabled": rag.config.enabled,
                        "top_k": rag.config.top_k, "source": str(rag.converter.path)})
    except Exception as exc:
        return jsonify(ready=False, error=str(exc)), 503


@app.post("/api/rag/index")
def rag_index():
    try:
        return jsonify(get_rag().build_index())
    except Exception as exc:
        return jsonify(error=str(exc)), 500


@app.post("/api/rag/search")
def rag_search():
    payload = request.get_json(silent=True) or {}
    query = str(payload.get("query", "")).strip()
    if len(query) < 3:
        return jsonify(error="Query phải có ít nhất 3 ký tự."), 400
    try:
        return jsonify(query=query, results=get_rag().retrieve(query, payload.get("top_k")))
    except Exception as exc:
        return jsonify(error=str(exc)), 500


@app.get("/api/rag/backends")
def rag_backends():
    try:
        return jsonify(backend_statuses(active_rag=get_rag()))
    except Exception as exc:
        return jsonify(error=str(exc)), 503


@app.post("/api/rag/migrate")
def rag_migrate():
    payload = request.get_json(silent=True) or {}
    targets = payload.get("targets", ["qdrant", "faiss"])
    if isinstance(targets, str):
        targets = [targets]
    if not isinstance(targets, list):
        return jsonify(error="targets phải là mảng qdrant/faiss."), 400
    try:
        result = migrate_from_chroma(
            targets,
            batch_size=max(1, min(1024, int(payload.get("batch_size", 128)))),
        )
        return jsonify(result), 200 if result["ok"] else 207
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/graph/generate")
def graph_generate():
    try:
        structured = _structured_payload()
        graph = build_graph_model(structured)
        return jsonify(
            graph=graph, dot=to_dot(graph), mermaid=to_mermaid(graph),
            networkx=to_networkx_json(graph),
            renderers=renderer_status(),
        )
    except Exception as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/graph/render")
def graph_render():
    payload = request.get_json(silent=True) or {}
    output_format = str(payload.get("format", "svg")).lower()
    engine = str(payload.get("engine", "graphviz")).lower()
    if output_format not in ("svg", "png", "dot", "mmd", "json"):
        return jsonify(error="Format phải là svg, png, dot, mmd hoặc json."), 400
    if engine not in ("graphviz", "mermaid", "networkx"):
        return jsonify(error="Engine phải là graphviz, mermaid hoặc networkx."), 400
    try:
        graph = build_graph_model(_structured_payload(payload))
        if output_format == "svg":
            return _artifact(render_svg(graph, engine), "image/svg+xml", "attack-graph.svg")
        if output_format == "png":
            return _artifact(render_png(graph, engine), "image/png", "attack-graph.png")
        if output_format == "dot":
            return _artifact(to_dot(graph).encode(), "text/vnd.graphviz", "attack-graph.dot")
        if output_format == "mmd":
            return _artifact(to_mermaid(graph).encode(), "text/plain", "attack-graph.mmd")
        return jsonify(to_networkx_json(graph))
    except Exception as exc:
        return jsonify(error=str(exc)), 400


@app.get("/api/renderers/status")
def renderers_status():
    return jsonify(renderer_status())


@app.get("/api/orchestration/status")
def orchestrator_status():
    return jsonify(orchestration_status())


@app.get("/api/knowledge/status")
def knowledge_status():
    try:
        return jsonify(get_knowledge_base().status())
    except Exception as exc:
        return jsonify(ready=False, error=str(exc)), 503


@app.get("/api/knowledge/manifest")
def knowledge_manifest():
    try:
        return jsonify(get_knowledge_base().source_manifest())
    except Exception as exc:
        return jsonify(error=str(exc)), 503


@app.post("/api/knowledge/sync")
def knowledge_sync():
    payload = request.get_json(silent=True) or {}
    try:
        result = get_knowledge_base().sync(str(payload.get("source", "all")))
        return jsonify(result), 200 if result.get("ok") else 207
    except (OSError, TypeError, ValueError) as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/knowledge/index")
def knowledge_index():
    payload = request.get_json(silent=True) or {}
    source = str(payload.get("source", "all")).strip().lower()
    try:
        kb = get_knowledge_base()
        result = kb.ingest_all() if source == "all" else kb.ingest_source(source)
        return jsonify(result)
    except (OSError, TypeError, ValueError) as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/knowledge/search")
def knowledge_search():
    payload = request.get_json(silent=True) or {}
    query = str(payload.get("query", "")).strip()
    if len(query) < 2:
        return jsonify(error="Query phải có ít nhất 2 ký tự."), 400
    try:
        return jsonify(
            get_knowledge_base().search(
                query,
                sources=payload.get("sources"),
                limit=payload.get("limit", 10),
            )
        )
    except (OSError, TypeError, ValueError) as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/assets/import")
def assets_import():
    upload = request.files.get("file")
    payload = request.get_json(silent=True) if request.is_json else None
    try:
        if upload and upload.filename:
            result = import_enterprise_assets(
                upload.read(),
                filename=upload.filename,
                mode=str(request.form.get("mode", "merge")),
            )
        elif payload is not None:
            result = import_enterprise_assets(
                payload.get("assets", payload),
                filename=str(payload.get("filename", "enterprise-assets.json"))
                if isinstance(payload, dict)
                else "enterprise-assets.json",
                mode=str(payload.get("mode", "merge"))
                if isinstance(payload, dict)
                else "merge",
            )
        else:
            return jsonify(error="Cần tệp CSV/JSON hoặc JSON assets."), 400
        return jsonify(result)
    except (OSError, TypeError, ValueError) as exc:
        return jsonify(error=str(exc)), 400


@app.get("/api/assets")
def assets_query():
    filters = {
        key: value
        for key in ("asset_type", "owner", "criticality", "environment")
        if (value := request.args.get(key))
    }
    try:
        return jsonify(
            query_enterprise_assets(request.args.get("query", ""), **filters)
        )
    except (OSError, TypeError, ValueError) as exc:
        return jsonify(error=str(exc)), 400


@app.get("/api/report/capabilities")
def reports_status():
    return jsonify(report_capabilities())


@app.post("/api/report/<report_format>")
def report_export(report_format):
    normalized = report_format.strip().lower()
    if normalized not in {"pdf", "docx", "pptx"}:
        return jsonify(error="Format báo cáo phải là pdf, docx hoặc pptx."), 400
    try:
        structured = _structured_payload()
        graph = build_graph_model(structured)
        graph_png = _report_graph_png(graph)
        artifact = generate_report(
            normalized,
            structured,
            graph_image=graph_png,
        )
        mimetypes = {
            "pdf": "application/pdf",
            "docx": (
                "application/vnd.openxmlformats-officedocument."
                "wordprocessingml.document"
            ),
            "pptx": (
                "application/vnd.openxmlformats-officedocument."
                "presentationml.presentation"
            ),
        }
        return send_file(
            artifact,
            mimetype=mimetypes[normalized],
            as_attachment=True,
            download_name=f'{structured["incident_id"]}-report.{normalized}',
            conditional=True,
        )
    except (ReportGenerationError, OSError, TypeError, ValueError) as exc:
        status = 503 if isinstance(exc, ReportGenerationError) else 400
        return jsonify(error=str(exc), capabilities=report_capabilities()), status


def _report_graph_png(graph):
    """Render a report-friendly graph and keep export available on failure.

    NetworkX uses the available page area more effectively for long attack
    chains.  Graphviz remains the native fallback and is still the default
    interactive/UI graph engine.
    """
    for engine in ("networkx", "graphviz"):
        try:
            return render_png(graph, engine)
        except (ImportError, OSError, RuntimeError, subprocess.SubprocessError):
            continue
    return None


def _structured_payload(payload=None):
    payload = payload if payload is not None else (request.get_json(silent=True) or {})
    return payload.get("structured_json", payload)


def _artifact(content, mimetype, filename):
    return Response(content, mimetype=mimetype, headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
    })


@app.get("/api/schema/incident")
def incident_schema():
    return jsonify(INCIDENT_JSON_SCHEMA)


@app.post("/api/schema/incident/validate")
def incident_validate():
    try:
        document = validate_structured_incident(request.get_json(silent=True) or {})
        return jsonify(valid=True, incident_id=document["incident_id"], schema_version=document["schema_version"])
    except ValueError as exc:
        return jsonify(valid=False, errors=str(exc).split("; ")), 400


@app.get("/api/config")
def config_get():
    return jsonify(get_config().public_dict())


@app.put("/api/config")
def config_put():
    payload = request.get_json(silent=True) or {}
    try:
        config = update_config(payload, persist=bool(payload.get("persist", False)))
        return jsonify(config.public_dict())
    except (TypeError, ValueError) as exc:
        return jsonify(error=f"Cấu hình không hợp lệ: {exc}"), 400


@app.post("/api/config/test")
def config_test():
    payload = request.get_json(silent=True) or {}
    try:
        config = preview_config(payload)
        return jsonify(test_connection(config))
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)), 400


@app.post("/api/extract")
def extract_document():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify(error="Không tìm thấy tệp tải lên."), 400
    try:
        raw = upload.read()
        return jsonify(parse_document(upload.filename, raw).to_dict())
    except Exception as exc:
        return jsonify(error=f"Không thể đọc tài liệu: {exc}"), 400


@app.get("/api/parsers/status")
def parsers_status():
    return jsonify(parser_capabilities())


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Tệp vượt quá giới hạn 10MB."), 413


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
