"""PHASE 3 — canonical structured attack JSON.

This contract is the backbone shared by diagram generation, ATT&CK mapping,
reporting, exports and future persistence.
"""
from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import datetime, timezone


SCHEMA_VERSION = "1.0"
SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")

INCIDENT_JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://cybervision.local/schemas/incident-v1.json",
    "title": "CyberVision Structured Incident",
    "type": "object",
    "required": ["schema_version", "incident_id", "incident_name", "severity", "steps", "entities", "metadata"],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "incident_id": {"type": "string"},
        "incident_name": {"type": "string", "minLength": 1},
        "severity": {"enum": list(SEVERITIES)},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "summary": {"type": "string"},
        "display_vi": {"type": "object"},
        "entities": {
            "type": "object",
            "required": ["actors", "targets", "assets"],
            "properties": {
                "actors": {"type": "array", "items": {"type": "string"}},
                "targets": {"type": "array", "items": {"type": "string"}},
                "assets": {"type": "array", "items": {"type": "string"}},
                "indicators": {"type": "array", "items": {"type": "string"}},
            },
        },
        "steps": {
            "type": "array", "minItems": 1,
            "items": {
                "type": "object",
                "required": ["order", "actor", "action", "target", "asset", "severity", "mitre"],
                "properties": {
                    "order": {"type": "integer", "minimum": 1},
                    "actor": {"type": "string"}, "action": {"type": "string", "minLength": 1},
                    "target": {"type": "string"}, "asset": {"type": "string"},
                    "severity": {"enum": list(SEVERITIES)},
                    "mitre": {
                        "type": "object", "required": ["tactic", "technique_id"],
                        "properties": {"tactic": {"type": "string"}, "technique_id": {"type": "string"}},
                    },
                    "evidence": {"type": "string"}, "detection": {"type": "string"},
                    "retrieval": {
                        "type": "object",
                        "properties": {"query_en": {"type": "string"}},
                    },
                    "display_vi": {"type": "object"},
                },
            },
        },
        "metadata": {"type": "object"},
    },
}


def build_structured_incident(description, phase2_steps, *, model, provider, fallback=False):
    if not phase2_steps:
        raise ValueError("PHASE 3 yêu cầu ít nhất một bước từ PHASE 2.")
    normalized_steps = []
    for index, raw in enumerate(phase2_steps, 1):
        severity = _severity(raw.get("severity"))
        normalized_steps.append({
            "order": index,
            "actor": _text(raw.get("actor")),
            "action": _text(raw.get("action"), "Unknown Action"),
            "target": _text(raw.get("target")),
            "asset": _text(raw.get("asset")),
            "severity": severity,
            "mitre": {
                "tactic": _text(raw.get("mitre_tactic") or raw.get("tactic")),
                "technique_id": _text(raw.get("technique_id") or raw.get("techniqueId")),
            },
            "retrieval": {
                "query_en": _text(
                    raw.get("retrieval_query_en") or raw.get("retrieval_query")
                ),
            },
            "evidence": _text(raw.get("evidence")),
            "detection": _text(raw.get("detection")),
        })
    confidence, confidence_breakdown = _structure_confidence(normalized_steps, fallback)
    incident = {
        "schema_version": SCHEMA_VERSION,
        "incident_id": "CVI-" + hashlib.sha256(description.encode("utf-8")).hexdigest()[:12].upper(),
        "incident_name": _incident_name(normalized_steps),
        "severity": _highest_severity(step["severity"] for step in normalized_steps),
        "confidence": confidence,
        "confidence_breakdown": confidence_breakdown,
        "summary": _summary(normalized_steps),
        "source": {"language": "vi", "input_type": "normalized_text", "characters": len(description)},
        "entities": {
            "actors": _unique(step["actor"] for step in normalized_steps),
            "targets": _unique(step["target"] for step in normalized_steps),
            "assets": _unique(step["asset"] for step in normalized_steps),
            "indicators": [],
        },
        "steps": normalized_steps,
        "attack_summary": {
            "total_steps": len(normalized_steps),
            "first_action": normalized_steps[0]["action"],
            "last_action": normalized_steps[-1]["action"],
            "tactics": _unique(step["mitre"]["tactic"] for step in normalized_steps),
        },
        "metadata": {
            "pipeline": ["phase_1_normalize", "phase_2_understand", "phase_3_structure"],
            "model": model, "provider": provider, "fallback": bool(fallback),
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    return validate_structured_incident(incident)


def validate_structured_incident(value):
    data = deepcopy(value)
    errors = []
    for field in ("schema_version", "incident_id", "incident_name", "severity", "steps", "entities", "metadata"):
        if field not in data:
            errors.append(f"Thiếu trường bắt buộc: {field}")
    if errors:
        raise ValueError("; ".join(errors))
    if data["schema_version"] != SCHEMA_VERSION:
        errors.append(f"schema_version phải là {SCHEMA_VERSION}")
    if data["severity"] not in SEVERITIES:
        errors.append("severity không hợp lệ")
    if not isinstance(data["steps"], list) or not data["steps"]:
        errors.append("steps phải là danh sách không rỗng")
    else:
        for index, step in enumerate(data["steps"], 1):
            if not isinstance(step, dict):
                errors.append(f"steps[{index}] phải là object")
                continue
            if step.get("order") != index:
                errors.append(f"steps[{index}].order phải liên tục và bắt đầu từ 1")
            if not str(step.get("action", "")).strip():
                errors.append(f"steps[{index}].action không được rỗng")
            if step.get("severity") not in SEVERITIES:
                errors.append(f"steps[{index}].severity không hợp lệ")
            if not isinstance(step.get("mitre"), dict):
                errors.append(f"steps[{index}].mitre phải là object")
    confidence = data.get("confidence", 0)
    if not isinstance(confidence, int) or not 0 <= confidence <= 100:
        errors.append("confidence phải là số nguyên từ 0 đến 100")
    if errors:
        raise ValueError("; ".join(errors))
    return data


def to_ui_result(structured):
    """Compatibility projection. UI consumers still read one canonical source."""
    data = validate_structured_incident(structured)
    rank = data["severity"].lower()
    severity = rank if rank in ("critical", "high", "medium", "low") else "medium"
    steps = []
    for step in data["steps"]:
        display = step.get("display_vi") or {}
        steps.append({
            "id": step["order"],
            "action": display.get("action") or step["action"],
            "tactic": display.get("tactic") or step["mitre"]["tactic"],
            "tacticCanonical": step["mitre"]["tactic"],
            "techniqueId": step["mitre"]["technique_id"],
            "description": display.get("description") or step["evidence"],
            "source": display.get("actor") or step["actor"],
            "target": display.get("target") or step["target"],
            "detection": display.get("detection") or step["detection"],
            "icon": "◆",
        })
    phase2 = [{
        "step": s["order"],
        "actor": (s.get("display_vi") or {}).get("actor") or s["actor"],
        "action": (s.get("display_vi") or {}).get("action") or s["action"],
        "target": (s.get("display_vi") or {}).get("target") or s["target"],
        "asset": (s.get("display_vi") or {}).get("asset") or s["asset"],
        "severity": s["severity"],
        "severity_vi": (s.get("display_vi") or {}).get("severity"),
        "mitre_tactic": s["mitre"]["tactic"],
        "mitre_tactic_vi": (s.get("display_vi") or {}).get("tactic"),
        "technique_id": s["mitre"]["technique_id"],
        "retrieval_query_en": (s.get("retrieval") or {}).get("query_en"),
    } for s in data["steps"]]
    techniques = [{"id": s["techniqueId"], "name": s["action"], "tactic": s["tactic"]}
                  for s in steps if s["techniqueId"] != "Unknown"]
    localized_entities = _unique(
        value
        for step in data["steps"]
        for value in (
            (step.get("display_vi") or {}).get("actor"),
            (step.get("display_vi") or {}).get("target"),
            (step.get("display_vi") or {}).get("asset"),
        )
        if value
    )
    return {
        "incidentName": (data.get("display_vi") or {}).get("incident_name") or data["incident_name"],
        "severity": severity,
        "confidence": data["confidence"], "entities": localized_entities or _unique(
            data["entities"]["actors"] + data["entities"]["targets"] + data["entities"]["assets"]
        ), "steps": steps, "techniques": techniques, "phase2": phase2,
        "structured_json": data, "engine": data["metadata"]["model"],
        "executiveSummary": (data.get("display_vi") or {}).get("summary") or data["summary"],
        "recommendations": _incident_recommendations(data),
    }


def _text(value, default="Unknown"):
    text = str(value or "").strip()
    return text if text and text.lower() not in ("none", "null", "n/a") else default


def _severity(value):
    candidate = _text(value).title()
    return candidate if candidate in SEVERITIES else "Unknown"


def _highest_severity(values):
    rank = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return max(values, key=lambda value: rank.get(value, 0), default="Unknown")


def _unique(values):
    return list(dict.fromkeys(value for value in values if value != "Unknown"))


def _incident_name(steps):
    final = steps[-1]["action"]
    return final if final != "Unknown Action" else "Cyber Security Incident"


def _summary(steps):
    return f"Chuỗi sự cố gồm {len(steps)} bước: {steps[0]['action']} → {steps[-1]['action']}."


def _incident_recommendations(data):
    actions = [
        "Cô lập endpoint và tạm khóa tài khoản có dấu hiệu bị xâm nhập, đồng thời bảo toàn chứng cứ.",
        "Chặn các IOC đã xác thực trên email gateway, DNS, proxy, EDR và firewall.",
    ]
    tactics = {step["mitre"]["tactic"] for step in data["steps"]}
    if "Credential Access" in tactics:
        actions.append(
            "Thu hồi phiên đăng nhập, xoay vòng thông tin xác thực và áp dụng MFA chống phishing."
        )
    if "Command and Control" in tactics or "Command And Control" in tactics:
        actions.append(
            "Threat hunt lưu lượng C2 liên quan và cách ly các host có telemetry trùng khớp."
        )
    if "Exfiltration" in tactics:
        actions.append(
            "Kiểm tra DLP/NDR, xác định phạm vi dữ liệu rò rỉ và kích hoạt quy trình thông báo sự cố."
        )
    for step in data["steps"]:
        mitigation = str(
            (step.get("display_vi") or {}).get("mitigation")
            or step.get("mitigation", "")
        ).strip()
        if mitigation and mitigation.lower() not in ("unknown", "none", "n/a"):
            actions.append(mitigation)
    return list(dict.fromkeys(actions))[:8]


def _structure_confidence(steps, fallback):
    """Explainable PHASE 2/3 confidence, not a model probability."""
    total = max(1, len(steps))
    required_fields = ("actor", "action", "target", "asset")
    known_fields = sum(
        1 for step in steps for field in required_fields
        if step.get(field) not in ("Unknown", "Unknown Action", "", None)
    )
    completeness = known_fields / (total * len(required_fields))
    tactic_coverage = sum(step["mitre"]["tactic"] != "Unknown" for step in steps) / total
    severity_coverage = sum(step["severity"] != "Unknown" for step in steps) / total
    source_reliability = 0.55 if fallback else 0.85
    score = round(100 * (
        0.40 * completeness +
        0.20 * tactic_coverage +
        0.15 * severity_coverage +
        0.25 * source_reliability
    ))
    return max(0, min(100, score)), {
        "stage": "phase_3_structure",
        "source": "local_fallback" if fallback else "llm",
        "structure_completeness": round(completeness, 4),
        "tactic_coverage": round(tactic_coverage, 4),
        "severity_coverage": round(severity_coverage, 4),
        "source_reliability": source_reliability,
        "rag_coverage": 0.0,
        "rag_mean_score": 0.0,
        "methodology": "weighted_pipeline_quality_v1",
    }
