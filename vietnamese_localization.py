"""Vietnamese presentation layer for English-first ATT&CK retrieval data.

The raw MITRE ATT&CK documents and canonical machine fields stay unchanged so
embedding, reranking, validation and audit trails remain reproducible.  This
module adds ``display_vi`` objects that are consumed by the UI, diagrams and
server-side reports.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Callable

from llm_service import _extract_json, _provider_call


TACTIC_VI = {
    "Reconnaissance": "Trinh sát",
    "Resource Development": "Phát triển nguồn lực",
    "Initial Access": "Truy cập ban đầu",
    "Execution": "Thực thi",
    "Persistence": "Duy trì hiện diện",
    "Privilege Escalation": "Nâng quyền",
    "Defense Evasion": "Né tránh phòng thủ",
    "Credential Access": "Truy cập thông tin xác thực",
    "Discovery": "Khám phá",
    "Lateral Movement": "Di chuyển ngang",
    "Collection": "Thu thập",
    "Command and Control": "Chỉ huy và điều khiển",
    "Command And Control": "Chỉ huy và điều khiển",
    "Exfiltration": "Đưa dữ liệu ra ngoài",
    "Impact": "Gây ảnh hưởng",
    "Unknown": "Chưa xác định",
}

SEVERITY_VI = {
    "Critical": "Nghiêm trọng",
    "High": "Cao",
    "Medium": "Trung bình",
    "Low": "Thấp",
    "Unknown": "Chưa xác định",
}

TERM_VI = {
    "Attacker": "Kẻ tấn công",
    "Threat Actor": "Kẻ tấn công",
    "Actor": "Đối tượng tấn công",
    "Employee": "Nhân viên",
    "User": "Người dùng",
    "Malware": "Mã độc",
    "Malicious macro": "Macro độc hại",
    "Office process": "Tiến trình Office",
    "Remote host": "Máy chủ từ xa",
    "Compromised host": "Máy chủ đã bị xâm nhập",
    "Compromised endpoint": "Thiết bị đầu cuối đã bị xâm nhập",
    "Compromised account": "Tài khoản đã bị xâm nhập",
    "Local system": "Hệ thống cục bộ",
    "Endpoint": "Thiết bị đầu cuối",
    "Workstation": "Máy trạm",
    "Web server": "Máy chủ web",
    "Public server": "Máy chủ công khai",
    "Database server": "Máy chủ cơ sở dữ liệu",
    "External server": "Máy chủ bên ngoài",
    "C2 server": "Máy chủ C2",
    "Corporate email": "Email doanh nghiệp",
    "Email account": "Tài khoản email",
    "Email": "Email",
    "Email gateway": "Cổng bảo mật email",
    "Word document": "Tài liệu Word",
    "Browser": "Trình duyệt",
    "Browser credentials": "Thông tin xác thực trình duyệt",
    "Credentials": "Thông tin xác thực",
    "Data": "Dữ liệu",
    "Enterprise data": "Dữ liệu doanh nghiệp",
    "Customer data": "Dữ liệu khách hàng",
    "Backup data": "Dữ liệu sao lưu",
    "Unknown": "Chưa xác định",
    "Unknown Action": "Hành vi chưa xác định",
}

TECHNIQUE_NAME_VI = {
    "T1190": "Khai thác ứng dụng công khai",
    "T1204": "Thực thi bởi người dùng",
    "T1204.002": "Thực thi tệp độc hại bởi người dùng",
    "T1059.001": "Thực thi PowerShell",
    "T1105": "Truyền công cụ xâm nhập",
    "T1071.001": "Giao tiếp qua giao thức web",
    "T1555.003": "Lấy thông tin xác thực từ trình duyệt",
    "T1056": "Thu thập dữ liệu nhập",
    "T1021": "Sử dụng dịch vụ từ xa",
    "T1560": "Lưu trữ dữ liệu đã thu thập",
    "T1560.001": "Nén dữ liệu đã thu thập",
    "T1041": "Đưa dữ liệu qua kênh C2",
    "T1567": "Đưa dữ liệu qua dịch vụ web",
    "T1486": "Mã hóa dữ liệu gây ảnh hưởng",
    "T1490": "Ngăn chặn khôi phục hệ thống",
    "T1566": "Lừa đảo",
    "T1566.001": "Lừa đảo qua tệp đính kèm",
    "T1566.002": "Lừa đảo qua liên kết",
}

LOCALIZATION_SYSTEM_PROMPT = """Bạn là biên dịch viên chuyên ngành SOC, DFIR và MITRE ATT&CK.
Dịch chính xác từng giá trị trong object `texts` từ tiếng Anh sang tiếng Việt.
Quy tắc bắt buộc:
- Không thêm dữ kiện, không suy diễn và không rút gọn ý nghĩa kỹ thuật.
- Không dịch hoặc thay đổi ATT&CK ID, CVE, IOC, hash, địa chỉ IP, domain, URL,
  đường dẫn, tên tiến trình, câu lệnh, tên sản phẩm và tên model.
- Dùng thuật ngữ an toàn thông tin tự nhiên, phù hợp báo cáo SOC tiếng Việt.
- Giữ nguyên toàn bộ key và chỉ trả JSON object dạng
  {"translations":{"t0001":"bản dịch"}}; không markdown."""

_VIETNAMESE_RE = re.compile(
    r"[ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩị"
    r"óòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ]",
    re.IGNORECASE,
)
_UNKNOWN = {"", "unknown", "none", "null", "n/a"}
_PRESERVE_TERMS = {
    "PowerShell", "Ransomware", "C2", "EDR", "NDR", "DLP", "WAF", "IDS",
    "IPS", "SIEM", "SOAR", "Windows", "Linux", "VPN", "Active Directory",
    "Microsoft 365", "SQL Server", "Chrome", "Firefox", "Office", "Macro",
}
_MAX_TRANSLATION_CHARACTERS = 32_000


def localize_structured_incident(
    structured: dict[str, Any],
    llm_config: Any = None,
    translator: Callable[[dict[str, str]], dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Attach Vietnamese display fields without mutating raw retrieval data."""
    result = deepcopy(structured)
    _seed_deterministic_display(result)
    texts, references = _translation_plan(result)
    translations: dict[str, str] = {}
    error = ""
    requested_llm = bool(
        translator
        or (
            getattr(llm_config, "enabled", False)
            and getattr(llm_config, "api_key", "")
            and getattr(llm_config, "localize_rag", True)
        )
    )
    try:
        if translator:
            translated_payload = translator(dict(texts)) or {}
            if not isinstance(translated_payload, dict):
                raise RuntimeError("Translator không trả về object bản dịch hợp lệ.")
            translations = translated_payload
        elif requested_llm:
            translations = _translate_with_llm(texts, llm_config)
    except Exception as exc:  # Localization must never break incident analysis.
        error = str(exc)

    applied = 0
    for token, targets in references.items():
        translated = str(translations.get(token) or "").strip()
        if not translated:
            continue
        for container, field in targets:
            container[field] = translated
            applied += 1

    _ensure_vietnamese_fallbacks(result)
    metadata = result.setdefault("metadata", {})
    pipeline = metadata.setdefault("pipeline", [])
    if "phase_4_localize_vi" not in pipeline:
        pipeline.append("phase_4_localize_vi")
    status = "translated" if applied else "fallback" if requested_llm else "deterministic"
    metadata["localization"] = {
        "language": "vi",
        "source_language": "en",
        "raw_preserved": True,
        "status": status,
        "engine": (
            str(getattr(llm_config, "model", "configured-llm"))
            if applied else "deterministic-vi"
        ),
        "translated_fields": applied,
        "requested_fields": len(references),
    }
    if error:
        metadata["localization"]["error"] = error
    return result


def localize_phase2_steps(
    phase2_steps: list[dict[str, Any]],
    canonical_steps: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Project PHASE 2 faithfully while translating display-only enums."""
    canonical = {
        int(step.get("order", index + 1)): step
        for index, step in enumerate(canonical_steps or [])
    }
    output = []
    for index, raw in enumerate(phase2_steps or [], 1):
        order = int(raw.get("step") or index)
        display = (canonical.get(order, {}).get("display_vi") or {})
        tactic = str(raw.get("mitre_tactic") or raw.get("tactic") or "Unknown")
        severity = str(raw.get("severity") or "Unknown").title()
        output.append({
            **raw,
            "step": order,
            "actor": display.get("actor") or _term_vi(raw.get("actor"), "Đối tượng liên quan"),
            "action": display.get("action") or _term_vi(raw.get("action"), "Hành vi đáng ngờ"),
            "target": display.get("target") or _term_vi(raw.get("target"), "Mục tiêu liên quan"),
            "asset": display.get("asset") or _term_vi(raw.get("asset"), "Tài sản liên quan"),
            "severity": severity,
            "severity_vi": display.get("severity") or SEVERITY_VI.get(severity, "Chưa xác định"),
            "mitre_tactic": tactic,
            "mitre_tactic_vi": display.get("tactic") or tactic_vi(tactic),
        })
    return output


def tactic_vi(value: Any) -> str:
    return TACTIC_VI.get(str(value or "Unknown"), "Chưa xác định")


def severity_vi(value: Any) -> str:
    return SEVERITY_VI.get(str(value or "Unknown").title(), "Chưa xác định")


def _seed_deterministic_display(result: dict[str, Any]) -> None:
    top = result.setdefault("display_vi", {})
    top["severity"] = severity_vi(result.get("severity"))
    for step in result.get("steps") or []:
        display = step.setdefault("display_vi", {})
        display.update({
            "actor": _term_vi(step.get("actor"), "Đối tượng liên quan"),
            "action": _action_vi(step),
            "target": _term_vi(step.get("target"), "Mục tiêu liên quan"),
            "asset": _term_vi(step.get("asset"), "Tài sản liên quan"),
            "severity": severity_vi(step.get("severity")),
            "tactic": tactic_vi((step.get("mitre") or {}).get("tactic")),
        })
        technique_id = str((step.get("mitre") or {}).get("technique_id") or "Unknown")
        display["technique_name"] = TECHNIQUE_NAME_VI.get(
            technique_id, f"Kỹ thuật ATT&CK {technique_id}"
        )
        display["description"] = _description_fallback(step)
        display["detection"] = _detection_fallback(step)
        display["mitigation"] = _mitigation_fallback(step)
        display["procedure"] = _procedure_fallback(step)

        for match in ((step.get("rag") or {}).get("matches") or []):
            match_display = match.setdefault("display_vi", {})
            match_id = str(match.get("technique_id") or "Unknown")
            match_display.update({
                "technique_name": TECHNIQUE_NAME_VI.get(
                    match_id, f"Kỹ thuật ATT&CK {match_id}"
                ),
                "tactics": _tactics_vi(match.get("tactics")),
                "description": (
                    f"Ứng viên {match_id} được RAG truy xuất để đối chiếu với "
                    f"hành vi “{display['action']}”."
                ),
                "detection": _detection_fallback(step, match_id),
                "mitigation": _mitigation_fallback(step, match_id),
                "procedure": _procedure_fallback(step),
            })

        for match in ((step.get("knowledge") or {}).get("matches") or []):
            source = str(match.get("source") or "kho tri thức")
            match.setdefault("display_vi", {}).update({
                "title": f"Bằng chứng liên quan từ {source}",
                "snippet": (
                    f"Tài liệu từ {source} được truy xuất để hỗ trợ kiểm chứng "
                    f"bước “{display['action']}”."
                ),
            })

    steps = result.get("steps") or []
    if steps:
        first = steps[0]["display_vi"]["action"]
        last = steps[-1]["display_vi"]["action"]
        top.setdefault("incident_name", last)
        top.setdefault(
            "summary",
            f"Chuỗi sự cố gồm {len(steps)} bước, bắt đầu từ {first.lower()} và kết thúc bằng {last.lower()}.",
        )
    else:
        top.setdefault("incident_name", "Sự cố an ninh mạng")
        top.setdefault("summary", "Chưa có bước sự cố để phân tích.")


def _translation_plan(result: dict[str, Any]):
    texts: dict[str, str] = {}
    references: dict[str, list[tuple[dict[str, str], str]]] = {}
    by_text: dict[str, str] = {}
    used = 0

    def register(container, field, value, limit=700):
        nonlocal used
        text = _raw_text(value).strip()
        if not _needs_translation(text):
            if text and text.lower() not in _UNKNOWN:
                if text not in _PRESERVE_TERMS or not container.get(field):
                    container[field] = _term_vi(text, text)
            return
        text = text[:limit]
        if text in by_text:
            references[by_text[text]].append((container, field))
            return
        if used + len(text) > _MAX_TRANSLATION_CHARACTERS:
            return
        token = f"t{len(texts) + 1:04d}"
        texts[token] = text
        references[token] = [(container, field)]
        by_text[text] = token
        used += len(text)

    top = result.setdefault("display_vi", {})
    register(top, "incident_name", result.get("incident_name"), 260)
    register(top, "summary", result.get("summary"), 700)
    for step in result.get("steps") or []:
        display = step.setdefault("display_vi", {})
        for field in ("actor", "action", "target", "asset"):
            register(display, field, step.get(field), 240)
        register(display, "description", step.get("evidence"), 700)
        register(display, "detection", step.get("detection"), 650)
        register(display, "mitigation", step.get("mitigation"), 650)
        register(display, "procedure", step.get("procedure"), 650)
        for match in ((step.get("rag") or {}).get("matches") or []):
            match_display = match.setdefault("display_vi", {})
            register(match_display, "technique_name", match.get("technique_name"), 180)
            register(match_display, "description", match.get("description"), 520)
            register(match_display, "detection", match.get("detection"), 420)
            register(match_display, "mitigation", match.get("mitigation"), 420)
            register(match_display, "procedure", match.get("procedure"), 420)
        for match in ((step.get("knowledge") or {}).get("matches") or [])[:3]:
            match_display = match.setdefault("display_vi", {})
            register(match_display, "title", match.get("title"), 220)
            register(match_display, "snippet", match.get("snippet"), 320)
    return texts, references


def _translate_with_llm(texts: dict[str, str], config: Any) -> dict[str, str]:
    if not texts:
        return {}
    raw = _provider_call(config, [
        {"role": "system", "content": LOCALIZATION_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Dịch object sau sang tiếng Việt và giữ nguyên key:\n"
                + __import__("json").dumps({"texts": texts}, ensure_ascii=False)
            ),
        },
    ])
    data = _extract_json(raw)
    translated = data.get("translations") if isinstance(data, dict) else None
    if not isinstance(translated, dict):
        raise RuntimeError("LLM không trả về object translations hợp lệ.")
    return {str(key): str(value) for key, value in translated.items()}


def _ensure_vietnamese_fallbacks(result: dict[str, Any]) -> None:
    """Reject untranslated prose from the presentation layer, keep raw aside."""
    top = result.get("display_vi") or {}
    steps = result.get("steps") or []
    for step in steps:
        display = step.get("display_vi") or {}
        matches = ((step.get("rag") or {}).get("matches") or [])
        if matches:
            best_display = matches[0].get("display_vi") or {}
            current_name = str(display.get("technique_name") or "")
            if not current_name or current_name.startswith("Kỹ thuật ATT&CK"):
                display["technique_name"] = (
                    best_display.get("technique_name") or current_name
                )
            if str(step.get("evidence") or "").strip().lower() in _UNKNOWN:
                display["description"] = (
                    best_display.get("description") or display.get("description")
                )
        fallbacks = {
            "actor": _term_vi(step.get("actor"), "Đối tượng liên quan"),
            "action": _action_vi(step),
            "target": _term_vi(step.get("target"), "Mục tiêu liên quan"),
            "asset": _term_vi(step.get("asset"), "Tài sản liên quan"),
            "description": _description_fallback(step),
            "detection": _detection_fallback(step),
            "mitigation": _mitigation_fallback(step),
            "procedure": _procedure_fallback(step),
        }
        for field, fallback in fallbacks.items():
            if _needs_translation(str(display.get(field) or "")):
                display[field] = fallback
        for match in matches:
            match_display = match.get("display_vi") or {}
            match_id = str(match.get("technique_id") or "Unknown")
            match_fallbacks = {
                "technique_name": TECHNIQUE_NAME_VI.get(match_id, f"Kỹ thuật ATT&CK {match_id}"),
                "description": f"Ứng viên {match_id} được truy xuất để đối chiếu với bước này.",
                "detection": _detection_fallback(step, match_id),
                "mitigation": _mitigation_fallback(step, match_id),
                "procedure": _procedure_fallback(step),
            }
            for field, fallback in match_fallbacks.items():
                if _needs_translation(str(match_display.get(field) or "")):
                    match_display[field] = fallback
        for match in ((step.get("knowledge") or {}).get("matches") or []):
            match_display = match.get("display_vi") or {}
            source = str(match.get("source") or "kho tri thức")
            if _needs_translation(str(match_display.get("title") or "")):
                match_display["title"] = f"Bằng chứng liên quan từ {source}"
            if _needs_translation(str(match_display.get("snippet") or "")):
                match_display["snippet"] = "Tài liệu liên quan được truy xuất để kiểm chứng bước tấn công."
    if _needs_translation(str(top.get("incident_name") or "")):
        top["incident_name"] = (
            steps[-1]["display_vi"]["action"] if steps else "Sự cố an ninh mạng"
        )
    if _needs_translation(str(top.get("summary") or "")):
        top["summary"] = (
            f"Phân tích xác định chuỗi sự cố gồm {len(steps)} bước có liên quan."
        )
    top["entities"] = {
        group: list(dict.fromkeys(
            step["display_vi"][field]
            for step in steps
            if step.get("display_vi", {}).get(field) not in ("", "Chưa xác định")
        ))
        for group, field in (
            ("actors", "actor"), ("targets", "target"), ("assets", "asset")
        )
    }


def _action_vi(step: dict[str, Any]) -> str:
    raw = str(step.get("action") or "").strip()
    exact = TERM_VI.get(raw)
    if exact:
        return exact
    if _is_vietnamese(raw):
        return raw
    technique_id = str((step.get("mitre") or {}).get("technique_id") or "")
    if technique_id in TECHNIQUE_NAME_VI:
        return TECHNIQUE_NAME_VI[technique_id]
    tactic = tactic_vi((step.get("mitre") or {}).get("tactic"))
    return f"Phát hiện hành vi thuộc chiến thuật {tactic.lower()}"


def _description_fallback(step: dict[str, Any]) -> str:
    display = step.get("display_vi") or {}
    technique_id = str((step.get("mitre") or {}).get("technique_id") or "Unknown")
    return (
        f"Hành vi “{display.get('action') or _action_vi(step)}” được ánh xạ với "
        f"kỹ thuật {technique_id}, thuộc chiến thuật "
        f"{display.get('tactic') or tactic_vi((step.get('mitre') or {}).get('tactic'))}."
    )


def _detection_fallback(step: dict[str, Any], technique_id: str | None = None) -> str:
    display = step.get("display_vi") or {}
    tid = technique_id or str((step.get("mitre") or {}).get("technique_id") or "Unknown")
    return (
        f"Giám sát nhật ký và telemetry liên quan đến hành vi “"
        f"{display.get('action') or _action_vi(step)}” trên "
        f"{display.get('asset') or _term_vi(step.get('asset'), 'tài sản liên quan')}; "
        f"đối chiếu kỹ thuật {tid}."
    )


def _mitigation_fallback(step: dict[str, Any], technique_id: str | None = None) -> str:
    display = step.get("display_vi") or {}
    tid = technique_id or str((step.get("mitre") or {}).get("technique_id") or "Unknown")
    return (
        f"Tăng cường kiểm soát trên "
        f"{display.get('asset') or _term_vi(step.get('asset'), 'tài sản liên quan')} "
        f"và áp dụng biện pháp giảm thiểu phù hợp cho kỹ thuật {tid}."
    )


def _procedure_fallback(step: dict[str, Any]) -> str:
    display = step.get("display_vi") or {}
    return (
        f"{display.get('actor') or _term_vi(step.get('actor'), 'Đối tượng liên quan')} "
        f"thực hiện “{display.get('action') or _action_vi(step)}” nhằm vào "
        f"{display.get('target') or _term_vi(step.get('target'), 'mục tiêu liên quan')}."
    )


def _term_vi(value: Any, fallback: str) -> str:
    text = str(value or "").strip()
    if text.lower() in _UNKNOWN:
        return "Chưa xác định"
    if text in TERM_VI:
        return TERM_VI[text]
    if text in _PRESERVE_TERMS:
        return text
    if _is_vietnamese(text):
        return text
    return fallback


def _tactics_vi(value: Any) -> str:
    items = [part.strip() for part in str(value or "Unknown").split(",")]
    return ", ".join(tactic_vi(item) for item in items if item) or "Chưa xác định"


def _raw_text(value: Any) -> str:
    if isinstance(value, list):
        return "\n".join(str(item) for item in value if str(item).strip())
    return str(value or "")


def _is_vietnamese(text: str) -> bool:
    lowered = str(text or "").lower()
    if _VIETNAMESE_RE.search(lowered):
        return True
    markers = (
        "kẻ tấn công", "người dùng", "nhân viên", "máy chủ", "dữ liệu",
        "mã độc", "thông tin", "tài khoản", "thực thi", "phát hiện",
        "giảm thiểu", "truy cập", "kết nối", "hành vi", "sự cố",
    )
    return any(marker in lowered for marker in markers)


def _needs_translation(text: str) -> bool:
    value = str(text or "").strip()
    if value.lower() in _UNKNOWN or not value:
        return False
    if value in TERM_VI or _is_vietnamese(value):
        return False
    if value in _PRESERVE_TERMS:
        return False
    if re.fullmatch(r"(?:T\d{4}(?:\.\d{3})?|CVE-\d{4}-\d+|[A-Fa-f0-9]{32,})", value):
        return False
    return bool(re.search(r"[A-Za-z]", value))
