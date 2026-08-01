"""Provider-agnostic LLM client used by the Flask API.

Supports OpenAI, Azure OpenAI, Anthropic, Gemini, Ollama and any
OpenAI-compatible server (vLLM, LM Studio, Groq, Together, OpenRouter...).
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict


PROVIDER_DEFAULTS = {
    "dashscope": ("https://dashscope-intl.aliyuncs.com/compatible-mode/v1", "glm-5.2"),
    "zhipu": ("https://open.bigmodel.cn/api/paas/v4", "glm-5.2"),
    "openai": ("https://api.openai.com/v1", "gpt-4o-mini"),
    "azure": ("", "gpt-4o"),
    "anthropic": ("https://api.anthropic.com/v1", "claude-3-5-sonnet-latest"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta", "gemini-1.5-flash"),
    "ollama": ("http://127.0.0.1:11434", "qwen2.5:7b"),
    "compatible": ("http://127.0.0.1:8000/v1", "Qwen/Qwen2.5-7B-Instruct"),
}


@dataclass
class LLMConfig:
    enabled: bool = False
    provider: str = "dashscope"
    api_key: str = ""
    base_url: str = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    model: str = "glm-5.2"
    temperature: float = 0.1
    timeout: int = 60
    rag_enabled: bool = True
    localize_rag: bool = True
    system_prompt: str = ""
    azure_api_version: str = "2024-10-21"

    @classmethod
    def from_env(cls):
        provider = os.getenv("LLM_PROVIDER", "dashscope").lower()
        default_url, default_model = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["openai"])
        provider_key = os.getenv("DASHSCOPE_API_KEY", "") if provider == "dashscope" else ""
        return cls(
            enabled=os.getenv("LLM_ENABLED", "false").lower() == "true",
            provider=provider,
            api_key=os.getenv("LLM_API_KEY", "") or provider_key,
            base_url=os.getenv("LLM_BASE_URL", default_url).rstrip("/"),
            model=os.getenv("LLM_MODEL", default_model),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.1")),
            timeout=int(os.getenv("LLM_TIMEOUT", "60")),
            rag_enabled=os.getenv("RAG_ENABLED", "true").lower() == "true",
            localize_rag=os.getenv("RAG_LOCALIZATION_ENABLED", "true").lower() == "true",
            system_prompt=os.getenv("LLM_SYSTEM_PROMPT", ""),
            azure_api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21"),
        )

    def public_dict(self):
        data = asdict(self)
        key = data.pop("api_key")
        data["has_api_key"] = bool(key)
        data["api_key_masked"] = f"{key[:3]}••••{key[-3:]}" if len(key) > 7 else ("••••••" if key else "")
        return data


SYSTEM_PROMPT = """Bạn là chuyên gia DFIR và MITRE ATT&CK. Phân tích mô tả sự cố tiếng Việt.
Chỉ trả về một JSON object hợp lệ, không markdown, theo schema:
{
 "incidentName": "string tiếng Việt",
 "severity": "critical|high|medium|low",
 "confidence": 0-100,
 "entities": ["string"],
 "steps": [{
   "action": "string ngắn bằng tiếng Việt",
   "tactic": "MITRE tactic English",
   "techniqueId": "Txxxx hoặc Txxxx.xxx",
   "description": "string tiếng Việt",
   "source": "string tiếng Việt", "target": "string tiếng Việt",
   "detection": "string tiếng Việt",
   "icon": "một ký tự"
 }],
 "executiveSummary": "string tiếng Việt",
 "recommendations": ["string tiếng Việt"]
}
Không bịa IOC. Chỉ ánh xạ technique có bằng chứng trong mô tả. Tối đa 8 bước."""

PHASE2_SYSTEM_PROMPT = """Bạn là chuyên gia Cyber Security và hiểu sâu tiếng Việt.
Nhiệm vụ:
- Hiểu đúng mô tả sự cố.
- Chia diễn biến thành từng bước theo đúng thứ tự.
- Với mỗi bước xác định Actor, Target, Action, Asset, Severity và MITRE tactic.
- Nếu dữ liệu không nói rõ Actor, Target hoặc Asset, dùng "Unknown".
- Nếu chưa chắc chắn MITRE tactic, bắt buộc dùng "Unknown"; không suy đoán.
- Severity chỉ được là Critical, High, Medium, Low hoặc Unknown.
- Actor, Target, Action và Asset phải viết ngắn gọn, rõ nghĩa bằng tiếng Việt.
- `mitre_tactic` và `technique_id` giữ đúng tên/ID chính thức của MITRE ATT&CK bằng tiếng Anh.
- Tạo `retrieval_query_en` bằng tiếng Anh để tìm semantic trong ATT&CK; không dùng trường này để hiển thị.

Chỉ trả về JSON object hợp lệ, không markdown:
{"steps":[
  {"step":1,"actor":"Kẻ tấn công","action":"Gửi email lừa đảo",
   "target":"Nhân viên","asset":"Tài khoản email","severity":"High",
   "mitre_tactic":"Initial Access","technique_id":"T1566",
   "retrieval_query_en":"attacker sends phishing email to employee email account"}
]}
Không thêm nội dung ngoài JSON."""

PHASE2_OUTPUT_CONTRACT = """YÊU CẦU ĐẦU RA BẮT BUỘC:
- Chỉ trả JSON object có mảng `steps`, tuyệt đối không markdown.
- `actor`, `action`, `target`, `asset` phải là tiếng Việt.
- `severity` chỉ là Critical, High, Medium, Low hoặc Unknown.
- `mitre_tactic` và `technique_id` giữ chuẩn MITRE ATT&CK bằng tiếng Anh.
- Mỗi bước phải có `retrieval_query_en` bằng tiếng Anh để phục vụ RAG.
- Không dịch hoặc thay đổi ATT&CK ID, CVE, IOC, hash, IP, domain, tên tiến trình hay câu lệnh."""

_RETRIEVAL_HINTS_EN = {
    "T1190": "exploit public-facing application vulnerability",
    "T1204": "user execution malicious file",
    "T1204.002": "user execution malicious file attachment",
    "T1059.001": "execute PowerShell command script",
    "T1105": "ingress tool transfer download malware payload",
    "T1071.001": "command and control web protocol connection",
    "T1555.003": "credentials from web browser credential store",
    "T1056": "input capture credential theft",
    "T1021": "remote services lateral movement",
    "T1560.001": "archive collected data compression",
    "T1041": "exfiltration over command and control channel",
    "T1486": "data encrypted for impact ransomware",
    "T1490": "inhibit system recovery delete backups",
    "T1566": "phishing",
    "T1566.001": "spearphishing attachment",
    "T1566.002": "spearphishing link",
}

_VIETNAMESE_QUERY_RE = re.compile(
    r"[ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩị"
    r"óòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ]",
    re.IGNORECASE,
)

_MITRE_TACTICS = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
_TACTIC_ALIASES = {value.casefold(): value for value in _MITRE_TACTICS}
_TACTIC_ALIASES.update({
    "trinh sát": "Reconnaissance",
    "phát triển nguồn lực": "Resource Development",
    "truy cập ban đầu": "Initial Access",
    "thực thi": "Execution",
    "duy trì hiện diện": "Persistence",
    "nâng quyền": "Privilege Escalation",
    "né tránh phòng thủ": "Defense Evasion",
    "truy cập thông tin xác thực": "Credential Access",
    "khám phá": "Discovery",
    "di chuyển ngang": "Lateral Movement",
    "thu thập": "Collection",
    "chỉ huy và điều khiển": "Command and Control",
    "chỉ huy và kiểm soát": "Command and Control",
    "đưa dữ liệu ra ngoài": "Exfiltration",
    "gây ảnh hưởng": "Impact",
})


def _request(url, headers, payload, timeout):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, body, headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"LLM HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Không kết nối được LLM: {exc.reason}") from exc


def _extract_json(text):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise RuntimeError("LLM không trả về JSON hợp lệ.")
    return json.loads(text[start:end + 1])


def _provider_call(config: LLMConfig, messages):
    p, base, model = config.provider, config.base_url.rstrip("/"), config.model
    if p in ("openai", "compatible", "zhipu", "dashscope"):
        data = _request(f"{base}/chat/completions", {"Authorization": f"Bearer {config.api_key}"},
                        {"model": model, "messages": messages, "temperature": config.temperature,
                         "response_format": {"type": "json_object"}}, config.timeout)
        return data["choices"][0]["message"]["content"]
    if p == "azure":
        url = f"{base}/openai/deployments/{urllib.parse.quote(model)}/chat/completions?api-version={config.azure_api_version}"
        data = _request(url, {"api-key": config.api_key},
                        {"messages": messages, "temperature": config.temperature,
                         "response_format": {"type": "json_object"}}, config.timeout)
        return data["choices"][0]["message"]["content"]
    if p == "anthropic":
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        user_messages = [m for m in messages if m["role"] != "system"]
        data = _request(f"{base}/messages",
                        {"x-api-key": config.api_key, "anthropic-version": "2023-06-01"},
                        {"model": model, "system": system, "messages": user_messages,
                         "temperature": config.temperature, "max_tokens": 4096}, config.timeout)
        return data["content"][0]["text"]
    if p == "gemini":
        prompt = "\n\n".join(m["content"] for m in messages)
        url = f"{base}/models/{urllib.parse.quote(model)}:generateContent?key={urllib.parse.quote(config.api_key)}"
        data = _request(url, {}, {"contents": [{"parts": [{"text": prompt}]}],
                                  "generationConfig": {"temperature": config.temperature,
                                                       "responseMimeType": "application/json"}}, config.timeout)
        return data["candidates"][0]["content"]["parts"][0]["text"]
    if p == "ollama":
        data = _request(f"{base}/api/chat", {},
                        {"model": model, "messages": messages, "stream": False,
                         "format": "json", "options": {"temperature": config.temperature}}, config.timeout)
        return data["message"]["content"]
    raise RuntimeError(f"Provider không được hỗ trợ: {p}")


def analyze_with_llm(description, config: LLMConfig, attack_context=""):
    prompt = config.system_prompt.strip() or SYSTEM_PROMPT
    user = f"MÔ TẢ SỰ CỐ:\n{description}"
    if config.rag_enabled and attack_context:
        user += f"\n\nATT&CK CONTEXT ĐƯỢC TRUY XUẤT:\n{attack_context}"
    result = _extract_json(_provider_call(config, [
        {"role": "system", "content": prompt},
        {"role": "user", "content": user},
    ]))
    return validate_result(result)


def understand_phase2(description, config: LLMConfig):
    """PHASE 2: Vietnamese semantic decomposition with GLM-5.2."""
    custom_prompt = config.system_prompt.strip()
    prompt = (
        f"{custom_prompt}\n\n{PHASE2_OUTPUT_CONTRACT}"
        if custom_prompt
        else PHASE2_SYSTEM_PROMPT
    )
    raw = _extract_json(_provider_call(config, [
        {"role": "system", "content": prompt},
        {"role": "user", "content": f"MÔ TẢ CẦN PHÂN TÍCH:\n{description}"},
    ]))
    return validate_phase2(raw)


def validate_phase2(data):
    source = data.get("steps") if isinstance(data, dict) else data
    if not isinstance(source, list) or not source:
        raise RuntimeError("GLM-5.2 không trả về danh sách bước hợp lệ.")
    valid_severity = {"Critical", "High", "Medium", "Low", "Unknown"}
    steps = []
    for index, item in enumerate(source[:12], 1):
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "Unknown")).title()
        steps.append({
            "step": index,
            "actor": str(item.get("actor") or "Unknown"),
            "action": str(item.get("action") or "Unknown"),
            "target": str(item.get("target") or "Unknown"),
            "asset": str(item.get("asset") or "Unknown"),
            "severity": severity if severity in valid_severity else "Unknown",
            "mitre_tactic": _canonical_mitre_tactic(
                item.get("mitre_tactic") or item.get("tactic")
            ),
            "technique_id": _canonical_technique_id(
                item.get("technique_id") or item.get("techniqueId")
            ),
            "retrieval_query_en": _retrieval_query_en(item),
        })
    if not steps:
        raise RuntimeError("GLM-5.2 không trích xuất được bước hành vi.")
    return steps


def _fallback_retrieval_query(item):
    """Keep legacy/custom prompts searchable without changing display text."""
    value = " ".join(
        str(item.get(field) or "")
        for field in ("action", "actor", "target", "asset")
    ).lower()
    vocabulary = {
        "chạy powershell": "execute powershell",
        "email lừa đảo": "phishing email",
        "email giả mạo": "phishing email",
        "tệp độc hại": "malicious file",
        "tệp đính kèm": "malicious attachment",
        "thực thi": "execution",
        "tải mã độc": "download malware",
        "tải ransomware": "download ransomware",
        "mã độc": "malware",
        "thông tin đăng nhập": "credentials",
        "kết nối c2": "command and control connection",
        "mã hóa dữ liệu": "data encrypted for impact",
        "xóa bản sao lưu": "delete backups inhibit system recovery",
        "đưa dữ liệu ra ngoài": "data exfiltration",
        "đánh cắp dữ liệu": "data exfiltration",
        "khai thác lỗ hổng": "exploit public-facing application vulnerability",
        "kẻ tấn công": "attacker",
        "nhân viên": "employee",
        "máy chủ web": "web server",
        "máy chủ": "server",
    }
    translated = value
    for source, target in vocabulary.items():
        translated = translated.replace(source, target)
    technique_id = _canonical_technique_id(
        item.get("technique_id") or item.get("techniqueId")
    )
    tactic = _canonical_mitre_tactic(
        item.get("mitre_tactic") or item.get("tactic")
    )
    parts = []
    for part in (
        technique_id if technique_id.lower() != "unknown" else "",
        tactic if tactic.lower() != "unknown" and not _contains_vietnamese(part=tactic) else "",
        _RETRIEVAL_HINTS_EN.get(technique_id, ""),
        translated if not _contains_vietnamese(part=translated) else "",
    ):
        normalized = re.sub(r"\s+", " ", str(part or "")).strip()
        if normalized and normalized not in parts:
            parts.append(normalized)
    return " | ".join(parts) or "cybersecurity suspicious activity"


def _retrieval_query_en(item):
    supplied = str(
        item.get("retrieval_query_en") or item.get("retrieval_query") or ""
    ).strip()
    if supplied and not _contains_vietnamese(part=supplied):
        return supplied
    return _fallback_retrieval_query(item)


def _contains_vietnamese(*, part):
    text = str(part or "").strip().lower()
    if not text:
        return False
    if _VIETNAMESE_QUERY_RE.search(text):
        return True
    markers = (
        "kẻ tấn công", "ke tan cong", "nguoi dung", "nhan vien", "may chu",
        "du lieu", "ma doc", "thong tin", "tai khoan", "thuc thi",
        "phat hien", "giam thieu", "truy cap", "ket noi", "hanh vi",
        "su co", "chay powershell", "tai ransomware", "tai ma doc",
        "xoa ban sao", "email lua dao", "email gia mao",
    )
    return any(marker in text for marker in markers)


def _canonical_mitre_tactic(value):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text or text.casefold() == "unknown":
        return "Unknown"
    return _TACTIC_ALIASES.get(text.casefold(), "Unknown")


def _canonical_technique_id(value):
    text = str(value or "").strip().upper()
    return text if re.fullmatch(r"T\d{4}(?:\.\d{3})?", text) else "Unknown"


def phase2_to_attack_result(steps):
    """Adapter keeps the current diagram UI usable before PHASE 3 mapping."""
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    highest = max((s["severity"] for s in steps), key=lambda x: rank.get(x, 0))
    severity = highest.lower() if highest != "Unknown" else "medium"
    diagram_steps = [{
        "id": s["step"], "action": s["action"], "tactic": s["mitre_tactic"],
        "techniqueId": "Unknown", "description": f"{s['actor']} → {s['action']} → {s['target']}",
        "source": s["actor"], "target": s["target"], "detection": "Pending PHASE 3",
        "icon": "◆",
    } for s in steps]
    entities = list(dict.fromkeys(x for s in steps for x in (s["actor"], s["target"], s["asset"]) if x != "Unknown"))
    total = max(1, len(steps))
    known_fields = sum(
        value not in ("", "Unknown", None)
        for step in steps
        for value in (
            step.get("actor"),
            step.get("action"),
            step.get("target"),
            step.get("asset"),
        )
    )
    completeness = known_fields / (total * 4)
    tactic_coverage = sum(
        step.get("mitre_tactic") not in ("", "Unknown", None) for step in steps
    ) / total
    severity_coverage = sum(
        step.get("severity") not in ("", "Unknown", None) for step in steps
    ) / total
    source_reliability = 0.85
    confidence = round(
        100
        * (
            0.40 * completeness
            + 0.20 * tactic_coverage
            + 0.15 * severity_coverage
            + 0.25 * source_reliability
        )
    )
    return {
        "incidentName": "GLM-5.2 Vietnamese Incident Analysis",
        "severity": severity, "confidence": confidence, "entities": entities,
        "steps": diagram_steps, "techniques": [], "phase2": steps, "engine": "glm-5.2",
        "confidence_breakdown": {
            "stage": "phase_2_adapter",
            "source": "llm",
            "structure_completeness": round(completeness, 4),
            "tactic_coverage": round(tactic_coverage, 4),
            "severity_coverage": round(severity_coverage, 4),
            "source_reliability": source_reliability,
            "methodology": "weighted_pipeline_quality_v1",
        },
        "executiveSummary": f"GLM-5.2 đã chia mô tả tiếng Việt thành {len(steps)} bước hành vi có cấu trúc.",
        "recommendations": ["Tiếp tục PHASE 3 để ánh xạ technique ID và nguồn tri thức MITRE ATT&CK."],
    }


def test_connection(config: LLMConfig):
    text = _provider_call(config, [
        {"role": "system", "content": "Trả về duy nhất JSON hợp lệ."},
        {"role": "user", "content": '{"status":"ok"}'},
    ])
    return {"ok": True, "provider": config.provider, "model": config.model, "response": text[:160]}


def validate_result(data):
    required = ("incidentName", "severity", "confidence", "steps", "executiveSummary", "recommendations")
    if not isinstance(data, dict) or any(k not in data for k in required):
        raise RuntimeError("Structured output thiếu trường bắt buộc.")
    if data["severity"] not in ("critical", "high", "medium", "low"):
        data["severity"] = "medium"
    data["confidence"] = max(0, min(100, int(data.get("confidence", 70))))
    data["entities"] = list(data.get("entities") or [])
    clean_steps = []
    for i, step in enumerate(data.get("steps") or []):
        if not isinstance(step, dict):
            continue
        clean_steps.append({
            "id": i + 1, "action": str(step.get("action", "Hành vi đáng ngờ")),
            "tactic": str(step.get("tactic", "Unknown")),
            "techniqueId": str(step.get("techniqueId", "N/A")),
            "description": str(step.get("description", "")), "source": str(step.get("source", "Unknown")),
            "target": str(step.get("target", "Unknown")), "detection": str(step.get("detection", "Cần điều tra")),
            "icon": str(step.get("icon", "◆"))[:2],
        })
    if not clean_steps:
        raise RuntimeError("LLM không trích xuất được bước tấn công.")
    data["steps"] = clean_steps[:8]
    data["techniques"] = [{"id": s["techniqueId"], "name": s["action"], "tactic": s["tactic"]} for s in data["steps"]]
    data["engine"] = "llm"
    return data
