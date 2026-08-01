"""Local Vietnamese incident analysis and MITRE ATT&CK mapping engine."""

CATALOG = [
    (["email", "phishing", "giả mạo", "lừa đảo", "đính kèm"], "Gửi email lừa đảo", "Initial Access", "T1566.001", "Email lừa đảo có tệp đính kèm độc hại được dùng để tiếp cận người dùng.", "Kẻ tấn công", "Nhân viên", "Nhật ký cổng bảo mật email", "✉"),
    (["macro", "word", "tài liệu", "mở tệp"], "Thực thi tệp độc hại", "Execution", "T1204.002", "Người dùng mở tệp đính kèm và kích hoạt nội dung khiến mã độc được thực thi.", "Tệp đính kèm", "Thiết bị đầu cuối", "Telemetry EDR", "▣"),
    (["powershell", "script", "cmd"], "Chạy PowerShell", "Execution", "T1059.001", "PowerShell được dùng để thực thi lệnh và tải payload từ hạ tầng bên ngoài.", "Tiến trình Office", "PowerShell", "Nhật ký Script Block", "⌘"),
    (["tải malware", "tải mã độc", "payload", "ransomware"], "Tải mã độc", "Command and Control", "T1105", "Payload bổ sung được truyền từ hệ thống bên ngoài vào môi trường nạn nhân.", "Máy chủ từ xa", "Thiết bị đầu cuối", "Nhật ký Proxy / NDR", "↓"),
    (["c2", "command and control", "kết nối"], "Thiết lập kết nối C2", "Command and Control", "T1071.001", "Mã độc giao tiếp với hạ tầng điều khiển qua giao thức web để nhận lệnh.", "Máy chủ đã bị xâm nhập", "Máy chủ C2", "Nhật ký DNS / mạng", "⌁"),
    (["đăng nhập", "credential", "thông tin đăng nhập", "mật khẩu"], "Đánh cắp thông tin đăng nhập", "Credential Access", "T1555.003", "Thông tin xác thực lưu trong trình duyệt bị thu thập để mở rộng quyền truy cập.", "Mã độc", "Thông tin xác thực trình duyệt", "Hành vi EDR", "⌾"),
    (["nâng quyền", "privilege"], "Nâng quyền đặc biệt", "Privilege Escalation", "T1068", "Đối tượng khai thác quyền truy cập hiện có để đạt đặc quyền cao hơn.", "Tài khoản đã bị xâm nhập", "Hệ thống cục bộ", "Sự kiện Windows", "⬆"),
    (["cơ sở dữ liệu", "database", "máy chủ"], "Truy cập máy chủ dữ liệu", "Lateral Movement", "T1021", "Thông tin xác thực bị đánh cắp được dùng để truy cập tài nguyên nội bộ quan trọng.", "Thiết bị đã bị xâm nhập", "Máy chủ cơ sở dữ liệu", "Nhật ký xác thực", "▤"),
    (["nén", "archive", "zip"], "Nén dữ liệu thu thập", "Collection", "T1560.001", "Dữ liệu được gom và nén trước khi đưa ra khỏi hệ thống.", "Cơ sở dữ liệu", "Tệp nén", "Telemetry tệp", "▥"),
    (["gửi ra ngoài", "gửi dữ liệu ra ngoài", "exfiltration", "tải lượng lớn", "đánh cắp dữ liệu"], "Đưa dữ liệu ra ngoài", "Exfiltration", "T1041", "Dữ liệu nhạy cảm được truyền qua kênh C2 hiện hữu đến hạ tầng đối tượng.", "Máy chủ nội bộ", "Máy chủ bên ngoài", "Cảnh báo DLP / NDR", "↗"),
    (["mã hóa dữ liệu", "xóa bản sao", "ransomware"], "Mã hóa dữ liệu", "Impact", "T1486", "Đối tượng mã hóa dữ liệu nhằm làm gián đoạn hoạt động và tống tiền.", "Ransomware", "Dữ liệu doanh nghiệp", "Cảnh báo EDR / sao lưu", "◆"),
    (["lỗ hổng", "khai thác"], "Khai thác dịch vụ công khai", "Initial Access", "T1190", "Lỗ hổng trên ứng dụng hướng Internet được khai thác để giành quyền truy cập ban đầu.", "Kẻ tấn công", "Máy chủ công khai", "Cảnh báo WAF / IDS", "⚡"),
]

RETRIEVAL_QUERIES_EN = {
    "T1566.001": "attacker sends spearphishing email with malicious attachment to employee",
    "T1204.002": "user opens malicious document and enables active content",
    "T1059.001": "powershell command and script interpreter executes malicious payload",
    "T1105": "malware downloads ingress tool transfer payload from remote host",
    "T1071.001": "malware establishes command and control over web protocol",
    "T1555.003": "malware steals credentials from web browser credential store",
    "T1068": "adversary exploits vulnerability to escalate privileges",
    "T1021": "adversary uses remote services for lateral movement",
    "T1560.001": "adversary compresses and archives collected data",
    "T1041": "adversary exfiltrates data over command and control channel",
    "T1486": "ransomware encrypts data for impact and deletes recovery copies",
    "T1190": "adversary exploits public-facing web application vulnerability",
}

SAMPLE = "Kẻ tấn công gửi email giả mạo phòng nhân sự có đính kèm tài liệu Word độc hại cho nhân viên. Khi người dùng mở tệp và bật macro, một script PowerShell được thực thi để tải malware từ máy chủ bên ngoài. Malware thiết lập kết nối C2, đánh cắp thông tin đăng nhập trình duyệt, sau đó truy cập máy chủ cơ sở dữ liệu và nén dữ liệu khách hàng để gửi ra ngoài."


def analyze_incident(text: str) -> dict:
    normalized = text.lower()
    steps, seen = [], set()
    for keys, action, tactic, tid, description, source, target, detection, icon in CATALOG:
        if any(key in normalized for key in keys) and tid not in seen:
            seen.add(tid)
            steps.append({"id": len(steps) + 1, "action": action, "tactic": tactic,
                          "techniqueId": tid, "description": description, "source": source,
                          "target": target, "detection": detection, "icon": icon})
    steps = steps[:7]
    if not steps:
        # A degraded local fallback must remain honest when no rule matches.
        # Do not manufacture a phishing/PowerShell/C2 chain merely to make the
        # diagram look populated.
        steps.append({
            "id": 1,
            "action": "Phân tích hoạt động đáng ngờ",
            "tactic": "Unknown",
            "techniqueId": "Unknown",
            "description": (
                "Không đủ bằng chứng trong mô tả để ánh xạ hành vi ATT&CK."
            ),
            "source": "Unknown",
            "target": "Unknown",
            "detection": "Cần bổ sung log và telemetry để xác minh.",
            "icon": "◆",
        })
    critical = any(s["tactic"] in ("Exfiltration", "Impact") for s in steps)
    high = any(s["tactic"] in ("Credential Access", "Lateral Movement", "Command and Control") for s in steps)
    severity = "critical" if critical else "high" if high else "medium" if len(steps) >= 3 else "low"
    completeness = sum(
        value not in ("", "Unknown", None)
        for step in steps
        for value in (
            step.get("source"),
            step.get("action"),
            step.get("target"),
            step.get("detection"),
        )
    ) / (max(1, len(steps)) * 4)
    tactic_coverage = sum(
        step.get("tactic") not in ("", "Unknown", None) for step in steps
    ) / max(1, len(steps))
    severity_coverage = 1.0 if severity else 0.0
    source_reliability = 0.55
    confidence = round(
        100
        * (
            0.40 * completeness
            + 0.20 * tactic_coverage
            + 0.15 * severity_coverage
            + 0.25 * source_reliability
        )
    )
    entity_rules = [("Email", "email"), ("PowerShell", "powershell"), ("Tệp Word", "word"),
                    ("Máy chủ C2", "c2"), ("Cơ sở dữ liệu", "cơ sở dữ liệu"),
                    ("Thông tin đăng nhập", "đăng nhập"), ("Ransomware", "ransomware"),
                    ("Dữ liệu khách hàng", "khách hàng")]
    entities = [name for name, key in entity_rules if key in normalized] or ["Kẻ tấn công", "Thiết bị đầu cuối", "Hạ tầng mạng"]
    result = {
        "incidentName": "Xâm nhập và đánh cắp dữ liệu đa giai đoạn" if critical else "Chiến dịch xâm nhập hệ thống" if high else "Hoạt động đáng ngờ trên endpoint",
        "severity": severity, "confidence": confidence,
        "confidence_breakdown": {
            "stage": "local_rule_engine",
            "source": "local_fallback",
            "structure_completeness": round(completeness, 4),
            "tactic_coverage": round(tactic_coverage, 4),
            "severity_coverage": severity_coverage,
            "source_reliability": source_reliability,
            "methodology": "weighted_pipeline_quality_v1",
        },
        "steps": steps, "techniques": [{"id": s["techniqueId"], "name": s["action"], "tactic": s["tactic"]} for s in steps],
        "entities": entities,
        "executiveSummary": f"Phân tích xác định một chuỗi tấn công gồm {len(steps)} giai đoạn, từ {steps[0]['action'].lower()} đến {steps[-1]['action'].lower()}. Đối tượng kết hợp nhiều kỹ thuật nhằm gây ảnh hưởng đến tính bảo mật của hệ thống.",
        "engine": "local",
        "recommendations": [
            "Cô lập ngay các endpoint và tài khoản có dấu hiệu bị xâm nhập.",
            "Chặn IOC liên quan trên email gateway, DNS, proxy và firewall.",
            "Thu hồi phiên đăng nhập, xoay vòng thông tin xác thực bị ảnh hưởng.",
            "Bật giám sát PowerShell, process tree và lưu lượng outbound bất thường.",
            "Threat hunting toàn môi trường theo các technique ATT&CK đã ánh xạ."
        ]
    }
    result["phase2"] = [{
        "step": step["id"], "actor": step["source"], "action": step["action"],
        "target": step["target"], "asset": step["target"],
        "severity": severity.title(), "mitre_tactic": step["tactic"] or "Unknown",
        "technique_id": step["techniqueId"],
        "retrieval_query_en": RETRIEVAL_QUERIES_EN.get(
            step["techniqueId"], f"{step['techniqueId']} {step['tactic']}"
        ),
    } for step in steps]
    return result


def retrieve_attack_context(text: str, limit: int = 8) -> str:
    """Small deterministic RAG retriever over the bundled ATT&CK catalog."""
    normalized = text.lower()
    scored = []
    for row in CATALOG:
        keys, action, tactic, tid, description, *_ = row
        score = sum(2 if key in normalized else sum(1 for token in key.split() if token in normalized)
                    for key in keys)
        if score:
            scored.append((score, f"{tid} | {tactic} | {action} | {description}"))
    scored.sort(key=lambda item: item[0], reverse=True)
    return "\n".join(item[1] for item in scored[:limit])
