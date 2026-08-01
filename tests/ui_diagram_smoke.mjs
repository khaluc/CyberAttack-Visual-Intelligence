import fs from "node:fs";
import vm from "node:vm";

const app = { innerHTML: "" };
const document = {
  querySelector: selector => selector === "#app" ? app : null,
  querySelectorAll: () => [],
  addEventListener: () => {},
};
const sandbox = {
  document,
  window: { CYBER_SAMPLE: "incident sample" },
  fetch: () => new Promise(() => {}),
  setTimeout,
  clearTimeout,
  URL,
  Blob,
  console,
};
const context = vm.createContext(sandbox);
vm.runInContext(
  fs.readFileSync(new URL("../static/app.js", import.meta.url), "utf8"),
  context,
);

sandbox.__fixture = {
  incidentName: "RAW Ransomware incident",
  severity: "critical",
  confidence: 87,
  entities: ["Attacker", "Web server"],
  techniques: [{ id: "T1059.001" }],
  steps: [],
  structured_json: {
    incident_name: "RAW PowerShell ransomware incident",
    summary: "RAW attacker used PowerShell to deploy ransomware.",
    display_vi: {
      incident_name: "Sự cố ransomware qua PowerShell",
      summary: "Chuỗi tấn công bằng PowerShell đã được hợp nhất.",
      severity: "Nghiêm trọng",
    },
    metadata: {
      rag: { backend: "chroma", embedding: "BAAI/bge-m3" },
      knowledge: { ready: true, matches: 1, sources: ["sigma"] },
    },
    steps: [{
      order: 1,
      actor: "RAW Attacker",
      action: "RAW Execute PowerShell",
      target: "RAW Web server",
      asset: "RAW Production server",
      severity: "Critical",
      evidence: "RAW PowerShell downloaded ransomware.",
      detection: "RAW Monitor PowerShell telemetry.",
      mitigation: "RAW Restrict PowerShell.",
      procedure: "RAW Threat actor downloads a payload.",
      mitre: { tactic: "Execution", technique_id: "T1059.001" },
      display_vi: {
        actor: "Kẻ tấn công",
        action: "Thực thi <img src=x onerror=alert(1)> PowerShell",
        target: "Máy chủ web",
        asset: "Máy chủ sản xuất",
        severity: "Nghiêm trọng",
        tactic: "Thực thi",
        technique_name: "PowerShell",
        description: "PowerShell đã tải ransomware.",
        detection: "Giám sát telemetry của PowerShell.",
        mitigation: "Hạn chế PowerShell.",
        procedure: "Đối tượng đe dọa tải payload.",
      },
      rag_confidence: 0.4321,
      rag: {
        query: "PowerShell execution",
        matches: [{
          technique_id: "T1059.001",
          technique_name: "RAW PowerShell technique",
          tactics: "Execution",
          score: 0.4321,
          description: "RAW Adversaries may abuse PowerShell.",
          display_vi: {
            technique_name: "PowerShell",
            tactics: "Thực thi",
            description: "Đối tượng tấn công có thể lạm dụng PowerShell.",
          },
        }],
      },
      knowledge: {
        matches: [{
          source: "sigma",
          document_type: "detection_rule",
          title: "RAW Suspicious PowerShell",
          snippet: "RAW Detects encoded PowerShell.",
          display_vi: {
            title: "Quy tắc PowerShell đáng ngờ",
            snippet: "Phát hiện PowerShell mã hóa.",
          },
          origin: "rules/powershell.yml",
          metadata: { level: "high" },
        }],
      },
    }],
  },
};

vm.runInContext(
  "state.result=globalThis.__fixture;state.selected=0;globalThis.__diagram=diagram();",
  context,
);

const html = sandbox.__diagram;
for (const expected of [
  "Luồng tấn công tổng hợp",
  "Ngữ cảnh hành vi",
  "Tri thức MITRE ATT&CK",
  "T1059.001 · PowerShell",
  "SIM 0.432",
  "Sự cố ransomware qua PowerShell",
  "Thực thi &lt;img src=x onerror=alert(1)&gt; PowerShell",
  "Giám sát telemetry của PowerShell.",
  "Hạn chế PowerShell.",
  "Đối tượng đe dọa tải payload.",
  "Các ứng viên RAG",
  "Bằng chứng từ kho tri thức",
  "Quy tắc PowerShell đáng ngờ",
]) {
  if (!html.includes(expected)) {
    throw new Error(`Consolidated diagram is missing: ${expected}`);
  }
}
for (const rawEnglish of [
  "RAW PowerShell ransomware incident",
  "RAW attacker used PowerShell to deploy ransomware.",
  "RAW Attacker",
  "RAW Execute PowerShell",
  "RAW Web server",
  "RAW Production server",
  "RAW PowerShell downloaded ransomware.",
  "RAW Monitor PowerShell telemetry.",
  "RAW Restrict PowerShell.",
  "RAW Threat actor downloads a payload.",
  "RAW PowerShell technique",
  "RAW Adversaries may abuse PowerShell.",
  "RAW Suspicious PowerShell",
  "RAW Detects encoded PowerShell.",
]) {
  if (html.includes(rawEnglish)) {
    throw new Error(`Primary diagram leaked raw English content: ${rawEnglish}`);
  }
}
if (html.includes("<img src=x onerror=alert(1)>")) {
  throw new Error("Consolidated diagram did not escape dynamic content.");
}
if (vm.runInContext("similarityLabel(null)", context) !== "") {
  throw new Error("A missing RAG score must not be rendered as SIM 0.000.");
}

console.log(`diagram-render-ok ${html.length}`);
