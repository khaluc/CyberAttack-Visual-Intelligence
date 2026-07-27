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
  incidentName: "Ransomware incident",
  severity: "critical",
  confidence: 87,
  entities: ["Attacker", "Web server"],
  techniques: [{ id: "T1059.001" }],
  steps: [],
  structured_json: {
    incident_name: "Ransomware incident",
    summary: "Chuỗi tấn công đã được hợp nhất.",
    metadata: {
      rag: { backend: "chroma", embedding: "BAAI/bge-m3" },
      knowledge: { ready: true, matches: 1, sources: ["sigma"] },
    },
    steps: [{
      order: 1,
      actor: "Attacker",
      action: "Execute <script>alert(1)</script> PowerShell",
      target: "Web server",
      asset: "Production server",
      severity: "Critical",
      evidence: "PowerShell tải ransomware.",
      detection: "Monitor PowerShell telemetry.",
      mitigation: "Restrict PowerShell.",
      procedure: "Threat actor downloads a payload.",
      mitre: { tactic: "Execution", technique_id: "T1059.001" },
      rag_confidence: 0.4321,
      rag: {
        query: "PowerShell execution",
        matches: [{
          technique_id: "T1059.001",
          technique_name: "PowerShell",
          tactics: "Execution",
          score: 0.4321,
          description: "Adversaries may abuse PowerShell.",
        }],
      },
      knowledge: {
        matches: [{
          source: "sigma",
          document_type: "detection_rule",
          title: "Suspicious PowerShell",
          snippet: "Detects encoded PowerShell.",
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
  "Attack Flow tổng hợp",
  "Ngữ cảnh hành vi",
  "MITRE ATT&CK Intelligence",
  "T1059.001 · PowerShell",
  "SIM 0.432",
  "Monitor PowerShell telemetry.",
  "Restrict PowerShell.",
  "Threat actor downloads a payload.",
  "RAG candidates",
  "Knowledge evidence",
  "Suspicious PowerShell",
]) {
  if (!html.includes(expected)) {
    throw new Error(`Consolidated diagram is missing: ${expected}`);
  }
}
if (html.includes("<script>alert(1)</script>")) {
  throw new Error("Consolidated diagram did not escape dynamic content.");
}
if (vm.runInContext("similarityLabel(null)", context) !== "") {
  throw new Error("A missing RAG score must not be rendered as SIM 0.000.");
}

console.log(`diagram-render-ok ${html.length}`);
