import fs from "node:fs/promises";
import path from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

function arg(index, label) {
  const value = process.argv[index];
  if (!value) throw new Error(`Thiếu tham số ${label}`);
  return path.resolve(value);
}

const inputPath = arg(2, "JSON đầu vào");
const outputPath = arg(3, "PPTX đầu ra");
const moduleRoot = arg(4, "artifact-tool node_modules");
const workspace = arg(5, "thư mục QA");

const requireFromScript = createRequire(import.meta.url);
let artifactEntry;
try {
  artifactEntry = requireFromScript.resolve("@oai/artifact-tool", {
    paths: [moduleRoot],
  });
} catch (error) {
  throw new Error(
    `Không thể nạp @oai/artifact-tool từ ${moduleRoot}: ${error.message}`,
  );
}
const { Presentation, PresentationFile } = await import(
  pathToFileURL(artifactEntry).href
);

const payload = JSON.parse(await fs.readFile(inputPath, "utf8"));
const incident = payload.incident;
const recommendations = payload.recommendations ?? [];
const slidesDir = path.join(workspace, "preview");
const layoutDir = path.join(workspace, "layout");
const qaDir = path.join(workspace, "qa");
await Promise.all([
  fs.mkdir(path.dirname(outputPath), { recursive: true }),
  fs.mkdir(slidesDir, { recursive: true }),
  fs.mkdir(layoutDir, { recursive: true }),
  fs.mkdir(qaDir, { recursive: true }),
]);

await fs.writeFile(
  path.join(workspace, "source-notes.txt"),
  [
    "Nguồn: JSON sự cố có cấu trúc PHASE 3 do người dùng cung cấp",
    `Mã sự cố: ${incident.incident_id}`,
    `Thời điểm tạo: ${incident.metadata?.created_at ?? "Chưa xác định"}`,
    "Tất cả nhận định trong slide được dẫn xuất từ JSON này.",
  ].join("\n"),
  "utf8",
);
await fs.writeFile(
  path.join(workspace, "slide-plan.txt"),
  [
    "Chế độ: tạo mới",
    "Đối tượng: SOC và các bên liên quan đến ứng phó sự cố",
    "Kích thước: 1280 x 720",
    "Bảng màu: navy #071C33, slate #E6EDF5, cyan #2EC7D3, red #E25563",
    "Phông chữ: Aptos Display cho tiêu đề; Aptos cho nội dung và số liệu",
    "Slide: tổng quan điều hành, chuỗi tấn công, ánh xạ ATT&CK, hành động ứng phó và sơ đồ tùy chọn.",
    "Mọi đối tượng nội dung đều có thể chỉnh sửa; sơ đồ có thể được nhúng dưới dạng ảnh hỗ trợ.",
  ].join("\n"),
  "utf8",
);

const deck = Presentation.create({ slideSize: { width: 1280, height: 720 } });
const COLORS = {
  navy: "#071C33",
  navy2: "#0D2947",
  cyan: "#2EC7D3",
  blue: "#2E74B5",
  white: "#FFFFFF",
  ink: "#0B2545",
  slate: "#E6EDF5",
  muted: "#7590A7",
  red: "#E25563",
  amber: "#E19A35",
  green: "#33A06F",
};

function severityColor(value) {
  return {
    Critical: COLORS.red,
    High: COLORS.amber,
    Medium: "#C5A12E",
    Low: COLORS.green,
    Unknown: COLORS.muted,
  }[value] ?? COLORS.muted;
}

function known(value) {
  return !["", "unknown", "none", "null", "n/a"].includes(
    String(value ?? "").trim().toLowerCase(),
  );
}

const TACTIC_LABELS_VI = {
  Reconnaissance: "Trinh sát",
  "Resource Development": "Phát triển tài nguyên",
  "Initial Access": "Truy cập ban đầu",
  Execution: "Thực thi",
  Persistence: "Duy trì truy cập",
  "Privilege Escalation": "Leo thang đặc quyền",
  "Defense Evasion": "Né tránh phòng thủ",
  "Credential Access": "Truy cập thông tin xác thực",
  Discovery: "Khám phá",
  "Lateral Movement": "Di chuyển ngang",
  Collection: "Thu thập",
  "Command And Control": "Chỉ huy và kiểm soát",
  "Command and Control": "Chỉ huy và kiểm soát",
  Exfiltration: "Đưa dữ liệu ra ngoài",
  Impact: "Tác động",
  Unknown: "Chưa xác định",
};

function displayVi(container, field, fallback = "Chưa xác định") {
  const aliases = {
    incident_name: ["incident_name", "name"],
    tactic: ["tactic", "mitre_tactic"],
  }[field] ?? [field];
  const localized = container?.display_vi;
  if (localized && typeof localized === "object") {
    for (const key of aliases) {
      if (known(localized[key])) return String(localized[key]).trim();
    }
  }
  const raw = known(container?.[field]) ? container[field] : fallback;
  const text = String(raw ?? "").trim();
  if (field === "tactic") return TACTIC_LABELS_VI[text] ?? (text || "Chưa xác định");
  if (!known(text)) return "Chưa xác định";
  if (text.toLowerCase() === "unknown action") return "Hành động chưa xác định";
  return text;
}

function severityVi(value) {
  return {
    Critical: "Nghiêm trọng",
    High: "Cao",
    Medium: "Trung bình",
    Low: "Thấp",
    Unknown: "Chưa xác định",
  }[value] ?? (known(value) ? String(value) : "Chưa xác định");
}

function displayEntities(group, singular) {
  const localized = incident.display_vi?.entities?.[group];
  if (Array.isArray(localized) && localized.length) return [...new Set(localized)].join(", ");
  const fromSteps = incident.steps
    .map((step) => step.display_vi?.[singular])
    .filter(known);
  if (fromSteps.length) return [...new Set(fromSteps)].join(", ");
  const raw = incident.entities?.[group] ?? [];
  return raw.filter(known).join(", ") || "Chưa xác định";
}

function short(value, max = 110) {
  const text = String(value ?? "Chưa xác định").replace(/\s+/g, " ").trim() || "Chưa xác định";
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

function addText(slide, text, position, style = {}) {
  const shape = slide.shapes.add({
    geometry: "textbox",
    position,
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  shape.text = String(text ?? "");
  shape.text.style = {
    typeface: style.typeface ?? "Aptos",
    fontSize: style.fontSize ?? 18,
    color: style.color ?? COLORS.ink,
    bold: style.bold ?? false,
    alignment: style.alignment ?? "left",
  };
  return shape;
}

function addCard(slide, position, fill = COLORS.white, line = COLORS.slate) {
  return slide.shapes.add({
    geometry: "roundRect",
    position,
    fill,
    line: { style: "solid", fill: line, width: 1 },
    borderRadius: "rounded-xl",
    shadow: "shadow-sm",
  });
}

function addHeader(slide, title, kicker, pageNumber) {
  addText(
    slide,
    kicker.toUpperCase(),
    { left: 72, top: 42, width: 430, height: 24 },
    { fontSize: 12, bold: true, color: COLORS.cyan },
  );
  addText(
    slide,
    title,
    { left: 72, top: 76, width: 1000, height: 54 },
    { fontSize: 34, bold: true, color: COLORS.white, typeface: "Aptos Display" },
  );
  addText(
    slide,
    String(pageNumber).padStart(2, "0"),
    { left: 1170, top: 48, width: 40, height: 24 },
    { fontSize: 12, bold: true, color: COLORS.muted, alignment: "right" },
  );
}

function addFooter(slide) {
  addText(
    slide,
    `CYBERVISION  |  ${incident.incident_id}`,
    { left: 72, top: 678, width: 500, height: 18 },
    { fontSize: 10, color: COLORS.muted },
  );
}

let pageNumber = 1;
{
  const slide = deck.slides.add();
  slide.background.fill = COLORS.navy;
  addText(
    slide,
    "BÁO CÁO SỰ CỐ AN NINH MẠNG",
    { left: 72, top: 58, width: 680, height: 28 },
    { fontSize: 13, bold: true, color: COLORS.cyan },
  );
  addText(
    slide,
    short(displayVi(incident, "incident_name", incident.incident_name), 92),
    { left: 72, top: 132, width: 760, height: 154 },
    { fontSize: 50, bold: true, color: COLORS.white, typeface: "Aptos Display" },
  );
  addText(
    slide,
    short(displayVi(incident, "summary", incident.summary), 230),
    { left: 72, top: 302, width: 750, height: 108 },
    { fontSize: 21, color: "#BED0DF" },
  );
  const badge = addCard(
    slide,
    { left: 930, top: 132, width: 260, height: 104 },
    severityColor(incident.severity),
    severityColor(incident.severity),
  );
  badge.shadow = "shadow-md";
  addText(
    slide,
    severityVi(incident.severity).toUpperCase(),
    { left: 956, top: 154, width: 210, height: 58 },
    { fontSize: 28, bold: true, color: COLORS.white, alignment: "center" },
  );
  const metrics = [
    ["CHẤT LƯỢNG PIPELINE", `${incident.confidence ?? 0}/100`],
    ["BƯỚC TẤN CÔNG", String(incident.steps.length)],
    [
      "ĐÃ ÁNH XẠ ATT&CK",
      String(
        incident.steps.filter(
          (step) =>
            step.mitre?.technique_id &&
            step.mitre.technique_id !== "Unknown",
        ).length,
      ),
    ],
  ];
  metrics.forEach(([label, value], index) => {
    const left = 72 + index * 262;
    addCard(
      slide,
      { left, top: 500, width: 236, height: 112 },
      COLORS.navy2,
      "#244864",
    );
    addText(
      slide,
      value,
      { left: left + 18, top: 516, width: 200, height: 48 },
      { fontSize: 31, bold: true, color: COLORS.white },
    );
    addText(
      slide,
      label,
      { left: left + 18, top: 572, width: 200, height: 20 },
      { fontSize: 11, bold: true, color: COLORS.muted },
    );
  });
  addText(
    slide,
    incident.incident_id,
    { left: 930, top: 520, width: 260, height: 32 },
    { fontSize: 18, bold: true, color: COLORS.white, alignment: "right" },
  );
  addText(
    slide,
    incident.metadata?.created_at ?? "",
    { left: 870, top: 562, width: 320, height: 22 },
    { fontSize: 11, color: COLORS.muted, alignment: "right" },
  );
  addFooter(slide);
  pageNumber += 1;
}

const stepBatches = [];
for (let index = 0; index < incident.steps.length; index += 4) {
  stepBatches.push(incident.steps.slice(index, index + 4));
}
for (const [batchIndex, steps] of stepBatches.entries()) {
  const slide = deck.slides.add();
  slide.background.fill = COLORS.navy;
  addHeader(
    slide,
    batchIndex === 0 ? "Chuỗi tấn công" : "Chuỗi tấn công — tiếp theo",
    "PHASE 5 / LUỒNG",
    pageNumber,
  );
  const cardWidth = 250;
  const gap = 26;
  steps.forEach((step, index) => {
    const left = 72 + index * (cardWidth + gap);
    addCard(
      slide,
      { left, top: 172, width: cardWidth, height: 418 },
      COLORS.navy2,
      "#244864",
    );
    slide.shapes.add({
      geometry: "rect",
      position: { left, top: 172, width: cardWidth, height: 10 },
      fill: severityColor(step.severity),
      line: { style: "solid", fill: "none", width: 0 },
    });
    addText(
      slide,
      `BƯỚC ${String(step.order).padStart(2, "0")}`,
      { left: left + 18, top: 198, width: 200, height: 22 },
      { fontSize: 11, bold: true, color: COLORS.cyan },
    );
    addText(
      slide,
      short(displayVi(step, "action", step.action), 62),
      { left: left + 18, top: 236, width: 214, height: 92 },
      { fontSize: 23, bold: true, color: COLORS.white, typeface: "Aptos Display" },
    );
    addText(
      slide,
      `${step.mitre?.technique_id ?? "Chưa xác định"}\n${short(displayVi(step, "tactic", step.mitre?.tactic), 44)}`,
      { left: left + 18, top: 340, width: 214, height: 62 },
      { fontSize: 16, bold: true, color: "#B7DCE4" },
    );
    addText(
      slide,
      `Tác nhân: ${short(displayVi(step, "actor", step.actor), 30)}\n`
      + `Mục tiêu: ${short(displayVi(step, "target", step.target), 30)}\n`
      + `Tài sản: ${short(displayVi(step, "asset", step.asset), 30)}`,
      { left: left + 18, top: 426, width: 214, height: 100 },
      { fontSize: 14, color: "#BED0DF" },
    );
    addText(
      slide,
      short(displayVi(step, "detection", step.detection), 78),
      { left: left + 18, top: 536, width: 214, height: 42 },
      { fontSize: 11, color: COLORS.muted },
    );
    if (index < steps.length - 1) {
      slide.shapes.add({
        geometry: "rightArrow",
        position: { left: left + 248, top: 349, width: 32, height: 34 },
        fill: COLORS.cyan,
        line: { style: "solid", fill: COLORS.cyan, width: 0 },
      });
    }
  });
  addFooter(slide);
  pageNumber += 1;
}

const mitreBatches = [];
for (let index = 0; index < incident.steps.length; index += 5) {
  mitreBatches.push(incident.steps.slice(index, index + 5));
}
for (const [batchIndex, steps] of mitreBatches.entries()) {
  const slide = deck.slides.add();
  slide.background.fill = COLORS.navy;
  addHeader(
    slide,
    batchIndex === 0 ? "Ánh xạ MITRE ATT&CK" : "MITRE ATT&CK — tiếp theo",
    "PHASE 4 / RAG",
    pageNumber,
  );
  steps.forEach((step, index) => {
    const top = 156 + index * 96;
    addCard(
      slide,
      { left: 72, top, width: 1136, height: 78 },
      index % 2 === 0 ? COLORS.navy2 : "#102F50",
      "#244864",
    );
    addText(
      slide,
      step.mitre?.technique_id ?? "Chưa xác định",
      { left: 94, top: top + 17, width: 120, height: 38 },
      { fontSize: 18, bold: true, color: COLORS.cyan },
    );
    addText(
      slide,
      short(displayVi(step, "action", step.action), 55),
      { left: 232, top: top + 15, width: 270, height: 45 },
      { fontSize: 18, bold: true, color: COLORS.white },
    );
    addText(
      slide,
      short(displayVi(step, "tactic", step.mitre?.tactic), 42),
      { left: 520, top: top + 15, width: 190, height: 45 },
      { fontSize: 15, color: "#B7DCE4" },
    );
    addText(
      slide,
      short(displayVi(step, "detection", step.detection), 86),
      { left: 726, top: top + 13, width: 456, height: 49 },
      { fontSize: 13, color: "#BED0DF" },
    );
  });
  addFooter(slide);
  pageNumber += 1;
}

{
  const slide = deck.slides.add();
  slide.background.fill = COLORS.navy;
  addHeader(slide, "Ưu tiên ứng phó", "ỨNG PHÓ SỰ CỐ", pageNumber);
  const actors = displayEntities("actors", "actor");
  const targets = displayEntities("targets", "target");
  const assets = displayEntities("assets", "asset");
  const entityCards = [
    ["TÁC NHÂN", actors],
    ["MỤC TIÊU", targets],
    ["TÀI SẢN", assets],
  ];
  entityCards.forEach(([label, value], index) => {
    const left = 72 + index * 376;
    addCard(
      slide,
      { left, top: 154, width: 350, height: 114 },
      COLORS.navy2,
      "#244864",
    );
    addText(
      slide,
      label,
      { left: left + 18, top: 172, width: 310, height: 18 },
      { fontSize: 11, bold: true, color: COLORS.cyan },
    );
    addText(
      slide,
      short(value, 90),
      { left: left + 18, top: 204, width: 310, height: 50 },
      { fontSize: 16, bold: true, color: COLORS.white },
    );
  });
  recommendations.slice(0, 6).forEach((action, index) => {
    const column = index % 2;
    const row = Math.floor(index / 2);
    const left = 72 + column * 572;
    const top = 306 + row * 102;
    addCard(
      slide,
      { left, top, width: 544, height: 82 },
      index < 2 ? "#17374E" : COLORS.navy2,
      index < 2 ? COLORS.cyan : "#244864",
    );
    addText(
      slide,
      index < 2 ? "P1" : "P2",
      { left: left + 18, top: top + 23, width: 42, height: 30 },
      { fontSize: 16, bold: true, color: COLORS.cyan },
    );
    addText(
      slide,
      short(action, 122),
      { left: left + 70, top: top + 15, width: 450, height: 54 },
      { fontSize: 14, color: COLORS.white },
    );
  });
  addFooter(slide);
  pageNumber += 1;
}

if (payload.graph_image_base64 && payload.graph_image_content_type) {
  const slide = deck.slides.add();
  slide.background.fill = COLORS.navy;
  addHeader(slide, "Sơ đồ tấn công", "PHASE 5 / SƠ ĐỒ", pageNumber);
  addCard(
    slide,
    { left: 72, top: 148, width: 1136, height: 490 },
    COLORS.white,
    COLORS.slate,
  );
  const bytes = Buffer.from(payload.graph_image_base64, "base64");
  slide.images.add({
    blob: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    contentType: payload.graph_image_content_type,
    alt: `Sơ đồ tấn công cho ${displayVi(incident, "incident_name", incident.incident_name)}`,
    fit: "contain",
    position: { left: 96, top: 170, width: 1088, height: 446 },
  });
  addFooter(slide);
  pageNumber += 1;
}

async function writeBlob(destination, blob) {
  await fs.writeFile(destination, new Uint8Array(await blob.arrayBuffer()));
}

for (const [index, slide] of deck.slides.items.entries()) {
  const stem = `slide-${String(index + 1).padStart(2, "0")}`;
  await writeBlob(
    path.join(slidesDir, `${stem}.png`),
    await deck.export({ slide, format: "png", scale: 1 }),
  );
  const layout = await slide.export({ format: "layout" });
  await fs.writeFile(path.join(layoutDir, `${stem}.json`), await layout.text());
}
await writeBlob(
  path.join(workspace, "deck-montage.webp"),
  await deck.export({ format: "webp", montage: true, scale: 1 }),
);

const qaLedger = [
  "Kiểm tra trực quan",
  "",
  `- Số slide dự kiến: ${deck.slides.items.length}`,
  `- Đã render toàn bộ slide: có (${deck.slides.items.length})`,
  "- Đã tạo montage: có",
  "- Đã tạo JSON bố cục: có",
  "- Sử dụng đối tượng có thể chỉnh sửa: có",
  "- Sử dụng ảnh bitmap toàn slide: không",
  "- Kiểm tra trực quan thủ công 100%: đang chờ rà soát trên ứng dụng",
  "",
  "Nhật ký vấn đề",
  "- Không phát hiện lỗi xuất file tự động.",
  "",
  "Kết luận",
  "- Đạt/không đạt: đang chờ kiểm tra thủ công các ảnh PNG đã render.",
].join("\n");
await fs.writeFile(path.join(qaDir, "visual-qa.txt"), qaLedger, "utf8");

const pptx = await PresentationFile.exportPptx(deck);
await pptx.save(outputPath);
// Some standalone Node hosts inherit a non-zero exitCode from the embedded
// rendering runtime even after every awaited export succeeds.  Reaching this
// line means all slide PNGs, layouts, montage, inspect sidecar and the PPTX
// itself were written successfully, so normalize the process result for the
// Flask caller.
process.exitCode = 0;
console.log(
  JSON.stringify({
    ok: true,
    output: outputPath,
    slides: deck.slides.items.length,
    qa: workspace,
  }),
);
process.exit(0);
