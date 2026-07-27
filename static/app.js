const $ = (s, root=document) => root.querySelector(s);
const esc = value => String(value == null ? "" : value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {nav:"Phân tích sự cố", result:null, selected:0, tab:"diagram", graphEngine:"graphviz", graphPreviewUrl:null, history:[], config:null, knowledge:null, knowledgeResults:null, knowledgeBusy:false, vectorBackends:null};
const sev = {critical:["Nghiêm trọng","critical"],high:["Cao","high"],medium:["Trung bình","medium"],low:["Thấp","low"]};
const icons = {dashboard:"▦",analysis:"◉",knowledge:"◇",history:"◷",help:"?",settings:"⚙"};

function shell(content){
  return `<div class="app">
  <aside class="sidebar">
    <div class="brand"><div class="brand-mark">⬡<span></span></div><div><b>CYBERVISION</b><small>VISUAL INTELLIGENCE</small></div></div>
    <nav>
      ${navButton("Tổng quan",icons.dashboard)}${navButton("Phân tích sự cố",icons.analysis)}${navButton("Kho tri thức",icons.knowledge)}${navButton("Lịch sử",icons.history)}
    </nav>
    <div class="side-bottom"><div class="system-status"><div><span class="live-dot"></span>Hệ thống hoạt động</div><small>Flask API · Sẵn sàng</small></div>
      <button onclick="toast('Tài liệu vận hành nằm trong README.md')">◯ <span>Trợ giúp</span></button><button onclick="openSettings()">⚙ <span>Cấu hình LLM & API</span></button>
      <div class="profile"><div class="avatar">NA</div><div><b>Nguyễn An</b><small>SOC Analyst</small></div><span>›</span></div>
    </div>
  </aside>
  <main><header><button class="mobile-menu" onclick="toggleMenu()">☰</button><div class="crumb"><span>Workspace</span><b>›</b><b>${state.nav}</b></div>
  <div class="header-actions"><button class="icon-btn">⌕</button><button class="icon-btn alert">♢<i></i></button><button class="connection" onclick="openSettings()"><span></span>${state.config&&state.config.enabled?"LLM ENABLED":"LOCAL ENGINE"}</button></div></header>${content}</main></div>`;
}
function navButton(name,icon){return `<button data-nav="${name}" class="${state.nav===name?"active":""}" onclick="navigate('${name}')"><b>${icon}</b><span>${name}</span>${name==="Lịch sử"&&state.history.length?`<em>${state.history.length}</em>`:""}</button>`}
function navigate(name){state.nav=name;render();if(name==="Kho tri thức")loadKnowledgeStatus()}
function toggleMenu(){$(".sidebar").classList.toggle("open")}
function pageTitle(title,subtitle,action=""){return `<div class="title-row"><div><h1>${title}</h1><p>${subtitle}</p></div>${action}</div>`}

function analysisPage(){
 return `<div class="page">${pageTitle("Phân tích sự cố","Chuyển đổi mô tả tiếng Việt thành sơ đồ tấn công và ATT&CK intelligence.",'<div class="title-badge">✦ AI-assisted analysis</div>')}
 <div class="workspace">
 <section class="input-panel panel">
  <div class="panel-head"><div><span class="step">01</span><b>Dữ liệu đầu vào</b></div><button class="ghost" onclick="clearInput()">Xóa</button></div>
  <div class="phase-strip"><span>PHASE 1</span><b>Chuẩn bị & chuẩn hóa dữ liệu</b></div>
  <div class="mode-tabs"><button id="desc-tab" class="active" onclick="setInputMode('desc')">▤ Text</button><button id="file-tab" onclick="setInputMode('file')">⇧ Email / Tài liệu / Log</button></div>
  <div id="desc-input" class="textarea-wrap"><textarea id="incident-input" maxlength="12000" oninput="updateCount()" placeholder="Mô tả sự cố bằng tiếng Việt...">${esc(window.CYBER_SAMPLE)}</textarea><span id="char-count">${window.CYBER_SAMPLE.length} ký tự</span></div>
  <label id="file-input" class="dropzone" style="display:none"><b style="font-size:26px">⇧</b><b>Thả dữ liệu bảo mật vào đây</b><span>hoặc bấm để chọn tệp</span><small>EMAIL · WORD · PDF · LOG · SYSLOG · FIREWALL · WINDOWS EVENT</small><input type="file" accept=".eml,.msg,.doc,.docx,.pdf,.txt,.md,.log,.syslog,.json,.xml,.csv,.cef,.leef,.evtx" onchange="loadFile(this.files[0])"></label>
  <div id="parser-info"></div>
  <div class="input-formats"><span>TXT</span><span>EML</span><span>DOCX</span><span>PDF</span><span>LOG</span><span>SYSLOG</span><span>CEF/LEEF</span><span>EVTX</span></div>
  <div class="quick-label">MẪU PHÂN TÍCH NHANH</div><div class="chips"><button onclick="sample('phishing')">Phishing & C2</button><button onclick="sample('ransomware')">Ransomware</button><button onclick="sample('exfil')">Data exfiltration</button></div>
  <button id="analyze" class="analyze-btn" onclick="analyze()">⚡ Phân tích sự cố <span>CTRL ↵</span></button>
  <div id="progress-wrap"></div><div class="privacy">✓ <span>Dữ liệu chỉ lưu trong phiên; khi bật LLM, mô tả được gửi đến provider đã cấu hình.</span></div>
 </section>
 <section class="result-panel panel"><div class="panel-head"><div><span class="step violet">02</span><b>Kết quả phân tích</b></div>${state.result?`<div class="export-menu"><button onclick="exportJSON()">JSON</button><button onclick="exportSVG()">SVG</button><button onclick="exportReport('docx')">DOCX</button><button onclick="exportReport('pptx')">PPTX</button><button class="primary-small" onclick="exportReport('pdf')">PDF</button></div>`:""}</div>
 ${state.result?resultsView():emptyView()}</section></div></div>`;
}
function emptyView(){return `<div class="empty"><div class="empty-orbit"><b style="font-size:28px">⬡</b><i></i><i></i></div><h3>Chưa có kết quả</h3><p>Nhập mô tả sự cố và chọn “Phân tích sự cố” để bắt đầu.</p></div>`}
function resultsView(){
 const r=state.result,[label,cl]=sev[r.severity];
 const engineLabel=r.fallback?"⚙ LOCAL ENGINE":`✦ ${String(r.engine||"LLM").toUpperCase()} + RAG`;
 return `${r.fallback?`<div class="fallback-notice">⚠ LLM gặp lỗi, kết quả được tạo bằng engine local. <button onclick="openSettings()">Kiểm tra cấu hình</button><small>${esc(r.llmError||"")}</small></div>`:""}<div class="summary"><div><span class="severity ${cl}">△ ${label}</span><span class="engine-badge">${esc(engineLabel)}</span><h2>${esc(r.incidentName)}</h2><p>⌾ ${r.entities.length} thực thể · ${r.techniques.length} kỹ thuật ATT&CK</p></div><button class="confidence" onclick="changeTab('phase3')" title="Xem cách tính confidence"><div style="--score:${r.confidence*3.6}deg"><b>${r.confidence}%</b></div><span>Pipeline confidence</span></button></div>
 <div class="result-tabs"><button data-tab="phase5" class="${state.tab==="phase5"?"active":""}" onclick="changeTab('phase5')">PHASE 5 · Graph</button><button data-tab="phase4" class="${state.tab==="phase4"?"active":""}" onclick="changeTab('phase4')">PHASE 4 · RAG</button><button data-tab="phase3" class="${state.tab==="phase3"?"active":""}" onclick="changeTab('phase3')">PHASE 3 · JSON</button><button data-tab="phase2" class="${state.tab==="phase2"?"active":""}" onclick="changeTab('phase2')">PHASE 2 · LLM</button><button data-tab="diagram" class="${state.tab==="diagram"?"active":""}" onclick="changeTab('diagram')">Sơ đồ</button><button data-tab="timeline" class="${state.tab==="timeline"?"active":""}" onclick="changeTab('timeline')">Timeline</button><button data-tab="report" class="${state.tab==="report"?"active":""}" onclick="changeTab('report')">Báo cáo</button></div>
 <div id="result-content">${renderResultTab()}</div>`;
}
function renderResultTab(){return state.tab==="phase5"?phase5View():state.tab==="phase4"?phase4View():state.tab==="phase3"?phase3View():state.tab==="phase2"?phase2View():state.tab==="diagram"?diagram():state.tab==="timeline"?timeline():report()}
function phase5View(){
 const d=state.result.structured_json,engine=state.graphEngine;
 return `<div class="phase5-output"><div class="graph-head"><div><span>PHASE 5</span><div><b>Graph Generation Engine</b><small>Structured JSON → node · edge · weight → visual artifact</small></div></div><div class="engine-switch">${["graphviz","mermaid","networkx"].map(x=>`<button class="${engine===x?"active":""}" onclick="setGraphEngine('${x}')">${x==="graphviz"?"Graphviz":x==="mermaid"?"Mermaid":"NetworkX"}</button>`).join("")}</div></div>
 <div class="visual-graph" id="graph-preview"><div class="graph-grid"></div><div class="graph-nodes">${d.steps.map((s,i)=>`${i?`<div class="graph-edge"><span>${Number(s.rag_confidence||d.confidence/100).toFixed(2)}</span><i></i><b>›</b></div>`:""}<div class="graph-node" style="--node-color:${graphColor(s.mitre.tactic)}"><small>STEP ${String(s.order).padStart(2,"0")}</small><b>${esc(s.action)}</b><span>${esc(s.mitre.technique_id)}</span><em>${esc(s.mitre.tactic)}</em></div>`).join("")}</div></div>
 <div class="graph-actions"><div><span>${engine==="graphviz"?"DOT → SVG / PNG":engine==="mermaid"?"flowchart LR → SVG":"DiGraph → Matplotlib PNG"}</span><b>${d.steps.length} nodes · ${Math.max(0,d.steps.length-1)} edges</b></div><button onclick="graphDownload('${engine}','${engine==="mermaid"?"mmd":engine==="networkx"?"json":"dot"}')">Source</button><button onclick="graphDownload('${engine}','svg')">SVG</button><button class="graph-primary" onclick="graphDownload('${engine}','png')">PNG</button></div>
 <div class="graph-source"><div><span>${engine==="graphviz"?"attack-graph.dot":engine==="mermaid"?"attack-graph.mmd":"networkx-graph.json"}</span><button onclick="graphDownload('${engine}','${engine==="mermaid"?"mmd":engine==="networkx"?"json":"dot"}')">↓ Download</button></div><pre>${esc(graphSource(engine,d))}</pre></div></div>`;
}
function setGraphEngine(engine){state.graphEngine=engine;$("#result-content").innerHTML=phase5View();loadGraphPreview(engine)}
async function loadGraphPreview(engine){const target=$("#graph-preview");if(!target||!state.result)return;target.classList.add("loading");try{const r=await fetch("/api/graph/render",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({structured_json:state.result.structured_json,engine,format:"svg"})});if(!r.ok){const d=await r.json();throw new Error(d.error||"Không render được sơ đồ.")}const blob=await r.blob();if(state.graphEngine!==engine||!target.isConnected)return;const url=URL.createObjectURL(blob),img=document.createElement("img");img.alt=`${engine} attack graph`;img.onload=()=>target.classList.remove("loading");img.onerror=()=>target.classList.remove("loading");img.src=url;target.replaceChildren(img);if(state.graphPreviewUrl)URL.revokeObjectURL(state.graphPreviewUrl);state.graphPreviewUrl=url}catch(e){if(!target.isConnected)return;target.classList.remove("loading");target.insertAdjacentHTML("beforeend",`<small class="graph-preview-error">${esc(e.message)}</small>`)}}
function graphColor(tactic){const colors={"Initial Access":"#1d78b5","Execution":"#8b5cf6","Credential Access":"#e08d3f","Command and Control":"#317bc2","Exfiltration":"#dc5a75","Impact":"#df4654"};return colors[tactic]||"#3b7087"}
function graphSource(engine,d){
 if(engine==="mermaid")return "flowchart LR\n"+d.steps.map(s=>`  step_${s.order}[\"${s.action}<br/>${s.mitre.technique_id}\"]`).join("\n")+"\n"+d.steps.slice(1).map((s,i)=>`  step_${i+1} --> step_${s.order}`).join("\n");
 if(engine==="networkx")return JSON.stringify({directed:true,nodes:d.steps.map(s=>({id:`step_${s.order}`,action:s.action,technique_id:s.mitre.technique_id})),links:d.steps.slice(1).map((s,i)=>({source:`step_${i+1}`,target:`step_${s.order}`,weight:s.rag_confidence||d.confidence/100}))},null,2);
 return `digraph CyberVisionAttack {\n  rankdir=LR;\n${d.steps.map(s=>`  step_${s.order} [label=\"${s.action}\\n${s.mitre.technique_id}\"];`).join("\n")}\n${d.steps.slice(1).map((s,i)=>`  step_${i+1} -> step_${s.order};`).join("\n")}\n}`;
}
async function graphDownload(engine,format){try{const r=await fetch("/api/graph/render",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({structured_json:state.result.structured_json,engine,format})});if(!r.ok){const e=await r.json();throw new Error(e.error)}const blob=await r.blob(),a=document.createElement("a");a.href=URL.createObjectURL(blob);const ext=format==="json"?"json":format;a.download=`cybervision-${engine}-graph.${ext}`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);toast(`Đã xuất ${engine} ${format.toUpperCase()}.`)}catch(e){toast(e.message)}}
function phase4View(){
 const d=state.result.structured_json,steps=d.steps||[],rag=d.metadata.rag;
 if(!rag)return `<div class="empty"><div class="empty-orbit"><b>◇</b><i></i><i></i></div><h3>MITRE ATT&CK RAG chưa sẵn sàng</h3><p>${esc(d.metadata.rag_error||"Hãy kiểm tra hoặc xây lại vector index.")}</p></div>`;
 const backendState=state.vectorBackends&&state.vectorBackends.backends;
 const backendChips=backendState?`<div class="vector-backend-status">${["chroma","qdrant","faiss"].map(name=>{const item=backendState[name]||{};return `<span class="${item.ready?"ready":"pending"}"><i></i>${name.toUpperCase()} · ${item.ready?`${item.chunks||0} chunks`:"chưa có index"}</span>`}).join("")}</div>`:"";
 return `<div class="phase4-output"><div class="rag-banner"><div><span>PHASE 4</span><div><b>MITRE ATT&CK Retrieval-Augmented Generation</b><small>Enterprise ATT&CK · ${rag.chunks} chunks · ${esc(rag.backend)} · ${esc(rag.embedding)}</small></div></div><span class="rag-ready">● INDEX READY</span></div>
 <div class="rag-pipeline"><span>Document</span><i>→</i><span>Chunk</span><i>→</i><span>Embedding</span><i>→</i><span>VectorDB</span><i>→</i><span>Top-K</span></div>${backendChips}
 <div class="rag-results">${steps.map((s,i)=>{const matches=s.rag?s.rag.matches:[],best=matches[0];return `<div class="rag-step"><div class="rag-step-head"><span>STEP ${s.order}</span><b>${esc(s.action)}</b><i>→</i>${best?`<strong>${esc(best.technique_id)} · ${esc(best.technique_name)}</strong><em title="Cosine similarity, không phải xác suất">SIM ${Number(best.score).toFixed(3)}</em>`:'<strong>Unknown</strong>'}</div>${best?`<div class="rag-detail"><div><small>DESCRIPTION</small><p>${esc(shortText(best.description,300))}</p></div><div><small>DETECTION</small><p>${esc(shortText(best.detection[0]||"Unknown",220))}</p></div><div><small>MITIGATION</small><p>${esc(shortText(best.mitigation[0]||"Unknown",220))}</p></div></div><div class="rag-candidates">${matches.slice(1).map(m=>`<span>${esc(m.technique_id)} ${esc(m.technique_name)} <b>SIM ${Number(m.score).toFixed(3)}</b></span>`).join("")}</div>`:""}</div>`}).join("")}</div>${knowledgeEvidence(d)}</div>`;
}
function knowledgeEvidence(d){const meta=d.metadata.knowledge;if(!meta||!meta.ready)return "";const rows=d.steps.filter(s=>s.knowledge&&s.knowledge.matches.length);return `<section class="knowledge-evidence"><div><span>MULTI-SOURCE EVIDENCE</span><b>${meta.matches} matches · ${meta.sources.map(x=>esc(x)).join(" · ")}</b></div>${rows.map(s=>`<article><small>STEP ${s.order} · ${esc(s.action)}</small>${s.knowledge.matches.slice(0,3).map(m=>`<p><b>${esc(m.source)}</b><span>${esc(m.title)}</span><em>${esc(shortText(m.snippet,180))}</em></p>`).join("")}</article>`).join("")}</section>`}
function shortText(text,max){text=String(text||"");return text.length>max?text.slice(0,max)+"…":text}
function phase3View(){
 const d=state.result.structured_json;
 if(!d)return '<div class="empty"><h3>Structured JSON chưa sẵn sàng</h3></div>';
 return `<div class="phase3-output"><div class="backbone-banner"><div><span>PHASE 3</span><div><b>Canonical Incident JSON</b><small>Single source of truth cho diagram, timeline, report và export</small></div></div><div class="schema-ok">✓ SCHEMA v${esc(d.schema_version)}</div></div>
 <div class="incident-core"><div><small>INCIDENT ID</small><code>${esc(d.incident_id)}</code></div><div class="core-name"><small>INCIDENT NAME</small><b>${esc(d.incident_name)}</b></div><div><small>SEVERITY</small><span class="severity ${d.severity.toLowerCase()}">${esc(d.severity)}</span></div><div><small>CONFIDENCE</small><b>${d.confidence}%</b></div></div>
 <div class="schema-stats"><span><b>${d.steps.length}</b> Ordered steps</span><span><b>${d.entities.actors.length}</b> Actors</span><span><b>${d.entities.assets.length}</b> Assets</span><span><b>${d.attack_summary.tactics.length}</b> Tactics</span></div>
 ${confidenceBreakdown(d)}
 <div class="json-code"><div><span>structured_incident.json</span><button onclick="copyStructured()">Copy JSON</button></div><pre>${syntaxJSON(d)}</pre></div></div>`;
}
function confidenceBreakdown(d){const c=d.confidence_breakdown||{};return `<div class="confidence-method"><div><small>CONFIDENCE METHODOLOGY</small><b>Weighted pipeline quality v1</b><p>Đây là điểm chất lượng pipeline, không phải xác suất tuyệt đối của mô hình.</p></div><div class="confidence-parts"><span>Structure <b>${Math.round((c.structure_completeness||0)*100)}%</b></span><span>Tactic <b>${Math.round((c.tactic_coverage||0)*100)}%</b></span><span>RAG coverage <b>${Math.round((c.rag_coverage||0)*100)}%</b></span><span>Cosine similarity <b>${Number(c.rag_mean_score||0).toFixed(3)}</b></span><span class="confidence-final">Final <b>${d.confidence}%</b></span></div></div>`}
function syntaxJSON(value){return esc(JSON.stringify(value,null,2)).replace(/(&quot;.*?&quot;)(\s*:)?/g,(m,p1,p2)=>p2?`<span class="json-key">${p1}</span>${p2}`:`<span class="json-string">${p1}</span>`).replace(/\b(true|false|null)\b/g,'<span class="json-bool">$1</span>').replace(/\b(\d+)\b/g,'<span class="json-number">$1</span>')}
async function copyStructured(){try{await navigator.clipboard.writeText(JSON.stringify(state.result.structured_json,null,2));toast("Đã copy canonical JSON.")}catch(e){toast("Trình duyệt không cho phép copy tự động.")}}
function phase2View(){
 const rows=state.result.phase2||[];
 const phase2Engine=state.result.fallback?"LOCAL ENGINE":String(state.result.engine||"GLM-5.2").toUpperCase();
 return `<div class="phase2-output"><div class="phase2-head"><div><span>PHASE 2</span><b>Vietnamese Understanding</b></div><div class="glm-badge">✦ ${esc(phase2Engine)}</div></div>
 <div class="structured-list">${rows.map(s=>`<div class="structured-step"><div class="step-number">${String(s.step).padStart(2,"0")}</div><div class="step-main"><small>ACTION</small><b>${esc(s.action)}</b><span>${esc(s.actor)} <i>→</i> ${esc(s.target)}</span></div><div><small>ASSET</small><b>${esc(s.asset)}</b></div><div><small>SEVERITY</small><span class="severity ${(s.severity||"unknown").toLowerCase()}">${esc(s.severity)}</span></div><div><small>MITRE TACTIC</small><b class="${s.mitre_tactic==="Unknown"?"unknown":""}">${esc(s.mitre_tactic)}</b></div></div>`).join("")}</div>
 <details class="json-preview"><summary>JSON structured output</summary><pre>${esc(JSON.stringify(rows,null,2))}</pre></details></div>`;
}
function diagram(){
 const r=state.result,s=r.steps[state.selected];
 return `<div class="diagram-area" id="diagram-area"><div class="diagram-toolbar"><div>⌁ Attack flow</div><span>${r.steps.length} bước</span></div>
 <div class="flow">${r.steps.map((x,i)=>`${i?'<div class="connector"><i></i>›</div>':""}<button class="node ${state.selected===i?"selected":""}" onclick="selectStep(${i})"><div class="node-icon c${i%5}">${x.icon}</div><span>BƯỚC ${i+1}</span><b>${esc(x.action)}</b><small>${x.techniqueId}</small></button>`).join("")}</div>
 <div class="detail-card"><div class="detail-top"><div class="node-icon c${state.selected%5}">◎</div><div><span>${esc(s.tactic)}</span><h3>${esc(s.action)}</h3></div><span class="tech-id">${s.techniqueId}</span></div><p>${esc(s.description)}</p>
 <div class="detail-grid"><div><small>NGUỒN</small><b>${esc(s.source)}</b></div><div><small>MỤC TIÊU</small><b>${esc(s.target)}</b></div><div><small>PHÁT HIỆN</small><b>${esc(s.detection)}</b></div></div></div></div>`;
}
function timeline(){return `<div class="timeline">${state.result.steps.map((s,i)=>`<div class="timeline-row"><div class="time-dot"><i></i>${i<state.result.steps.length-1?"<span></span>":""}</div><div class="timeline-content"><small>GIAI ĐOẠN ${i+1} · ${esc(s.tactic)}</small><h3>${esc(s.action)} <em>${s.techniqueId}</em></h3><p>${esc(s.description)}</p></div></div>`).join("")}</div>`}
function report(){const r=state.result;return `<div class="report"><div class="report-block"><h3>ⓘ Tóm tắt điều hành</h3><p>${esc(r.executiveSummary)}</p></div><div class="report-cols"><div class="report-block"><h3>◎ Chỉ dấu & thực thể</h3>${r.entities.map(x=>`<span class="entity">${esc(x)}</span>`).join("")}</div><div class="report-block"><h3>✓ Khuyến nghị ưu tiên</h3><ol>${r.recommendations.map(x=>`<li>${esc(x)}</li>`).join("")}</ol></div></div></div>`}

function overviewPage(){
 const r=state.result,metrics=[["Phân tích hôm nay",state.history.length,"◉"],["Kỹ thuật phát hiện",r?r.techniques.length:0,"⌾"],["Mức rủi ro",r?sev[r.severity][0]:"—","△"],["Độ tin cậy",r?`${r.confidence}%`:"—","✓"]];
 return `<div class="page">${pageTitle("Trung tâm điều hành","Tổng quan tình hình phân tích visual intelligence.","<button class=\"new-analysis\" onclick=\"navigate('Phân tích sự cố')\">＋ Phân tích mới</button>")}
 <div class="metric-grid">${metrics.map(m=>`<div class="metric panel"><span style="font-size:22px;color:#48c8d4">${m[2]}</span><span>${m[0]}</span><b>${m[1]}</b></div>`).join("")}</div>
 <div class="overview-grid"><div class="panel overview-card"><div class="panel-head"><b>Chuỗi tấn công gần nhất</b><span>⌁</span></div>${r?`<div class="mini-flow">${r.steps.map((s,i)=>`<div><i class="c${i%5}">${i+1}</i><span>${esc(s.action)}</span></div>`).join("")}</div>`:emptyView()}</div>
 <div class="panel overview-card"><div class="panel-head"><b>Hoạt động gần đây</b><span>◷</span></div>${state.history.length?state.history.map(h=>`<div class="history-mini"><span class="dot"></span><div><b>${esc(h.name)}</b><small>${h.time}</small></div></div>`).join(""):'<p class="muted">Chưa có hoạt động.</p>'}</div></div></div>`;
}
function knowledgePage(){
 const descriptions={mitre_attack:"Enterprise techniques, tactics, mitigation và procedure.",sigma:"Quy tắc phát hiện SIEM từ SigmaHQ.",yara:"Metadata rule thật từ Yara-Rules; hỗ trợ file .yar/.yara nội bộ.",threat_intelligence:"IOC, CVE, malware và campaign intelligence.",nist_cis:"Hướng dẫn NIST/CIS và kiểm soát an ninh.",playbooks:"Incident response playbook có thể truy vấn.",enterprise_assets:"Asset inventory và network context của tổ chức."};
 const order=["mitre_attack","sigma","yara","threat_intelligence","nist_cis","playbooks","enterprise_assets"],sources=state.knowledge&&state.knowledge.sources;
 const action=`<div class="knowledge-actions"><label class="asset-upload">＋ Assets<input type="file" accept=".csv,.json" onchange="importAssets(this.files[0])"></label><button class="new-analysis" ${state.knowledgeBusy?"disabled":""} onclick="syncKnowledge()">↻ ${state.knowledgeBusy?"Đang đồng bộ":"Đồng bộ nguồn"}</button></div>`;
 const cards=sources?order.map(key=>{const s=sources[key]||{},count=key==="enterprise_assets"?`${s.assets||0} assets`:`${s.documents||0} documents`,status=s.ready?"✓ Sẵn sàng":s.last_error?"× Có lỗi":"○ Chưa có dữ liệu";return `<button class="knowledge-card panel" onclick="filterKnowledge('${key}')"><div><span style="font-size:26px;color:#5bd1dc">◇</span><span class="synced ${s.ready?"":"inactive"}">${status}</span></div><h3>${esc(s.label||key)}</h3><p>${esc(descriptions[key])}</p><small><span>${count} · ${s.files||0} files</span><b>›</b></small>${s.last_error?`<em>${esc(shortText(s.last_error,120))}</em>`:""}</button>`}).join(""):`<div class="knowledge-loading panel">Đang đọc registry và SQLite index...</div>`;
 const totals=state.knowledge&&state.knowledge.totals?`<div class="knowledge-summary"><span><b>${state.knowledge.totals.documents}</b> documents</span><span><b>${state.knowledge.totals.files}</b> files</span><span><b>${state.knowledge.totals.assets}</b> assets</span><span>${esc(state.knowledge.search_engine)}</span></div>`:"";
 const results=knowledgeSearchResults();
 return `<div class="page">${pageTitle("Kho tri thức","Nguồn dữ liệu thật phục vụ Retrieval-Augmented Generation.",action)}${totals}<div class="search-wide">⌕<input id="knowledge-query" placeholder="Tìm technique, IOC, detection rule..." onkeydown="if(event.key==='Enter')searchKnowledge()"><button onclick="searchKnowledge()">Tìm</button></div><div class="knowledge-grid">${cards}</div>${results}</div>`;
}
function knowledgeSearchResults(){const data=state.knowledgeResults;if(!data)return "";if(!data.results.length)return '<div class="knowledge-results panel"><p>Không tìm thấy tài liệu phù hợp.</p></div>';return `<div class="knowledge-results panel"><div class="panel-head"><b>Kết quả tìm kiếm</b><span>${data.count} tài liệu</span></div>${data.results.map(x=>`<article><span>${esc(x.source)} · ${esc(x.document_type)}</span><h3>${esc(x.title)}</h3><p>${esc(x.snippet||shortText(x.text,360))}</p><small>${esc(x.origin)}</small></article>`).join("")}</div>`}
async function loadKnowledgeStatus(){try{const r=await fetch("/api/knowledge/status"),d=await r.json();if(!r.ok)throw new Error(d.error);state.knowledge=d;if(state.nav==="Kho tri thức")render()}catch(e){toast(e.message)}}
async function syncKnowledge(){state.knowledgeBusy=true;render();toast("Đang tải và lập chỉ mục các nguồn tri thức thật...");try{const r=await fetch("/api/knowledge/sync",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({source:"all"})}),d=await r.json();if(!r.ok&&r.status!==207)throw new Error(d.error||"Đồng bộ thất bại.");state.knowledge=d.status;const failed=Object.values(d.results||{}).filter(x=>!x.ok).length;toast(failed?`Đồng bộ xong, ${failed} nguồn cần kiểm tra.`:"Đã đồng bộ và lập chỉ mục tất cả nguồn.")}catch(e){toast(e.message)}finally{state.knowledgeBusy=false;render()}}
async function searchKnowledge(source){const input=$("#knowledge-query"),query=(input&&input.value.trim())||"";if(query.length<2)return toast("Nhập ít nhất 2 ký tự.");try{const r=await fetch("/api/knowledge/search",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query,sources:source?[source]:null,limit:20})}),d=await r.json();if(!r.ok)throw new Error(d.error);state.knowledgeResults=d;render()}catch(e){toast(e.message)}}
function filterKnowledge(source){const input=$("#knowledge-query");if(!input||input.value.trim().length<2){toast("Nhập từ khóa rồi chọn nguồn để lọc.");return}searchKnowledge(source)}
async function importAssets(file){if(!file)return;const form=new FormData();form.append("file",file);form.append("mode","merge");try{const r=await fetch("/api/assets/import",{method:"POST",body:form}),d=await r.json();if(!r.ok)throw new Error(d.error);toast(`Đã nhập ${d.imported} assets.`);await loadKnowledgeStatus()}catch(e){toast(e.message)}}
function historyPage(){
 return `<div class="page">${pageTitle("Lịch sử phân tích","Các phiên phân tích gần đây trong workspace.")}<div class="panel history-table"><div class="table-head"><span>Sự cố</span><span>Thời gian</span><span>Mức độ</span><span>Trạng thái</span></div>${state.history.length?state.history.map(h=>`<button class="table-row" onclick="navigate('Phân tích sự cố')"><b>${esc(h.name)}</b><span>${h.time}</span><span class="severity ${h.severity}">${sev[h.severity][0]}</span><span class="done">✓ Hoàn tất</span></button>`).join(""):emptyView()}</div></div>`;
}
function render(){const pages={"Phân tích sự cố":analysisPage,"Tổng quan":overviewPage,"Kho tri thức":knowledgePage,"Lịch sử":historyPage};$("#app").innerHTML=shell(pages[state.nav]());if(state.result&&state.nav==="Phân tích sự cố"&&state.tab==="phase5")setTimeout(()=>loadGraphPreview(state.graphEngine),0)}
function updateCount(){$("#char-count").textContent=`${$("#incident-input").value.length} ký tự`}
function clearInput(){$("#incident-input").value="";updateCount()}
function setInputMode(mode){$("#desc-input").style.display=mode==="desc"?"block":"none";$("#file-input").style.display=mode==="file"?"flex":"none";$("#desc-tab").classList.toggle("active",mode==="desc");$("#file-tab").classList.toggle("active",mode==="file")}
async function loadFile(file){if(!file)return;if(file.size>10*1024*1024)return toast("Tệp vượt quá 10MB.");const form=new FormData();form.append("file",file);toast(`Đang trích xuất ${file.name}...`);try{const r=await fetch("/api/extract",{method:"POST",body:form}),d=await r.json();if(!r.ok)throw new Error(d.error);setInputMode("desc");$("#incident-input").value=d.text;updateCount();$("#parser-info").innerHTML=`<div class="parser-info"><i>✓</i><div><b>${esc(d.source_type)} đã được chuẩn hóa</b><small>${esc(d.filename)} · ${esc(d.parser)} · ${d.lines} dòng · ${d.characters} ký tự${d.truncated?" · đã cắt giới hạn":""}</small></div></div>`;toast(`PHASE 1 hoàn tất bằng ${d.parser}.`)}catch(e){toast(e.message)}}
function sample(type){const samples={phishing:window.CYBER_SAMPLE,ransomware:"Máy chủ web bị khai thác lỗ hổng, kẻ tấn công chạy PowerShell tải ransomware, mã hóa dữ liệu và xóa bản sao lưu.",exfil:"Tài khoản quản trị bị đăng nhập bất thường. Đối tượng nâng quyền, truy vấn cơ sở dữ liệu, nén rồi tải lượng lớn dữ liệu khách hàng ra ngoài."};$("#incident-input").value=samples[type];updateCount()}
async function analyze(){
 const description=$("#incident-input").value.trim();if(description.length<10)return toast("Hãy nhập mô tả ít nhất 10 ký tự.");
 const btn=$("#analyze");btn.disabled=true;btn.innerHTML='<span class="spin">↻</span> Đang phân tích...';$("#progress-wrap").innerHTML='<div class="progress"><i style="width:18%"></i><span>Đang trích xuất thực thể...</span></div>';
 let p=18;const timer=setInterval(()=>{p=Math.min(92,p+13);const bar=$(".progress i");if(bar)bar.style.width=p+"%";const label=$(".progress span");if(label)label.textContent=p<55?"Đang trích xuất thực thể...":p<80?"Đang ánh xạ ATT&CK...":"Đang tạo attack graph..."},180);
 try{const res=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({description})});const data=await res.json();if(!res.ok)throw new Error(data.error||"Không thể phân tích.");state.result=data;state.selected=0;state.tab="phase5";state.history.unshift({name:data.incidentName,time:new Date().toLocaleTimeString("vi-VN"),severity:data.severity});state.history=state.history.slice(0,8);render();toast(`PHASE 5 đã dựng graph ${data.steps.length} nodes.`)}catch(e){toast(e.message);btn.disabled=false;btn.textContent="⚡ Phân tích sự cố"}finally{clearInterval(timer)}
}
function changeTab(tab){state.tab=tab;$("#result-content").innerHTML=renderResultTab();document.querySelectorAll(".result-tabs button").forEach(b=>b.classList.toggle("active",b.dataset.tab===tab));if(tab==="phase5")loadGraphPreview(state.graphEngine)}
function selectStep(i){state.selected=i;$("#result-content").innerHTML=diagram()}
function download(content,name,type){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([content],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function exportJSON(){download(JSON.stringify(state.result.structured_json||state.result,null,2),"cybervision-structured-incident.json","application/json");toast("Đã xuất canonical JSON.")}
function exportSVG(){graphDownload("graphviz","svg")}
async function exportReport(format){try{toast(`Đang tạo ${format.toUpperCase()} phía server...`);const r=await fetch(`/api/report/${format}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({structured_json:state.result.structured_json})});if(!r.ok){const d=await r.json();throw new Error(d.error)}const blob=await r.blob(),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`cybervision-${state.result.structured_json.incident_id}.${format}`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);toast(`Đã xuất báo cáo ${format.toUpperCase()} phía server.`)}catch(e){toast(e.message)}}
function toast(message){let el=$("#toast");if(!el){el=document.createElement("div");el.id="toast";el.className="toast";document.body.appendChild(el)}el.innerHTML=`✓ ${esc(message)}`;clearTimeout(window.toastTimer);window.toastTimer=setTimeout(()=>el.remove(),3000)}
function updateConnectionStatus(){const button=$(".connection");if(!button)return;button.innerHTML=`<span></span>${state.config&&state.config.enabled?"LLM ENABLED":"LOCAL ENGINE"}`}
async function loadConfig(){try{const r=await fetch("/api/config");if(!r.ok)throw new Error(`HTTP ${r.status}`);state.config=await r.json()}catch(e){state.config={enabled:false,provider:"openai"}}finally{updateConnectionStatus()}}
async function loadVectorBackends(){try{const r=await fetch("/api/rag/backends"),d=await r.json();if(r.ok)state.vectorBackends=d}catch(e){}}
const providerDefaults={
 dashscope:["https://dashscope-intl.aliyuncs.com/compatible-mode/v1","glm-5.2"],
 zhipu:["https://open.bigmodel.cn/api/paas/v4","glm-5.2"],
 openai:["https://api.openai.com/v1","gpt-4o-mini"],
 azure:["https://YOUR-RESOURCE.openai.azure.com","YOUR-DEPLOYMENT"],
 anthropic:["https://api.anthropic.com/v1","claude-3-5-sonnet-latest"],
 gemini:["https://generativelanguage.googleapis.com/v1beta","gemini-1.5-flash"],
 ollama:["http://127.0.0.1:11434","qwen2.5:7b"],
 compatible:["http://127.0.0.1:8000/v1","Qwen/Qwen2.5-7B-Instruct"]
};
async function openSettings(){
 if(!state.config)await loadConfig();const c=state.config;
 const wrap=document.createElement("div");wrap.className="modal-wrap";wrap.id="settings-modal";wrap.innerHTML=`<div class="modal">
 <div class="modal-head"><div><span class="step violet">LLM</span><div><b>Cấu hình LLM & API</b><small>Structured extraction · ATT&CK RAG · Local fallback</small></div></div><button onclick="closeSettings()">×</button></div>
 <div class="modal-body"><div class="settings-status"><div><i class="${c.enabled?"on":""}"></i><span><b>${c.enabled?"LLM đang bật":"Đang dùng engine local"}</b><small>API key ${c.has_api_key?"đã được cấu hình":"chưa được cấu hình"}</small></span></div><label class="switch"><input id="cfg-enabled" type="checkbox" ${c.enabled?"checked":""}><span></span></label></div>
 <div class="form-grid">
 <label>Provider<select id="cfg-provider" onchange="providerChanged()">${Object.keys(providerDefaults).map(p=>`<option value="${p}" ${c.provider===p?"selected":""}>${{dashscope:"Qwen Cloud / DashScope",zhipu:"Z.AI / Zhipu GLM",openai:"OpenAI",azure:"Azure OpenAI",anthropic:"Anthropic",gemini:"Google Gemini",ollama:"Ollama (local)",compatible:"OpenAI-compatible"}[p]}</option>`).join("")}</select></label>
 <label>Model / Deployment<input id="cfg-model" value="${esc(c.model)}" placeholder="Tên model"></label>
 <label class="full">Base URL<input id="cfg-url" value="${esc(c.base_url)}" placeholder="https://..."></label>
 <label class="full">API key <span class="field-hint">${esc(c.api_key_masked||"")}</span><div class="password-field"><input id="cfg-key" type="password" placeholder="${c.has_api_key?"Để trống để giữ key hiện tại":"sk-..."}"><button type="button" onclick="toggleKey()">Hiện</button></div></label>
 <label>Temperature<input id="cfg-temp" type="number" min="0" max="2" step=".1" value="${c.temperature}"></label>
 <label>Timeout (giây)<input id="cfg-timeout" type="number" min="5" max="300" value="${c.timeout}"></label>
 </div>
 <div class="option-row"><div><b>ATT&CK RAG context</b><small>Đưa technique liên quan từ knowledge base vào prompt</small></div><label class="switch"><input id="cfg-rag" type="checkbox" ${c.rag_enabled?"checked":""}><span></span></label></div>
 <details><summary>Advanced system prompt</summary><textarea id="cfg-prompt" placeholder="Để trống để dùng prompt mặc định">${esc(c.system_prompt||"")}</textarea></details>
 <div id="config-result"></div></div>
 <div class="modal-foot"><label><input id="cfg-persist" type="checkbox"> Lưu vào .env trên máy chủ</label><div><button class="test-btn" onclick="testLLM()">Kiểm tra kết nối</button><button class="save-btn" onclick="saveConfig()">Lưu cấu hình</button></div></div></div>`;
 document.body.appendChild(wrap);setTimeout(()=>wrap.classList.add("show"),10);
}
function closeSettings(){const m=$("#settings-modal");if(m){m.classList.remove("show");setTimeout(()=>m.remove(),180)}}
function providerChanged(){const p=$("#cfg-provider").value,[url,model]=providerDefaults[p];$("#cfg-url").value=url;$("#cfg-model").value=model}
function toggleKey(){const i=$("#cfg-key");i.type=i.type==="password"?"text":"password";i.nextElementSibling.textContent=i.type==="password"?"Hiện":"Ẩn"}
function configPayload(){return {enabled:$("#cfg-enabled").checked,provider:$("#cfg-provider").value,model:$("#cfg-model").value.trim(),base_url:$("#cfg-url").value.trim(),api_key:$("#cfg-key").value.trim(),temperature:Number($("#cfg-temp").value),timeout:Number($("#cfg-timeout").value),rag_enabled:$("#cfg-rag").checked,system_prompt:$("#cfg-prompt").value,persist:$("#cfg-persist").checked}}
async function testLLM(){const out=$("#config-result");out.className="config-result loading";out.textContent="◷ Đang kết nối tới provider...";try{const r=await fetch("/api/config/test",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(configPayload())}),d=await r.json();if(!r.ok)throw new Error(d.error);out.className="config-result success";out.textContent=`✓ Kết nối thành công · ${d.provider} / ${d.model}`}catch(e){out.className="config-result error";out.textContent=`× ${e.message}`}}
async function saveConfig(){const out=$("#config-result");try{const r=await fetch("/api/config",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(configPayload())}),d=await r.json();if(!r.ok)throw new Error(d.error);state.config=d;out.className="config-result success";out.textContent="✓ Đã lưu cấu hình. Các phân tích mới sẽ dùng thiết lập này.";setTimeout(()=>{closeSettings();render();toast("Đã cập nhật LLM engine.")},900)}catch(e){out.className="config-result error";out.textContent=`× ${e.message}`}}
document.addEventListener("keydown",e=>{if((e.ctrlKey||e.metaKey)&&e.key==="Enter"&&state.nav==="Phân tích sự cố")analyze()});
render();
void loadConfig();
void loadVectorBackends();
