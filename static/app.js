const $ = (s, root=document) => root.querySelector(s);
const esc = value => String(value == null ? "" : value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {nav:"Phân tích sự cố", result:null, selected:0, tab:"diagram", graphEngine:"graphviz", graphPreviewUrl:null, history:[], config:null, knowledge:null, knowledgeResults:null, knowledgeBusy:false, vectorBackends:null};
const sev = {critical:["Nghiêm trọng","critical"],high:["Cao","high"],medium:["Trung bình","medium"],low:["Thấp","low"]};
const icons = {dashboard:"▦",analysis:"◉",knowledge:"◇",history:"◷",help:"?",settings:"⚙"};
const TACTIC_VI = {
 "Reconnaissance":"Trinh sát","Resource Development":"Phát triển nguồn lực",
 "Initial Access":"Truy cập ban đầu","Execution":"Thực thi","Persistence":"Duy trì hiện diện",
 "Privilege Escalation":"Nâng quyền","Defense Evasion":"Né tránh phòng thủ",
 "Credential Access":"Truy cập thông tin xác thực","Discovery":"Khám phá",
 "Lateral Movement":"Di chuyển ngang","Collection":"Thu thập",
 "Command and Control":"Chỉ huy và điều khiển","Command And Control":"Chỉ huy và điều khiển",
 "Exfiltration":"Đưa dữ liệu ra ngoài","Impact":"Gây ảnh hưởng","Unknown":"Chưa xác định"
};
const SEVERITY_VI = {critical:"Nghiêm trọng",high:"Cao",medium:"Trung bình",low:"Thấp",unknown:"Chưa xác định"};
const DOCUMENT_TYPE_VI = {technique:"Kỹ thuật",mitigation:"Biện pháp giảm thiểu",procedure:"Quy trình",detection:"Phát hiện",detection_rule:"Quy tắc phát hiện",rule:"Quy tắc",threat_intelligence:"Tình báo mối đe dọa",control:"Kiểm soát",playbook:"Kịch bản ứng phó",asset:"Tài sản",document:"Tài liệu"};
const SOURCE_LABEL_VI = {mitre_attack:"MITRE ATT&CK",sigma:"Quy tắc Sigma",yara:"Quy tắc YARA",threat_intelligence:"Tình báo mối đe dọa",nist_cis:"Kiểm soát NIST/CIS",playbooks:"Kịch bản ứng phó",enterprise_assets:"Tài sản doanh nghiệp"};

function displayValue(owner,key,...fallbacks){
 const translated=owner&&owner.display_vi&&owner.display_vi[key];
 return firstKnown(translated,...fallbacks)||"Chưa xác định";
}
function tacticVi(value){if(Array.isArray(value))return value.map(tacticVi).filter(Boolean).join(" · ")||"Chưa xác định";const text=firstKnown(value),parts=text.split(/\s*,\s*/).filter(Boolean);if(parts.length>1)return parts.map(item=>TACTIC_VI[item]||item).join(" · ");return TACTIC_VI[text]||text||"Chưa xác định"}
function severityVi(value){const text=firstKnown(value);return SEVERITY_VI[text.toLowerCase()]||text||"Chưa xác định"}
function documentTypeVi(value){const text=firstKnown(value);return DOCUMENT_TYPE_VI[text.toLowerCase()]||text||"Tài liệu"}
function stepValue(step,key,...fallbacks){return displayValue(step,key,...fallbacks)}
function matchValue(match,key,...fallbacks){return displayValue(match,key,...fallbacks)}
function topValue(structured,key,...fallbacks){return displayValue(structured,key,...fallbacks)}
function displayList(owner,key,fallback=[]){const value=owner&&owner.display_vi&&owner.display_vi[key];return Array.isArray(value)&&value.length?value:fallback}

function shell(content){
  return `<div class="app">
  <aside class="sidebar">
    <div class="brand"><div class="brand-mark">⬡<span></span></div><div><b>CYBERVISION</b><small>TRÍ TUỆ TRỰC QUAN</small></div></div>
    <nav>
      ${navButton("Tổng quan",icons.dashboard)}${navButton("Phân tích sự cố",icons.analysis)}${navButton("Kho tri thức",icons.knowledge)}${navButton("Lịch sử",icons.history)}
    </nav>
    <div class="side-bottom"><div class="system-status"><div><span class="live-dot"></span>Hệ thống hoạt động</div><small>Flask API · Sẵn sàng</small></div>
      <button onclick="toast('Tài liệu vận hành nằm trong README.md')">◯ <span>Trợ giúp</span></button><button onclick="openSettings()">⚙ <span>Cấu hình LLM & API</span></button>
      <div class="profile"><div class="avatar">NA</div><div><b>Nguyễn An</b><small>Chuyên viên SOC</small></div><span>›</span></div>
    </div>
  </aside>
  <main><header><button class="mobile-menu" onclick="toggleMenu()">☰</button><div class="crumb"><span>Không gian làm việc</span><b>›</b><b>${state.nav}</b></div>
  <div class="header-actions"><button class="icon-btn">⌕</button><button class="icon-btn alert">♢<i></i></button><button class="connection" onclick="openSettings()"><span></span>${state.config&&state.config.enabled?"LLM ĐANG BẬT":"BỘ MÁY CỤC BỘ"}</button></div></header>${content}</main></div>`;
}
function navButton(name,icon){return `<button data-nav="${name}" class="${state.nav===name?"active":""}" onclick="navigate('${name}')"><b>${icon}</b><span>${name}</span>${name==="Lịch sử"&&state.history.length?`<em>${state.history.length}</em>`:""}</button>`}
function navigate(name){state.nav=name;render();if(name==="Kho tri thức")loadKnowledgeStatus()}
function toggleMenu(){$(".sidebar").classList.toggle("open")}
function pageTitle(title,subtitle,action=""){return `<div class="title-row"><div><h1>${title}</h1><p>${subtitle}</p></div>${action}</div>`}

function analysisPage(){
 return `<div class="page">${pageTitle("Phân tích sự cố","Chuyển đổi mô tả tiếng Việt thành sơ đồ tấn công và tri thức MITRE ATT&CK.",'<div class="title-badge">✦ Phân tích có AI hỗ trợ</div>')}
 <div class="workspace">
 <section class="input-panel panel">
  <div class="panel-head"><div><span class="step">01</span><b>Dữ liệu đầu vào</b></div><button class="ghost" onclick="clearInput()">Xóa</button></div>
  <div class="phase-strip"><span>PHASE 1</span><b>Chuẩn bị & chuẩn hóa dữ liệu</b></div>
  <div class="mode-tabs"><button id="desc-tab" class="active" onclick="setInputMode('desc')">▤ Văn bản</button><button id="file-tab" onclick="setInputMode('file')">⇧ Email / Tài liệu / Nhật ký</button></div>
  <div id="desc-input" class="textarea-wrap"><textarea id="incident-input" maxlength="12000" oninput="updateCount()" placeholder="Mô tả sự cố bằng tiếng Việt...">${esc(window.CYBER_SAMPLE)}</textarea><span id="char-count">${window.CYBER_SAMPLE.length} ký tự</span></div>
  <label id="file-input" class="dropzone" style="display:none"><b style="font-size:26px">⇧</b><b>Thả dữ liệu bảo mật vào đây</b><span>hoặc bấm để chọn tệp</span><small>EMAIL · WORD · PDF · NHẬT KÝ · SYSLOG · TƯỜNG LỬA · SỰ KIỆN WINDOWS</small><input type="file" accept=".eml,.msg,.doc,.docx,.pdf,.txt,.md,.log,.syslog,.json,.xml,.csv,.cef,.leef,.evtx" onchange="loadFile(this.files[0])"></label>
  <div id="parser-info"></div>
  <div class="input-formats"><span>TXT</span><span>EML</span><span>DOCX</span><span>PDF</span><span>LOG</span><span>SYSLOG</span><span>CEF/LEEF</span><span>EVTX</span></div>
  <div class="quick-label">MẪU PHÂN TÍCH NHANH</div><div class="chips"><button onclick="sample('phishing')">Lừa đảo & C2</button><button onclick="sample('ransomware')">Mã độc tống tiền</button><button onclick="sample('exfil')">Đưa dữ liệu ra ngoài</button></div>
  <button id="analyze" class="analyze-btn" onclick="analyze()">⚡ Phân tích sự cố <span>CTRL ↵</span></button>
  <div id="progress-wrap"></div><div class="privacy">✓ <span>Dữ liệu chỉ lưu trong phiên; khi bật LLM, mô tả được gửi đến nhà cung cấp đã cấu hình.</span></div>
 </section>
 <section class="result-panel panel"><div class="panel-head"><div><span class="step violet">02</span><b>Kết quả phân tích</b></div>${state.result?`<div class="export-menu"><button onclick="exportJSON()">JSON</button><button onclick="exportSVG()">SVG</button><button onclick="exportReport('docx')">DOCX</button><button onclick="exportReport('pptx')">PPTX</button><button class="primary-small" onclick="exportReport('pdf')">PDF</button></div>`:""}</div>
 ${state.result?resultsView():emptyView()}</section></div></div>`;
}
function emptyView(){return `<div class="empty"><div class="empty-orbit"><b style="font-size:28px">⬡</b><i></i><i></i></div><h3>Chưa có kết quả</h3><p>Nhập mô tả sự cố và chọn “Phân tích sự cố” để bắt đầu.</p></div>`}
function resultsView(){
 const r=state.result,[label,cl]=sev[r.severity]||["Chưa xác định","unknown"];
 const d=r.structured_json||{},engineLabel=r.fallback?"⚙ BỘ MÁY CỤC BỘ":`✦ ${String(r.engine||"LLM").toUpperCase()} + RAG`;
 const incidentName=topValue(d,"incident_name",r.incidentName);
 return `${r.fallback?`<div class="fallback-notice">⚠ LLM gặp lỗi, kết quả được tạo bằng bộ máy cục bộ. <button onclick="openSettings()">Kiểm tra cấu hình</button><small>${esc(r.llmError||"")}</small></div>`:""}<div class="summary"><div><span class="severity ${cl}">△ ${label}</span><span class="engine-badge">${esc(engineLabel)}</span><h2>${esc(incidentName)}</h2><p>⌾ ${r.entities.length} thực thể · ${r.techniques.length} kỹ thuật ATT&CK</p></div><button class="confidence" onclick="changeTab('phase3')" title="Xem cách tính độ tin cậy"><div style="--score:${r.confidence*3.6}deg"><b>${r.confidence}%</b></div><span>Độ tin cậy của quy trình</span></button></div>
 <div class="result-tabs"><button data-tab="phase5" class="${state.tab==="phase5"?"active":""}" onclick="changeTab('phase5')">PHASE 5 · Đồ thị</button><button data-tab="phase4" class="${state.tab==="phase4"?"active":""}" onclick="changeTab('phase4')">PHASE 4 · RAG</button><button data-tab="phase3" class="${state.tab==="phase3"?"active":""}" onclick="changeTab('phase3')">PHASE 3 · JSON</button><button data-tab="phase2" class="${state.tab==="phase2"?"active":""}" onclick="changeTab('phase2')">PHASE 2 · LLM</button><button data-tab="diagram" class="${state.tab==="diagram"?"active":""}" onclick="changeTab('diagram')">Sơ đồ tổng hợp</button><button data-tab="timeline" class="${state.tab==="timeline"?"active":""}" onclick="changeTab('timeline')">Dòng thời gian</button><button data-tab="report" class="${state.tab==="report"?"active":""}" onclick="changeTab('report')">Báo cáo</button></div>
 <div id="result-content">${renderResultTab()}</div>`;
}
function renderResultTab(){return state.tab==="phase5"?phase5View():state.tab==="phase4"?phase4View():state.tab==="phase3"?phase3View():state.tab==="phase2"?phase2View():state.tab==="diagram"?diagram():state.tab==="timeline"?timeline():report()}
function phase5View(){
 const d=state.result.structured_json,engine=state.graphEngine;
 return `<div class="phase5-output"><div class="graph-head"><div><span>PHASE 5</span><div><b>Bộ máy tạo đồ thị</b><small>JSON có cấu trúc → nút · cạnh · trọng số → sản phẩm trực quan</small></div></div><div class="engine-switch">${["graphviz","mermaid","networkx"].map(x=>`<button class="${engine===x?"active":""}" onclick="setGraphEngine('${x}')">${x==="graphviz"?"Graphviz":x==="mermaid"?"Mermaid":"NetworkX"}</button>`).join("")}</div></div>
 <div class="visual-graph" id="graph-preview"><div class="graph-grid"></div><div class="graph-nodes">${d.steps.map((s,i)=>`${i?`<div class="graph-edge"><span>${Number(s.rag_confidence||d.confidence/100).toFixed(2)}</span><i></i><b>›</b></div>`:""}<div class="graph-node" style="--node-color:${graphColor(s.mitre.tactic)}"><small>BƯỚC ${String(s.order).padStart(2,"0")}</small><b>${esc(stepValue(s,"action",s.action))}</b><span>${esc(s.mitre.technique_id)}</span><em>${esc(stepValue(s,"tactic",tacticVi(s.mitre.tactic)))}</em></div>`).join("")}</div></div>
 <div class="graph-actions"><div><span>${engine==="graphviz"?"DOT → SVG / PNG":engine==="mermaid"?"flowchart LR → SVG":"DiGraph → Matplotlib PNG"}</span><b>${d.steps.length} nút · ${Math.max(0,d.steps.length-1)} cạnh</b></div><button onclick="graphDownload('${engine}','${engine==="mermaid"?"mmd":engine==="networkx"?"json":"dot"}')">Mã nguồn</button><button onclick="graphDownload('${engine}','svg')">SVG</button><button class="graph-primary" onclick="graphDownload('${engine}','png')">PNG</button></div>
 <div class="graph-source"><div><span>${engine==="graphviz"?"attack-graph.dot":engine==="mermaid"?"attack-graph.mmd":"networkx-graph.json"}</span><button onclick="graphDownload('${engine}','${engine==="mermaid"?"mmd":engine==="networkx"?"json":"dot"}')">↓ Tải xuống</button></div><pre>${esc(graphSource(engine,d))}</pre></div></div>`;
}
function setGraphEngine(engine){state.graphEngine=engine;$("#result-content").innerHTML=phase5View();loadGraphPreview(engine)}
async function loadGraphPreview(engine){const target=$("#graph-preview");if(!target||!state.result)return;target.classList.add("loading");try{const r=await fetch("/api/graph/render",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({structured_json:state.result.structured_json,engine,format:"svg"})});if(!r.ok){const d=await r.json();throw new Error(d.error||"Không dựng được sơ đồ.")}const blob=await r.blob();if(state.graphEngine!==engine||!target.isConnected)return;const url=URL.createObjectURL(blob),img=document.createElement("img");img.alt=`Sơ đồ tấn công ${engine}`;img.onload=()=>target.classList.remove("loading");img.onerror=()=>target.classList.remove("loading");img.src=url;target.replaceChildren(img);if(state.graphPreviewUrl)URL.revokeObjectURL(state.graphPreviewUrl);state.graphPreviewUrl=url}catch(e){if(!target.isConnected)return;target.classList.remove("loading");target.insertAdjacentHTML("beforeend",`<small class="graph-preview-error">${esc(e.message)}</small>`)}}
function graphColor(tactic){const colors={"Initial Access":"#1677b8","Execution":"#6d4aff","Credential Access":"#c56a0c","Command and Control":"#087f8c","Exfiltration":"#c23868","Impact":"#c52f4a"};return colors[tactic]||"#607086"}
function graphSource(engine,d){
 if(engine==="mermaid")return "flowchart LR\n"+d.steps.map(s=>`  step_${s.order}[\"${stepValue(s,"action",s.action)}<br/>${s.mitre.technique_id}\"]`).join("\n")+"\n"+d.steps.slice(1).map((s,i)=>`  step_${i+1} --> step_${s.order}`).join("\n");
 if(engine==="networkx")return JSON.stringify({directed:true,nodes:d.steps.map(s=>({id:`step_${s.order}`,action:stepValue(s,"action",s.action),technique_id:s.mitre.technique_id})),links:d.steps.slice(1).map((s,i)=>({source:`step_${i+1}`,target:`step_${s.order}`,weight:s.rag_confidence||d.confidence/100}))},null,2);
 return `digraph CyberVisionAttack {\n  rankdir=LR;\n${d.steps.map(s=>`  step_${s.order} [label=\"${stepValue(s,"action",s.action)}\\n${s.mitre.technique_id}\"];`).join("\n")}\n${d.steps.slice(1).map((s,i)=>`  step_${i+1} -> step_${s.order};`).join("\n")}\n}`;
}
async function graphDownload(engine,format){try{const r=await fetch("/api/graph/render",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({structured_json:state.result.structured_json,engine,format})});if(!r.ok){const e=await r.json();throw new Error(e.error)}const blob=await r.blob(),a=document.createElement("a");a.href=URL.createObjectURL(blob);const ext=format==="json"?"json":format;a.download=`cybervision-${engine}-graph.${ext}`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);toast(`Đã xuất ${engine} ${format.toUpperCase()}.`)}catch(e){toast(e.message)}}
function phase4View(){
 const d=state.result.structured_json,steps=d.steps||[],rag=d.metadata.rag;
 if(!rag)return `<div class="empty"><div class="empty-orbit"><b>◇</b><i></i><i></i></div><h3>MITRE ATT&CK RAG chưa sẵn sàng</h3><p>${esc(d.metadata.rag_error||"Hãy kiểm tra hoặc xây lại chỉ mục vector.")}</p></div>`;
 const backendState=state.vectorBackends&&state.vectorBackends.backends;
 const backendChips=backendState?`<div class="vector-backend-status">${["chroma","qdrant","faiss"].map(name=>{const item=backendState[name]||{};return `<span class="${item.ready?"ready":"pending"}"><i></i>${name.toUpperCase()} · ${item.ready?`${item.chunks||0} phân đoạn`:"chưa có chỉ mục"}</span>`}).join("")}</div>`:"";
 return `<div class="phase4-output"><div class="rag-banner"><div><span>PHASE 4</span><div><b>MITRE ATT&CK RAG</b><small>Enterprise ATT&CK · ${rag.chunks} phân đoạn · ${esc(rag.backend)} · ${esc(rag.embedding)}</small></div></div><span class="rag-ready">● CHỈ MỤC SẴN SÀNG</span></div>
 <div class="rag-pipeline"><span>Tài liệu</span><i>→</i><span>Phân đoạn</span><i>→</i><span>Vector hóa</span><i>→</i><span>Cơ sở dữ liệu vector</span><i>→</i><span>Top-K</span></div>${backendChips}
 <div class="rag-results">${steps.map(s=>{const matches=s.rag?s.rag.matches:[],best=matches[0],action=stepValue(s,"action",s.action);return `<div class="rag-step"><div class="rag-step-head"><span>BƯỚC ${s.order}</span><b>${esc(action)}</b><i>→</i>${best?`<strong>${esc(best.technique_id)} · ${esc(matchValue(best,"technique_name",best.technique_name))}</strong><em title="Độ tương đồng cosine, không phải xác suất">TƯƠNG ĐỒNG ${Number(best.score).toFixed(3)}</em>`:'<strong>Chưa xác định</strong>'}</div>${best?`<div class="rag-detail"><div><small>MÔ TẢ</small><p>${esc(shortText(matchValue(best,"description",best.description),300))}</p></div><div><small>PHÁT HIỆN</small><p>${esc(shortText(matchValue(best,"detection",best.detection,"Chưa xác định"),220))}</p></div><div><small>GIẢM THIỂU</small><p>${esc(shortText(matchValue(best,"mitigation",best.mitigation,"Chưa xác định"),220))}</p></div></div><div class="rag-candidates">${matches.slice(1).map(m=>`<span>${esc(m.technique_id)} ${esc(matchValue(m,"technique_name",m.technique_name))} <b>TƯƠNG ĐỒNG ${Number(m.score).toFixed(3)}</b></span>`).join("")}</div>`:""}</div>`}).join("")}</div>${knowledgeEvidence(d)}</div>`;
}
function knowledgeEvidence(d){const meta=d.metadata.knowledge;if(!meta||!meta.ready)return "";const rows=d.steps.filter(s=>s.knowledge&&s.knowledge.matches.length);return `<section class="knowledge-evidence"><div><span>BẰNG CHỨNG ĐA NGUỒN</span><b>${meta.matches} kết quả · ${meta.sources.map(x=>esc(SOURCE_LABEL_VI[x]||x)).join(" · ")}</b></div>${rows.map(s=>`<article><small>BƯỚC ${s.order} · ${esc(stepValue(s,"action",s.action))}</small>${s.knowledge.matches.slice(0,3).map(m=>`<p><b>${esc(SOURCE_LABEL_VI[m.source]||m.source)}</b><span>${esc(matchValue(m,"title",m.title))}</span><em>${esc(shortText(matchValue(m,"snippet",m.snippet),180))}</em></p>`).join("")}</article>`).join("")}</section>`}
function shortText(text,max){text=String(text||"");return text.length>max?text.slice(0,max)+"…":text}
function phase3View(){
 const d=state.result.structured_json;
 if(!d)return '<div class="empty"><h3>JSON có cấu trúc chưa sẵn sàng</h3></div>';
 return `<div class="phase3-output"><div class="backbone-banner"><div><span>PHASE 3</span><div><b>JSON sự cố chuẩn hóa</b><small>Nguồn dữ liệu thống nhất cho sơ đồ, dòng thời gian, báo cáo và xuất tệp</small></div></div><div class="schema-ok">✓ LƯỢC ĐỒ v${esc(d.schema_version)}</div></div>
 <div class="incident-core"><div><small>MÃ SỰ CỐ</small><code>${esc(d.incident_id)}</code></div><div class="core-name"><small>TÊN SỰ CỐ</small><b>${esc(topValue(d,"incident_name",d.incident_name))}</b></div><div><small>MỨC ĐỘ</small><span class="severity ${d.severity.toLowerCase()}">${esc(topValue(d,"severity",severityVi(d.severity)))}</span></div><div><small>ĐỘ TIN CẬY</small><b>${d.confidence}%</b></div></div>
 <div class="schema-stats"><span><b>${d.steps.length}</b> bước có thứ tự</span><span><b>${d.entities.actors.length}</b> tác nhân</span><span><b>${d.entities.assets.length}</b> tài sản</span><span><b>${d.attack_summary.tactics.length}</b> chiến thuật</span></div>
 ${confidenceBreakdown(d)}
 <div class="json-code"><div><span>structured_incident.json</span><button onclick="copyStructured()">Sao chép JSON</button></div><pre>${syntaxJSON(d)}</pre></div></div>`;
}
function confidenceBreakdown(d){const c=d.confidence_breakdown||{};return `<div class="confidence-method"><div><small>PHƯƠNG PHÁP TÍNH ĐỘ TIN CẬY</small><b>Chất lượng quy trình có trọng số v1</b><p>Đây là điểm chất lượng của quy trình phân tích, không phải xác suất tuyệt đối của mô hình.</p></div><div class="confidence-parts"><span>Cấu trúc <b>${Math.round((c.structure_completeness||0)*100)}%</b></span><span>Chiến thuật <b>${Math.round((c.tactic_coverage||0)*100)}%</b></span><span>Độ phủ RAG <b>${Math.round((c.rag_coverage||0)*100)}%</b></span><span>Tương đồng cosine <b>${Number(c.rag_mean_score||0).toFixed(3)}</b></span><span class="confidence-final">Tổng hợp <b>${d.confidence}%</b></span></div></div>`}
function syntaxJSON(value){return esc(JSON.stringify(value,null,2)).replace(/(&quot;.*?&quot;)(\s*:)?/g,(m,p1,p2)=>p2?`<span class="json-key">${p1}</span>${p2}`:`<span class="json-string">${p1}</span>`).replace(/\b(true|false|null)\b/g,'<span class="json-bool">$1</span>').replace(/\b(\d+)\b/g,'<span class="json-number">$1</span>')}
async function copyStructured(){try{await navigator.clipboard.writeText(JSON.stringify(state.result.structured_json,null,2));toast("Đã sao chép JSON chuẩn hóa.")}catch(e){toast("Trình duyệt không cho phép sao chép tự động.")}}
function phase2View(){
 const canonical=state.result.structured_json&&state.result.structured_json.steps||[];
 const rows=(state.result.phase2||[]).map((row,index)=>{const step=canonical[index]||row;return {...row,actor:stepValue(step,"actor",row.actor),action:stepValue(step,"action",row.action),target:stepValue(step,"target",row.target),asset:stepValue(step,"asset",row.asset),severity:stepValue(step,"severity",severityVi(row.severity)),mitre_tactic:stepValue(step,"tactic",tacticVi(row.mitre_tactic))}});
 const phase2Engine=state.result.fallback?"BỘ MÁY CỤC BỘ":String(state.result.engine||"GLM-5.2").toUpperCase();
 return `<div class="phase2-output"><div class="phase2-head"><div><span>PHASE 2</span><b>Hiểu và trích xuất tiếng Việt</b></div><div class="glm-badge">✦ ${esc(phase2Engine)}</div></div>
 <div class="structured-list">${rows.map(s=>`<div class="structured-step"><div class="step-number">${String(s.step).padStart(2,"0")}</div><div class="step-main"><small>HÀNH ĐỘNG</small><b>${esc(s.action)}</b><span>${esc(s.actor)} <i>→</i> ${esc(s.target)}</span></div><div><small>TÀI SẢN</small><b>${esc(s.asset)}</b></div><div><small>MỨC ĐỘ</small><span class="severity ${(canonical[s.step-1]&&canonical[s.step-1].severity||"unknown").toLowerCase()}">${esc(s.severity)}</span></div><div><small>CHIẾN THUẬT MITRE</small><b class="${s.mitre_tactic==="Chưa xác định"?"unknown":""}">${esc(s.mitre_tactic)}</b></div></div>`).join("")}</div>
 <details class="json-preview"><summary>Đầu ra JSON có cấu trúc</summary><pre>${esc(JSON.stringify(rows,null,2))}</pre></details></div>`;
}
function knownText(value){
 if(Array.isArray(value))return value.map(knownText).filter(Boolean).join(" · ");
 const text=String(value==null?"":value).trim();
 return text&&!["unknown","none","null","n/a"].includes(text.toLowerCase())?text:"";
}
function firstKnown(...values){for(const value of values){const text=knownText(value);if(text)return text}return ""}
function diagramSteps(result){
 const canonical=result&&result.structured_json&&result.structured_json.steps;
 if(Array.isArray(canonical)&&canonical.length)return canonical;
 return (result&&result.steps||[]).map((step,index)=>({
  order:index+1,actor:step.source,action:step.action,target:step.target,asset:"Unknown",
  severity:"Unknown",mitre:{tactic:step.tactic,technique_id:step.techniqueId},
  evidence:step.description,detection:step.detection
 }));
}
function selectedMitreMatch(step){
 const matches=step&&step.rag&&Array.isArray(step.rag.matches)?step.rag.matches:[];
 const technique=step&&step.mitre?step.mitre.technique_id:"";
 return matches.find(match=>match.technique_id===technique)||matches[0]||null;
}
function similarityLabel(value){
 if(value==null||value==="")return "";
 const number=Number(value);
 return Number.isFinite(number)?`SIM ${number.toFixed(3)}`:"";
}
function severityClass(value){
 const name=String(value||"").toLowerCase();
 return ["critical","high","medium","low"].includes(name)?name:"unknown";
}
function diagram(){
 const r=state.result||{},d=r.structured_json||{},steps=diagramSteps(r);
 if(!steps.length)return '<div class="attack-empty">Không có bước tấn công để tổng hợp.</div>';
 if(state.selected>=steps.length)state.selected=0;
 const s=steps[state.selected],mitre=s.mitre||{},matches=s.rag&&Array.isArray(s.rag.matches)?s.rag.matches:[],best=selectedMitreMatch(s);
 const knowledge=s.knowledge&&Array.isArray(s.knowledge.matches)?s.knowledge.matches:[],metadata=d.metadata||{},ragMeta=metadata.rag||{},knowledgeMeta=metadata.knowledge||{};
 const tactics=[...new Set(steps.map(step=>firstKnown(step.mitre&&step.mitre.tactic)).filter(Boolean))];
 const techniques=[...new Set(steps.map(step=>firstKnown(step.mitre&&step.mitre.technique_id)).filter(Boolean))];
 const actors=[...new Set(steps.map(step=>firstKnown(step.actor)).filter(Boolean))];
 const assets=[...new Set(steps.map(step=>firstKnown(step.asset)).filter(Boolean))];
 const sources=Array.isArray(knowledgeMeta.sources)?knowledgeMeta.sources:[...new Set(steps.flatMap(step=>(step.knowledge&&step.knowledge.matches||[]).map(match=>match.source)).filter(Boolean))];
 const score=similarityLabel(s.rag_confidence!=null?s.rag_confidence:best&&best.score);
 const techniqueName=best?matchValue(best,"technique_name",stepValue(s,"technique_name"),best.technique_name,"Chưa xác định tên kỹ thuật"):stepValue(s,"technique_name","Chưa xác định tên kỹ thuật");
 const description=stepValue(s,"description",best?matchValue(best,"description",best.description):"",s.evidence,"Chưa có mô tả ATT&CK.");
 const detection=stepValue(s,"detection",s.detection,best?matchValue(best,"detection",best.detection):"","Chưa có hướng dẫn phát hiện.");
 const mitigation=stepValue(s,"mitigation",s.mitigation,best?matchValue(best,"mitigation",best.mitigation):"","Chưa có biện pháp giảm thiểu.");
 const procedure=stepValue(s,"procedure",s.procedure,best?matchValue(best,"procedure",best.procedure):"","Chưa có quy trình mẫu.");
 const incidentName=topValue(d,"incident_name",d.incident_name,r.incidentName,"Sự cố an ninh mạng");
 const incidentSummary=topValue(d,"summary",d.summary,r.executiveSummary,`${steps.length} bước tấn công đã được tổng hợp.`);
 return `<div class="attack-overview diagram-area" id="diagram-area">
 <div class="attack-toolbar"><div><span>ĐẦU RA</span><div><b>Luồng tấn công tổng hợp</b><small>LLM → JSON có cấu trúc → MITRE ATT&CK RAG → Kho tri thức</small></div></div><div class="attack-summary"><span><b>${steps.length}</b> bước</span><span><b>${techniques.length}</b> kỹ thuật</span><span><b>${tactics.length}</b> chiến thuật</span></div></div>
 <section class="attack-incident"><div><small>SỰ CỐ ĐÃ HỢP NHẤT</small><h3>${esc(incidentName)}</h3><p>${esc(incidentSummary)}</p></div><div class="attack-source-status"><span class="${metadata.rag?"ready":""}">MITRE RAG · ${esc(firstKnown(ragMeta.backend,ragMeta.store,"sẵn sàng"))}</span><span class="${knowledgeMeta.ready?"ready":""}">Kho tri thức · ${knowledgeMeta.matches||0} bằng chứng</span><span>${actors.length} tác nhân · ${assets.length} tài sản</span></div></section>
 <div class="attack-flow" aria-label="Chuỗi bước tấn công">${steps.map((step,index)=>{const stepMitre=step.mitre||{},stepBest=selectedMitreMatch(step),stepScore=similarityLabel(step.rag_confidence!=null?step.rag_confidence:stepBest&&stepBest.score);return `${index?'<div class="attack-connector"><i></i><b>›</b></div>':""}<button class="attack-node ${state.selected===index?"selected":""}" style="--node-color:${graphColor(stepMitre.tactic)}" onclick="selectStep(${index})"><span class="attack-node-order">BƯỚC ${String(step.order||index+1).padStart(2,"0")}</span><strong>${esc(stepValue(step,"action",step.action,"Hành động chưa xác định"))}</strong><small>${esc(stepValue(step,"tactic",tacticVi(stepMitre.tactic)))}</small><div><em>${esc(firstKnown(stepMitre.technique_id,"Chưa xác định"))}</em><i class="${severityClass(step.severity)}">${esc(stepValue(step,"severity",severityVi(step.severity)))}</i></div>${stepScore?`<span class="attack-node-score" title="Độ tương đồng cosine, không phải xác suất">${stepScore}</span>`:""}</button>`}).join("")}</div>
 <section class="attack-detail">
  <div class="attack-detail-head"><div><span>BƯỚC ${String(s.order||state.selected+1).padStart(2,"0")} / ${String(steps.length).padStart(2,"0")}</span><h3>${esc(stepValue(s,"action",s.action,"Hành động chưa xác định"))}</h3></div><div class="attack-detail-tags"><span class="severity ${severityClass(s.severity)}">${esc(stepValue(s,"severity",severityVi(s.severity)))}</span><span class="tech-id">${esc(firstKnown(mitre.technique_id,"Chưa xác định"))}</span>${score?`<span class="similarity" title="Độ tương đồng cosine, không phải xác suất">${score}</span>`:""}</div></div>
  <div class="attack-detail-layout">
   <article class="attack-context"><div class="attack-section-title"><span>01</span><div><b>Ngữ cảnh hành vi</b><small>Dữ liệu trích xuất từ mô tả đầu vào</small></div></div>
    <div class="attack-facts"><div><small>TÁC NHÂN / NGUỒN</small><b>${esc(stepValue(s,"actor",s.actor))}</b></div><div><small>ĐÍCH / MỤC TIÊU</small><b>${esc(stepValue(s,"target",s.target))}</b></div><div><small>TÀI SẢN</small><b>${esc(stepValue(s,"asset",s.asset))}</b></div><div><small>CHIẾN THUẬT</small><b>${esc(stepValue(s,"tactic",tacticVi(mitre.tactic)))}</b></div></div>
    <div class="attack-evidence"><small>DIỄN GIẢI HÀNH VI</small><p>${esc(shortText(description,420))}</p></div>
   </article>
   <article class="attack-intel"><div class="attack-section-title violet"><span>02</span><div><b>Tri thức MITRE ATT&CK</b><small>Kết quả ánh xạ ngữ nghĩa từ PHASE 4</small></div></div>
    <div class="attack-mapping"><div><small>KỸ THUẬT ĐƯỢC CHỌN</small><b>${esc(firstKnown(mitre.technique_id,"Chưa xác định"))} · ${esc(techniqueName)}</b></div>${score?`<span title="Độ tương đồng cosine, không phải xác suất">${score}</span>`:""}</div>
    <p class="attack-description">${esc(shortText(description,520))}</p>
    <div class="attack-response-grid"><div><small>PHÁT HIỆN</small><p>${esc(shortText(detection,420))}</p></div><div><small>GIẢM THIỂU</small><p>${esc(shortText(mitigation,420))}</p></div><div><small>QUY TRÌNH</small><p>${esc(shortText(procedure,420))}</p></div></div>
   </article>
  </div>
  <details class="attack-rag-details" ${matches.length?"":"disabled"}><summary><span>Các ứng viên RAG</span><b>${matches.length} kết quả ngữ nghĩa</b><em>Truy vấn kỹ thuật đã chuẩn hóa</em></summary><div class="attack-candidate-list">${matches.length?matches.map(match=>{const candidateScore=similarityLabel(match.score),selected=match.technique_id===mitre.technique_id;return `<article class="${selected?"selected":""}"><div><span>${selected?"ĐÃ CHỌN":"ỨNG VIÊN"}</span><b>${esc(firstKnown(match.technique_id,"Chưa xác định"))} · ${esc(matchValue(match,"technique_name",match.technique_name,"Kỹ thuật chưa xác định"))}</b>${candidateScore?`<em>${candidateScore}</em>`:""}</div><small>${esc(matchValue(match,"tactics",tacticVi(match.tactics)))}</small><p>${esc(shortText(matchValue(match,"description",match.description,"Không có mô tả."),280))}</p></article>`}).join(""):'<div class="attack-empty-inline">RAG chưa trả về ứng viên cho bước này.</div>'}</div></details>
  <details class="attack-kb-details" ${knowledge.length?"":"disabled"}><summary><span>Bằng chứng từ kho tri thức</span><b>${knowledge.length} tài liệu liên quan</b><em>${sources.length?esc(sources.map(source=>SOURCE_LABEL_VI[source]||source).join(" · ")):"Chưa có nguồn đa dữ liệu"}</em></summary><div class="attack-kb-list">${knowledge.length?knowledge.map(match=>`<article><div><span>${esc(SOURCE_LABEL_VI[match.source]||firstKnown(match.source,"Kho tri thức"))}</span><small>${esc(documentTypeVi(match.document_type))}</small></div><b>${esc(matchValue(match,"title",match.title,"Bằng chứng chưa đặt tên"))}</b><p>${esc(shortText(matchValue(match,"snippet",match.snippet,"Không có trích đoạn."),360))}</p>${match.origin?`<em title="${esc(match.origin)}">${esc(shortText(match.origin,120))}</em>`:""}</article>`).join(""):'<div class="attack-empty-inline">Kho tri thức chưa có bằng chứng liên quan cho bước này.</div>'}</div></details>
 </section></div>`;
}
function timeline(){const r=state.result,d=r.structured_json||{},steps=d.steps||[];return `<div class="timeline">${steps.map((s,i)=>`<div class="timeline-row"><div class="time-dot"><i></i>${i<steps.length-1?"<span></span>":""}</div><div class="timeline-content"><small>GIAI ĐOẠN ${i+1} · ${esc(stepValue(s,"tactic",tacticVi(s.mitre&&s.mitre.tactic)))}</small><h3>${esc(stepValue(s,"action",s.action))} <em>${esc(firstKnown(s.mitre&&s.mitre.technique_id,"Chưa xác định"))}</em></h3><p>${esc(stepValue(s,"description",s.evidence,"Chưa có mô tả."))}</p></div></div>`).join("")}</div>`}
function report(){const r=state.result,d=r.structured_json||{},localizedEntities=(d.steps||[]).flatMap(s=>[stepValue(s,"actor",s.actor),stepValue(s,"target",s.target),stepValue(s,"asset",s.asset)]).filter((x,i,a)=>x!=="Chưa xác định"&&a.indexOf(x)===i),entities=localizedEntities.length?localizedEntities:r.entities,recommendations=displayList(d,"recommendations",r.recommendations||[]);return `<div class="report"><div class="report-block"><h3>ⓘ Tóm tắt điều hành</h3><p>${esc(topValue(d,"summary",d.summary,r.executiveSummary))}</p></div><div class="report-cols"><div class="report-block"><h3>◎ Chỉ dấu & thực thể</h3>${entities.map(x=>`<span class="entity">${esc(x)}</span>`).join("")}</div><div class="report-block"><h3>✓ Khuyến nghị ưu tiên</h3><ol>${recommendations.map(x=>`<li>${esc(x)}</li>`).join("")}</ol></div></div></div>`}

function overviewPage(){
 const r=state.result,d=r&&r.structured_json||{},metrics=[["Phân tích hôm nay",state.history.length,"◉"],["Kỹ thuật phát hiện",r?r.techniques.length:0,"⌾"],["Mức rủi ro",r?(sev[r.severity]||["Chưa xác định"])[0]:"—","△"],["Độ tin cậy",r?`${r.confidence}%`:"—","✓"]];
 return `<div class="page">${pageTitle("Trung tâm điều hành","Tổng quan tình hình phân tích và trực quan hóa an ninh mạng.","<button class=\"new-analysis\" onclick=\"navigate('Phân tích sự cố')\">＋ Phân tích mới</button>")}
 <div class="metric-grid">${metrics.map(m=>`<div class="metric panel"><span style="font-size:22px;color:#087f8c">${m[2]}</span><span>${m[0]}</span><b>${m[1]}</b></div>`).join("")}</div>
 <div class="overview-grid"><div class="panel overview-card"><div class="panel-head"><b>Chuỗi tấn công gần nhất</b><span>⌁</span></div>${r?`<div class="mini-flow">${(d.steps||[]).map((s,i)=>`<div><i class="c${i%5}">${i+1}</i><span>${esc(stepValue(s,"action",s.action))}</span></div>`).join("")}</div>`:emptyView()}</div>
 <div class="panel overview-card"><div class="panel-head"><b>Hoạt động gần đây</b><span>◷</span></div>${state.history.length?state.history.map(h=>`<div class="history-mini"><span class="dot"></span><div><b>${esc(h.name)}</b><small>${h.time}</small></div></div>`).join(""):'<p class="muted">Chưa có hoạt động.</p>'}</div></div></div>`;
}
function knowledgePage(){
 const descriptions={mitre_attack:"Kỹ thuật, chiến thuật, biện pháp giảm thiểu và quy trình Enterprise ATT&CK.",sigma:"Quy tắc phát hiện SIEM từ SigmaHQ.",yara:"Siêu dữ liệu quy tắc thật từ Yara-Rules; hỗ trợ tệp .yar/.yara nội bộ.",threat_intelligence:"IOC, CVE, mã độc và thông tin về chiến dịch tấn công.",nist_cis:"Hướng dẫn NIST/CIS và kiểm soát an ninh.",playbooks:"Kịch bản ứng phó sự cố có thể truy vấn.",enterprise_assets:"Danh mục tài sản và ngữ cảnh mạng của tổ chức."};
 const order=["mitre_attack","sigma","yara","threat_intelligence","nist_cis","playbooks","enterprise_assets"],sources=state.knowledge&&state.knowledge.sources;
 const action=`<div class="knowledge-actions"><label class="asset-upload">＋ Tài sản<input type="file" accept=".csv,.json" onchange="importAssets(this.files[0])"></label><button class="new-analysis" ${state.knowledgeBusy?"disabled":""} onclick="syncKnowledge()">↻ ${state.knowledgeBusy?"Đang đồng bộ":"Đồng bộ nguồn"}</button></div>`;
 const cards=sources?order.map(key=>{const s=sources[key]||{},count=key==="enterprise_assets"?`${s.assets||0} tài sản`:`${s.documents||0} tài liệu`,status=s.ready?"✓ Sẵn sàng":s.last_error?"× Có lỗi":"○ Chưa có dữ liệu";return `<button class="knowledge-card panel" onclick="filterKnowledge('${key}')"><div><span style="font-size:26px;color:#087f8c">◇</span><span class="synced ${s.ready?"":"inactive"}">${status}</span></div><h3>${esc(SOURCE_LABEL_VI[key]||s.label||key)}</h3><p>${esc(descriptions[key])}</p><small><span>${count} · ${s.files||0} tệp</span><b>›</b></small>${s.last_error?`<em>${esc(shortText(s.last_error,120))}</em>`:""}</button>`}).join(""):`<div class="knowledge-loading panel">Đang đọc danh mục nguồn và chỉ mục SQLite...</div>`;
 const totals=state.knowledge&&state.knowledge.totals?`<div class="knowledge-summary"><span><b>${state.knowledge.totals.documents}</b> tài liệu</span><span><b>${state.knowledge.totals.files}</b> tệp</span><span><b>${state.knowledge.totals.assets}</b> tài sản</span><span>${esc(state.knowledge.search_engine)}</span></div>`:"";
 const results=knowledgeSearchResults();
 return `<div class="page">${pageTitle("Kho tri thức","Nguồn dữ liệu thật phục vụ RAG.",action)}${totals}<div class="search-wide">⌕<input id="knowledge-query" placeholder="Tìm kỹ thuật, IOC, quy tắc phát hiện..." onkeydown="if(event.key==='Enter')searchKnowledge()"><button onclick="searchKnowledge()">Tìm</button></div><div class="knowledge-grid">${cards}</div>${results}</div>`;
}
function knowledgeSearchResults(){const data=state.knowledgeResults;if(!data)return "";if(!data.results.length)return '<div class="knowledge-results panel"><p>Không tìm thấy tài liệu phù hợp.</p></div>';return `<div class="knowledge-results panel"><div class="panel-head"><b>Kết quả tìm kiếm</b><span>${data.count} tài liệu</span></div>${data.results.map(x=>`<article><span>${esc(SOURCE_LABEL_VI[x.source]||x.source)} · ${esc(documentTypeVi(x.document_type))}</span><h3>${esc(matchValue(x,"title",x.title))}</h3><p>${esc(matchValue(x,"snippet",x.snippet,shortText(x.text,360)))}</p><small>${esc(x.origin)}</small></article>`).join("")}</div>`}
async function loadKnowledgeStatus(){try{const r=await fetch("/api/knowledge/status"),d=await r.json();if(!r.ok)throw new Error(d.error);state.knowledge=d;if(state.nav==="Kho tri thức")render()}catch(e){toast(e.message)}}
async function syncKnowledge(){state.knowledgeBusy=true;render();toast("Đang tải và lập chỉ mục các nguồn tri thức thật...");try{const r=await fetch("/api/knowledge/sync",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({source:"all"})}),d=await r.json();if(!r.ok&&r.status!==207)throw new Error(d.error||"Đồng bộ thất bại.");state.knowledge=d.status;const failed=Object.values(d.results||{}).filter(x=>!x.ok).length;toast(failed?`Đồng bộ xong, ${failed} nguồn cần kiểm tra.`:"Đã đồng bộ và lập chỉ mục tất cả nguồn.")}catch(e){toast(e.message)}finally{state.knowledgeBusy=false;render()}}
async function searchKnowledge(source){const input=$("#knowledge-query"),query=(input&&input.value.trim())||"";if(query.length<2)return toast("Nhập ít nhất 2 ký tự.");try{const r=await fetch("/api/knowledge/search",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query,sources:source?[source]:null,limit:20})}),d=await r.json();if(!r.ok)throw new Error(d.error);state.knowledgeResults=d;render()}catch(e){toast(e.message)}}
function filterKnowledge(source){const input=$("#knowledge-query");if(!input||input.value.trim().length<2){toast("Nhập từ khóa rồi chọn nguồn để lọc.");return}searchKnowledge(source)}
async function importAssets(file){if(!file)return;const form=new FormData();form.append("file",file);form.append("mode","merge");try{const r=await fetch("/api/assets/import",{method:"POST",body:form}),d=await r.json();if(!r.ok)throw new Error(d.error);toast(`Đã nhập ${d.imported} tài sản.`);await loadKnowledgeStatus()}catch(e){toast(e.message)}}
function historyPage(){
 return `<div class="page">${pageTitle("Lịch sử phân tích","Các phiên phân tích gần đây trong không gian làm việc.")}<div class="panel history-table"><div class="table-head"><span>Sự cố</span><span>Thời gian</span><span>Mức độ</span><span>Trạng thái</span></div>${state.history.length?state.history.map(h=>`<button class="table-row" onclick="navigate('Phân tích sự cố')"><b>${esc(h.name)}</b><span>${h.time}</span><span class="severity ${h.severity}">${(sev[h.severity]||["Chưa xác định"])[0]}</span><span class="done">✓ Hoàn tất</span></button>`).join(""):emptyView()}</div></div>`;
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
 let p=18;const timer=setInterval(()=>{p=Math.min(92,p+13);const bar=$(".progress i");if(bar)bar.style.width=p+"%";const label=$(".progress span");if(label)label.textContent=p<55?"Đang trích xuất thực thể...":p<80?"Đang ánh xạ ATT&CK...":"Đang tạo đồ thị tấn công..."},180);
 try{const res=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({description})});const data=await res.json();if(!res.ok)throw new Error(data.error||"Không thể phân tích.");state.result=data;state.selected=0;state.tab="phase5";state.history.unshift({name:topValue(data.structured_json||{},"incident_name",data.incidentName),time:new Date().toLocaleTimeString("vi-VN"),severity:data.severity});state.history=state.history.slice(0,8);render();toast(`PHASE 5 đã dựng đồ thị gồm ${data.steps.length} nút.`)}catch(e){toast(e.message);btn.disabled=false;btn.textContent="⚡ Phân tích sự cố"}finally{clearInterval(timer)}
}
function changeTab(tab){state.tab=tab;$("#result-content").innerHTML=renderResultTab();document.querySelectorAll(".result-tabs button").forEach(b=>b.classList.toggle("active",b.dataset.tab===tab));if(tab==="phase5")loadGraphPreview(state.graphEngine)}
function selectStep(i){state.selected=i;$("#result-content").innerHTML=diagram()}
function download(content,name,type){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([content],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function exportJSON(){download(JSON.stringify(state.result.structured_json||state.result,null,2),"cybervision-structured-incident.json","application/json");toast("Đã xuất JSON chuẩn hóa.")}
function exportSVG(){graphDownload("graphviz","svg")}
async function exportReport(format){try{toast(`Đang tạo ${format.toUpperCase()} trên máy chủ...`);const r=await fetch(`/api/report/${format}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({structured_json:state.result.structured_json})});if(!r.ok){const d=await r.json();throw new Error(d.error)}const blob=await r.blob(),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`cybervision-${state.result.structured_json.incident_id}.${format}`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);toast(`Đã xuất báo cáo ${format.toUpperCase()} trên máy chủ.`)}catch(e){toast(e.message)}}
function toast(message){let el=$("#toast");if(!el){el=document.createElement("div");el.id="toast";el.className="toast";document.body.appendChild(el)}el.innerHTML=`✓ ${esc(message)}`;clearTimeout(window.toastTimer);window.toastTimer=setTimeout(()=>el.remove(),3000)}
function updateConnectionStatus(){const button=$(".connection");if(!button)return;button.innerHTML=`<span></span>${state.config&&state.config.enabled?"LLM ĐANG BẬT":"BỘ MÁY CỤC BỘ"}`}
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
 <div class="modal-head"><div><span class="step violet">LLM</span><div><b>Cấu hình LLM & API</b><small>Trích xuất có cấu trúc · ATT&CK RAG · Dự phòng cục bộ</small></div></div><button onclick="closeSettings()">×</button></div>
 <div class="modal-body"><div class="settings-status"><div><i class="${c.enabled?"on":""}"></i><span><b>${c.enabled?"LLM đang bật":"Đang dùng bộ máy cục bộ"}</b><small>Khóa API ${c.has_api_key?"đã được cấu hình":"chưa được cấu hình"}</small></span></div><label class="switch"><input id="cfg-enabled" type="checkbox" ${c.enabled?"checked":""}><span></span></label></div>
 <div class="form-grid">
 <label>Nhà cung cấp<select id="cfg-provider" onchange="providerChanged()">${Object.keys(providerDefaults).map(p=>`<option value="${p}" ${c.provider===p?"selected":""}>${{dashscope:"Qwen Cloud / DashScope",zhipu:"Z.AI / Zhipu GLM",openai:"OpenAI",azure:"Azure OpenAI",anthropic:"Anthropic",gemini:"Google Gemini",ollama:"Ollama (cục bộ)",compatible:"Tương thích OpenAI"}[p]}</option>`).join("")}</select></label>
 <label>Mô hình / Bản triển khai<input id="cfg-model" value="${esc(c.model)}" placeholder="Tên mô hình"></label>
 <label class="full">URL cơ sở<input id="cfg-url" value="${esc(c.base_url)}" placeholder="https://..."></label>
 <label class="full">Khóa API <span class="field-hint">${esc(c.api_key_masked||"")}</span><div class="password-field"><input id="cfg-key" type="password" placeholder="${c.has_api_key?"Để trống để giữ khóa hiện tại":"sk-..."}"><button type="button" onclick="toggleKey()">Hiện</button></div></label>
 <label>Mức ngẫu nhiên<input id="cfg-temp" type="number" min="0" max="2" step=".1" value="${c.temperature}"></label>
 <label>Thời gian chờ (giây)<input id="cfg-timeout" type="number" min="5" max="300" value="${c.timeout}"></label>
 </div>
 <div class="option-row"><div><b>Ngữ cảnh ATT&CK RAG</b><small>Đưa kỹ thuật liên quan từ kho tri thức vào câu lệnh cho mô hình</small></div><label class="switch"><input id="cfg-rag" type="checkbox" ${c.rag_enabled?"checked":""}><span></span></label></div>
 <div class="option-row"><div><b>Việt hóa kết quả RAG</b><small>Giữ dữ liệu ATT&CK gốc tiếng Anh nhưng hiển thị và báo cáo bằng tiếng Việt</small></div><label class="switch"><input id="cfg-localize-rag" type="checkbox" ${c.localize_rag!==false?"checked":""}><span></span></label></div>
 <details><summary>Câu lệnh hệ thống nâng cao</summary><textarea id="cfg-prompt" placeholder="Để trống để dùng câu lệnh mặc định">${esc(c.system_prompt||"")}</textarea></details>
 <div id="config-result"></div></div>
 <div class="modal-foot"><label><input id="cfg-persist" type="checkbox"> Lưu vào .env trên máy chủ</label><div><button class="test-btn" onclick="testLLM()">Kiểm tra kết nối</button><button class="save-btn" onclick="saveConfig()">Lưu cấu hình</button></div></div></div>`;
 document.body.appendChild(wrap);setTimeout(()=>wrap.classList.add("show"),10);
}
function closeSettings(){const m=$("#settings-modal");if(m){m.classList.remove("show");setTimeout(()=>m.remove(),180)}}
function providerChanged(){const p=$("#cfg-provider").value,[url,model]=providerDefaults[p];$("#cfg-url").value=url;$("#cfg-model").value=model}
function toggleKey(){const i=$("#cfg-key");i.type=i.type==="password"?"text":"password";i.nextElementSibling.textContent=i.type==="password"?"Hiện":"Ẩn"}
function configPayload(){return {enabled:$("#cfg-enabled").checked,provider:$("#cfg-provider").value,model:$("#cfg-model").value.trim(),base_url:$("#cfg-url").value.trim(),api_key:$("#cfg-key").value.trim(),temperature:Number($("#cfg-temp").value),timeout:Number($("#cfg-timeout").value),rag_enabled:$("#cfg-rag").checked,localize_rag:$("#cfg-localize-rag").checked,system_prompt:$("#cfg-prompt").value,persist:$("#cfg-persist").checked}}
async function testLLM(){const out=$("#config-result");out.className="config-result loading";out.textContent="◷ Đang kết nối tới nhà cung cấp...";try{const r=await fetch("/api/config/test",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(configPayload())}),d=await r.json();if(!r.ok)throw new Error(d.error);out.className="config-result success";out.textContent=`✓ Kết nối thành công · ${d.provider} / ${d.model}`}catch(e){out.className="config-result error";out.textContent=`× ${e.message}`}}
async function saveConfig(){const out=$("#config-result");try{const r=await fetch("/api/config",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(configPayload())}),d=await r.json();if(!r.ok)throw new Error(d.error);state.config=d;out.className="config-result success";out.textContent="✓ Đã lưu cấu hình. Các phân tích mới sẽ dùng thiết lập này.";setTimeout(()=>{closeSettings();render();toast("Đã cập nhật bộ máy LLM.")},900)}catch(e){out.className="config-result error";out.textContent=`× ${e.message}`}}
document.addEventListener("keydown",e=>{if((e.ctrlKey||e.metaKey)&&e.key==="Enter"&&state.nav==="Phân tích sự cố")analyze()});
render();
void loadConfig();
void loadVectorBackends();
