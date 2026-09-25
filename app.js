const $=s=>document.querySelector(s);
function hide(sel){const el=$(sel);if(el)el.classList.add("hidden")}
function show(sel){const el=$(sel);if(el)el.classList.remove("hidden")}
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]))}
function parse(s){const o={};(s||"").replace(/\r?\n/g," ").split(";").map(x=>x.trim()).filter(Boolean).forEach(x=>{let a=x.split(/\s+/),d=a.shift().toLowerCase();if(!o[d])o[d]=[];a.forEach(v=>{if(!o[d].includes(v))o[d].push(v)})});return o}
const fallbackToDefault=new Set(["child-src","connect-src","font-src","frame-src","img-src","manifest-src","media-src","object-src","prefetch-src","script-src","script-src-elem","script-src-attr","style-src","style-src-elem","style-src-attr","worker-src"]);
function effective(p,d){
 if(p[d])return {values:p[d],via:d,explicit:true};
 if(fallbackToDefault.has(d)&&p["default-src"])return {values:p["default-src"],via:"default-src",explicit:false};
 return {values:null,via:null,explicit:false};
}
function nonceValues(p){return Object.values(p).flat().filter(v=>/^'nonce-[^']+'$/i.test(v))}
function sourceClass(v){if(v==="'unsafe-eval'")return"bad";if(v==="'unsafe-inline'"||v==="*"||v==="http:"||v==="https:")return"risk";if(/^'nonce-/i.test(v))return"nonce";return""}
function analyzePolicy(p){
 const f=[],add=(sev,title,why,rec)=>f.push({sev,title,why,rec}),has=(d,v)=>(p[d]||[]).includes(v);
 ["script-src","script-src-elem","script-src-attr"].forEach(d=>{if(has(d,"'unsafe-eval'"))add("HIGH",`${d} contains 'unsafe-eval'`,"This permits JavaScript string-to-code evaluation, which weakens CSP's protection against some script injection paths.","Identify the dependency requiring eval/new Function and test an upgrade or replacement before removing it.");if(has(d,"'unsafe-inline'"))add("MEDIUM",`${d} contains 'unsafe-inline'`,"Inline script execution is broadly permitted.","Where compatible, migrate inline scripts to nonces or hashes and verify runtime behavior.")});
 ["style-src","style-src-elem","style-src-attr"].forEach(d=>{if(has(d,"'unsafe-inline'"))add("MEDIUM",`${d} contains 'unsafe-inline'`,"Inline styles are allowed by this directive.","Inspect runtime style attributes and libraries first; nonce/hash support does not cover every style-attribute pattern.")});
 const form=effective(p,"form-action");
 if(!form.values)add("MEDIUM","form-action has no policy","form-action does not fall back to default-src, so form submission destinations are not restricted by CSP.","Define the destinations the application actually needs, commonly 'self' plus explicit trusted origins.");
 else if(form.values.includes("*")||form.values.includes("http:")||form.values.includes("https:"))add("MEDIUM","form-action is broad","The current form-action allows a broad set of submission destinations.","Replace scheme-wide or wildcard allowances with the specific destinations required by the application.");
 const frame=effective(p,"frame-ancestors");
 if(!frame.values)add("MEDIUM","frame-ancestors has no policy","frame-ancestors does not fall back to default-src, so the CSP does not restrict which parent pages may frame this page.","Use frame-ancestors 'self', 'none', or an explicit allowlist according to the embedding requirement.");
 const obj=effective(p,"object-src");
 if(!obj.values)add("MEDIUM","object-src has no effective policy","Neither object-src nor default-src provides a restriction for object/embed/plugin content.","If this content is unused, consider object-src 'none'.");
 else if(obj.values.includes("'none'")&&obj.via==="default-src")add("INFO","object-src inherits default-src 'none'","object-src is not explicitly present, but its effective policy falls back to default-src 'none'.","No immediate change is required for this specific fallback; an explicit object-src can still improve readability.");
 if(!p["base-uri"])add("MEDIUM","base-uri has no policy","base-uri does not fall back to default-src, so CSP is not restricting the document's base URL.","Consider base-uri 'self' or 'none' according to application requirements.");
 return f;
}
function effectiveRows(p){
 const ds=["script-src","style-src","img-src","connect-src","font-src","object-src","frame-src","worker-src","frame-ancestors","form-action","base-uri"];
 return ds.map(d=>[d,effective(p,d)]);
}

function clonePolicy(p){const out={};Object.entries(p).forEach(([k,v])=>out[k]=[...v]);return out}
function serializePolicy(p){return Object.entries(p).map(([d,v])=>d+(v.length?" "+v.join(" "):"")+";").join("\n")}
function buildRecommendations(p){
 const q=clonePolicy(p), fixes=[];
 function removeToken(dir,token,reason){
   if(q[dir]?.includes(token)){
     const before=dir+" "+q[dir].join(" ")+";";
     q[dir]=q[dir].filter(x=>x!==token);
     const after=dir+(q[dir].length?" "+q[dir].join(" "):"")+";";
     fixes.push({title:`Review removing ${token} from ${dir}`,before,after,reason,dir});
   }
 }
 ["script-src","script-src-elem","script-src-attr"].forEach(d=>{
   removeToken(d,"'unsafe-eval'","Test dependencies for eval/new Function usage before enforcing this change.");
   removeToken(d,"'unsafe-inline'","Only test this change when inline scripts are covered by nonces/hashes or have been removed.");
 });
 ["style-src","style-src-elem","style-src-attr"].forEach(d=>{
   removeToken(d,"'unsafe-inline'","Runtime style attributes may still require this allowance. Verify the rendered application before enforcing.");
 });
 if(!q["frame-ancestors"]){
   q["frame-ancestors"]=["'self'"];
   fixes.push({title:"Add frame-ancestors",before:"(not set)",after:"frame-ancestors 'self';",reason:"Starting point only. Add explicit trusted origins if this site must be embedded elsewhere.",dir:"frame-ancestors"});
 }
 if(!q["form-action"]){
   q["form-action"]=["'self'"];
   fixes.push({title:"Add form-action",before:"(not set)",after:"form-action 'self';",reason:"Starting point only. Add external submission endpoints if forms legitimately post off-site.",dir:"form-action"});
 } else if(q["form-action"].some(x=>["*","http:","https:"].includes(x))){
   const before="form-action "+q["form-action"].join(" ")+";";
   q["form-action"]=["'self'"];
   fixes.push({title:"Narrow form-action",before,after:"form-action 'self';",reason:"This is a conservative starting point. Preserve any required external form endpoints.",dir:"form-action"});
 }
 if(!q["base-uri"]){
   q["base-uri"]=["'self'"];
   fixes.push({title:"Add base-uri",before:"(not set)",after:"base-uri 'self';",reason:"Use 'none' instead if the application never needs a base element.",dir:"base-uri"});
 }
 const obj=effective(q,"object-src");
 if(!obj.values){
   q["object-src"]=["'none'"];
   fixes.push({title:"Add object-src",before:"(no effective restriction)",after:"object-src 'none';",reason:"Appropriate when object/embed/plugin content is not required.",dir:"object-src"});
 }
 return {policy:q,fixes};
}

function render(d){
 const csp=d.csp||"",p=parse(csp),entries=Object.entries(p),fs=analyzePolicy(p),nonces=nonceValues(p);
 $("#site").textContent=d.requestedUrl;$("#finalUrl").textContent=d.finalUrl&&d.finalUrl!==d.requestedUrl?"Final URL: "+d.finalUrl:"";
 $("#dirs").textContent=entries.length;$("#sources").textContent=entries.reduce((n,[,s])=>n+s.length,0);$("#findingsCount").textContent=fs.filter(x=>x.sev!=="INFO").length;$("#infoCount").textContent=fs.filter(x=>x.sev==="INFO").length;
 $("#cspStatus").textContent=csp?"✓ CSP detected":"⚠ CSP not detected";$("#cspStatus").className=csp?"ok":"warn";
 let pills=[]; if(csp)pills.push('<span class="pill good">Enforced CSP</span>'); if(d.reportOnly)pills.push('<span class="pill">Report-only CSP</span>');
 if (p["default-src"]?.includes("'none'")) {
    pills.push(`<span class="pill good">default-src 'none'</span>`);
  }
  if (nonces.length) {
    pills.push(`<span class="pill nonce">Nonce-based scripts/styles · ${nonces.length}</span>`);
  }
 $("#statusPills").innerHTML=pills.join("");
 const actionable=fs.filter(x=>x.sev!=="INFO"), infos=fs.filter(x=>x.sev==="INFO");
 const dirFromTitle=t=>(t.match(/^(script-src(?:-elem|-attr)?|style-src(?:-elem|-attr)?|form-action|frame-ancestors|object-src|base-uri)/)||[])[1]||"";
 const cards=arr=>arr.map(x=>{const dir=dirFromTitle(x.title);return `<div class="finding ${dir?"jumpable":""}" ${dir?`data-jump="${dir}" title="Jump to ${dir}"`:""}><div class="fhead"><b>${esc(x.title)}</b><span class="sev ${x.sev==="HIGH"?"high":x.sev==="MEDIUM"?"medium":"info"}">${x.sev}</span></div><p>${esc(x.why)}</p><p class="advice"><b>${x.sev==="INFO"?"NOTE":"REVIEW"}</b><br>${esc(x.rec)}</p></div>`}).join("");
 $("#findings").innerHTML=(actionable.length?cards(actionable):'<div style="font-size:11px;color:#6f7b8e">No common actionable findings from this rule set.</div>')+(infos.length?`<div style="font-size:10px;font-weight:800;letter-spacing:.08em;color:#66758b;margin:16px 0 8px">INFORMATION</div>${cards(infos)}`:"");
 $("#effective").innerHTML=effectiveRows(p).map(([name,e])=>{let txt,state,cls;if(!e.values){txt="No CSP restriction";state="No policy";cls="warn"}else if(e.explicit){txt=e.values.join(" ");state="Explicit";cls=e.values.includes("'none'")?"good":""}else{txt=`↳ ${e.via} ${e.values.join(" ")}`;state="Inherited";cls=e.values.includes("'none'")?"good":""}return `<div class="effective"><span class="eff-name">${esc(name)}</span><span class="inherit">${esc(txt)}</span><span class="state ${cls}">${state}</span></div>`}).join("");
 $("#directiveList").innerHTML=entries.length?entries.map(([n,s])=>`<div class="directive" id="directive-${esc(n)}"><div class="dname">${esc(n)}</div><div class="sources">${s.map(v=>`<span class="src ${sourceClass(v)}">${esc(v)}</span>`).join("")||'<span class="src">no value</span>'}</div></div>`).join(""):'<div style="font-size:11px;color:#6f7b8e">No enforced CSP header detected.</div>';
 const map={}; entries.forEach(([dir,vals])=>vals.forEach(v=>{if(!map[v])map[v]=[];map[v].push(dir)}));
 const isOrigin=v=>/^https?:\/\/[^/]+/i.test(v);
 const origins=Object.entries(map).filter(([v])=>isOrigin(v)).sort((a,b)=>b[1].length-a[1].length);
 const tokens=Object.entries(map).filter(([v])=>!isOrigin(v)).sort((a,b)=>b[1].length-a[1].length);
 const rows=arr=>arr.map(([src,dirs])=>`<div class="source-row"><span class="host">${esc(src)}</span><span class="used">${dirs.map(x=>`<span class="src ${sourceClass(src)}">${esc(x)}</span>`).join("")}</span></div>`).join("");
 $("#sourceSummary").innerHTML=`<div class="summary-group"><h4>TRUSTED ORIGINS</h4>${origins.length?rows(origins):'<div style="font-size:11px;color:#6f7b8e">No explicit HTTP(S) origins.</div>'}</div><div class="summary-group"><h4>KEYWORDS &amp; SCHEMES</h4>${tokens.length?rows(tokens):'<div style="font-size:11px;color:#6f7b8e">No keywords or schemes.</div>'}</div>`;

 $("#findings").querySelectorAll("[data-jump]").forEach(el=>el.onclick=()=>{
   const target=document.getElementById("directive-"+el.dataset.jump);
   if(target){target.scrollIntoView({behavior:"smooth",block:"center"});target.classList.remove("flash");void target.offsetWidth;target.classList.add("flash")}
 });

 const rec=buildRecommendations(p);
 $("#fixes").innerHTML=rec.fixes.length?rec.fixes.map((f,i)=>`<div class="fix"><div class="fix-title"><b>${esc(f.title)}</b><button class="copy-small" data-copyfix="${i}">Copy change</button></div><div class="diff"><div class="minus">− ${esc(f.before)}</div><div class="plus">+ ${esc(f.after)}</div></div><div class="fix-note">${esc(f.reason)}</div></div>`).join(""):'<div style="font-size:11px;color:#6f7b8e">No automatic hardening changes suggested by this version.</div>';
 const proposed=serializePolicy(rec.policy);
 $("#proposedCsp").textContent=proposed||"No CSP available to propose changes from.";
 $("#fixes").querySelectorAll("[data-copyfix]").forEach(b=>b.onclick=async()=>{const f=rec.fixes[+b.dataset.copyfix];try{await navigator.clipboard.writeText(f.after);const old=b.textContent;b.textContent="Copied";setTimeout(()=>b.textContent=old,1000)}catch{}});
 $("#copyProposed").onclick=async()=>{try{await navigator.clipboard.writeText(proposed);const b=$("#copyProposed"),old=b.textContent;b.textContent="Copied";setTimeout(()=>b.textContent=old,1000)}catch{}};

 $("#rawCsp").textContent=csp||"No Content-Security-Policy header detected.";$("#rawReport").textContent=d.reportOnly||"No Content-Security-Policy-Report-Only header detected.";
 const headers=d.headers||{};$("#headerTable").innerHTML=Object.entries(headers).map(([k,v])=>`<tr><th>${esc(k)}</th><td>${esc(v||"—")}</td></tr>`).join("");
 $("#result").classList.remove("hidden");
}
function shortPath(raw){
 try{const u=new URL(raw);return u.pathname+(u.search||"")}catch{return raw}
}

let siteGroups=[];
function escAttr(v){return esc(v).replace(/"/g,"&quot;")}
function statusClass(n){return n>=500?"http-bad":n>=400?"http-warn":""}
function parsePolicyLocal(csp){
 const o={};(csp||"").split(";").map(x=>x.trim()).filter(Boolean).forEach(x=>{const a=x.split(/\s+/),d=a.shift().toLowerCase();o[d]=a});return o
}
function effLocal(p,d){
 const noFallback=["frame-ancestors","form-action","base-uri"];
 if(p[d])return {values:p[d],mode:"Explicit"};
 if(!noFallback.includes(d)&&p["default-src"])return {values:p["default-src"],mode:"Inherited"};
 return {values:null,mode:"No policy"};
}
function pageFindings(p){
 const out=[],has=(d,v)=>(p[d]||[]).includes(v);
 ["script-src","script-src-elem","script-src-attr"].forEach(d=>{if(has(d,"'unsafe-eval'"))out.push({sev:"HIGH",title:`${d} contains 'unsafe-eval'`,why:"Allows JavaScript string-to-code evaluation.",rec:"Identify dependencies requiring eval/new Function before removing it."});if(has(d,"'unsafe-inline'"))out.push({sev:"HIGH",title:`${d} contains 'unsafe-inline'`,why:"Inline scripts are allowed by this directive.",rec:"Move inline scripts or cover them with nonces/hashes before removing it."})});
 ["style-src","style-src-elem","style-src-attr"].forEach(d=>{if(has(d,"'unsafe-inline'"))out.push({sev:"MEDIUM",title:`${d} contains 'unsafe-inline'`,why:"Inline styles are allowed.",rec:"Inspect runtime style attributes and library behavior before removing it."})});
 if(!p["frame-ancestors"])out.push({sev:"MEDIUM",title:"frame-ancestors has no policy",why:"CSP does not restrict which parent pages may frame this page.",rec:"Consider 'self', 'none', or explicit trusted origins."});
 if(!p["form-action"])out.push({sev:"MEDIUM",title:"form-action has no policy",why:"Form submission destinations are not restricted by CSP.",rec:"Define only the form destinations the application needs."});else if(p["form-action"].some(x=>["*","http:","https:"].includes(x)))out.push({sev:"MEDIUM",title:"form-action is broad",why:"Form submissions allow broad destination schemes.",rec:"Replace broad schemes with required destinations."});
 if(!p["base-uri"])out.push({sev:"MEDIUM",title:"base-uri has no policy",why:"The document base URL is not restricted by CSP.",rec:"Consider base-uri 'self' or 'none'."});
 return out;
}
function recommendationsLocal(p){
 const q={};Object.entries(p).forEach(([k,v])=>q[k]=[...v]);const fixes=[];
 const remove=(d,t,note)=>{if(q[d]?.includes(t)){const before=d+" "+q[d].join(" ")+";";q[d]=q[d].filter(x=>x!==t);fixes.push({title:`Review removing ${t} from ${d}`,before,after:d+(q[d].length?" "+q[d].join(" "):"")+";",note})}};
 ["script-src","script-src-elem","script-src-attr"].forEach(d=>{remove(d,"'unsafe-eval'","Test eval/new Function dependencies first.");remove(d,"'unsafe-inline'","Only remove after inline scripts are nonce/hash covered.")});
 ["style-src","style-src-elem","style-src-attr"].forEach(d=>remove(d,"'unsafe-inline'","Runtime style attributes may still require this allowance."));
 if(!q["frame-ancestors"]){q["frame-ancestors"]=["'self'"];fixes.push({title:"Add frame-ancestors",before:"(not set)",after:"frame-ancestors 'self';",note:"Add trusted origins if this site must be framed elsewhere."})}
 if(!q["form-action"]||q["form-action"].some(x=>["*","http:","https:"].includes(x))){const before=q["form-action"]?"form-action "+q["form-action"].join(" ")+";":"(not set)";q["form-action"]=["'self'"];fixes.push({title:"Restrict form-action",before,after:"form-action 'self';",note:"Preserve any required external form endpoints."})}
 if(!q["base-uri"]){q["base-uri"]=["'self'"];fixes.push({title:"Add base-uri",before:"(not set)",after:"base-uri 'self';",note:"Use 'none' if a base element is never required."})}
 const proposed=Object.entries(q).map(([d,v])=>d+(v.length?" "+v.join(" "):"")+";").join("\n");
 return {fixes,proposed};
}
function openInspector(page, group=null){
 const p=parsePolicyLocal(page.csp||""),fs=pageFindings(p),rec=recommendationsLocal(p);
 $("#inspectorName").textContent=group?group.id+" Inspector":"Page Inspector";
 $("#inspectorUrl").textContent=group?`${group.pages.length} pages share this CSP`:page.url;
 $("#iStatus").textContent=group?"Multiple":(page.status||"—");
 $("#iStatus").className=group?"":statusClass(page.status||0);
 $("#iCspStatus").textContent=page.csp?"Detected":"Not detected";$("#iPolicy").textContent=page.policyId||group?.id||"—";$("#iFindingCount").textContent=fs.length;
 if(group){$("#policyApplies").textContent=`This policy applies to ${group.pages.length} scanned pages.`;show("#policyApplies")}else hide("#policyApplies");
 $("#iFindings").innerHTML=fs.length?fs.map(f=>`<div class="i-finding"><b>${esc(f.title)} · ${f.sev}</b><p>${esc(f.why)}</p><p><b>REVIEW</b> ${esc(f.rec)}</p></div>`).join(""):'<div style="font-size:10px;color:#087a49">No common findings from this rule set.</div>';
 const dirs=["script-src","style-src","img-src","connect-src","font-src","object-src","frame-src","worker-src","frame-ancestors","form-action","base-uri"];
 $("#iEffective").innerHTML=dirs.map(d=>{const e=effLocal(p,d);return `<div class="i-directive"><b>${d}</b><span>${e.values?esc(e.values.join(" ")):"No CSP restriction"} · ${e.mode}</span></div>`}).join("");
 $("#iDirectives").innerHTML=Object.entries(p).map(([d,v])=>`<div class="i-directive"><b>${esc(d)}</b><span>${v.length?esc(v.join(" ")):"no value"}</span></div>`).join("")||'<span style="font-size:10px;color:#6f7b8e">No CSP directives.</span>';
 const sm={};Object.entries(p).forEach(([d,vs])=>vs.forEach(v=>(sm[v]??=[]).push(d)));
 $("#iSources").innerHTML=Object.entries(sm).map(([v,ds])=>`<div class="i-directive"><b>${esc(v)}</b><span>${esc(ds.join(", "))}</span></div>`).join("")||'<span style="font-size:10px;color:#6f7b8e">No CSP sources.</span>';
 $("#iRawCsp").textContent=page.csp||"No Content-Security-Policy header detected.";
 $("#iRecommendations").innerHTML=rec.fixes.length?rec.fixes.map(f=>`<div class="reco"><div class="reco-title">${esc(f.title)}</div><div class="reco-minus">− ${esc(f.before)}</div><div class="reco-plus">+ ${esc(f.after)}</div><div class="reco-note">${esc(f.note)}</div></div>`).join(""):'<div style="font-size:10px;color:#6f7b8e">No automatic changes suggested.</div>';
 $("#iProposed").textContent=rec.proposed||"No CSP available.";
 const hdrs=page.headers||{};
 $("#iHeaders").innerHTML=Object.entries(hdrs).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v||"—")}</td></tr>`).join("")||'<tr><td colspan="2">Headers were not captured for this result.</td></tr>';
 $("#inspectorBackdrop").classList.remove("hidden");
 document.querySelectorAll(".itab").forEach((b,i)=>b.classList.toggle("active",i===0));document.querySelectorAll(".ipane").forEach((x,i)=>x.classList.toggle("active",i===0));
}
let sitePages=[],siteFilter="all",sitePage=1;
const sitePageSize=15;

function renderPageTable(){
 const q=($("#pageSearch")?.value||"").trim().toLowerCase();
 let rows=sitePages.filter(p=>{
   const filterOk=siteFilter==="all"||(siteFilter==="csp"&&p.kind==="valid"&&p.isHtml&&!!p.csp)||(siteFilter==="nocsp"&&p.kind==="valid"&&p.isHtml&&!p.csp)||(siteFilter==="broken"&&p.kind==="broken")||(siteFilter==="http"&&p.kind==="http")||(siteFilter==="error"&&p.kind==="error");
   return filterOk&&(!q||p.url.toLowerCase().includes(q)||(p.policyId||"").toLowerCase().includes(q));
 });
 const totalPages=Math.max(1,Math.ceil(rows.length/sitePageSize));if(sitePage>totalPages)sitePage=totalPages;
 const slice=rows.slice((sitePage-1)*sitePageSize,sitePage*sitePageSize);
 $("#pageRows").innerHTML=slice.length?slice.map(p=>`<tr><td><span class="click-url" data-pageurl="${escAttr(p.url)}">${esc(p.url)}</span></td><td class="${statusClass(p.status||0)}">${esc(p.status||"—")}</td><td class="${!p.csp&&!p.error?"badtext":""}">${p.kind==="error"?"Not checked":p.kind==="broken"?"N/A":p.kind==="http"?"N/A":p.csp?"Detected":"Not detected"}</td><td>${esc(p.policyId||"—")}</td></tr>`).join(""):`<tr><td colspan="4" style="text-align:center;color:#6f7b8e;padding:22px">No matching pages.</td></tr>`;
 $("#pageRows").querySelectorAll("[data-pageurl]").forEach(el=>el.onclick=()=>{const p=sitePages.find(x=>x.url===el.dataset.pageurl);if(p)openInspector(p)});
  $("#pageInfo").textContent=`${sitePage} / ${totalPages}`;
 $("#prevPage").disabled=sitePage<=1;$("#nextPage").disabled=sitePage>=totalPages;
}
function renderSite(data){
 $("#siteResult").classList.remove("hidden");$("#result").classList.add("hidden");
 const x=data.summary;sitePages=data.pages;siteGroups=data.groups;siteFilter="all";sitePage=1;
 $("#cScanned").textContent=x.scanned;$("#cValid").textContent=x.validPages;$("#cWith").textContent=x.withCsp;$("#cWithout").textContent=x.withoutCsp;$("#cBroken").textContent=x.brokenLinks;$("#cErrors").textContent=x.errors;
 $("#siteScanRatio").textContent=`${x.scanned} / ${x.discovered}`;
 const reviewCount=x.withoutCsp+x.brokenLinks+x.httpIssues+x.errors;
 $("#siteHeadline").textContent=reviewCount?`${reviewCount} item${reviewCount===1?"":"s"} require review`:"No review items found";
 $("#siteSubline").textContent=`CSP coverage: ${x.withCsp} of ${x.validPages} valid HTML pages. Broken/error responses are excluded from CSP coverage.`;
 if(x.discovered>x.scanned){$("#limitWarning").innerHTML=`<b>⚠ Scan limit reached.</b> ${x.discovered} URLs were discovered, but only ${x.scanned} were scanned. Increase Max Pages to inspect more discovered URLs.`;$("#limitWarning").classList.remove("hidden")}else $("#limitWarning").classList.add("hidden");

 $("#policyGroups").innerHTML=data.groups.length?data.groups.map((g,i)=>`<div class="policy-card"><div class="policy-top"><div><b>${g.id}</b><div class="policy-meta">${g.pages.length} page${g.pages.length===1?"":"s"} · ${g.findings} finding${g.findings===1?"":"s"}</div></div><span class="pill ${g.findings?"risk":"good"}">${g.findings?"Review":"No common findings"}</span></div><div class="policy-preview">${esc(g.csp)}</div><div class="policy-actions"><button data-pages="${i}">View ${g.pages.length} pages</button><button data-policy="${i}">View policy</button></div><div class="group-pages hidden" id="gp-${i}">${g.pages.map(u=>`<div class="page-row"><span class="page-url">${esc(shortPath(u))}</span><span class="page-status">CSP</span></div>`).join("")}</div></div>`).join(""):'<div style="font-size:11px;color:#6f7b8e">No CSP policies detected.</div>';
 $("#policyGroups").querySelectorAll("[data-pages]").forEach(b=>b.onclick=()=>document.querySelector("#gp-"+b.dataset.pages).classList.toggle("hidden"));
 $("#policyGroups").querySelectorAll("[data-policy]").forEach(b=>b.onclick=()=>{const g=data.groups[+b.dataset.policy];const representative=sitePages.find(p=>p.policyId===g.id)||{url:g.pages[0]||"",status:0,csp:g.csp,headers:{},policyId:g.id};openInspector(representative,g)});

 const review=data.pages.filter(p=>p.kind==="error"||p.kind==="broken"||p.kind==="http"||(p.kind==="valid"&&p.isHtml&&!p.csp));
 $("#reviewPages").innerHTML=review.length?review.slice(0,12).map(p=>`<div class="page-row"><span class="page-url">${esc(shortPath(p.url))}</span><span class="page-status ${p.error?"badtext":"warn"}">${p.kind==="error"?"CRAWL ERROR":p.kind==="broken"?"BROKEN "+p.status:p.kind==="http"?"HTTP "+p.status:"NO CSP"}</span></div>`).join(""):'<div style="font-size:11px;color:#087a49">✓ No missing CSP or crawl errors in scanned pages.</div>';

 let findings=[];
 if(x.brokenLinks)findings.push(`<div class="site-finding"><span class="icon">!</span><div><b>${x.brokenLinks} broken internal link${x.brokenLinks===1?"":"s"}</b><p>404/410 responses are reported but excluded from CSP coverage and are not crawled further.</p></div></div>`);
 if(x.httpIssues)findings.push(`<div class="site-finding"><span class="icon">!</span><div><b>${x.httpIssues} other HTTP issue${x.httpIssues===1?"":"s"}</b><p>Review non-success response codes in All scanned pages.</p></div></div>`);
 if(x.withoutCsp)findings.push(`<div class="site-finding"><span class="icon">!</span><div><b>${x.withoutCsp} page${x.withoutCsp===1?"":"s"} without CSP</b><p>Review the affected URLs below.</p></div></div>`);
 data.groups.forEach(g=>{if(g.findings)findings.push(`<div class="site-finding"><span class="icon">!</span><div><b>${g.id} · ${g.findings} finding${g.findings===1?"":"s"}</b><p>Applies to ${g.pages.length} scanned page${g.pages.length===1?"":"s"}.</p></div></div>`)});
 findings.push(`<div class="site-finding ${x.errors?"":"ok"}"><span class="icon">${x.errors?"!":"✓"}</span><div><b>${x.errors?x.errors+" crawl error"+(x.errors===1?"":"s"):"No crawl errors"}</b><p>${x.errors?"Some pages could not be inspected.":"All requested page fetches completed successfully."}</p></div></div>`);
 $("#siteFindings").innerHTML=findings.join("");

 $("#fAll").textContent=x.scanned;$("#fCsp").textContent=x.withCsp;$("#fNo").textContent=x.withoutCsp;$("#fBroken").textContent=x.brokenLinks;$("#fHttp").textContent=x.httpIssues;$("#fErr").textContent=x.errors;
 $("#pageSearch").value="";
 $("#pageFilters").querySelectorAll(".filter").forEach(b=>{b.classList.toggle("active",b.dataset.filter==="all");b.onclick=()=>{$("#pageFilters").querySelectorAll(".filter").forEach(x=>x.classList.remove("active"));b.classList.add("active");siteFilter=b.dataset.filter;sitePage=1;renderPageTable()}});
 $("#pageSearch").oninput=()=>{sitePage=1;renderPageTable()};
 $("#prevPage").onclick=()=>{if(sitePage>1){sitePage--;renderPageTable()}};
 $("#nextPage").onclick=()=>{sitePage++;renderPageTable()};
 renderPageTable();
}
async function run(){
 let u=$("#url").value.trim();
 if(!u){$("#result").classList.add("hidden");$("#siteResult").classList.add("hidden");$("#error").textContent="Enter a website URL to analyze.";show("#error");$("#url").focus();return}
 if(!/^https?:\/\//i.test(u))u="https://"+u;
 const mode=document.querySelector('input[name="mode"]:checked').value;
 hide("#result");hide("#siteResult");hide("#error");hide("#loading");
 if(mode==="single"){
   show("#loading");
   try{const r=await fetch("/api/analyze?url="+encodeURIComponent(u));const data=await r.json();if(!r.ok)throw new Error(data.error||"Analysis failed");render(data)}
   catch(e){$("#error").textContent=e.message;show("#error")}finally{hide("#loading")}
   return;
 }
 show("#progress");$("#progressText").textContent="Crawling internal pages…";$("#progressCount").textContent="Please wait";$("#barfill").style.width="20%";
 try{
   const max=$("#maxPages").value;
   const r=await fetch("/api/crawl?url="+encodeURIComponent(u)+"&maxPages="+max);
   $("#barfill").style.width="75%";
   const data=await r.json();if(!r.ok)throw new Error(data.error||"Crawl failed");
   $("#barfill").style.width="100%";$("#progressText").textContent="Crawl complete";$("#progressCount").textContent=data.summary.scanned+" scanned";
   renderSite(data);
   setTimeout(()=>hide("#progress"),900);
 }catch(e){hide("#progress");$("#error").textContent=e.message;show("#error")}
}
document.querySelectorAll('input[name="mode"]').forEach(r=>r.onchange=()=>$("#go").textContent=r.value==="site"&&r.checked?"Scan site":"Analyze");

document.addEventListener("DOMContentLoaded",()=>{
 const close=$("#closeInspector"),backdrop=$("#inspectorBackdrop");
 if(close) close.onclick=()=>backdrop?.classList.add("hidden");
 if(backdrop) backdrop.onclick=e=>{if(e.target===backdrop)backdrop.classList.add("hidden")};
 document.querySelectorAll(".itab").forEach(b=>b.onclick=()=>{
   document.querySelectorAll(".itab").forEach(x=>x.classList.remove("active"));
   document.querySelectorAll(".ipane").forEach(x=>x.classList.remove("active"));
   b.classList.add("active");
   const pane=$("#"+b.dataset.itab); if(pane)pane.classList.add("active");
 });
});
document.addEventListener("keydown",e=>{if(e.key==="Escape")$("#inspectorBackdrop")?.classList.add("hidden")});

$("#go").onclick=run;$("#url").onkeydown=e=>{if(e.key==="Enter")run()};
document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));document.querySelectorAll(".tabpane").forEach(x=>x.classList.remove("active"));b.classList.add("active");$("#"+b.dataset.tab).classList.add("active")});
