const express=require("express");
const dns=require("node:dns").promises;
const net=require("node:net");
const crypto=require("node:crypto");
const app=express(),PORT=process.env.PORT||3000;
app.use(express.static(__dirname));

function isPrivate(ip){
 if(net.isIPv4(ip)){const a=ip.split(".").map(Number);return a[0]===10||a[0]===127||a[0]===0||(a[0]===169&&a[1]===254)||(a[0]===172&&a[1]>=16&&a[1]<=31)||(a[0]===192&&a[1]===168)||(a[0]===100&&a[1]>=64&&a[1]<=127)}
 if(net.isIPv6(ip)){const x=ip.toLowerCase();return x==="::1"||x==="::"||x.startsWith("fc")||x.startsWith("fd")||x.startsWith("fe8")||x.startsWith("fe9")||x.startsWith("fea")||x.startsWith("feb")}
 return true;
}
async function validateUrl(raw){
 let u;try{u=new URL(raw)}catch{throw new Error("Invalid URL")}
 if(!["http:","https:"].includes(u.protocol))throw new Error("Only HTTP/HTTPS URLs are allowed");
 if(u.username||u.password)throw new Error("URLs with credentials are not allowed");
 const h=u.hostname.toLowerCase();if(h==="localhost"||h.endsWith(".localhost"))throw new Error("Local addresses are blocked");
 const rs=await dns.lookup(h,{all:true,verbatim:true});if(!rs.length||rs.some(r=>isPrivate(r.address)))throw new Error("Private or reserved network targets are blocked");
 return u;
}
async function fetchSafe(raw,redirects=0){
 if(redirects>5)throw new Error("Too many redirects");
 const u=await validateUrl(raw),controller=new AbortController(),timer=setTimeout(()=>controller.abort(),8000);let r;
 try{r=await fetch(u,{method:"GET",redirect:"manual",signal:controller.signal,headers:{"User-Agent":"CSP-Lens/0.6.5","Accept":"text/html,application/xhtml+xml"}})}finally{clearTimeout(timer)}
 if([301,302,303,307,308].includes(r.status)){const loc=r.headers.get("location");if(loc)return fetchSafe(new URL(loc,u).href,redirects+1)}
 return {r,finalUrl:u.href};
}
function normalize(u){
 const x=new URL(u);x.hash="";
 ["utm_source","utm_medium","utm_campaign","utm_term","utm_content","fbclid","gclid"].forEach(k=>x.searchParams.delete(k));
 if([...x.searchParams].length===0)x.search="";
 return x.href;
}
function linksFromHtml(html,base,origin){
 const out=[];const re=/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;let m;
 while((m=re.exec(html))){const href=m[1]??m[2]??m[3]??"";if(!href||href.startsWith("#")||/^(mailto:|tel:|javascript:|data:)/i.test(href))continue;
  try{const u=new URL(href,base);if(u.origin!==origin||!["http:","https:"].includes(u.protocol))continue;
   if(/\.(?:jpg|jpeg|png|gif|webp|svg|ico|pdf|zip|rar|7z|mp4|mp3|avi|mov|css|js|woff2?|ttf|eot)(?:$|\?)/i.test(u.pathname))continue;
   out.push(normalize(u.href));
  }catch{}
 }
 return [...new Set(out)];
}

const HEADER_NAMES=[
 "content-security-policy","content-security-policy-report-only","strict-transport-security",
 "x-frame-options","x-content-type-options","referrer-policy","permissions-policy",
 "cross-origin-opener-policy","cross-origin-resource-policy","cross-origin-embedder-policy"
];
function captureHeaders(h){
 const o={};HEADER_NAMES.forEach(k=>o[k]=h.get(k)||"");return o;
}
function parseCsp(s){const o={};(s||"").split(";").map(x=>x.trim()).filter(Boolean).forEach(x=>{const a=x.split(/\s+/),d=a.shift().toLowerCase();o[d]=a});return o}
function findingCount(csp){
 const p=parseCsp(csp);let n=0,has=(d,v)=>(p[d]||[]).includes(v);
 ["script-src","script-src-elem","script-src-attr"].forEach(d=>{if(has(d,"'unsafe-eval'"))n++;if(has(d,"'unsafe-inline'"))n++});
 ["style-src","style-src-elem","style-src-attr"].forEach(d=>{if(has(d,"'unsafe-inline'"))n++});
 if(!p["frame-ancestors"])n++;if(!p["form-action"]||p["form-action"].some(x=>["*","http:","https:"].includes(x)))n++;if(!p["base-uri"])n++;
 return n;
}
app.get("/api/analyze",async(req,res)=>{
 try{if(!req.query.url)return res.status(400).json({error:"URL is required"});const {r,finalUrl}=await fetchSafe(req.query.url),csp=r.headers.get("content-security-policy")||"",reportOnly=r.headers.get("content-security-policy-report-only")||"";
 const headers=captureHeaders(r.headers);
 res.json({requestedUrl:req.query.url,finalUrl,status:r.status,csp,reportOnly,headers})}catch(e){res.status(400).json({error:e.name==="AbortError"?"Request timed out":e.message})}
});
app.get("/api/crawl",async(req,res)=>{
 try{
  if(!req.query.url)return res.status(400).json({error:"URL is required"});
  const max=Math.min(Math.max(parseInt(req.query.maxPages)||50,1),500);
  const startUrl=await validateUrl(req.query.url),start=normalize(startUrl.href),origin=startUrl.origin;
  const queue=[start],queued=new Set([start]),seen=new Set(),pages=[];
  const LOCALE_PAIR=/\/(?:th|en)\/(?:th|en)(?:\/|$)/i;
  const SKIP_EXT=/\.(?:jpg|jpeg|png|gif|webp|svg|ico|pdf|zip|rar|7z|mp4|mp3|avi|mov|css|js|mjs|map|woff2?|ttf|eot|docx?|xlsx?|pptx?)(?:$|\?)/i;
  function cleanLink(href,base){
   if(!href||href.startsWith("#")||/^(?:mailto:|tel:|javascript:|data:)/i.test(href))return null;
   try{const u=new URL(href,base);if(u.origin!==origin||!["http:","https:"].includes(u.protocol))return null;u.hash="";u.pathname=u.pathname.replace(/\/{2,}/g,"/");if(LOCALE_PAIR.test(u.pathname)||SKIP_EXT.test(u.pathname))return null;return normalize(u.href)}catch{return null}
  }
  while(queue.length&&seen.size<max){
   const url=queue.shift();if(seen.has(url))continue;seen.add(url);
   try{
    const {r,finalUrl}=await fetchSafe(url),type=(r.headers.get("content-type")||"").toLowerCase(),csp=r.headers.get("content-security-policy")||"";
    const isHtml=type.includes("text/html"),valid=r.status>=200&&r.status<400,broken=r.status===404||r.status===410,httpIssue=!valid&&!broken;
    pages.push({url,finalUrl,status:r.status,csp,reportOnly:r.headers.get("content-security-policy-report-only")||"",headers:captureHeaders(r.headers),error:"",policyId:"",kind:broken?"broken":httpIssue?"http":"valid",isHtml});
    if(valid&&isHtml){
      const html=(await r.text()).slice(0,2_000_000),bm=html.match(/<base\b[^>]*href\s*=\s*["']([^"']+)["']/i);
      const base=bm?(cleanLink(bm[1],finalUrl)||finalUrl):finalUrl,re=/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;let m;
      while((m=re.exec(html))){const link=cleanLink(m[1]??m[2]??m[3]??"",base);if(link&&!seen.has(link)&&!queued.has(link)&&queued.size<2000){queue.push(link);queued.add(link)}}
    }
   }catch(e){pages.push({url,status:0,csp:"",reportOnly:"",headers:{},error:e.name==="AbortError"?"Timeout":e.message,policyId:"",kind:"error",isHtml:false})}
  }
  const validPages=pages.filter(p=>p.kind==="valid"&&p.isHtml),groupMap=new Map();
  for(const p of validPages){if(!p.csp)continue;const key=crypto.createHash("sha1").update(p.csp).digest("hex");if(!groupMap.has(key))groupMap.set(key,{csp:p.csp,pages:[]});groupMap.get(key).pages.push(p.url)}
  const groups=[...groupMap.values()].sort((a,b)=>b.pages.length-a.pages.length).map((g,i)=>({...g,id:"Policy "+String.fromCharCode(65+i),findings:findingCount(g.csp)}));
  for(const p of validPages){const g=groups.find(g=>g.csp===p.csp);if(g)p.policyId=g.id}
  res.json({root:start,summary:{discovered:queued.size,scanned:pages.length,validPages:validPages.length,withCsp:validPages.filter(x=>x.csp).length,withoutCsp:validPages.filter(x=>!x.csp).length,brokenLinks:pages.filter(x=>x.kind==="broken").length,httpIssues:pages.filter(x=>x.kind==="http").length,errors:pages.filter(x=>x.kind==="error").length,uniquePolicies:groups.length},groups,pages});
 }catch(e){res.status(400).json({error:e.name==="AbortError"?"Request timed out":e.message})}
});

app.listen(PORT,()=>console.log(`CSP Lens v0.6.5 running at http://localhost:${PORT}`));
