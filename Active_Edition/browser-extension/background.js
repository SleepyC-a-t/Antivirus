/* SentinelGuard Active browser companion — no browsing-history access.
   URL entries are treated as data, never fetched or executed.
   Firefox uses background.scripts; Chromium uses service_worker. */
const ext = typeof browser !== "undefined" ? browser : chrome;
const FEED = "https://openphish.com/feed.txt";
const SYNC_ALARM = "sentinel-active-sync";
const MAX_RULES = 1200; // safe dynamic urlFilter rules, no regex quota
const MAX_FEED_AGE_MS = 12 * 60 * 60 * 1000;

async function stored() { return await ext.storage.local.get(["pair","useFeed","cachedURLs","lastFeedAt","status"]); }
async function setStatus(message, enabled, count) {
  await ext.storage.local.set({status:{message,enabled,count,checkedAt:Date.now()}});
}
async function removeAllRules() {
  const existing = await ext.declarativeNetRequest.getDynamicRules();
  if(existing.length) await ext.declarativeNetRequest.updateDynamicRules({removeRuleIds:existing.map(r=>r.id)});
}
// URL filters avoid Chrome's 1,000-regex-rule limit. Exact URL rules
// cannot be bypassed by adding a query to a feed URL that had no query.
// We deliberately do not block entire domains based on a single reported URL.
function safePhishingURLs(feedText) {
  const urls=[], seen=new Set();
  for (const candidate of feedText.split(/\r?\n/)) {
    if (urls.length >= MAX_RULES) break;
    const line=candidate.trim();
    if (!line || line.length > 800 || line.startsWith("#")) continue;
    try {
      const u=new URL(line);
      if (!["http:","https:"].includes(u.protocol) || u.username || u.password) continue;
      if (!u.hostname || u.hostname==="localhost" || u.hostname==="127.0.0.1" ||
          u.hostname==="::1" || u.hostname.endsWith(".invalid")) continue;
      u.hash="";
      const canonical=u.href;
      // DNR urlFilter treats these symbols as wildcard/anchor characters.
      // Don't silently turn a literal URL into a broad blocking pattern.
      if (/[|*^]/.test(canonical) || /[^\x20-\x7e]/.test(canonical)) continue;
      if (seen.has(canonical))continue;
      seen.add(canonical);urls.push(canonical);
    }catch{}
  }
  return urls;
}
function toRules(urls) {
  const out=[];
  let id=1000;
  for (const original of urls.slice(0,MAX_RULES)) {
    let u;
    try{u=new URL(original)}catch{continue}
    if (u.protocol!=="http:"&&u.protocol!=="https:")continue;
    const canonical=u.href.split("#")[0];
    if (/[|*^]/.test(canonical) || /[^\x20-\x7e]/.test(canonical)) continue;
    out.push({
      id:id++, priority:1, action:{type:"block"},
      condition:{urlFilter:"|"+canonical+"|",isUrlFilterCaseSensitive:false,
                 resourceTypes:["main_frame","sub_frame"]}
    });
    // Preserve the exact path boundary. This blocks added query parameters
    // without matching unrelated sibling paths (e.g. /payment vs /payments).
    if (!u.search && out.length < MAX_RULES*2) {
      out.push({
        id:id++,priority:1,action:{type:"block"},
        condition:{urlFilter:"|"+canonical+"?",isUrlFilterCaseSensitive:false,
                   resourceTypes:["main_frame","sub_frame"]}
      });
    }
  }
  return out;
}
function ruleSignature(rule) {
  return rule.id+"|"+(rule.condition?.urlFilter||"")+"|"+(rule.action?.type||"");
}
async function fetchFeed() {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),12000);
  try{
    const response=await fetch(FEED,{cache:"no-store",signal:controller.signal,credentials:"omit",referrerPolicy:"no-referrer"});
    if(!response.ok)throw Error("feed returned HTTP "+response.status);
    const raw=await response.text();
    if(raw.length>2_000_000)throw Error("feed exceeds maximum length");
    const urls=safePhishingURLs(raw);
    if(!urls.length)throw Error("feed contained no valid phishing URLs");
    return urls;
  }finally{clearTimeout(timer);}
}
// Verify a fresh nonce/HMAC challenge before believing any localhost server.
// The persistent pairing secret NEVER travels in an HTTP request header.
async function pairedAppIsOn(pair) {
  if(!pair || typeof pair.endpoint!=="string" || typeof pair.token!=="string")return false;
  const endpoint=new URL(pair.endpoint);
  if(endpoint.protocol!=="http:"||endpoint.hostname!=="127.0.0.1"||
     endpoint.pathname!=="/api/active/extension-status"||endpoint.search)return false;
  const nonceBytes=new Uint8Array(24);
  crypto.getRandomValues(nonceBytes);
  const nonce=btoa(String.fromCharCode(...nonceBytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  const ctl=new AbortController(), timer=setTimeout(()=>ctl.abort(),5000);
  try{
    const response=await fetch(endpoint.href,{headers:{"X-Sentinel-Nonce":nonce},
      cache:"no-store",credentials:"omit",signal:ctl.signal,referrerPolicy:"no-referrer"});
    if(!response.ok)return false;
    const data=await response.json();
    if(data.edition!=="SentinelGuard 4.1" || data.nonce!==nonce ||
       typeof data.enabled!=="boolean" || typeof data.signature!=="string")return false;
    const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(pair.token),
      {name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const raw=atob(data.signature.replace(/-/g,"+").replace(/_/g,"/"));
    const mac=Uint8Array.from(raw,ch=>ch.charCodeAt(0));
    const message=nonce+"|"+String(data.enabled)+"|SentinelGuard 4.1";
    if(!await crypto.subtle.verify("HMAC",key,mac,new TextEncoder().encode(message)))return false;
    return data.enabled;
  }finally{clearTimeout(timer);}
}
let running=null;
async function syncProtection() {
  if(running)return running;
  running=(async()=>{
    const state=await stored();
    if(!state.pair || !state.useFeed) {
      await removeAllRules();
      await setStatus(state.pair?"Feed not enabled — no browser blocking":"Not paired — no browser blocking",false,0);
      return;
    }
    let appOn=false;
    try{appOn=await pairedAppIsOn(state.pair);}catch{}
    if(!appOn){
      await removeAllRules();
      await setStatus("SentinelGuard OFF or unreachable — browser protection off",false,0);
      return;
    }
    let urls=Array.isArray(state.cachedURLs)?state.cachedURLs:[];
    if(!urls.length || Date.now()-(state.lastFeedAt||0)>=MAX_FEED_AGE_MS) {
      try{
        urls=await fetchFeed();
        await ext.storage.local.set({cachedURLs:urls,lastFeedAt:Date.now()});
      }catch(error){
        // Fail safe: do not promise active website protection without a
        // working feed. Previously cached rules remain for <=24 hours.
        if(!urls.length || Date.now()-(state.lastFeedAt||0)>24*60*60*1000){
          await removeAllRules();await setStatus("Phishing feed unavailable — no active URL rules",false,0);return;
        }
      }
    }
    const desired=toRules(urls);
    const current=await ext.declarativeNetRequest.getDynamicRules();
    // Avoid updating the persistent dynamic rules every alarm.
    if (current.length!==desired.length ||
        current.map(ruleSignature).sort().join("\n")!==desired.map(ruleSignature).sort().join("\n")){
      try {
        // One transaction: if the new list is invalid, preserve the last
        // working blocklist instead of clearing it on an update error.
        await ext.declarativeNetRequest.updateDynamicRules({
          removeRuleIds:current.map(r=>r.id), addRules:desired
        });
      } catch(error) {
        await setStatus("Rule update failed — previous blocking rules retained: "+
          String(error.message||error),current.length>0,current.length);
        return;
      }
    }
    await setStatus("Blocking known phishing URLs (exact and safe query variants)",true,desired.length);
  })().catch(async error=>{
    // Don't disable prior rules for transient feed/storage/browser errors
    // while the app is ON. The user must see an accurate degraded state.
    let current=[];
    try{current=await ext.declarativeNetRequest.getDynamicRules()}catch{}
    await setStatus("Protection degraded: "+String(error.message||error),
      current.length>0,current.length);
  }).finally(()=>{running=null});
  return running;
}
function init(){
  ext.alarms.create(SYNC_ALARM,{periodInMinutes:0.5});
  syncProtection();
}
ext.runtime.onInstalled.addListener(init);
ext.runtime.onStartup.addListener(init);
ext.alarms.onAlarm.addListener(event=>{if(event.name===SYNC_ALARM)syncProtection();});
ext.runtime.onMessage.addListener(message=>{
  if(message?.type==="sync"){return syncProtection().then(()=>({ok:true}));}
});
init();

// Pure helpers are exposed only to Node's development test runner.
if (typeof module!=="undefined" && module.exports) {module.exports={safePhishingURLs,toRules,ruleSignature,syncProtection};}
