/* SentinelGuard Active browser companion — no browsing-history access.
   URL entries are treated as data, never fetched or executed.
   Firefox uses background.scripts; Chromium uses service_worker. */
const ext = typeof browser !== "undefined" ? browser : chrome;
const FEED = "https://openphish.com/feed.txt";
const RULES_VERSION = 3;
const SYNC_ALARM = "sentinel-active-sync";
const MAX_RULES = 1200; // urlFilter rules avoid Chrome's 1000 regex-rule cap
const MAX_FEED_AGE_MS = 12 * 60 * 60 * 1000;

async function stored() { return await ext.storage.local.get(["pair","useFeed","cachedURLs","lastFeedAt","status","rulesVersion","skippedSpecial"]); }
async function setStatus(message, enabled, count) {
  await ext.storage.local.set({status:{message,enabled,count,checkedAt:Date.now()}});
}
async function removeAllRules() {
  const existing = await ext.declarativeNetRequest.getDynamicRules();
  if(existing.length) await ext.declarativeNetRequest.updateDynamicRules({removeRuleIds:existing.map(r=>r.id)});
}
function safePhishingURLs(feedText) {
  const urls=[];
  const seen=new Set();
  let skippedSpecial=0;
  for(const candidate of feedText.split(/\r?\n/)){
    if(urls.length>=MAX_RULES) break;
    const line=candidate.trim();
    if(!line || line.length>1000 || line.startsWith("#")) continue;
    // Chrome urlFilter assigns wildcard/anchor semantics to '*', '^',
    // and '|'. Reject rather than dangerously over-match such URLs.
    if(/[|*^]/.test(line)){skippedSpecial++;continue;}
    try{
      const u=new URL(line);
      if((u.protocol!=="http:"&&u.protocol!=="https:")||u.username||u.password)continue;
      if(!u.hostname || u.hostname==="localhost" || u.hostname==="127.0.0.1" || u.hostname.endsWith(".invalid"))continue;
      // Fragments are not transmitted over the network.
      const canonical=u.href.split("#")[0];
      if(/[|*^]/.test(canonical)){skippedSpecial++;continue;}
      if(seen.has(canonical))continue;
      seen.add(canonical);urls.push(canonical);
    }catch{}
  }
  return {urls,skippedSpecial};
}
function toRules(urls) {
  // Chrome limits *regexFilter* dynamic rules to 1000; urlFilter is not
  // subject to that special cap. '|' anchors both ends of the URL.
  return urls.filter(url=>typeof url==="string"&&!/[|*^]/.test(url)).slice(0,MAX_RULES).map((url,index)=>({
    id:1000+index,priority:1,action:{type:"block"},
    condition:{urlFilter:"|"+url+"|",isUrlFilterCaseSensitive:true,
      resourceTypes:["main_frame","sub_frame"]}
  }));
}
async function fetchFeed() {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),12000);
  try{
    const response=await fetch(FEED,{cache:"no-store",signal:controller.signal,credentials:"omit",referrerPolicy:"no-referrer"});
    if(!response.ok)throw Error("feed returned HTTP "+response.status);
    const raw=await response.text();
    if(raw.length>2_000_000)throw Error("feed exceeds maximum length");
    const result=safePhishingURLs(raw);
    if(!result.urls.length)throw Error("feed contained no valid phishing URLs");
    return result;
  }finally{clearTimeout(timer);}
}
function base64URLBytes(value) {
  if(!/^[A-Za-z0-9_-]{43}$/.test(value))throw Error("Invalid browser-pairing credential");
  const s=value.replace(/-/g,"+").replace(/_/g,"/");
  return Uint8Array.from(atob(s+"="),c=>c.charCodeAt(0));
}
function toBase64URL(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function pairedAppIsOn(pair) {
  if(!pair || typeof pair.endpoint!=="string" || typeof pair.token!=="string")return false;
  const endpoint=new URL(pair.endpoint);
  if(endpoint.protocol!=="http:"||endpoint.hostname!=="127.0.0.1"||
     endpoint.pathname!=="/api/active/extension-challenge"||endpoint.search)return false;
  const nonce=toBase64URL(crypto.getRandomValues(new Uint8Array(24)));
  endpoint.searchParams.set("nonce",nonce);
  const key=await crypto.subtle.importKey("raw",base64URLBytes(pair.token),
        {name:"HMAC",hash:"SHA-256"},false,["verify"]);
  const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),5000);
  try{
    // The secret is never sent. A spoofed localhost listener cannot forge
    // a response for this fresh challenge without the paired DPAPI secret.
    const response=await fetch(endpoint.href,{cache:"no-store",credentials:"omit",
      signal:ctl.signal,referrerPolicy:"no-referrer"});
    if(!response.ok)return false;
    const payload=await response.json();
    if(payload.nonce!==nonce||payload.edition!=="SentinelGuard 4.2"||
       typeof payload.enabled!=="boolean"||typeof payload.mac!=="string")return false;
    let macBytes;
    try{
      const s=payload.mac.replace(/-/g,"+").replace(/_/g,"/");
      macBytes=Uint8Array.from(atob(s+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
    }catch{return false;}
    const message=new TextEncoder().encode("SG4.2|"+nonce+"|"+payload.enabled+"|"+payload.edition);
    if(!await crypto.subtle.verify("HMAC",key,macBytes,message))return false;
    return payload.enabled===true;
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
    let skipped=state.skippedSpecial||0;
    if(!urls.length || Date.now()-(state.lastFeedAt||0)>=MAX_FEED_AGE_MS) {
      try{
        const feed=await fetchFeed();
        urls=feed.urls;skipped=feed.skippedSpecial;
        await ext.storage.local.set({cachedURLs:urls,lastFeedAt:Date.now(),rulesVersion:RULES_VERSION,skippedSpecial:skipped});
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
    if(state.rulesVersion!==RULES_VERSION || current.length!==desired.length ||
       current.some((rule,i)=>rule.condition.urlFilter!==desired[i]?.condition.urlFilter)){
      await ext.declarativeNetRequest.updateDynamicRules({
        removeRuleIds:current.map(r=>r.id),addRules:desired
      });
    }
    await setStatus("Blocking known phishing URLs (exact matches; "+skipped+" skipped unsafe feed entries)",true,desired.length);
  })().catch(async error=>{
    // Do not destroy a working ruleset after a transient feed or rule-update
    // failure. The status must disclose degraded protection and real rule count.
    const retained=await ext.declarativeNetRequest.getDynamicRules().catch(()=>[]);
    await setStatus("Update error (existing rules retained): "+String(error.message||error),
                    retained.length>0,retained.length);
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
