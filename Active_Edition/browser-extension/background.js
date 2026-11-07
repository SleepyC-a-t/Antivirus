/* SentinelGuard 4.2 browser companion — no browsing-history access.
   URL entries are treated as data, never fetched or executed.
   Firefox uses background.scripts; Chromium uses service_worker. */
const ext = typeof browser !== "undefined" ? browser : chrome;
const FEED = "https://openphish.com/feed.txt";
const RULES_VERSION = 3;
const SYNC_ALARM = "sentinel-active-sync";
const MAX_RULES = 1200; // urlFilter rules avoid Chrome's 1000 regex-rule cap
const MAX_FEED_AGE_MS = 12 * 60 * 60 * 1000;

async function stored() { return await ext.storage.local.get(["pair","useFeed","cachedURLs","lastFeedAt","status","rulesVersion"]); }
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
  for(const candidate of feedText.split(/\r?\n/)){
    if(urls.length>=MAX_RULES) break;
    const line=candidate.trim();
    if(!line || line.length>1000 || line.startsWith("#") || /[|*^]/.test(line)) continue;
    try{
      const u=new URL(line);
      if((u.protocol!=="http:"&&u.protocol!=="https:")||u.username||u.password)continue;
      if(!u.hostname || u.hostname==="localhost" || u.hostname==="127.0.0.1" || u.hostname.endsWith(".invalid"))continue;
      // Fragments are not transmitted over the network.
      const canonical=u.href.split("#")[0];
      // In declarativeNetRequest urlFilter these are operators, not text.
      // Fail closed on unsupported feed URLs rather than accidentally
      // matching additional destinations.
      if(/[|*^]/.test(canonical))continue;
      if(seen.has(canonical))continue;
      seen.add(canonical);urls.push(canonical);
    }catch{}
  }
  return urls;
}
function toRules(urls) {
  // Chrome limits *regexFilter* dynamic rules to 1000; urlFilter is not
  // subject to that special cap. '|' anchors both ends of the URL.
  const valid=urls.filter(url=>!/[|*^]/.test(url));
  return valid.slice(0,MAX_RULES).map((url,index)=>({
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
    const urls=safePhishingURLs(raw);
    if(!urls.length)throw Error("feed contained no valid phishing URLs");
    return urls;
  }finally{clearTimeout(timer);}
}
function fromBase64url(encoded) {
  const raw=atob(encoded.replace(/-/g,"+").replace(/_/g,"/")+
    "=".repeat((4-encoded.length%4)%4));
  return Uint8Array.from(raw,character=>character.charCodeAt(0));
}
function toBase64url(bytes) {
  let raw="";
  for(const b of bytes)raw+=String.fromCharCode(b);
  return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function hexString(bytes) {
  return Array.from(bytes,b=>b.toString(16).padStart(2,"0")).join("");
}
async function pairedAppIsOn(pair) {
  if(!pair || typeof pair.endpoint!=="string" || typeof pair.token!=="string")return false;
  const endpoint=new URL(pair.endpoint);
  if(endpoint.protocol!=="http:"||endpoint.hostname!=="127.0.0.1"||
     endpoint.pathname!=="/api/active/extension-status"||endpoint.search)return false;
  const ctl=new AbortController();
  const timer=setTimeout(()=>ctl.abort(),5000);
  try {
    const nonce=toBase64url(crypto.getRandomValues(new Uint8Array(32)));
    const response=await fetch(endpoint.origin+"/api/active/extension-challenge",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({nonce}),
      cache:"no-store",credentials:"omit",
      signal:ctl.signal,referrerPolicy:"no-referrer"
    });
    if(!response.ok)return false;
    const payload=await response.json();
    if(payload.nonce!==nonce||payload.edition!=="SentinelGuard 4.2"||
       typeof payload.enabled!=="boolean"||!(/^[0-9a-f]{64}$/).test(payload.proof||""))return false;
    const material="SentinelGuard4.2|"+nonce+"|"+(payload.enabled?"1":"0")+"|"+payload.edition;
    const secret=fromBase64url(pair.token);
    if(secret.length!==32)return false;
    const key=await crypto.subtle.importKey("raw",secret,{name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const bytes=Uint8Array.from(payload.proof.match(/../g).map(h=>parseInt(h,16)));
    const genuine=await crypto.subtle.verify("HMAC",key,bytes,new TextEncoder().encode(material));
    // Only a verified proof can turn on URL blocking.
    return genuine && payload.enabled===true;
  }finally {clearTimeout(timer);}
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
        await ext.storage.local.set({cachedURLs:urls,lastFeedAt:Date.now(),rulesVersion:RULES_VERSION});
      }catch(error){
        // Fail safe: do not promise active website protection without a
        // working feed. Previously cached rules remain for <=24 hours.
        if(!urls.length || Date.now()-(state.lastFeedAt||0)>24*60*60*1000){
          await removeAllRules();await setStatus("Phishing feed unavailable — no active URL rules",false,0);return;
        }
      }
    }
    const desired=toRules(urls);
    if(!desired.length){
      await removeAllRules();
      await setStatus("No valid literal phishing URLs in feed — no blocking rules",false,0);
      return;
    }
    const current=await ext.declarativeNetRequest.getDynamicRules();
    // Avoid updating the persistent dynamic rules every alarm.
    if(state.rulesVersion!==RULES_VERSION || current.length!==desired.length ||
       current.some((rule,i)=>rule.condition.urlFilter!==desired[i]?.condition.urlFilter)){
      await ext.declarativeNetRequest.updateDynamicRules({
        removeRuleIds:current.map(r=>r.id),addRules:desired
      });
    }
    await setStatus("Blocking known phishing URLs (exact matches)"+(urls.length>desired.length?" — "+(urls.length-desired.length)+" special-character URLs omitted":""),true,desired.length);
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
