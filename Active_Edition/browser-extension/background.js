/* SentinelGuard Active browser companion — no browsing-history access.
   URL entries are treated as data, never fetched or executed.
   Firefox uses background.scripts; Chromium uses service_worker. */
const ext = typeof browser !== "undefined" ? browser : chrome;
const FEED = "https://openphish.com/feed.txt";
const SYNC_ALARM = "sentinel-active-sync";
const MAX_RULES = 1200;
const MAX_FEED_AGE_MS = 12 * 60 * 60 * 1000;

async function stored() { return await ext.storage.local.get(["pair","useFeed","cachedURLs","lastFeedAt","status"]); }
async function setStatus(message, enabled, count) {
  await ext.storage.local.set({status:{message,enabled,count,checkedAt:Date.now()}});
}
async function removeAllRules() {
  const existing = await ext.declarativeNetRequest.getDynamicRules();
  if(existing.length) await ext.declarativeNetRequest.updateDynamicRules({removeRuleIds:existing.map(r=>r.id)});
}
function escapeRegExp(value) {
  const special = ".+*?^$()[]{}|\\";
  let result="";
  for(const character of value){result+=special.includes(character)?"\\"+character:character;}
  return result;
}
function safePhishingURLs(feedText) {
  const urls=[];
  const seen=new Set();
  for(const candidate of feedText.split(/\r?\n/)){
    if(urls.length>=MAX_RULES) break;
    const line=candidate.trim();
    if(!line || line.length>1000 || line.startsWith("#")) continue;
    try{
      const u=new URL(line);
      if((u.protocol!=="http:"&&u.protocol!=="https:")||u.username||u.password)continue;
      if(!u.hostname || u.hostname==="localhost" || u.hostname==="127.0.0.1" || u.hostname.endsWith(".invalid"))continue;
      // Fragments are not transmitted over the network.
      const canonical=u.href.split("#")[0];
      if(seen.has(canonical))continue;
      seen.add(canonical);urls.push(canonical);
    }catch{}
  }
  return urls;
}
function toRules(urls) {
  return urls.slice(0,MAX_RULES).map((url,index)=>({
    id:1000+index,priority:1,action:{type:"block"},
    condition:{regexFilter:"^"+escapeRegExp(url)+"$",isUrlFilterCaseSensitive:false,
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
async function pairedAppIsOn(pair) {
  if(!pair || typeof pair.endpoint!=="string" || typeof pair.token!=="string")return false;
  const endpoint=new URL(pair.endpoint);
  if(endpoint.protocol!=="http:"||endpoint.hostname!=="127.0.0.1"||
     endpoint.pathname!=="/api/active/extension-status"||endpoint.search)return false;
  const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),5000);
  try{
    const response=await fetch(endpoint.href,{headers:{"X-Sentinel-Token":pair.token},
      cache:"no-store",credentials:"omit",signal:ctl.signal,referrerPolicy:"no-referrer"});
    if(!response.ok)return false;
    const payload=await response.json();
    return payload.enabled===true && payload.edition==="SentinelGuard 4.0";
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
    if(current.length!==desired.length ||
       current.some((rule,i)=>rule.condition.regexFilter!==desired[i]?.condition.regexFilter)){
      await ext.declarativeNetRequest.updateDynamicRules({
        removeRuleIds:current.map(r=>r.id),addRules:desired
      });
    }
    await setStatus("Blocking known phishing URLs (exact matches)",true,desired.length);
  })().catch(async error=>{
    await removeAllRules().catch(()=>{});
    await setStatus("Protection error: "+String(error.message||error),false,0);
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
