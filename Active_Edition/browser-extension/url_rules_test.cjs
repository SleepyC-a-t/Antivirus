// Inert, offline unit tests. No network requests or browsing events.
const assert=require("node:assert/strict");
const {webcrypto,createHmac}=require("node:crypto");
global.crypto=webcrypto;
let forged=false;
let dynamicRules=[],enabled=true,updateFailure=false;
const storage={pair:{endpoint:"http://127.0.0.1:38591/api/active/extension-status",token:"dummy-pair-token"},
  useFeed:true,cachedURLs:[],lastFeedAt:0,status:{}};
global.chrome={
  storage:{local:{
    async get(keys){const o={};for(const k of keys)o[k]=storage[k];return o},
    async set(o){Object.assign(storage,o)}
  }},
  alarms:{create(){},onAlarm:{addListener(){}}},
  runtime:{
    onInstalled:{addListener(){}},onStartup:{addListener(){}},
    onMessage:{addListener(){}}
  },
  declarativeNetRequest:{
    async getDynamicRules(){return dynamicRules.slice()},
    async updateDynamicRules({removeRuleIds=[],addRules=[]}){
      if(updateFailure)throw new Error("simulated rejected update");
      const gone=new Set(removeRuleIds);
      dynamicRules=[...dynamicRules.filter(r=>!gone.has(r.id)),...addRules]
    }
  }
};
global.fetch=async (url,options={})=>{
  if(String(url).includes("openphish.com"))return {ok:true,async text(){return ""}};
  const nonce=options.headers?.["X-Sentinel-Nonce"];
  if(!nonce)throw Error("pairing token/nonce not supplied");
  const message=nonce+"|"+String(enabled)+"|SentinelGuard 4.1";
  const mac=createHmac("sha256",storage.pair.token).update(message).digest("base64url");
  return {ok:true,async json(){return {enabled,edition:"SentinelGuard 4.1",nonce,
    signature:forged?"AAAAAAAAAAAAAAAA":mac}}};
};
const extension=require("./background.js");
async function main(){
  assert.equal(extension.toRules(["https://test.invalid/a"]).length,2);
  const urls=Array.from({length:1200},(_,i)=>"https://phish"+i+".example.test/verify");
  const rules=extension.toRules(urls);
  assert.equal(rules.length,2400);
  assert.ok(rules.every(r=>r.condition.urlFilter && !r.condition.regexFilter));
  assert.equal(new Set(rules.map(r=>r.id)).size,rules.length);
  const sample=extension.toRules(["https://phishing.example.test/payment"]);
  assert.equal(sample[0].condition.urlFilter,"|https://phishing.example.test/payment|");
  assert.equal(sample[1].condition.urlFilter,"|https://phishing.example.test/payment?");
  storage.cachedURLs=urls;storage.lastFeedAt=Date.now();
  await extension.syncProtection();
  assert.equal(dynamicRules.length,2400);
  assert.equal(storage.status.enabled,true);
  updateFailure=true;
  storage.cachedURLs=["https://changed.example.test/login"];
  await extension.syncProtection();
  assert.equal(dynamicRules.length,2400,"failure must preserve prior working rules");
  assert.match(storage.status.message,/previous blocking rules retained/);
  updateFailure=false;
  forged=true;
  await extension.syncProtection();
  assert.equal(dynamicRules.length,0,"invalid server signature must turn protection OFF");
  forged=false;
  enabled=false;
  await extension.syncProtection();
  assert.equal(dynamicRules.length,0,"switch OFF must remove all rules");
  assert.equal(storage.status.enabled,false);
  enabled=true;
  storage.useFeed=false;
  await extension.syncProtection();
  assert.equal(dynamicRules.length,0);
  console.log("PASS 4.1: 2400 safe urlFilter rules, query boundaries, atomic recovery and OFF cleanup");
}
main().catch(e=>{console.error(e);process.exitCode=1;});
