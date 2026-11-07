// No live phishing URLs are fetched by this independent extension test.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const vm=require("node:vm");
const nodeCrypto=require("node:crypto");
const webcrypto=nodeCrypto.webcrypto;
const rules=[];
const chrome={
  storage:{local:{get:async()=>({}),set:async()=>{}}},
  alarms:{create:()=>{},onAlarm:{addListener:()=>{}}},
  runtime:{onInstalled:{addListener:()=>{}},onStartup:{addListener:()=>{}},onMessage:{addListener:()=>{}}},
  declarativeNetRequest:{
    getDynamicRules:async()=>rules,
    updateDynamicRules:async()=>{}
  }
};
const context=vm.createContext({chrome,URL,AbortController,setTimeout,clearTimeout,Date,console,
  crypto:webcrypto,TextEncoder,atob,btoa,Uint8Array});
const script=fs.readFileSync(__dirname+"/background.js","utf8");
vm.runInContext(script,context);
const mockUrls=Array.from({length:1200},(_,i)=>`https://phish${i}.example.invalid/login?session=${i}`);
const generated=vm.runInContext("toRules",context)(mockUrls);
assert.equal(generated.length,1200);
assert.equal(generated.filter(x=>x.condition.regexFilter).length,0);
assert.ok(generated.every(x=>x.condition.urlFilter.startsWith("|https://")&&x.condition.urlFilter.endsWith("|")));
assert.equal(generated[0].condition.urlFilter,"|"+mockUrls[0]+"|");
assert.equal(generated[1199].condition.urlFilter,"|"+mockUrls[1199]+"|");
console.log("PASS: 1,200 bounded, anchored, regex-free phishing rules");
const safe=vm.runInContext("safePhishingURLs",context)(
  "https://tests.example.org/legitimate\nhttps://tests.example.org/bad*wild\nhttps://tests.example.org/a^b\nhttps://tests.example.org/a|b");
assert.equal(safe.length,1,"URLs with special urlFilter metacharacters must be excluded");
assert.equal(vm.runInContext("toRules",context)(["https://tests.example.org/a|b","https://tests.example.org/ok"]).length,1);
const literal=generated[0].condition.urlFilter;
assert.ok(literal.startsWith("|")&&literal.endsWith("|"),"block rules are end-anchored");
assert.notEqual(literal,"|https://phish0.example.invalid/login?session=0-extra|","a near-miss URL cannot equal the exact anchored filter");
console.log("PASS: urlFilter operators skipped and exact-match anchoring retained");
(async()=>{
  const token=nodeCrypto.randomBytes(32).toString("base64url");
  const onState={
    pair:{endpoint:"http://127.0.0.1:17654/api/active/extension-status",token},
    useFeed:true,cachedURLs:["https://heldout.example.invalid/bad"],
    lastFeedAt:Date.now(),rulesVersion:3,
  };
  const activeRules=[{id:1000,condition:{urlFilter:"|https://existing.example.invalid/bad|"}}];
  let failAdds=true;
  const storage={local:{get:async()=>onState,set:async patch=>Object.assign(onState,patch)}};
  const mock={
    storage,
    alarms:{create:()=>{},onAlarm:{addListener:()=>{}}},
    runtime:{onInstalled:{addListener:()=>{}},onStartup:{addListener:()=>{}},onMessage:{addListener:()=>{}}},
    declarativeNetRequest:{
      getDynamicRules:async()=>activeRules.slice(),
      updateDynamicRules:async ({removeRuleIds=[],addRules=[]})=>{
        if(addRules.length&&failAdds)throw Error("simulated ruleset capacity failure");
        for(const id of removeRuleIds){
          const ix=activeRules.findIndex(r=>r.id===id);
          if(ix>=0)activeRules.splice(ix,1);
        }
        activeRules.push(...addRules);
      }
    }
  };
  let appEnabled=true;
  let forged=false;
  const fetch=async (url,request)=>{
    assert.equal(url,"http://127.0.0.1:17654/api/active/extension-challenge");
    assert.equal(request.method,"POST");
    assert.equal(request.headers["X-Sentinel-Token"],undefined,"never send secret to unverified localhost");
    assert.ok(!request.body.includes(token),"secret must never appear in outgoing request");
    const nonce=JSON.parse(request.body).nonce;
    const edition="SentinelGuard 4.2";
    const message="SentinelGuard4.2|"+nonce+"|"+(appEnabled?"1":"0")+"|"+edition;
    const proof=forged?"00".repeat(32):nodeCrypto.createHmac("sha256",Buffer.from(token,"base64url")).update(message).digest("hex");
    return {ok:true,json:async()=>({enabled:appEnabled,edition,nonce,proof})};
  };
  const sandbox=vm.createContext({chrome:mock,fetch,URL,AbortController,setTimeout,clearTimeout,Date,console,
    crypto:webcrypto,TextEncoder,atob,btoa,Uint8Array});
  vm.runInContext(script,sandbox);
  await vm.runInContext("syncProtection()",sandbox);
  assert.equal(activeRules.length,1,"update failure should retain prior blocking rules");
  assert.equal(onState.status.enabled,true,"degraded status should acknowledge existing rules");
  assert.match(onState.status.message,/Update error/);
  forged=true;
  await vm.runInContext("syncProtection()",sandbox);
  assert.equal(activeRules.length,0,"forged localhost proof must remove unsafe existing rules");
  assert.equal(onState.status.enabled,false,"fake listener must not be trusted");
  forged=false;
  appEnabled=false;
  await vm.runInContext("syncProtection()",sandbox);
  assert.equal(activeRules.length,0,"turning protection OFF must clear browser blocking rules");
  assert.equal(onState.status.enabled,false);
  console.log("PASS: failed update retains active rules; OFF switch removes them");
})().catch(error=>{console.error(error);process.exitCode=1});
