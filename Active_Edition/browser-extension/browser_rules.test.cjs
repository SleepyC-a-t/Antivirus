// No live phishing URLs are fetched by this independent extension test.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const vm=require("node:vm");
const nodeCrypto=require("node:crypto");
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
const context=vm.createContext({chrome,URL,AbortController,setTimeout,clearTimeout,Date,console,crypto:nodeCrypto.webcrypto,TextEncoder,atob,btoa});
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
(async()=>{
  const testSecret=Buffer.alloc(32,7).toString("base64url");
  const onState={
    pair:{endpoint:"http://127.0.0.1:17654/api/active/extension-challenge",token:testSecret},
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
  let spoofed=false;
  const fetch=async(url)=>{
    const nonce=new URL(url).searchParams.get("nonce");
    const edition="SentinelGuard 4.2";
    const hmac=nodeCrypto.createHmac("sha256",Buffer.from(testSecret,"base64url"))
     .update("SG4.2|"+nonce+"|"+appEnabled+"|"+edition).digest("base64url");
    return {ok:true,json:async()=>({nonce,enabled:appEnabled,edition,mac:spoofed?"invalid":hmac})};
  };
  const sandbox=vm.createContext({chrome:mock,fetch,URL,AbortController,setTimeout,clearTimeout,Date,console,crypto:nodeCrypto.webcrypto,TextEncoder,atob,btoa});
  vm.runInContext(script,sandbox);
  await vm.runInContext("syncProtection()",sandbox);
  assert.equal(activeRules.length,1,"update failure should retain prior blocking rules");
  assert.equal(onState.status.enabled,true,"degraded status should acknowledge existing rules");
  assert.match(onState.status.message,/Update error/);
  appEnabled=false;
  await vm.runInContext("syncProtection()",sandbox);
  assert.equal(activeRules.length,0,"turning protection OFF must clear browser blocking rules");
  assert.equal(onState.status.enabled,false);
  console.log("PASS: failed update retains active rules; OFF switch removes them");
  appEnabled=true;spoofed=true;
  const accepted=await vm.runInContext("pairedAppIsOn",sandbox)(onState.pair);
  assert.equal(accepted,false,"forged localhost server must not be trusted");
  const parser=vm.runInContext("safePhishingURLs",sandbox);
  const risky=parser("https://phish.example.test/pay*all\nhttps://phish.example.test/track^id\nhttps://phish.example.test/path|end\nhttps://phish.example.test/good");
  assert.equal(risky.urls.length,1);
  assert.equal(risky.skippedSpecial,3);
  const generatedRules=vm.runInContext("toRules",sandbox)(risky.urls);
  assert.equal(generatedRules.length,1);
  const matchPattern=generatedRules[0].condition.urlFilter;
  assert.equal(matchPattern,"|https://phish.example.test/good|");
  assert.notEqual("|https://phish.example.test/good?changed=1|",matchPattern,"near-miss query must not be an exact filter match");
  console.log("PASS: HMAC rejects spoofing and dangerous filter metacharacters skipped");
})().catch(error=>{console.error(error);process.exitCode=1});
