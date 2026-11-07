// No live phishing URLs are fetched by this independent extension test.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const vm=require("node:vm");
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
const context=vm.createContext({chrome,URL,AbortController,setTimeout,clearTimeout,Date,console});
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