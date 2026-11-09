const ext = typeof browser !== "undefined" ? browser : chrome;
const pairEl=document.getElementById("pair");
const statusEl=document.getElementById("status");
const feedEl=document.getElementById("feed");
function validate(text){
  const u=new URL(text.trim());
  if(u.protocol!=="http:" || u.hostname!=="127.0.0.1" ||
     u.pathname!=="/api/active/extension-challenge" || !/^[A-Za-z0-9_-]{40,60}$/.test(u.searchParams.get("pair")||""))
    throw Error("Invalid SentinelGuard Active pairing link");
  return {endpoint:u.origin+u.pathname,token:u.searchParams.get("pair")};
}
async function refresh(){
  const s=await ext.storage.local.get(["pair","useFeed","status"]);
  feedEl.checked=!!s.useFeed;
  pairEl.placeholder=s.pair?"Paired. Paste a new link to change pairing.":"Paste pairing link here";
  const state=s.status||{};
  statusEl.textContent=(state.enabled?"PROTECTED":"NOT PROTECTED")+
      "\n"+(state.message||"No status yet")+
      "\nBlocked URL rules: "+(state.count||0)+
      (state.checkedAt?"\nLast checked: "+new Date(state.checkedAt).toLocaleTimeString():"");
}
document.getElementById("save").onclick=async()=>{
  try {
    const pair=validate(pairEl.value);
    await ext.storage.local.set({pair});pairEl.value="";
    await ext.runtime.sendMessage({type:"sync"});await refresh();
  } catch(e){statusEl.textContent=String(e.message||e);}
};
document.getElementById("disconnect").onclick=async()=>{
  await ext.storage.local.remove("pair");
  await ext.runtime.sendMessage({type:"sync"});await refresh();
};
feedEl.onchange=async()=>{
  await ext.storage.local.set({useFeed:feedEl.checked});
  await ext.runtime.sendMessage({type:"sync"});await refresh();
};
document.getElementById("sync").onclick=async()=>{
  await ext.runtime.sendMessage({type:"sync"});await refresh();
};
refresh();
