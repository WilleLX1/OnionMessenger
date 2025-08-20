// ================== Small utils ==================
const $ = s => document.querySelector(s);
const api = async (p, data=null) => {
  const r = await fetch(p, data ? {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(data)} : {});
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
};
function ab2b64(buf){ const b=new Uint8Array(buf); let s=""; const ch=0x8000; for(let i=0;i<b.length;i+=ch){ s+=String.fromCharCode.apply(null,b.subarray(i,i+ch)); } return btoa(s); }
function b642ab(b64){ const bin=atob(b64); const l=bin.length; const out=new Uint8Array(l); for(let i=0;i<l;i++) out[i]=bin.charCodeAt(i); return out.buffer; }
const utf8 = s => new TextEncoder().encode(s);
const hex = buf => [...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,"0")).join("");
async function sha256_hex(buf){ return hex(await crypto.subtle.digest("SHA-256", buf)); }
function fpShort(h){ return (h||"").slice(0,32).match(/.{1,4}/g)?.join(" ") || ""; }
const PREFERRED_SIG_ALG = "ECDSA-P256"; // cross-browser signatures

// ================== Storage keys ==================
const KEY_PRIV = "priv_pkcs8_b64";     // RSA-OAEP private
const KEY_PUB  = "pub_spki_b64";       // RSA-OAEP public
const SIGN_PRIV = "sign_priv_b64";
const SIGN_PUB  = "sign_pub_b64";
const SIGN_ALG  = "sign_alg";
const PIN_PREFIX = "pin::";
const NICKS_KEY = "nicknames";
const NOTIF_DESKTOP = "notif_desktop";
const NOTIF_SOUND   = "notif_sound";

// ================== Views ==================
const VIEWS = ["view-landing","view-login","view-export","view-app"];
function showView(id){
  VIEWS.forEach(v => $("#"+v).classList.toggle("hidden", v!==id));
  if (id !== "view-app") closeDrawer();
}

// ================== Identity / Crypto ==================
async function importMyEncKeysFromStorage(){
  const privB64 = localStorage.getItem(KEY_PRIV);
  const pubB64  = localStorage.getItem(KEY_PUB);
  if (!privB64 || !pubB64) return {priv:null, pub:null};
  const priv = await crypto.subtle.importKey("pkcs8", b642ab(privB64), {name:"RSA-OAEP", hash:"SHA-256"}, true, ["decrypt"]);
  const pub  = await crypto.subtle.importKey("spki", b642ab(pubB64), {name:"RSA-OAEP", hash:"SHA-256"}, true, ["encrypt"]);
  return {priv, pub};
}
async function generateEncKeysAndSave(){
  const kp = await crypto.subtle.generateKey(
    {name:"RSA-OAEP", modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:"SHA-256"},
    true, ["encrypt","decrypt"]);
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  const pkcs8= await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  localStorage.setItem(KEY_PUB,  ab2b64(spki));
  localStorage.setItem(KEY_PRIV, ab2b64(pkcs8));
  return kp;
}
async function generateSignKeysAndSave(){
  if (PREFERRED_SIG_ALG === "ECDSA-P256"){
    const kp = await crypto.subtle.generateKey({name:"ECDSA", namedCurve:"P-256"}, true, ["sign","verify"]);
    const pub = await crypto.subtle.exportKey("spki", kp.publicKey);
    const priv= await crypto.subtle.exportKey("pkcs8", kp.privateKey);
    localStorage.setItem(SIGN_ALG, "ECDSA-P256");
    localStorage.setItem(SIGN_PUB,  ab2b64(pub));
    localStorage.setItem(SIGN_PRIV, ab2b64(priv));
    return {alg:"ECDSA-P256", kp};
  }
  const kp = await crypto.subtle.generateKey({name:"Ed25519"}, true, ["sign","verify"]);
  const pub = await crypto.subtle.exportKey("raw", kp.publicKey);
  const priv= await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  localStorage.setItem(SIGN_ALG, "Ed25519");
  localStorage.setItem(SIGN_PUB,  ab2b64(pub));
  localStorage.setItem(SIGN_PRIV, ab2b64(priv));
  return {alg:"Ed25519", kp};
}
async function importMySignKeysFromStorage(){
  const alg = localStorage.getItem(SIGN_ALG);
  const pubB64 = localStorage.getItem(SIGN_PUB);
  const privB64= localStorage.getItem(SIGN_PRIV);
  if (!alg || !pubB64 || !privB64) return {alg:null, pub:null, priv:null};
  const params = (alg==="Ed25519") ? {name:"Ed25519"} : {name:"ECDSA", namedCurve:"P-256"};
  const fmt    = (alg==="Ed25519") ? "raw" : "spki";
  const pub = await crypto.subtle.importKey(fmt, b642ab(pubB64), params, true, ["verify"]);
  const priv= await crypto.subtle.importKey("pkcs8", b642ab(privB64), params, true, ["sign"]);
  return {alg, pub, priv};
}
async function fetchPeerKeys(userId){
  const js = await (await fetch("/api/pubkey?user_id="+encodeURIComponent(userId))).json();
  if (!js.pub) throw new Error("Peer has no encryption key");

  // enc pub
  const encPub = await crypto.subtle.importKey("spki", b642ab(js.pub), {name:"RSA-OAEP", hash:"SHA-256"}, true, ["encrypt"]);
  const encFp  = await sha256_hex(b642ab(js.pub));

  // signing (optional)
  let signKey=null, signFp=null, signAlg=null;
  if (js.sign && js.sign.pub && js.sign.alg) {
    signAlg = js.sign.alg;
    const raw = b642ab(js.sign.pub);
    signFp = await sha256_hex(raw);
    try{
      const fmt=(signAlg==="Ed25519")?"raw":"spki";
      const params=(signAlg==="Ed25519")?{name:"Ed25519"}:{name:"ECDSA",namedCurve:"P-256"};
      signKey = await crypto.subtle.importKey(fmt, raw, params, true, ["verify"]);
    }catch(e){ console.warn("Signature alg unsupported:", signAlg, e); }
  }
  return { encPub, encFp, signKey, signFp, signAlg };
}
function signingParams(alg){ return (alg==="Ed25519") ? "Ed25519" : {name:"ECDSA", hash:"SHA-256"}; }
function normalizeAlg(alg){ return (alg && alg.toLowerCase().includes("ecdsa")) ? "ECDSA-P256" : alg; }
function signPreimage(m){
  const parts = [m.from_id||m.from,"|",m.to_id||m.to,"|",m.iv,"|",m.ciphertext,"|",m.ek_to,"|",m.ek_from,"|",m.nonce,"|",m.client_ts];
  return utf8(parts.join(""));
}
async function verifyMessageSig(m, pub, alg){
  if (!m.sig) return null;
  if (!pub || !alg) return null;
  try{
    return await crypto.subtle.verify(signingParams(alg), pub, b642ab(m.sig), signPreimage(m));
  }catch{ return null; }
}

// ================== Backup / Restore ==================
const BACKUP_ITER = 200000;
async function deriveKeyFromPass(pass, salt, iter=BACKUP_ITER){
  const km = await crypto.subtle.importKey("raw", utf8(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", hash:"SHA-256", salt, iterations:iter}, km, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
}
function getNickMap(){ try{ return JSON.parse(localStorage.getItem(NICKS_KEY)||"{}"); }catch{ return {}; } }
function saveNickMap(m){ localStorage.setItem(NICKS_KEY, JSON.stringify(m)); }
function nameFor(id){ const n=getNickMap()[id]; return n && n.trim() ? n : id; }

function snapshotIdentity(){
  const pins={};
  for(let i=0;i<localStorage.length;i++){
    const k = localStorage.key(i);
    if(k && k.startsWith(PIN_PREFIX)) pins[k.slice(PIN_PREFIX.length)] = JSON.parse(localStorage.getItem(k));
  }
  return {
    v:1, myId:localStorage.getItem("myId")||null,
    enc_pub:localStorage.getItem(KEY_PUB)||null,
    enc_priv:localStorage.getItem(KEY_PRIV)||null,
    sign_alg:localStorage.getItem(SIGN_ALG)||null,
    sign_pub:localStorage.getItem(SIGN_PUB)||null,
    sign_priv:localStorage.getItem(SIGN_PRIV)||null,
    pins,
    nicknames: getNickMap()
  };
}
function restoreSnapshot(o){
  if(!o || !o.myId || !o.enc_pub || !o.enc_priv) throw new Error("Incomplete identity");
  localStorage.setItem("myId",o.myId);
  localStorage.setItem(KEY_PUB,o.enc_pub);
  localStorage.setItem(KEY_PRIV,o.enc_priv);
  if(o.sign_alg && o.sign_pub && o.sign_priv){ localStorage.setItem(SIGN_ALG,o.sign_alg); localStorage.setItem(SIGN_PUB,o.sign_pub); localStorage.setItem(SIGN_PRIV,o.sign_priv); }
  for(const peer in (o.pins||{})){ localStorage.setItem(PIN_PREFIX+peer, JSON.stringify(o.pins[peer])); }
  if(o.nicknames) saveNickMap(o.nicknames);
}
async function exportIdentity(pass){
  if(!pass || pass.length<8) throw new Error("Use a longer passphrase.");
  const snap = snapshotIdentity();
  if(!snap.myId) throw new Error("No identity to export.");
  const pt = utf8(JSON.stringify(snap));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKeyFromPass(pass, salt);
  const ct   = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, pt);
  const pkg = {v:1,kdf:"PBKDF2-SHA256",iter:BACKUP_ITER,salt:ab2b64(salt.buffer),iv:ab2b64(iv.buffer),cipher:"AES-GCM",data:ab2b64(ct)};
  const blob=new Blob([JSON.stringify(pkg,null,2)],{type:"application/json"});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`oniondm-identity-${snap.myId}.json`; document.body.appendChild(a); a.click(); setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},0);
}
async function importIdentity(file, pass){
  if(!file) throw new Error("Pick a file."); if(!pass) throw new Error("Enter passphrase.");
  const pkg=JSON.parse(await file.text());
  const salt=new Uint8Array(b642ab(pkg.salt)); const iv=new Uint8Array(b642ab(pkg.iv));
  const key=await deriveKeyFromPass(pass,salt,pkg.iter||BACKUP_ITER);
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,b642ab(pkg.data));
  const snap=JSON.parse(new TextDecoder().decode(pt));
  restoreSnapshot(snap);
}

// ================== Pins ==================
function loadPin(peer){ const raw=localStorage.getItem(PIN_PREFIX+peer); return raw?JSON.parse(raw):null; }
function savePin(peer,pin){ localStorage.setItem(PIN_PREFIX+peer, JSON.stringify(pin)); }

// ================== Notifications ==================
function toast(msg){
  const t=$("#toast"); if(!t) return;
  t.textContent=msg; t.style.display="block";
  clearTimeout(toast._tmr); toast._tmr=setTimeout(()=>{ t.style.display="none"; }, 2200);
}
function beep(){
  try{
    const ctx = new (window.AudioContext||window.webkitAudioContext)();
    const o=ctx.createOscillator(), g=ctx.createGain(); o.type="sine"; o.frequency.value=880;
    o.connect(g); g.connect(ctx.destination);
    g.gain.value=0.0001; g.gain.exponentialRampToValueAtTime(0.05, ctx.currentTime+0.01);
    o.start();
    setTimeout(()=>{ g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime+0.15); o.stop(ctx.currentTime+0.18); ctx.close(); }, 180);
  }catch{}
}
function notifyNewMessage(fromId, preview){
  if(localStorage.getItem(NOTIF_SOUND)==="1") beep();
  toast(`New message from ${nameFor(fromId)}`);
  if (localStorage.getItem(NOTIF_DESKTOP)==="1" && "Notification" in window && Notification.permission==="granted" && document.hidden){
    try{ new Notification("Onion DM", { body: `${nameFor(fromId)}: ${preview}` }); }catch{}
  }
}

// ================== UI state ==================
const state = {
  me: localStorage.getItem("myId") || null,
  peer: null,
  contacts: [],
  lastId: null,
  pollAbort: null,
  myEncPriv: null, myEncPub: null,
  mySignAlg: null, mySignPriv: null, mySignPub: null,
  peerEncPub: null, peerEncFp: null,
  peerSignPub: null, peerSignFp: null, peerSignAlg: null,
  unread: {} // id -> count
};
let seen = new Set();

// ================== Sidebar / Drawer ==================
const sidebar = $("#sidebar");
const backdrop = $("#backdrop");
const menuBtn = $("#btnToggleSidebar");
function openDrawer(){ sidebar.classList.add("open"); backdrop.classList.add("show"); menuBtn.setAttribute("aria-expanded","true"); }
function closeDrawer(){ sidebar.classList.remove("open"); backdrop.classList.remove("show"); menuBtn.setAttribute("aria-expanded","false"); }
menuBtn?.addEventListener("click", ()=> { if (sidebar.classList.contains("open")) closeDrawer(); else openDrawer(); });
backdrop?.addEventListener("click", closeDrawer);

// ================== Sidebar & Chat UI helpers ==================
function setComposerEnabled(on){
  $("#btnSend").disabled = !on;
  const input=$("#msgInput");
  input.disabled = !on;
  input.placeholder = on ? "Type a message... (Enter to send, Shift+Enter = newline)" : "Verify & Trust this key to chat";
}

function drawContacts(){
  const list=$("#contactsList"); list.innerHTML="";
  state.contacts.forEach(id=>{
    const row=document.createElement("div"); row.className="contact"+(id===state.peer?" active":"");
    const label=document.createElement("div"); label.className="grow"; label.textContent=nameFor(id); row.appendChild(label);

    const cnt = state.unread[id]||0;
    if(cnt>0){ const b=document.createElement("span"); b.className="count"; b.textContent = cnt>99 ? "99+" : String(cnt); row.appendChild(b); }

    const actions=document.createElement("div"); actions.className="actions";
    const edit=document.createElement("button"); edit.className="iconbtn"; edit.title="Set nickname"; edit.textContent="✎";
    edit.addEventListener("click",(ev)=>{ ev.stopPropagation();
      const m=getNickMap(); const cur=m[id]||""; const name=prompt(`Set nickname for ${id}`, cur);
      if(name===null) return; const trimmed=(name||"").trim(); if(trimmed) { m[id]=trimmed; } else { delete m[id]; }
      saveNickMap(m); drawContacts(); if(state.peer===id) $("#peerLabel").textContent=nameFor(id);
    });
    const del=document.createElement("button"); del.className="iconbtn warn"; del.title="Delete contact"; del.textContent="🗑";
    del.addEventListener("click", async (ev)=>{ ev.stopPropagation();
      if(!confirm(`Remove contact ${nameFor(id)}?`)) return;
      try{
        await api("/api/remove_contact",{owner_id:state.me, contact_id:id});
        if(state.peer===id){ state.peer=null; $("#thread").innerHTML=""; setChatVisible(false); }
        await refreshContacts();
      }catch{ alert("Failed to remove contact."); }
    });
    actions.appendChild(edit); actions.appendChild(del);
    row.appendChild(actions);

    row.addEventListener("click",()=>{ openThread(id); closeDrawer(); });
    list.appendChild(row);
  });
}
async function refreshContacts(){
  if(!state.me) return;
  try{
    const r=await api("/api/contacts?user_id="+encodeURIComponent(state.me));
    state.contacts=r.contacts||[];
    // ensure unread map has keys
    state.contacts.forEach(id=>{ if(state.unread[id]==null) state.unread[id]=0; });
    drawContacts();
  }catch{}
}
function setChatVisible(on){
  $("#noChat").classList.toggle("hidden", on);
  $("#chatHeader").classList.toggle("hidden", !on);
  setComposerEnabled(on && ($("#keyBadge").classList.contains("ok")));
}
function setKeyUI(){
  if(!state.peer) return;
  const encShort=fpShort(state.peerEncFp||""); const sigShort= state.peerSignFp ? fpShort(state.peerSignFp) : "none";
  $("#encFp").textContent=`enc ${encShort}`;
  $("#sigFp").textContent=`sig ${sigShort}`;
  $("#fpRow").classList.remove("hidden");

  const pinned=loadPin(state.peer);
  const match = pinned && pinned.enc_fp===state.peerEncFp && pinned.sig_fp===(state.peerSignFp||null) && pinned.sig_alg===(state.peerSignAlg||null);
  const badge=$("#keyBadge"), trust=$("#btnTrustKey");
  if(match){ badge.textContent="Key pinned ✓"; badge.className="pill ok"; badge.classList.remove("hidden"); trust.classList.add("hidden"); setComposerEnabled(true); }
  else if(pinned){ badge.textContent="Key changed!"; badge.className="pill warn"; badge.classList.remove("hidden"); trust.classList.remove("hidden"); setComposerEnabled(false); }
  else { badge.textContent="Untrusted key"; badge.className="pill warn"; badge.classList.remove("hidden"); trust.classList.remove("hidden"); setComposerEnabled(false); }
}
function appendBubble(m,text,sigOk,sigAlg){
  const wrap=document.createElement("div"); wrap.className="bubble "+(m.from===state.me?"me":"them");
  const body=document.createElement("div"); body.textContent=text;
  const meta=document.createElement("div"); meta.className="timestamp";
  const tag=(sigOk===true)?"✓ signed":(sigOk===false)?"⚠ invalid sig":(m.sig?"sig unsupported":"unsigned");
  meta.textContent=`${new Date(m.ts).toLocaleString()} • ${tag}${m.sig && sigAlg? " ("+sigAlg+")":""}`;
  wrap.appendChild(body); wrap.appendChild(meta); $("#thread").appendChild(wrap);
  const th=$("#thread"); th.scrollTop=th.scrollHeight;
}

// ================== Long-poll & processing ==================
function cancelPolling(){ if(state.pollAbort){ state.pollAbort.abort(); state.pollAbort=null; } }
async function processMessages(items){
  let gotNew=false, notifyInfo=null;
  for(const m of items){
    if(m.id!=null && seen.has(m.id)) continue;
    let sigOk=null;
    if(m.from!==state.me){
      sigOk=await verifyMessageSig(
        {from:m.from,to:m.to,iv:m.iv,ciphertext:m.ct,ek_to:m.ek_to,ek_from:m.ek_from,nonce:m.nonce||"",client_ts:m.client_ts||""},
        state.peerSignPub, normalizeAlg(state.peerSignAlg)
      );
    }
    let text="[encrypted]";
    if(m.ct && m.iv){
      const ek=(m.to===state.me)?m.ek_to:(m.from===state.me)?m.ek_from:null;
      if(ek){
        try{
          const raw=await crypto.subtle.decrypt({name:"RSA-OAEP"}, state.myEncPriv, b642ab(ek));
          const aes=await crypto.subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["decrypt"]);
          const pt=await crypto.subtle.decrypt({name:"AES-GCM", iv:new Uint8Array(b642ab(m.iv))}, aes, b642ab(m.ct));
          text=new TextDecoder().decode(pt);
        }catch{ text="[failed to decrypt]"; }
      }else text="[not for me]";
    } else if (m.body){ text=m.body+" (legacy)"; }
    appendBubble(m,text,sigOk,m.sig_alg);
    if(m.id!=null) seen.add(m.id); state.lastId=m.id||state.lastId;

    // unread + notifications
    if(m.from!==state.me){
      if(state.peer!==m.from || document.hidden){
        state.unread[m.from]=(state.unread[m.from]||0)+1;
        gotNew=true; notifyInfo={from:m.from, text:text.slice(0,64)};
      }
    }
  }
  if(gotNew){ drawContacts(); if(notifyInfo) notifyNewMessage(notifyInfo.from, notifyInfo.text); }
}
async function longPollThread(){
  if(!state.me || !state.peer) return;
  const ac=new AbortController(); state.pollAbort=ac;
  try{
    let url=`/api/thread_lp?user_id=${encodeURIComponent(state.me)}&peer_id=${encodeURIComponent(state.peer)}`;
    if(state.lastId!=null) url+=`&since_id=${encodeURIComponent(state.lastId)}`;
    const r=await fetch(url,{signal:ac.signal}); if(!r.ok) throw new Error("HTTP "+r.status);
    const data=await r.json(); await processMessages(data.messages||[]);
  }catch{} finally{ if(state.pollAbort===ac) setTimeout(longPollThread,50); }
}

// ================== Flows ==================
async function signUpFlow(){
  // gen/load keys
  const haveEnc=await importMyEncKeysFromStorage(); if(!haveEnc.priv||!haveEnc.pub) await generateEncKeysAndSave();
  const enc=await importMyEncKeysFromStorage(); state.myEncPriv=enc.priv; state.myEncPub=enc.pub;

  const haveSign=await importMySignKeysFromStorage(); if(!haveSign.priv||!haveSign.pub) await generateSignKeysAndSave();
  const sign=await importMySignKeysFromStorage(); state.mySignAlg=sign.alg; state.mySignPriv=sign.priv; state.mySignPub=sign.pub;

  const res=await api("/api/signup",{ pub:localStorage.getItem(KEY_PUB), sign:{alg:state.mySignAlg, pub:localStorage.getItem(SIGN_PUB)} });
  state.me=res.id; localStorage.setItem("myId", state.me);

  // show onboarding export
  $("#onbMyId").textContent=state.me;
  showView("view-export");
  closeDrawer();
}

async function openThread(peerId){
  state.peer=peerId; state.lastId=null; seen.clear();
  $("#peerLabel").textContent=nameFor(peerId); $("#thread").innerHTML=""; setChatVisible(true); cancelPolling();

  try{
    const {encPub,encFp,signKey,signFp,signAlg}=await fetchPeerKeys(peerId);
    state.peerEncPub=encPub; state.peerEncFp=encFp; state.peerSignPub=signKey; state.peerSignFp=signFp||null; state.peerSignAlg=signAlg||null;
  }catch{ alert("Peer has not signed up (missing keys)."); return; }

  // clearing unread for this peer
  state.unread[peerId]=0; drawContacts();

  setKeyUI();

  try{
    const r=await api(`/api/thread?user_id=${encodeURIComponent(state.me)}&peer_id=${encodeURIComponent(state.peer)}`);
    await processMessages(r.messages||[]);
  }catch{}
  longPollThread();
}

// ================== Events: landing/login/export ==================
$("#btnLandingSignup").addEventListener("click", async () => {
  try{ await signUpFlow(); }catch(e){ alert("Signup failed: "+(e.message||e)); }
});
$("#btnLandingLogin").addEventListener("click", ()=> showView("view-login"));
$("#btnBackFromLogin").addEventListener("click", ()=> showView("view-landing"));

$("#btnLoginImport").addEventListener("click", async ()=>{
  try{
    await importIdentity($("#loginFile").files[0], $("#loginPass").value.trim());
    const enc=await importMyEncKeysFromStorage(); state.myEncPriv=enc.priv; state.myEncPub=enc.pub;
    const sign=await importMySignKeysFromStorage(); state.mySignAlg=sign.alg; state.mySignPriv=sign.priv; state.mySignPub=sign.pub;
    state.me=localStorage.getItem("myId");
    $("#myId").textContent=state.me; $("#userBadge").textContent="Signed in as "+state.me;
    showView("view-app"); refreshContacts(); setChatVisible(false);
  }catch(e){ alert("Import failed: "+(e.message||e)); }
});

// Export onboarding
$("#btnOnbCopy").addEventListener("click", async ()=>{ try{ await navigator.clipboard.writeText($("#onbMyId").textContent); }catch{} });
$("#btnOnbExport").addEventListener("click", async ()=>{
  try{ await exportIdentity($("#onbPass").value.trim()); }catch(e){ alert(e.message||e); return; }
  $("#myId").textContent=state.me; $("#userBadge").textContent="Signed in as "+state.me;
  showView("view-app"); refreshContacts(); setChatVisible(false);
});
$("#btnOnbSkip").addEventListener("click", ()=>{
  $("#myId").textContent=state.me; $("#userBadge").textContent="Signed in as "+state.me;
  showView("view-app"); refreshContacts(); setChatVisible(false);
});

// ================== Events: app shell ==================
$("#copyId").addEventListener("click", async ()=>{ try{ await navigator.clipboard.writeText(state.me); }catch{} });
$("#btnAddContact").addEventListener("click", async ()=>{
  const cid=$("#contactId").value.trim(); if(!cid) return; if(!state.me){ alert("Sign up or import first."); return; }
  try{ await api("/api/add_contact",{owner_id:state.me, contact_id:cid}); $("#contactId").value=""; refreshContacts(); }catch{ alert("Could not add contact."); }
});
$("#btnTrustKey").addEventListener("click", ()=>{
  if(!state.peer) return;
  savePin(state.peer, {enc_fp:state.peerEncFp, sig_alg:state.peerSignAlg||null, sig_fp:state.peerSignFp||null});
  setKeyUI();
});
$("#btnSend").addEventListener("click", async ()=>{
  const txt=$("#msgInput").value.trim(); if(!txt || !state.me || !state.peer) return;

  const pin=loadPin(state.peer);
  const ok = pin && pin.enc_fp===state.peerEncFp && pin.sig_fp===(state.peerSignFp||null) && pin.sig_alg===(state.peerSignAlg||null);
  if(!ok){ alert("Peer key not trusted yet or has changed. Verify & trust first."); return; }

  $("#msgInput").value="";

  try{
    if(!state.myEncPriv||!state.myEncPub){ const k=await importMyEncKeysFromStorage(); state.myEncPriv=k.priv; state.myEncPub=k.pub; }
    if(!state.mySignPriv||!state.mySignPub||!state.mySignAlg){ const k=await importMySignKeysFromStorage(); state.mySignPriv=k.priv; state.mySignPub=k.pub; state.mySignAlg=k.alg; }
    if(!state.peerEncPub){ const k=await fetchPeerKeys(state.peer); state.peerEncPub=k.encPub; state.peerEncFp=k.encFp; state.peerSignPub=k.signKey; state.peerSignFp=k.signFp; state.peerSignAlg=k.signAlg; setKeyUI(); }

    const aes=await crypto.subtle.generateKey({name:"AES-GCM", length:256}, true, ["encrypt","decrypt"]);
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const ct=await crypto.subtle.encrypt({name:"AES-GCM", iv}, aes, utf8(txt));
    const raw=await crypto.subtle.exportKey("raw", aes);
    const ek_to  =await crypto.subtle.encrypt({name:"RSA-OAEP"}, state.peerEncPub, raw);
    const ek_from=await crypto.subtle.encrypt({name:"RSA-OAEP"}, state.myEncPub,   raw);

    const nonce=crypto.getRandomValues(new Uint8Array(16));
    const client_ts=new Date().toISOString();
    const env={from_id:state.me,to_id:state.peer,ciphertext:ab2b64(ct),iv:ab2b64(iv.buffer),ek_to:ab2b64(ek_to),ek_from:ab2b64(ek_from),nonce:ab2b64(nonce.buffer),client_ts};
    const sigAlg=normalizeAlg(state.mySignAlg);
    const sig=await crypto.subtle.sign((sigAlg==="Ed25519")?"Ed25519":{name:"ECDSA", hash:"SHA-256"}, state.mySignPriv, signPreimage(env));

    await api("/api/send",{...env, sig:ab2b64(sig), sig_alg:sigAlg});
  }catch(e){ console.error(e); alert("Send failed"); }
});

// Enter-to-send (Shift+Enter = newline)
$("#msgInput").addEventListener("keydown", e=>{
  if(e.key==="Enter" && !e.shiftKey){
    e.preventDefault();
    if(!$("#btnSend").disabled) $("#btnSend").click();
  }
});

// Export/Import (sidebar)
$("#btnExport").addEventListener("click", async ()=>{ try{ await exportIdentity($("#backupPass").value.trim()); }catch(e){ alert("Export failed: "+(e.message||e)); } });
$("#btnImport").addEventListener("click", async ()=>{ try{
  await importIdentity($("#restoreFile").files[0], $("#restorePass").value.trim());
  const enc=await importMyEncKeysFromStorage(); state.myEncPriv=enc.priv; state.myEncPub=enc.pub;
  const sign=await importMySignKeysFromStorage(); state.mySignAlg=sign.alg; state.mySignPriv=sign.priv; state.mySignPub=sign.pub;
  state.me=localStorage.getItem("myId"); $("#myId").textContent=state.me; $("#userBadge").textContent="Signed in as "+state.me; refreshContacts();
  closeDrawer();
}catch(e){ alert("Import failed: "+(e.message||e)); }});

// Notifications toggles
(function notifInit(){
  const desk=$("#toggleDesktop"), snd=$("#toggleSound");
  if(desk){ desk.checked = localStorage.getItem(NOTIF_DESKTOP)==="1";
    desk.addEventListener("change", async ()=>{
      if(desk.checked){
        if(!("Notification" in window)){ alert("This browser does not support desktop notifications."); desk.checked=false; return; }
        if(Notification.permission!=="granted"){
          const p=await Notification.requestPermission();
          if(p!=="granted"){ desk.checked=false; return; }
        }
        localStorage.setItem(NOTIF_DESKTOP,"1");
      }else{
        localStorage.removeItem(NOTIF_DESKTOP);
      }
    });
  }
  if(snd){ snd.checked = localStorage.getItem(NOTIF_SOUND)==="1";
    snd.addEventListener("change", ()=>{ if(snd.checked) localStorage.setItem(NOTIF_SOUND,"1"); else localStorage.removeItem(NOTIF_SOUND); });
  }
})();

// ================== Boot ==================
(async function init(){
  const enc=await importMyEncKeysFromStorage(); state.myEncPriv=enc.priv; state.myEncPub=enc.pub;
  const sign=await importMySignKeysFromStorage(); state.mySignAlg=sign.alg; state.mySignPriv=sign.priv; state.mySignPub=sign.pub;
  state.me=localStorage.getItem("myId")||null;

  if(state.me){
    $("#myId").textContent=state.me; $("#userBadge").textContent="Signed in as "+state.me;
    showView("view-app"); refreshContacts(); setChatVisible(false);
  }else{
    showView("view-landing");
  }
})();
