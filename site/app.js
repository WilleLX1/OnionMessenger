// ---------- helpers ----------
const $ = sel => document.querySelector(sel);
const api = async (path, data=null) => {
  const opts = data ? { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(data)} : {};
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
};
function ab2b64(buf){
  const bytes = new Uint8Array(buf);
  const chunk = 0x8000;
  let binary = "";
  for (let i=0;i<bytes.length;i+=chunk){
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i+chunk));
  }
  return btoa(binary);
}
function b642ab(b64){
  const bin = atob(b64);
  const len = bin.length;
  const bytes = new Uint8Array(len);
  for (let i=0;i<len;i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// ---------- key management ----------
const KEY_PRIV = "priv_pkcs8_b64";
const KEY_PUB  = "pub_spki_b64";

async function importMyKeysFromStorage(){
  const privB64 = localStorage.getItem(KEY_PRIV);
  const pubB64  = localStorage.getItem(KEY_PUB);
  if (!privB64 || !pubB64) return {priv:null, pub:null};
  const priv = await crypto.subtle.importKey(
    "pkcs8", b642ab(privB64),
    {name:"RSA-OAEP", hash:"SHA-256"},
    true, ["decrypt"]
  );
  const pub = await crypto.subtle.importKey(
    "spki", b642ab(pubB64),
    {name:"RSA-OAEP", hash:"SHA-256"},
    true, ["encrypt"]
  );
  return {priv, pub};
}

async function generateKeysAndSave(){
  const kp = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
    true,
    ["encrypt","decrypt"]
  );
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  localStorage.setItem(KEY_PUB,  ab2b64(spki));
  localStorage.setItem(KEY_PRIV, ab2b64(pkcs8));
  return kp;
}

async function importPeerPubKey(userId){
  const js = await (await fetch("/api/pubkey?user_id="+encodeURIComponent(userId))).json();
  if (!js.pub) throw new Error("Peer has no public key");
  return crypto.subtle.importKey(
    "spki", b642ab(js.pub),
    {name:"RSA-OAEP", hash:"SHA-256"},
    true, ["encrypt"]
  );
}

// ---------- UI refs ----------
const myIdBox = $("#myId");
const signupView = $("#signupView");
const meView = $("#meView");
const userBadge = $("#userBadge");
const contactsPanel = $("#contactsPanel");
const contactsList = $("#contactsList");
const emptyState = $("#emptyState");
const chatView = $("#chatView");
const peerLabel = $("#peerLabel");
const threadEl = $("#thread");
const msgInput = $("#msgInput");

// ---------- state ----------
let state = {
  me: localStorage.getItem("myId") || null,
  peer: null,
  contacts: [],
  lastId: null,
  pollAbort: null,
  myPriv: null,
  myPub: null,
  peerPub: null
};
let seen = new Set();

// ---------- UI helpers ----------
function showMe() {
  if (state.me) {
    signupView.classList.add("hidden");
    meView.classList.remove("hidden");
    contactsPanel.classList.remove("hidden");
    myIdBox.textContent = state.me;
    userBadge.textContent = "Signed in as " + state.me;
    refreshContacts();
  } else {
    signupView.classList.remove("hidden");
    meView.classList.add("hidden");
    contactsPanel.classList.add("hidden");
    userBadge.textContent = "";
    contactsList.innerHTML = "";
  }
  setChatVisible(!!state.peer);
}
function setChatVisible(on) {
  if (on) { emptyState.classList.add("hidden"); chatView.classList.remove("hidden"); }
  else { chatView.classList.add("hidden"); emptyState.classList.remove("hidden"); }
}

// ---------- contacts ----------
async function refreshContacts() {
  if (!state.me) return;
  try {
    const res = await api("/api/contacts?user_id="+encodeURIComponent(state.me));
    state.contacts = res.contacts || [];
    drawContacts();
  } catch {}
}
function drawContacts() {
  contactsList.innerHTML = "";
  state.contacts.forEach(id => {
    const div = document.createElement("div");
    div.className = "contact" + (id === state.peer ? " active" : "");
    const span = document.createElement("div");
    span.className = "grow";
    span.textContent = id;
    div.appendChild(span);
    div.addEventListener("click", () => openThread(id));
    contactsList.appendChild(div);
  });
}

// ---------- long-poll ----------
function cancelPolling() {
  if (state.pollAbort) { state.pollAbort.abort(); state.pollAbort = null; }
}

async function openThread(peerId) {
  state.peer = peerId;
  state.lastId = null;
  seen.clear();
  peerLabel.textContent = peerId;
  setChatVisible(true);
  threadEl.innerHTML = "";
  cancelPolling();

  // fetch peer pubkey
  try {
    state.peerPub = await importPeerPubKey(peerId);
  } catch {
    alert("Peer has not signed up (no public key).");
    return;
  }

  // initial fill
  try {
    const res = await api(`/api/thread?user_id=${encodeURIComponent(state.me)}&peer_id=${encodeURIComponent(state.peer)}`);
    await processMessages(res.messages || []);
  } catch {}

  // start LP
  longPollThread();
}

async function longPollThread() {
  if (!state.me || !state.peer) return;
  const ac = new AbortController();
  state.pollAbort = ac;
  try {
    let url = `/api/thread_lp?user_id=${encodeURIComponent(state.me)}&peer_id=${encodeURIComponent(state.peer)}`;
    if (state.lastId != null) url += `&since_id=${encodeURIComponent(state.lastId)}`;
    const r = await fetch(url, { signal: ac.signal });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    await processMessages(data.messages || []);
  } catch (_) {
    // ignore abort/timeout
  } finally {
    if (state.pollAbort === ac) setTimeout(longPollThread, 50);
  }
}

// ---------- message decrypt & render ----------
async function processMessages(items){
  for (const m of items) {
    if (m.id != null && seen.has(m.id)) continue;
    let text = "[encrypted]";
    if (m.ct && m.iv) {
      try {
        const ek_b64 = (m.to === state.me) ? m.ek_to : (m.from === state.me) ? m.ek_from : null;
        if (ek_b64) {
          const rawAes = await crypto.subtle.decrypt({name:"RSA-OAEP"}, state.myPriv, b642ab(ek_b64));
          const aesKey = await crypto.subtle.importKey("raw", rawAes, {name:"AES-GCM"}, false, ["decrypt"]);
          const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:new Uint8Array(b642ab(m.iv))}, aesKey, b642ab(m.ct));
          text = new TextDecoder().decode(pt);
        } else {
          text = "[not for me]";
        }
      } catch (e) {
        text = "[failed to decrypt]";
      }
    } else if (m.body) {
      text = m.body + " (legacy)";
    }
    appendBubble(m, text);
    if (m.id != null) seen.add(m.id);
    state.lastId = m.id || state.lastId;
  }
  threadEl.scrollTop = threadEl.scrollHeight;
}
function appendBubble(m, text){
  const wrap = document.createElement("div");
  wrap.className = "bubble " + (m.from === state.me ? "me" : "them");
  const body = document.createElement("div");
  body.textContent = text;
  const ts = document.createElement("div");
  ts.className = "timestamp";
  ts.textContent = new Date(m.ts).toLocaleString();
  wrap.appendChild(body);
  wrap.appendChild(ts);
  threadEl.appendChild(wrap);
}

// ---------- events ----------
$("#btnSignup").addEventListener("click", async () => {
  try {
    // generate or load keys
    const existing = await importMyKeysFromStorage();
    if (!existing.priv || !existing.pub) {
      await generateKeysAndSave();
    }
    const {priv, pub} = await importMyKeysFromStorage();
    state.myPriv = priv; state.myPub = pub;

    // send public key, get ID
    const pubB64 = localStorage.getItem("pub_spki_b64");
    const res = await api("/api/signup", { pub: pubB64 });
    state.me = res.id;
    localStorage.setItem("myId", state.me);
    showMe();
  } catch(e) { console.error(e); alert("Signup failed"); }
});

$("#copyId").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(state.me); } catch {}
});

$("#btnAddContact").addEventListener("click", async () => {
  const cid = $("#contactId").value.trim();
  if (!cid) return;
  if (!state.me) return alert("Sign up first");
  try {
    await api("/api/add_contact", {owner_id: state.me, contact_id: cid});
    $("#contactId").value = "";
    refreshContacts();
  } catch(e) { alert("Could not add contact (ID may not exist)"); }
});

$("#btnSend").addEventListener("click", async () => {
  const txt = msgInput.value.trim();
  if (!txt || !state.me || !state.peer) return;
  msgInput.value = "";

  try {
    // ensure keys
    if (!state.myPriv || !state.myPub) {
      const {priv, pub} = await importMyKeysFromStorage();
      state.myPriv = priv; state.myPub = pub;
    }
    if (!state.peerPub) {
      state.peerPub = await importPeerPubKey(state.peer);
    }

    // AES-GCM encrypt plaintext
    const aesKey = await crypto.subtle.generateKey({name:"AES-GCM", length:256}, true, ["encrypt","decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, aesKey, new TextEncoder().encode(txt));

    // Export raw AES key
    const rawAes = await crypto.subtle.exportKey("raw", aesKey);

    // Wrap to recipient + sender
    const ek_to   = await crypto.subtle.encrypt({name:"RSA-OAEP"}, state.peerPub, rawAes);
    const ek_from = await crypto.subtle.encrypt({name:"RSA-OAEP"}, state.myPub,   rawAes);

    // Send blob
    await api("/api/send", {
      from_id: state.me,
      to_id: state.peer,
      ciphertext: ab2b64(ct),
      iv: ab2b64(iv.buffer),
      ek_to: ab2b64(ek_to),
      ek_from: ab2b64(ek_from)
    });
    // LP will deliver it
  } catch(e) {
    console.error(e);
    alert("Send failed");
  }
});

// ---------- boot ----------
(async function init(){
  const {priv, pub} = await importMyKeysFromStorage();
  state.myPriv = priv; state.myPub = pub;
  state.me = localStorage.getItem("myId") || null;
  showMe();
  if (state.me) refreshContacts();
})();
