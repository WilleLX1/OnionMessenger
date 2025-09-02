import http.server
import socketserver
import subprocess
import sys
import os
import time
import shutil
import argparse
import json
import threading
import urllib.parse
import re
import base64
from pathlib import Path
from datetime import datetime, timezone

# ---------------------------
# Utilities / Paths
# ---------------------------
def find_tor_binary():
    candidates = ["tor"]
    if os.name == "nt":
        candidates = ["tor.exe", os.path.join(os.getcwd(), "tor", "tor.exe")]
    for c in candidates:
        tor = shutil.which(os.path.expandvars(c))
        if tor:
            return tor
    return None

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, obj):
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

# ---------------------------
# App state (file-backed)
# ---------------------------
class Store:
    """
    Persistent JSON store.

    users: {
      "<id>": {
        "created_at": "...",
        "pub": "<RSA-SPKI-b64>",
        "sign": { "alg": "Ed25519"|"ECDSA-P256", "pub": "<b64>" },
        "token": "<random bearer token>"
      }
    }

    contacts: { "<owner_id>": ["<peer_id>", ...] }

    messages: [
      {
        "id":1,"from":"A","to":"B","ts":"...",
        "ct":"<b64>","iv":"<b64>","ek_to":"<b64>","ek_from":"<b64>",
        "sig":"<b64>","sig_alg":"Ed25519"|"ECDSA-P256",
        "nonce":"<b64>","client_ts":"..."
      }, ...
    ]

    replay: set of prior signatures (to drop duplicates)
    """
    def __init__(self, datadir: Path):
        self.lock = threading.RLock()
        self.datadir = datadir
        self.users_path = datadir / "users.json"
        self.contacts_path = datadir / "contacts.json"
        self.messages_path = datadir / "messages.json"
        self.replay_path = datadir / "replay.json"
        self.files_path = datadir / "files.json"  # metadata only; chunk bytes on disk
        self.files_dir = datadir / "files"
        self.groups_path = datadir / "groups.json"
        datadir.mkdir(parents=True, exist_ok=True)
        self.files_dir.mkdir(parents=True, exist_ok=True)

        self.users = load_json(self.users_path, {})
        self.contacts = load_json(self.contacts_path, {})
        self.messages = load_json(self.messages_path, [])
        self.replay = set(load_json(self.replay_path, []))
        self.files = load_json(self.files_path, {})  # file_id -> meta
        self.groups = load_json(self.groups_path, {})  # group_id -> {name, owner, members: [uid], created_at}

        if self.messages:
            self.next_id = 1 + max(int(m.get("id", 0)) for m in self.messages)
        else:
            self.next_id = 1

    def _persist_all(self):
        with self.lock:
            save_json(self.users_path, self.users)
            save_json(self.contacts_path, self.contacts)
            save_json(self.messages_path, self.messages)
            # store replay as a (bounded) list
            if len(self.replay) > 200000:
                # drop to last ~100k (unordered set -> take any 100k)
                self.replay = set(list(self.replay)[:100000])
            save_json(self.replay_path, list(self.replay))
            save_json(self.files_path, self.files)
            save_json(self.groups_path, self.groups)

    # ---- users
    def gen_id(self, n=14):
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        import secrets
        return "".join(secrets.choice(alphabet) for _ in range(n))

    def gen_token(self):
        import secrets
        return secrets.token_urlsafe(32)

    def signup(self, pub=None, sign=None):
        with self.lock:
            while True:
                uid = self.gen_id()
                if uid not in self.users:
                    break
            tok = self.gen_token()
            self.users[uid] = {"created_at": now_iso(), "pub": pub, "sign": sign, "token": tok}
            self._persist_all()
            return uid, tok

    def get_user_keys(self, uid):
        with self.lock:
            u = self.users.get(uid)
            if not u:
                return None
            return {"pub": u.get("pub"), "sign": u.get("sign")}

    def valid_user(self, uid):
        with self.lock:
            return uid in self.users

    def uid_from_token(self, token: str):
        if not token:
            return None
        with self.lock:
            for uid, u in self.users.items():
                if u.get("token") == token:
                    return uid
        return None

    # ---- contacts
    def add_contact(self, owner, contact):
        with self.lock:
            if owner not in self.users or contact not in self.users:
                return False
            lst = self.contacts.get(owner, [])
            if contact not in lst:
                lst.append(contact)
            self.contacts[owner] = lst
            self._persist_all()
            return True

    def remove_contact(self, owner, contact):
        with self.lock:
            if owner not in self.users or contact not in self.users:
                return False
            lst = self.contacts.get(owner, [])
            if contact in lst:
                lst = [c for c in lst if c != contact]
                self.contacts[owner] = lst
                self._persist_all()
                return True
            return False

    def get_contacts(self, owner):
        with self.lock:
            return list(self.contacts.get(owner, []))

    # ---- messages (E2EE blobs only)
    def send(self, from_id, to_id, ct, iv, ek_to, ek_from, sig, sig_alg, nonce, client_ts):
        if not (ct and iv and ek_to and ek_from and sig and sig_alg and nonce and client_ts):
            return False
        with self.lock:
            if from_id not in self.users or to_id not in self.users:
                return False
            # replay drop (idempotent)
            if sig in self.replay:
                return True  # already accepted
            self.replay.add(sig)

            mid = self.next_id
            self.next_id += 1
            self.messages.append({
                "id": mid,
                "from": from_id,
                "to": to_id,
                "ct": ct,
                "iv": iv,
                "ek_to": ek_to,
                "ek_from": ek_from,
                "sig": sig,
                "sig_alg": sig_alg,
                "nonce": nonce,
                "client_ts": client_ts,
                "ts": now_iso()
            })
            self._persist_all()
            return True

    def thread(self, a, b, since_iso=None, since_id=None, limit=200):
        with self.lock:
            out = []
            for m in self.messages:
                # exclude group messages from direct DM threads
                if m.get("group"):
                    continue
                ab = (m["from"] == a and m["to"] == b)
                ba = (m["from"] == b and m["to"] == a)
                if not (ab or ba):
                    continue
                if since_id is not None:
                    if int(m.get("id", 0)) <= int(since_id):
                        continue
                elif since_iso:
                    if m["ts"] <= since_iso:
                        continue
                out.append(m)
            out.sort(key=lambda x: (int(x.get("id", 0)), x["ts"]))
            return out[-limit:]

    # ---- groups ----
    def create_group(self, owner: str, name: str):
        with self.lock:
            if owner not in self.users:
                return None
            gid = self.gen_id(16)
            self.groups[gid] = {
                "name": str(name or "Group"),
                "owner": owner,
                "members": [owner],
                "created_at": now_iso(),
            }
            self._persist_all()
            return gid

    def group_join(self, gid: str, uid: str):
        with self.lock:
            g = self.groups.get(gid)
            if not g or uid not in self.users:
                return False
            if uid not in g["members"]:
                g["members"].append(uid)
                self._persist_all()
            return True

    def group_rename(self, gid: str, owner: str, name: str):
        with self.lock:
            g = self.groups.get(gid)
            if not g:
                return False
            if g.get("owner") != owner:
                return False
            g["name"] = str(name or "Group")[:100]
            self._persist_all()
            return True

    def user_groups(self, uid: str):
        with self.lock:
            out = []
            for gid, g in self.groups.items():
                if uid in g.get("members", []):
                    out.append({"id": gid, "name": g.get("name", "Group"), "owner": g.get("owner")})
            return out

    def group_members(self, gid: str):
        with self.lock:
            g = self.groups.get(gid)
            if not g:
                return []
            return list(g.get("members", []))

    def group_leave(self, gid: str, uid: str):
        with self.lock:
            g = self.groups.get(gid)
            if not g:
                return False
            if uid == g.get("owner"):
                # owner cannot leave (to keep semantics simple)
                return False
            if uid in g.get("members", []):
                g["members"] = [m for m in g["members"] if m != uid]
                self._persist_all()
                return True
            return False

    def group_remove(self, gid: str, owner: str, member: str):
        with self.lock:
            g = self.groups.get(gid)
            if not g:
                return False
            if g.get("owner") != owner:
                return False
            if member == owner:
                return False
            if member in g.get("members", []):
                g["members"] = [m for m in g["members"] if m != member]
                self._persist_all()
                return True
            return False

    # ---- files (encrypted blob relay) ----
    def file_init(self, owner_id, to_id, total_size, total_chunks, max_size_bytes, max_chunks):
        with self.lock:
            if owner_id not in self.users or to_id not in self.users:
                return None
            if not (0 < total_size <= max_size_bytes and 0 < total_chunks <= max_chunks):
                return None
            # simple cap: at most 5 active files per owner
            active = sum(1 for f in self.files.values() if f.get("from") == owner_id and not f.get("complete"))
            if active >= 5:
                return None
            fid = self.gen_id(20)
            self.files[fid] = {
                "from": owner_id,
                "to": to_id,
                "size": int(total_size),
                "chunks": int(total_chunks),
                "received": 0,
                "complete": False,
                "created_at": now_iso(),
            }
            (self.files_dir / fid).mkdir(parents=True, exist_ok=True)
            self._persist_all()
            return fid

    def file_chunk(self, fid, idx, data_bytes, max_chunk_bytes):
        with self.lock:
            meta = self.files.get(fid)
            if not meta:
                return False, "not found"
            if meta.get("complete"):
                return False, "already complete"
            chunks = int(meta.get("chunks", 0))
            if not (0 <= idx < chunks):
                return False, "invalid index"
            if not (1 <= len(data_bytes) <= max_chunk_bytes):
                return False, "invalid size"
            d = self.files_dir / fid
            d.mkdir(parents=True, exist_ok=True)
            part = d / f"{idx}.bin"
            if part.exists():
                return True, "duplicate"
            with open(part, "wb") as f:
                f.write(data_bytes)
            meta["received"] = int(meta.get("received", 0)) + 1
            self._persist_all()
            return True, "ok"

    def file_finish(self, fid):
        with self.lock:
            meta = self.files.get(fid)
            if not meta:
                return False
            if meta.get("complete"):
                return True
            chunks = int(meta.get("chunks", 0))
            d = self.files_dir / fid
            ok = all((d / f"{i}.bin").exists() for i in range(chunks))
            if not ok:
                return False
            meta["complete"] = True
            self._persist_all()
            return True

    def file_meta(self, fid):
        with self.lock:
            return dict(self.files.get(fid) or {})

# ---------------------------
# HTTP Handler (API + static)
# ---------------------------
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, store: Store = None, **kwargs):
        self.store = store
        super().__init__(*args, directory=str(self.directory), **kwargs)

    # --- security / limits ---
    MAX_BODY_BYTES = 200_000  # hard cap for JSON bodies (~200 KB)
    MAX_BODY_BYTES_FILE = 1_200_000  # higher cap for chunk uploads (~1.2 MB)
    MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB per file
    MAX_CHUNK_BYTES = 512 * 1024      # 512 KB per chunk (ciphertext size)
    MAX_FILE_CHUNKS = 200
    UID_RE = re.compile(r"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{6,32}$")

    def end_headers(self):
        # Security headers for all responses (API + static)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def list_directory(self, path):
        # Disable directory listings
        self._status(404, {"error": "not found"})
        return None

    # --- validation helpers ---
    def _valid_uid(self, s):
        return isinstance(s, str) and bool(self.UID_RE.match(s))

    def _b64_len(self, s, max_bytes=None):
        if not isinstance(s, str) or s == "":
            return None
        try:
            raw = base64.b64decode(s, validate=True)
        except Exception:
            return None
        if max_bytes is not None and len(raw) > max_bytes:
            return None
        return len(raw)

    # --- auth helpers ---
    def bearer_uid(self):
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            return None
        token = auth.split(" ", 1)[1].strip()
        return self.store.uid_from_token(token)

    def require_auth(self):
        uid = self.bearer_uid()
        if not uid:
            self._status(401, {"error": "auth required"})
            return None
        return uid

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/contacts":
            actor = self.require_auth()
            if not actor:
                return
            qs = urllib.parse.parse_qs(parsed.query)
            uid = (qs.get("user_id") or [""])[0]
            if not self._valid_uid(uid):
                return self._status(400, {"error": "invalid user_id"})
            if uid != actor:
                return self._status(403, {"error": "forbidden"})
            contacts = self.store.get_contacts(uid) if self.store.valid_user(uid) else []
            return self._json({"contacts": contacts})

        if path in ("/api/thread", "/api/thread_lp"):
            actor = self.require_auth()
            if not actor:
                return
            qs = urllib.parse.parse_qs(parsed.query)
            uid = (qs.get("user_id") or [""])[0]
            pid = (qs.get("peer_id") or [""])[0]
            since = (qs.get("since") or [None])[0]
            since_id_raw = (qs.get("since_id") or [None])[0]
            try:
                since_id = int(since_id_raw) if since_id_raw not in (None, "", []) else None
            except (TypeError, ValueError):
                return self._status(400, {"error": "invalid since_id"})
            if not (self._valid_uid(uid) and self._valid_uid(pid)):
                return self._status(400, {"error": "invalid user/peer"})
            if uid != actor:
                return self._status(403, {"error": "forbidden"})
            if not (self.store.valid_user(uid) and self.store.valid_user(pid)):
                return self._status(400, {"error": "invalid user/peer"})

            if path == "/api/thread":
                msgs = self.store.thread(uid, pid, since_iso=since, since_id=since_id)
                return self._json({"messages": msgs})
            else:
                msgs = self._longpoll_thread(uid, pid, since, since_id, timeout_s=25, interval=0.5)
                return self._json({"messages": msgs})

        if path == "/api/pubkey":
            qs = urllib.parse.parse_qs(parsed.query)
            uid = (qs.get("user_id") or [""])[0]
            if not self._valid_uid(uid):
                return self._status(400, {"error": "invalid user_id"})
            keys = self.store.get_user_keys(uid)
            if keys and keys.get("pub"):
                return self._json({"pub": keys["pub"], "sign": keys.get("sign")})
            else:
                return self._status(404, {"error": "not found"})

        # ---- groups GET ----
        if path == "/api/groups":
            actor = self.require_auth()
            if not actor:
                return
            qs = urllib.parse.parse_qs(parsed.query)
            uid = (qs.get("user_id") or [""])[0]
            if not self._valid_uid(uid) or uid != actor:
                return self._status(403, {"error": "forbidden"})
            return self._json({"groups": self.store.user_groups(uid)})

        if path == "/api/group_members":
            actor = self.require_auth()
            if not actor:
                return
            qs = urllib.parse.parse_qs(parsed.query)
            gid = (qs.get("group_id") or [""])[0]
            gmembers = self.store.group_members(gid)
            if not gmembers or actor not in gmembers:
                return self._status(403, {"error": "forbidden"})
            return self._json({"members": gmembers})

        if path in ("/api/gthread", "/api/gthread_lp"):
            actor = self.require_auth()
            if not actor:
                return
            qs = urllib.parse.parse_qs(parsed.query)
            gid = (qs.get("group_id") or [""])[0]
            since = (qs.get("since") or [None])[0]
            since_id_raw = (qs.get("since_id") or [None])[0]
            try:
                since_id = int(since_id_raw) if since_id_raw not in (None, "", []) else None
            except (TypeError, ValueError):
                return self._status(400, {"error": "invalid since_id"})
            members = self.store.group_members(gid)
            if not members or actor not in members:
                return self._status(403, {"error": "forbidden"})
            # collect messages for this actor within group (their inbound copies + one of their outbound)
            with self.store.lock:
                out = []
                seen_g = set()
                for m in self.store.messages:
                    if m.get("group") != gid:
                        continue
                    mid = int(m.get("id", 0))
                    if since_id is not None and mid <= since_id:
                        continue
                    elif since and m["ts"] <= since:
                        continue
                    if m.get("to") == actor:
                        out.append(m)
                    elif m.get("from") == actor:
                        gmsg = m.get("gmsg") or f"{m.get('client_ts','')}:{m.get('nonce','')}"
                        if gmsg in seen_g:
                            continue
                        seen_g.add(gmsg)
                        out.append(m)
                out.sort(key=lambda x: (int(x.get("id", 0)), x["ts"]))
                msgs = out[-200:]
            if path == "/api/gthread":
                return self._json({"messages": msgs})
            else:
                # long-poll
                t0 = time.time();
                if msgs:
                    return self._json({"messages": msgs})
                while time.time() - t0 < 25:
                    time.sleep(0.5)
                    with self.store.lock:
                        newer = [m for m in self.store.messages if m.get("group") == gid and int(m.get("id",0)) > (since_id or 0) and (m.get("to") == actor or m.get("from") == actor)]
                    if newer:
                        newer.sort(key=lambda x: (int(x.get("id", 0)), x["ts"]))
                        return self._json({"messages": newer[-200:]})
                return self._json({"messages": []})

        if path == "/api/download_chunk":
            actor = self.require_auth()
            if not actor:
                return
            qs = urllib.parse.parse_qs(parsed.query)
            fid = (qs.get("file_id") or [""])[0]
            idx_raw = (qs.get("index") or [""])[0]
            try:
                idx = int(idx_raw)
            except Exception:
                return self._status(400, {"error": "invalid index"})
            meta = self.store.file_meta(fid)
            if not meta:
                return self._status(404, {"error": "not found"})
            if actor not in (meta.get("from"), meta.get("to")):
                return self._status(403, {"error": "forbidden"})
            d = self.store.files_dir / fid
            part = d / f"{idx}.bin"
            if not (d.exists() and d.is_dir() and part.exists() and part.is_file()):
                return self._status(404, {"error": "chunk not found"})
            try:
                with open(part, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionAbortedError):
                pass
            return

        if path == "/favicon.ico":
            import base64
            png = base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGMAAQAABQABJ5mOGQAAAABJRU5ErkJggg=="
            )
            try:
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(png)))
                self.end_headers()
                self.wfile.write(png)
            except (BrokenPipeError, ConnectionAbortedError):
                pass
            return

        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        limit = self.MAX_BODY_BYTES if parsed.path != "/api/file_chunk" else self.MAX_BODY_BYTES_FILE
        if n < 0 or n > limit:
            return self._status(413, {"error": "request too large"})
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype not in ("application/json", "application/json; charset=utf-8", "application/json;charset=utf-8") and parsed.path.startswith("/api/"):
            return self._status(415, {"error": "content-type must be application/json"})
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            body = {}

        if parsed.path == "/api/signup":
            pub = body.get("pub") or body.get("pub_spki") or body.get("public_key")
            sign = body.get("sign")  # {"alg": "...", "pub": "..."} (b64)
            uid, tok = self.store.signup(pub=pub, sign=sign)
            return self._json({"id": uid, "token": tok})

        if parsed.path == "/api/add_contact":
            actor = self.require_auth()
            if not actor:
                return
            owner = body.get("owner_id", "")
            contact = body.get("contact_id", "")
            if not (self._valid_uid(owner) and self._valid_uid(contact)):
                return self._status(400, {"error": "invalid owner/contact"})
            if owner != actor:
                return self._status(403, {"error": "forbidden"})
            ok = self.store.add_contact(owner, contact)
            if ok: return self._json({"ok": True})
            else:  return self._status(400, {"ok": False, "error": "invalid owner/contact"})

        if parsed.path == "/api/remove_contact":
            actor = self.require_auth()
            if not actor:
                return
            owner = body.get("owner_id", "")
            contact = body.get("contact_id", "")
            if not (self._valid_uid(owner) and self._valid_uid(contact)):
                return self._status(400, {"error": "invalid owner/contact"})
            if owner != actor:
                return self._status(403, {"error": "forbidden"})
            ok = self.store.remove_contact(owner, contact)
            if ok: return self._json({"ok": True})
            else:  return self._status(400, {"ok": False, "error": "invalid owner/contact or not found"})

        if parsed.path == "/api/send":
            actor = self.require_auth()
            if not actor:
                return
            frm = body.get("from_id", "")
            to = body.get("to_id", "")
            if not (self._valid_uid(frm) and self._valid_uid(to)):
                return self._status(400, {"error": "invalid from/to"})
            if frm != actor:
                return self._status(403, {"error": "forbidden"})
            ct = body.get("ciphertext", "")
            iv = body.get("iv", "")
            ek_to = body.get("ek_to", "")
            ek_from = body.get("ek_from", "")
            sig = body.get("sig", "")
            sig_alg = body.get("sig_alg", "")
            nonce = body.get("nonce", "")
            client_ts = body.get("client_ts", "")
            group_id = body.get("group_id") or body.get("group") or None
            gmsg = body.get("gid") or None

            # Basic input validation / size bounds to mitigate abuse
            if self._b64_len(ct, max_bytes=64_000) is None:  # ~64 KB max ciphertext
                return self._status(400, {"error": "invalid ciphertext"})
            if self._b64_len(iv, max_bytes=32) not in (12, 16):  # AES-GCM IV typically 12
                return self._status(400, {"error": "invalid iv"})
            if self._b64_len(ek_to, max_bytes=1024) is None:
                return self._status(400, {"error": "invalid ek_to"})
            if self._b64_len(ek_from, max_bytes=1024) is None:
                return self._status(400, {"error": "invalid ek_from"})
            if sig and self._b64_len(sig, max_bytes=512) is None:
                return self._status(400, {"error": "invalid sig"})
            if nonce and self._b64_len(nonce, max_bytes=128) is None:
                return self._status(400, {"error": "invalid nonce"})
            if not isinstance(client_ts, str) or len(client_ts) > 64:
                return self._status(400, {"error": "invalid client_ts"})
            if group_id:
                members = self.store.group_members(group_id)
                if not members or frm not in members or to not in members:
                    return self._status(400, {"error": "invalid group/to"})

            ok = self.store.send(frm, to, ct, iv, ek_to, ek_from, sig, sig_alg, nonce, client_ts)
            if ok and group_id:
                # append group fields to last message (safe in single-threaded request context)
                with self.store.lock:
                    self.store.messages[-1]["group"] = group_id
                    if gmsg:
                        self.store.messages[-1]["gmsg"] = str(gmsg)[:64]
                    self.store._persist_all()
            if ok: return self._json({"ok": True})
            else:  return self._status(400, {"ok": False, "error": "invalid send"})

        # ---- Files API ----
        if parsed.path == "/api/file_init":
            actor = self.require_auth()
            if not actor:
                return
            owner = body.get("from_id", "")
            peer = body.get("to_id", "")
            size = body.get("size")
            chunks = body.get("chunks")
            if not (self._valid_uid(owner) and self._valid_uid(peer)):
                return self._status(400, {"error": "invalid from/to"})
            if actor != owner:
                return self._status(403, {"error": "forbidden"})
            try:
                size = int(size)
                chunks = int(chunks)
            except Exception:
                return self._status(400, {"error": "invalid size/chunks"})
            fid = self.store.file_init(owner, peer, size, chunks, self.MAX_FILE_SIZE, self.MAX_FILE_CHUNKS)
            if not fid:
                return self._status(400, {"error": "cannot init file (limits or users)"})
            return self._json({"file_id": fid})

        if parsed.path == "/api/file_chunk":
            actor = self.require_auth()
            if not actor:
                return
            fid = body.get("file_id", "")
            try:
                idx = int(body.get("index"))
            except Exception:
                return self._status(400, {"error": "invalid index"})
            data_b64 = body.get("data", "")
            # Only the file owner (sender) can upload chunks
            meta = self.store.file_meta(fid)
            if not meta:
                return self._status(404, {"error": "not found"})
            if meta.get("from") != actor:
                return self._status(403, {"error": "forbidden"})
            # validate base64 and size
            nbytes = self._b64_len(data_b64, max_bytes=self.MAX_CHUNK_BYTES)
            if nbytes is None:
                return self._status(400, {"error": "invalid data"})
            ok, msg = self.store.file_chunk(fid, idx, base64.b64decode(data_b64), self.MAX_CHUNK_BYTES)
            if ok:
                return self._json({"ok": True, "received": self.store.file_meta(fid).get("received")})
            else:
                return self._status(400, {"ok": False, "error": msg})

        if parsed.path == "/api/file_finish":
            actor = self.require_auth()
            if not actor:
                return
            fid = body.get("file_id", "")
            meta = self.store.file_meta(fid)
            if not meta:
                return self._status(404, {"error": "not found"})
            if meta.get("from") != actor:
                return self._status(403, {"error": "forbidden"})
            if not self.store.file_finish(fid):
                return self._status(400, {"error": "incomplete"})
            return self._json({"ok": True})

        # ---- Groups API ----
        if parsed.path == "/api/group_create":
            actor = self.require_auth()
            if not actor:
                return
            owner = body.get("owner_id", "")
            name = (body.get("name") or "Group").strip()
            if not self._valid_uid(owner) or owner != actor:
                return self._status(403, {"error": "forbidden"})
            gid = self.store.create_group(owner, name[:100])
            if not gid:
                return self._status(400, {"error": "cannot create group"})
            return self._json({"group_id": gid})

        if parsed.path == "/api/group_join":
            actor = self.require_auth()
            if not actor:
                return
            uid = body.get("user_id", "")
            gid = body.get("group_id", "")
            if not (self._valid_uid(uid) and uid == actor):
                return self._status(403, {"error": "forbidden"})
            ok = self.store.group_join(gid, uid)
            if not ok:
                return self._status(400, {"error": "cannot join"})
            return self._json({"ok": True})

        if parsed.path == "/api/group_rename":
            actor = self.require_auth()
            if not actor:
                return
            gid = body.get("group_id", "")
            name = (body.get("name") or "Group").strip()
            ok = self.store.group_rename(gid, actor, name[:100])
            if not ok:
                return self._status(403, {"error": "forbidden or not found"})
            return self._json({"ok": True})

        if parsed.path == "/api/group_leave":
            actor = self.require_auth()
            if not actor:
                return
            gid = body.get("group_id", "")
            ok = self.store.group_leave(gid, actor)
            if not ok:
                return self._status(400, {"error": "cannot leave (owner or not member)"})
            return self._json({"ok": True})

        if parsed.path == "/api/group_remove":
            actor = self.require_auth()
            if not actor:
                return
            gid = body.get("group_id", "")
            member = body.get("member_id", "")
            ok = self.store.group_remove(gid, actor, member)
            if not ok:
                return self._status(403, {"error": "forbidden or not found"})
            return self._json({"ok": True})

        return self._status(404, {"error": "not found"})

    # Helpers
    def _json(self, obj, code=200):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def _status(self, code, obj=None):
        if obj is None: obj = {"ok": False}
        self._json(obj, code=code)

    def _longpoll_thread(self, uid, pid, since_iso, since_id, timeout_s=25, interval=0.5):
        t0 = time.time()
        msgs = self.store.thread(uid, pid, since_iso=since_iso, since_id=since_id)
        if msgs: return msgs
        while time.time() - t0 < timeout_s:
            time.sleep(interval)
            msgs = self.store.thread(uid, pid, since_iso=since_iso, since_id=since_id)
            if msgs: return msgs
        return []

# ---------------------------
# Tor setup & HTTP server
# ---------------------------
def launch_tor(tor_bin: str, workdir: Path, service_port_local: int, hs_port: int = 80):
    datadir = workdir / "tor-data"
    hsdir = workdir / "hidden-service"
    datadir.mkdir(parents=True, exist_ok=True)
    hsdir.mkdir(parents=True, exist_ok=True)

    torrc = (
        f"DataDirectory {datadir.as_posix()}\n"
        f"HiddenServiceDir {hsdir.as_posix()}\n"
        f"HiddenServicePort {hs_port} 127.0.0.1:{service_port_local}\n"
        f"SOCKSPort 0\n"
        f"Log notice file { (workdir / 'tor.log').as_posix() }\n"
    )
    torrc_path = workdir / "torrc"
    torrc_path.write_text(torrc, encoding="utf-8")

    proc = subprocess.Popen(
        [tor_bin, "-f", str(torrc_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(workdir),
        text=True,
        bufsize=1
    )
    return proc, hsdir

def wait_for_hostname(hsdir: Path, timeout=120):
    hostname_file = hsdir / "hostname"
    start = time.time()
    while time.time() - start < timeout:
        if hostname_file.exists():
            onion = hostname_file.read_text(encoding="utf-8").strip()
            if onion:
                return onion
        time.sleep(0.25)
    return None

def run_http(docroot: Path, port: int, store: Store):
    class ThreadingHTTPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    def factory(*args, **kwargs):
        h = Handler
        h.directory = str(docroot)
        return h(*args, store=store, **kwargs)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), factory)
    return httpd

# ---------------------------
# Main
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Tor-hosted DM (E2EE+sign) with bearer auth & replay drop.")
    parser.add_argument("--docroot", type=str, default="site", help="Static folder to serve (default: ./site)")
    parser.add_argument("--port", type=int, default=8000, help="Local HTTP port (default: 8000)")
    parser.add_argument("--workdir", type=str, default=".tor_site_runtime", help="Working dir for Tor and data")
    args = parser.parse_args()

    tor_bin = find_tor_binary()
    if not tor_bin:
        print("ERROR: Tor binary not found in PATH. Install Tor (Expert Bundle on Windows).")
        sys.exit(1)

    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    data_dir = workdir / "app-data"
    store = Store(data_dir)

    docroot = Path(args.docroot).resolve()
    docroot.mkdir(parents=True, exist_ok=True)

    index_path = docroot / "index.html"
    if not index_path.exists():
        index_path.write_text("<!doctype html><meta charset='utf-8'><title>Onion DM</title><p>Upload site/index.html</p>", encoding="utf-8")

    try:
        httpd = run_http(docroot, args.port, store)
    except OSError as e:
        print(f"ERROR: Could not start HTTP server on 127.0.0.1:{args.port}: {e}")
        sys.exit(1)

    print(f"[HTTP] Serving {docroot} on http://127.0.0.1:{args.port} ...")

    tor_proc, hsdir = launch_tor(tor_bin, workdir, args.port, hs_port=80)
    print("[Tor] Launching Tor and creating Hidden Service...")

    try:
        onion = wait_for_hostname(hsdir, timeout=120)
        if not onion:
            print("ERROR: Timed out waiting for Tor to create the hidden service.")
            tor_proc.terminate()
            httpd.server_close()
            sys.exit(1)

        print("\n===============================================")
        print("  Onion DM is live!")
        print(f"  Address: http://{onion}")
        print("===============================================")
        print("Press Ctrl+C to stop.")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    finally:
        print("\nShutting down...")
        try:
            httpd.server_close()
        except Exception:
            pass
        if tor_proc and tor_proc.poll() is None:
            tor_proc.terminate()
            try:
                tor_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tor_proc.kill()

if __name__ == "__main__":
    main()
