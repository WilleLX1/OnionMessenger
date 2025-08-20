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
        "pub": "<RSA-SPKI-b64>",     # encryption public key (RSA-OAEP)
        "sign": { "alg": "Ed25519"|"ECDSA-P256", "pub": "<b64>" }  # signing pubkey
      }
    }

    messages: [
      {
        "id":1,"from":"A","to":"B","ts":"...",
        "ct":"<b64>","iv":"<b64>","ek_to":"<b64>","ek_from":"<b64>",
        "sig":"<b64>","sig_alg":"Ed25519"|"ECDSA-P256",
        "nonce":"<b64>","client_ts":"..."
      }, ...
    ]
    """
    def __init__(self, datadir: Path):
        self.lock = threading.RLock()
        self.datadir = datadir
        self.users_path = datadir / "users.json"
        self.contacts_path = datadir / "contacts.json"
        self.messages_path = datadir / "messages.json"
        datadir.mkdir(parents=True, exist_ok=True)

        self.users = load_json(self.users_path, {})
        self.contacts = load_json(self.contacts_path, {})
        self.messages = load_json(self.messages_path, [])

        if self.messages:
            self.next_id = 1 + max(int(m.get("id", 0)) for m in self.messages)
        else:
            self.next_id = 1

    def persist(self):
        with self.lock:
            save_json(self.users_path, self.users)
            save_json(self.contacts_path, self.contacts)
            save_json(self.messages_path, self.messages)

    # ---- users
    def gen_id(self, n=14):
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        import secrets
        return "".join(secrets.choice(alphabet) for _ in range(n))

    def signup(self, pub=None, sign=None):
        with self.lock:
            while True:
                uid = self.gen_id()
                if uid not in self.users:
                    break
            self.users[uid] = {"created_at": now_iso(), "pub": pub, "sign": sign}
            self.persist()
            return uid

    def get_user_keys(self, uid):
        with self.lock:
            u = self.users.get(uid)
            if not u:
                return None
            return {"pub": u.get("pub"), "sign": u.get("sign")}

    def valid_user(self, uid):
        with self.lock:
            return uid in self.users

    # ---- contacts
    def add_contact(self, owner, contact):
        with self.lock:
            if owner not in self.users or contact not in self.users:
                return False
            lst = self.contacts.get(owner, [])
            if contact not in lst:
                lst.append(contact)
            self.contacts[owner] = lst
            self.persist()
            return True

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
            self.persist()
            return True

    def thread(self, a, b, since_iso=None, since_id=None, limit=200):
        with self.lock:
            out = []
            for m in self.messages:
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

# ---------------------------
# HTTP Handler (API + static)
# ---------------------------
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, store: Store = None, **kwargs):
        self.store = store
        super().__init__(*args, directory=str(self.directory), **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/contacts":
            qs = urllib.parse.parse_qs(parsed.query)
            uid = (qs.get("user_id") or [""])[0]
            contacts = self.store.get_contacts(uid) if self.store.valid_user(uid) else []
            return self._json({"contacts": contacts})

        if path in ("/api/thread", "/api/thread_lp"):
            qs = urllib.parse.parse_qs(parsed.query)
            uid = (qs.get("user_id") or [""])[0]
            pid = (qs.get("peer_id") or [""])[0]
            since = (qs.get("since") or [None])[0]
            since_id = (qs.get("since_id") or [None])[0]
            since_id = int(since_id) if since_id not in (None, "", []) else None
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
            keys = self.store.get_user_keys(uid)
            if keys and keys.get("pub"):
                return self._json({"pub": keys["pub"], "sign": keys.get("sign")})
            else:
                return self._status(404, {"error": "not found"})

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
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            body = {}

        if parsed.path == "/api/signup":
            pub = body.get("pub") or body.get("pub_spki") or body.get("public_key")
            sign = body.get("sign")  # {"alg": "...", "pub": "..."} (b64)
            uid = self.store.signup(pub=pub, sign=sign)
            return self._json({"id": uid})

        if parsed.path == "/api/add_contact":
            owner = body.get("owner_id", "")
            contact = body.get("contact_id", "")
            ok = self.store.add_contact(owner, contact)
            if ok: return self._json({"ok": True})
            else:  return self._status(400, {"ok": False, "error": "invalid owner/contact"})

        if parsed.path == "/api/send":
            frm = body.get("from_id", "")
            to = body.get("to_id", "")
            ct = body.get("ciphertext", "")
            iv = body.get("iv", "")
            ek_to = body.get("ek_to", "")
            ek_from = body.get("ek_from", "")
            sig = body.get("sig", "")
            sig_alg = body.get("sig_alg", "")
            nonce = body.get("nonce", "")
            client_ts = body.get("client_ts", "")
            ok = self.store.send(frm, to, ct, iv, ek_to, ek_from, sig, sig_alg, nonce, client_ts)
            if ok: return self._json({"ok": True})
            else:  return self._status(400, {"ok": False, "error": "invalid send"})

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
    parser = argparse.ArgumentParser(description="Tor-hosted DM (E2EE+sign): IDs, pubkeys, encrypted+signed messaging with long-poll.")
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
