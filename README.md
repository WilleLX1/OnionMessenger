# 🧅 Onion DM

A lightweight, self-hosted **end-to-end encrypted messenger** served over a Tor hidden service.
Each user gets a random ID, which can be shared with others to add them as contacts.

---

## ✨ Features

* Anonymous messaging over the **Tor network**.
* **End-to-end encryption** with RSA-OAEP (for session keys) and ECDSA/Ed25519 (for signatures).
* **Key pinning** to detect changed/forged peer keys.
* Minimal metadata storage – server only relays encrypted blobs.
* Works fully in the browser – keys are generated client-side.

---

## 🚀 Quick Start

### 1. Install dependencies

* **Python 3.8+**
* **Tor** installed and in your PATH

  * Linux: `sudo apt install tor`
  * Windows: Install the *Tor Expert Bundle* and ensure `tor.exe` is available.

### 2. Run the server

```bash
python3 main.py --docroot site --port 8000
```

This will:

* Start an HTTP server on `127.0.0.1:8000`
* Launch Tor
* Create a hidden service (hostname is stored in `.tor_site_runtime/hidden-service/hostname`)

Once Tor finishes booting, your `.onion` URL will be displayed in the terminal.

### 3. Open in Tor Browser

Navigate to the provided `.onion` address in Tor Browser.
Sign up, copy your ID, and share it with a friend so they can add you.

---

## 🔐 Security Notes

* **All messages are encrypted client-side** using AES-GCM with ephemeral keys.
* RSA-OAEP encrypts the AES session key for both sender & recipient.
* Messages are **signed** with either ECDSA-P256 or Ed25519 to prevent forgery.
* The server:

  * Stores only ciphertext, encrypted keys, and metadata (`from`, `to`, `ts`).
  * Implements **replay protection** using signature deduplication.
  * Cannot read or modify plaintext messages.

---

## ⚠ Disclaimer

This is a research / hobby project.
Do **not** rely on it for life-critical communications — security has not been formally audited.
