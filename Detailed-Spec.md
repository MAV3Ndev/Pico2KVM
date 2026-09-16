# Pico2KVM — Detailed Communication Specification

[日本語版](Detailed-Spec.ja.md)

This document describes exactly how bytes flow between the browser, the
Cloudflare Worker, and the RP2350 device — including authentication,
framing, the E2E handshake, retry behaviour, and every timer/constant.

We start with a glossary and an end-to-end walkthrough, then go into the
per-layer details.

## Glossary

| Term | Meaning |
|---|---|
| USB HID | The standard that lets a device present itself as a keyboard/mouse. Works with built-in OS drivers — nothing to install on the target PC |
| HID report | The 8-byte payload describing which keys are held (modifiers + up to 6 keys). The PC treats it as real keyboard input |
| WebSocket / WSS | A persistent bidirectional connection that starts as HTTP. WSS = WebSocket over TLS |
| TLS | Encrypts the transport itself (the "S" in HTTPS) and authenticates the server via its certificate |
| CA pinning | Hardcoding which certificate authority (CA) must have issued the server cert; wrong/forged certs get rejected |
| Durable Object (DO) | Cloudflare's "stateful Worker": exactly one instance per ID. Used here as the relay between the two sockets |
| NAT | Lets devices inside a network reach out, but blocks unsolicited inbound connections — the reason the device dials out |
| E2E encryption | Only the two endpoints (browser and device) can read the payload. The Worker relay sees ciphertext only |
| Static / ephemeral key | Static = long-term "identity card" key. Ephemeral = generated per connection and thrown away |
| ECDH | Both sides exchange only public keys and independently derive the same shared secret |
| ECDSA | Sign with a private key, verify with the public key — used to prove possession of the static key |
| HKDF | Turns a shared secret into a proper cipher key; salt/info separate different key uses |
| AES-256-GCM | Encryption with built-in tamper detection. Reusing a nonce breaks it, so nonces are derived from a counter |
| nonce | A "number used once". Here, a random value that prevents handshake replay |
| seq (sequence number) | Per-message counter; lets the receiver detect replayed frames |
| Fingerprint | A hash of a public key, short enough for humans to compare visually |
| TOFU | Trust On First Use: trust the fingerprint seen the first time, warn if it ever changes (same idea as SSH) |
| Forward secrecy | Even if a private key leaks later, past sessions cannot be decrypted |
| PBKDF2 | Deliberately slow password hashing (many iterations) to make brute force expensive |
| TOTP | The 6-digit code from an authenticator app that changes every 30 s; the second login factor |
| MITM | Man-in-the-middle attack: intercepting or modifying traffic between the endpoints |

## Communication flow (step by step)

The full path of a single keystroke, from power-on to the target PC.

### A. Device boot → online

1. Pico 2 W powers up → connects to Wi-Fi (retries every 10 s on
   failure). LED: off → blinking
2. Resolves `SERVER_HOST` via DNS → TCP 443 → TLS handshake. The
   certificate is checked against the embedded GTS Root R4; abort on
   mismatch
3. Sends a WS upgrade request `GET /device/default` with
   `Authorization: Bearer <DEVICE_TOKEN>`
4. The Worker checks the token → hands the socket to the Durable Object →
   registered as the "device" role. LED solid = online

### B. Browser login → E2E established

5. Open the URL, log in with password + TOTP → receive the `session`
   cookie
6. Press "connect" → browser opens `wss://…/device/default` → the DO
   registers it as the "browser" role and reports device presence via a
   `peer` message
7. Browser sends `key-req` with a 16-byte random nonce
8. Device generates a throwaway ephemeral key pair and replies `hello`
   with static pubkey + ephemeral pubkey + signature
9. Browser checks the static-key fingerprint against the pinned value
   (visual confirm on first connect) + verifies the signature → sends its
   own ephemeral pubkey as `key`
10. Both sides run ECDH → HKDF (pairing code as salt) → arrive at the
    same AES-256-GCM key
11. Device sends an encrypted `ready` → if the browser can decrypt it,
    "E2E connected". Failure = wrong pairing code or an impostor

### C. Keystroke (repeats)

12. User presses a key → browser maps `KeyboardEvent.code` to a HID usage
    and builds the 8-byte report
13. Encrypts with AES-256-GCM + seq → WS binary frame → Worker/DO
    forwards it **without seeing the contents**
14. Device checks seq (drops stale numbers) → decrypts →
    `tud_hid_keyboard_report()` → the target PC receives ordinary USB
    keyboard input

### D. Disconnect / reconnect

15. If the WS drops, the device queues an all-keys-up report (prevents
    stuck keys), wipes all E2E state, and returns to step 2 after backoff
16. When the DO tells the browser the device rejoined, the browser drops
    the old session and restarts the handshake from step 7

## 1. Topology

```
┌──────────┐   HTTPS/WSS    ┌────────────────────────┐   WSS (device-initiated)  ┌─────────┐   USB HID   ┌────────┐
│ Browser  │ ◄────────────► │ Worker → DeviceSession │ ◄───────────────────────► │ RP2350  │ ──────────► │ Target │
└──────────┘                │ Durable Object (relay) │                            │ board   │   keyboard  │   PC   │
                            └────────────────────────┘                            └─────────┘             └────────┘
```

- The **device** always dials out: Wi-Fi STA → DNS → TCP 443 → TLS → WS
  upgrade. No inbound listener exists; NAT/firewall friendly.
- The **browser** connects to the same Worker origin over WSS.
- The **Durable Object** named by `/device/:id` is a dumb byte pipe between
  at most one device socket and one browser socket.
- There are **two independent layers of cryptography**:
  1. TLS on both WebSocket hops (device↔Worker is pinned to GTS Root R4).
  2. E2E encryption *inside* the WebSocket payloads, so the relay and any
     on-path observer only ever see ciphertext.

## 2. HTTP layer (Worker)

`worker/src/index.ts` handles:

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `GET /api/setup` | GET | none | `{configured: bool}` |
| `POST /api/setup` | POST | first-run only; `SETUP_TOKEN` secret if configured | creates account row; returns TOTP secret + otpauth URI; 409 on race |
| `POST /api/login` | POST | password + TOTP | sets `session` cookie |
| `POST /api/logout` | POST | — | clears cookie |
| `GET /api/status` | GET | none | `{ok, configured}` |
| `/device/:id` | GET (Upgrade) | device: `Authorization: Bearer <DEVICE_TOKEN>`; browser: `session` cookie | forwards to DO |
| everything else | GET | none | static assets (run through the Worker for security headers) |

### Login security

- Passwords stored as `pbkdf2$<iters>$<salt_hex>$<hash_hex>`
  (PBKDF2-SHA-256, 100 000 iterations — the Workers WebCrypto maximum —
  16-byte salt, 256-bit output). Legacy bare-SHA-256 rows are verified once
  and transparently re-written in PBKDF2 form on the next successful login.
- Rate limit: at most 10 failed attempts per client IP
  (`cf-connecting-ip`) per rolling 10-minute window (`login_attempt`
  table); further attempts return 429. A successful login clears that
  IP's rows.
- Session token: `<exp_ms>.<HMAC-SHA256(exp)>` signed with
  `SESSION_SECRET`, cookie flags `Secure; HttpOnly; SameSite=Strict`,
  8 h lifetime. Tokens are also recorded in the D1 `session` table at
  login and verified against it, so `/api/logout` (or deleting the row)
  actually revokes the session.
- Security headers on every response except 101 upgrades:
  `Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`,
  `Permissions-Policy`.

## 3. WebSocket hop: browser ↔ Worker ↔ device

### 3.1 Device connect (firmware `ws_client.c`)

```
GET /device/<id> HTTP/1.1
Host: <server>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <b64 16B>
Sec-WebSocket-Version: 13
Authorization: Bearer <DEVICE_TOKEN>
User-Agent: pico2kvm
```

- TLS first: `altcp_tls` + mbedTLS, `VERIFY_REQUIRED`, SNI = `SERVER_HOST`,
  chain pinned to embedded `gtsr4.pem` (GTS Root R4 — the CA that issues
  `*.workers.dev`). Cert validity is checked against
  `BUILD_EPOCH + uptime` (the board has no RTC).
- The response is validated on the status line (`HTTP/1.1 101`) **and**
  the `Sec-WebSocket-Accept` value must match
  `base64(SHA1(sent key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`;
  anything else is rejected. Headers are consumed up to `\r\n\r\n`
  (max 2048 bytes pending buffer).
- Client→server frames are masked per RFC 6455 (xorshift32 PRNG mask).
- Server→client frames are unmasked by the firmware before dispatch.

### 3.2 Browser connect

`new WebSocket("wss://<host>/device/default")` — the session cookie rides
along automatically. No extra headers are possible in the browser WS API,
which is why the device role uses `Authorization` but the browser relies
on the cookie.

### 3.3 Durable Object relay (`DeviceSession`)

- Role comes in on the internal `X-Pico2KVM-Role` header set by the Worker.
- One socket per role. A new connection of the same role **replaces** the
  old one (old socket closed, code 1000 "replaced").
- On browser connect the DO sends `{"type":"peer","device":<bool>}`;
  when the device socket connects/disconnects all browsers get
  `{"type":"peer","device":true|false}`.
- Message forwarding: every frame from one socket is forwarded verbatim to
  the other side. `Blob`/`ArrayBufferView` are normalised to
  `ArrayBuffer` first (Cloudflare delivers binary as `Blob`; sending it
  raw would stringify to `"[object Blob]"`).
- Frames larger than `MAX_FRAME = 16384` bytes close the sender's socket
  (1009). No content inspection — the DO never sees plaintext.

## 4. E2E handshake

All handshake messages are plaintext WS **text** frames relayed through
the DO. Sequencing on the browser side (`web/app.js`):

```
browser ──WS open──► sends {"type":"key-req","nonce":"<32 hex>"}   (16 random bytes)
device  ──text────►  {"type":"hello","fw":"pico2kvm",
                      "spub":"<130 hex>",      // static P-256 pubkey, 0x04||X||Y
                      "epub":"<130 hex>",      // fresh ephemeral pubkey
                      "sig":"<128 hex>"}       // ECDSA r||s
                       sig = ECDSA-SHA256(static_priv, SHA256(nonce_bytes || epub_bytes))
browser: 1. fingerprint = SHA256(spub) → compare with pinned localStorage
         2. verify sig with spub  (proves possession of static key)
         3. first connect: show fingerprint, wait for user confirm (TOFU)
         4. derive session key, then
            ──text──► {"type":"key","pub":"<130 hex browser ephemeral>"}
device:   ECDH(eph_d, browser_pub) → HKDF → AES-256-GCM key
          ──binary──► E2E frame of {"type":"ready"}
browser:  decrypts ready → "E2E 接続済み" (5 s timeout otherwise)

Whenever the DO reports the device (re)joining ({"type":"peer",
"device":true}) and no key-req is in flight, the browser drops its session
state and sends a fresh key-req — the device resets its E2E state on every
reconnect, so the old session key is gone.
```

Key points:

- **Static key = identity only.** It signs; it never encrypts. Generated
  once at firmware configure time into `device_key.h` (git-ignored).
- **Forward secrecy**: the ECDH shared secret uses ephemeral keys on both
  sides. The device regenerates its ephemeral pair on every `key-req` and
  zeroises it on disconnect/re-key.
- **The nonce is mandatory and binds the signature to this handshake**, so
  a replayed hello cannot satisfy a fresh `key-req`. A `key-req` without a
  valid 16-byte hex nonce is ignored.
- **Pairing code (required)**: the firmware must be built with
  `-DPAIRING_CODE` (CMake fails without it, and `e2e_init` fails closed at
  runtime). `e2e_salt = SHA256(UTF8(code))`; the browser derives the same
  salt from the input field. This is what authenticates the *browser* side:
  a peer that does not know the code derives a different key, so every
  frame it sends fails GCM authentication. Without it a stolen session
  cookie would suffice to inject keystrokes. Choose a high-entropy code.
- **TOFU pin**: `SHA256(spub)` is stored under `pico2kvm-fp-default` in
  localStorage after explicit user confirmation; any later mismatch aborts
  before ECDH.

### Session key derivation

```
shared = ECDH(ephemeral pairs) .X coordinate   (32 bytes)
key    = HKDF-SHA256(ikm=shared, salt=SHA256(pairing code), info="pico2kvm-e2e-v1", 32)
cipher = AES-256-GCM
```

## 5. E2E data frames

WS **binary** frames. Wire format:

```
[0x02][seq: u32 LE][ciphertext][GCM tag: 16 B]
   0        1..4          5..        last 16
```

- `seq` is a per-direction monotonic counter starting at 0 after every
  handshake (both sides reset `txSeq`/`rxSeqMax` on re-key).
- **Nonce (12 B)**: `[dir][7 zero bytes][seq u32 LE]`;
  `dir` 0 = browser→device, 1 = device→browser. Direction separation means
  the two sides can never reuse a nonce.
- **Replay rejection**: `seq <= last *authenticated* seq` is dropped before
  decryption (the window only advances on a valid GCM tag).
  (Strictly increasing; there is no reordering window — TCP guarantees
  order anyway.)
- **Downgrade prevention**: the device only accepts binary frames starting
  with `0x02` of exactly `21 + 8` bytes; a hypothetical plaintext `0x01`
  report is silently dropped.
- Inner plaintext, browser→device: 8-byte HID keyboard report
  `[0x01][modifier bitmap][key1..key6]` (boot-protocol format).
  Device→browser is reserved (currently only `{"type":"ready"}` JSON).

## 6. Firmware state machines

### 6.1 Wi-Fi (`main.c`)

- `cyw43_arch_wifi_connect_async` retried every **10 s** while link down
  (checked every 1 s).
- Watchdog 8 s; main loop feeds it every iteration.

### 6.2 WebSocket client (`ws_client.c`)

```
WS_IDLE ──link up──► WS_DNS ──► WS_CONNECTING ──► WS_HANDSHAKE ──101──► WS_OPEN
   ▲                                                                          │
   └────────────── WS_BACKOFF ◄── any error/timeout/close ◄────────────────────┘
```

Timers:

| Constant | Value | Meaning |
|---|---|---|
| `WS_PING_MS` | 20 000 | client pings every 20 s while open |
| `WS_RX_TIMEOUT_MS` | 60 000 | no inbound byte ⇒ reconnect |
| `WS_HS_TIMEOUT_MS` | 15 000 | upgrade must finish |
| `WS_BACKOFF_INIT_MS` | 2 000 | first retry delay |
| `WS_BACKOFF_MAX_MS` | 30 000 | doubling cap |

- On every transition to `WS_BACKOFF`: `e2e_reset()` (ephemeral key
  destroyed, sequence counters cleared — next browser must re-handshake)
  and an all-keys-up report is queued so the target PC never sees a stuck
  key.
- Received reports go through a 16-entry SPSC ring (callback → main loop);
  a full ring drops the newest report.
- Oversized inbound WS payloads are skipped via `ws_skip_len` rather than
  buffered (pending buffer is 2 KiB).

### 6.3 USB HID (`main.c`)

- `tud_hid_keyboard_report(0, modifier, keys)` for each popped report,
  whenever `tud_hid_ready()`.
- LED: **off** = no Wi-Fi link · **blinking 500 ms** = Wi-Fi up, WS not
  open · **solid** = WS open.

## 7. Browser send path (`web/app.js`)

- Physical-position mapping: `KeyboardEvent.code` → HID usage (US layout
  + JIS `IntlRo`/`IntlYen`/`Convert`/…). Modifier bits tracked separately;
  each state change emits one complete report.
- Sends are serialised through a promise chain (`queueSend`) so `seq`
  numbers and wire order always match.
- `blur` / WS close → `releaseAll()` (empty report) to clear held keys.
- Text paste types each ASCII char as press+release with 20 ms gaps.
- Buttons: Enter/Backspace/Tab/Esc/Ctrl+Alt+Del/Win via `sendRaw`.

## 8. Failure modes worth knowing

| Symptom | Cause |
|---|---|
| `E2E 確立失敗` | wrong/missing pairing code, or `ready` not decrypted within 5 s |
| `フィンガープリント不一致!` | device static key changed or MITM — aborts before key exchange |
| `ファームウェアが古い` | hello lacks `epub`/`sig` (pre-FS firmware) |
| keys stuck on target | can't happen while firmware runs: every WS teardown queues release-all; only a hard power loss mid-press could leave a key down |
| TLS failure after years | embedded `BUILD_EPOCH` too old for the cert validity window — rebuild & reflash |
| 429 on login | >10 failures in 10 min |
