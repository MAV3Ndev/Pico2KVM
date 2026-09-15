# Pico2KVM

[日本語](README.ja.md) · [Detailed communication spec](Detailed-Spec.md) ([日本語](Detailed-Spec.ja.md))

A minimal remote KVM (keyboard-only) built on a **Raspberry Pi Zero 2 W-class
RP2350 board** (Pico 2 W-compatible firmware; the name comes from the Pi Zero
2 W form factor the project actually runs on).

Type in a web page → keystrokes travel over TLS → Cloudflare Worker (Durable
Object relay) → the board → it acts as a USB HID keyboard on the target
machine. The whole path is additionally protected by **end-to-end encryption
with forward secrecy**, so the relay (or anyone on the path) only ever sees
ciphertext.

```
┌──────────┐  WSS + E2EE   ┌───────────────────────┐  WSS + E2EE  ┌───────────┐   USB HID   ┌────────┐
│ Browser  │ ◄───────────► │ Cloudflare Worker (DO)│ ◄──────────► │ Zero 2 W  │ ──────────► │ Target │
└──────────┘               └───────────────────────┘              └───────────┘             └────────┘
```

## Features

- **E2EE with forward secrecy**: every session uses ephemeral–ephemeral ECDH
  (P-256) → HKDF-SHA256 → AES-256-GCM. The device's long-term key is used only
  to *sign* the handshake; leaking it later cannot decrypt past sessions.
- **MITM detection**: the browser pins the device key fingerprint (TOFU). On
  first connect you compare the on-screen fingerprint against
  `firmware/device_fingerprint.txt`; any mismatch aborts the connection.
- **Replay protection**: per-direction monotonic sequence numbers inside every
  AEAD frame.
- **Device-side TLS verification**: the firmware pins Google Trust Services
  Root R4 (`firmware/gtsr4.pem`), the CA that issues `*.workers.dev` certs —
  full chain + hostname verification (`VERIFY_REQUIRED`).
- **Optional pairing code**: when `-DPAIRING_CODE=...` is set at firmware
  configure time, it is mixed into the HKDF salt — a stolen session cookie
  alone can no longer complete the E2E handshake.
- **Authenticated web UI**: PBKDF2-SHA-256 password hashing (legacy rows are
  migrated transparently), TOTP (RFC 6238), HMAC-signed session cookie,
  login rate limiting (10 tries / 10 min), and security headers (CSP,
  nosniff, DENY, …) on every response including assets.
- **Key capture**: physical-position mapping (`e.code` → HID usage, incl. JIS
  keys), modifier chord tracking, Ctrl+Alt+Del/Win buttons, ASCII text paste.
- **Self-healing firmware**: async Wi-Fi reconnect, WebSocket keepalive +
  exponential backoff, watchdog, status LED (off = no Wi-Fi, blinking = Wi-Fi
  up / relay connecting, solid = online).
- Video capture is out of scope (pair with an MS2109-class HDMI capture dongle
  on the viewing side if you need video).

## Repository layout

```
firmware/   RP2350 firmware (Pico SDK + TinyUSB + lwIP/altcp + mbedTLS)
  main.c              boot, Wi-Fi mgmt, HID ring consumption, LED, watchdog
  ws_client.c         WSS client: DNS → TLS(SNI) → WS upgrade → frame loop
  e2e.c / e2e.h       ECDH/ECDSA/HKDF/GCM handshake + frame crypto
  ws_frame.h          pure WebSocket frame parser (shared with host tests)
  gen_device_key.mjs  generates device_key.h + device_fingerprint.txt once
  gtsr4.pem           pinned trust root for workers.dev TLS verification
  test/               host-side parser test
worker/     Cloudflare Worker: auth API + Durable Object WS relay + assets
  src/index.ts        session/TOTP auth, /device/:id gate, DeviceSession DO
  schema.sql          D1 account table
  scripts/            totp.mjs, ws-test.mjs, e2e-sim.mjs, e2e-it.mjs
web/        Zero-dependency web UI (ES modules, WebCrypto only)
  app.js, e2e.js, index.html, styles.css
```

## Wire protocol

See [Detailed-Spec.md](Detailed-Spec.md) for the full specification.

Handshake (plaintext WS text frames):

```
browser → {"type":"key-req","nonce":"<32 hex>"}
device  → {"type":"hello","fw":"pico2kvm","spub":"<130 hex>",
           "epub":"<130 hex>","sig":"<128 hex r||s>"}
             sig = ECDSA-SHA256(static_priv, SHA256(nonce || epub))
browser → {"type":"key","pub":"<130 hex browser ephemeral>"}
device  → encrypted {"type":"ready"}
```

Data frames (WS binary): `[0x02][seq u32 LE][ciphertext][GCM tag 16]`

- Session key: `HKDF-SHA256(ECDH.X, salt=SHA256(pairing) or 32×0,
  info="pico2kvm-e2e-v1")`
- Nonce (12 B): `[dir][0×7][seq LE]`; dir 0 = browser→device, 1 = reverse
- Inner payload, browser→device: 8-byte HID report `[0x01][modifier][k1..k6]`

## Deploy

### Worker

```sh
cd worker
npm install
wrangler d1 create pico2kvm            # then set database_id in wrangler.toml
wrangler d1 execute pico2kvm --remote --file schema.sql
wrangler secret put DEVICE_TOKEN       # random bearer token for the device
wrangler secret put SESSION_SECRET     # random HMAC secret
wrangler deploy
```

The Worker name in `wrangler.toml`/`SERVER_HOST` is `pico2kvm`; rename it
before first deploy if you like.

### Firmware

Requirements: Pico SDK 2.x (`PICO_SDK_PATH`), CMake, Ninja, ARM GCC toolchain,
Node.js (used at configure time to generate the device key).

```sh
cmake -S firmware -B firmware/build -G Ninja \
  -DPICO_BOARD=pico2_w \
  -DWIFI_SSID=... -DWIFI_PASSWORD=... \
  -DDEVICE_TOKEN=<same as the Worker secret> \
  -DSERVER_HOST=<your-worker>.workers.dev \
  -DPAIRING_CODE=<optional>
cmake --build firmware/build
# hold BOOTSEL, plug in, copy build/pico2kvm.uf2 to the RP2350 drive
```

`device_key.h` and `device_fingerprint.txt` are generated once into
`firmware/` (both git-ignored). Delete them and rebuild to rotate the device
identity; clear the browser's `pico2kvm-fp-*` localStorage entry to re-pin.

### First run

Open `https://<your-worker>.workers.dev`, set a password, register the
displayed TOTP secret in your authenticator app, log in, press **接続**
(Connect), verify the fingerprint against `firmware/device_fingerprint.txt`,
and type.

## Tests

```sh
cd worker
npm run typecheck
node scripts/e2e-sim.mjs        # protocol-level crypto tests (pure Node)
node scripts/ws-test.mjs http://localhost:8787 <device-token> <pw> <totp-secret>
node scripts/e2e-it.mjs         # full relay + crypto against `wrangler dev`
```

## Security notes / limitations

- Device-side TLS pins **GTS Root R4** (`VERIFY_REQUIRED`). If Cloudflare
  ever re-issues `*.workers.dev` under a different root, replace
  `firmware/gtsr4.pem`, rebuild and reflash.
- TLS wraps transport; the E2E layer protects payloads end-to-end even if
  the transport were compromised.
- Session cookie lifetime is 8 h; `/api/login` is limited to 10 attempts
  per 10 minutes.
- The build epoch is embedded for certificate validity checks; reflashing
  a very old build can fail verification once the CA window no longer
  covers it — rebuild to refresh.
- Debug output goes to UART (GP0/GP1, 115200 baud).

## License

MIT — see [LICENSE](LICENSE).
