#pragma once

/* Browser<->device end-to-end encryption (ECDH P-256 + HKDF-SHA256 +
 * AES-256-GCM) layered on top of the WebSocket relay. The relay only ever
 * sees ciphertext.
 *
 * Threading note: after e2e_init() (called once from the main loop via
 * ws_client_init), EVERY function in this module is invoked only from
 * lwIP/altcp callbacks (async_context, single-threaded) through
 * ws_handle_frame(). In particular the shared ctr_drbg context is never
 * touched from the main loop, so no locking is required. */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Load the static device key and seed the DRBG. Call once at startup.
 * The static key is used ONLY for ECDSA signing of the handshake; the
 * session key is derived from a fresh ephemeral ECDH key per handshake
 * (forward secrecy). */
void e2e_init(void);

/* Copy the most recently built "hello" handshake JSON (the response to a
 * key-req) into buf. Returns the length, or 0 if no hello is pending or
 * it does not fit. */
size_t e2e_take_hello(char *buf, size_t cap);

/* Handle an inbound WS text frame.
 * For {"type":"key-req","nonce":"<32 hex>"}: generates a fresh ephemeral
 * ECDH key, signs SHA256(nonce||epub) with the static key, builds the
 * hello JSON and returns E2E_ACT_HELLO — the caller should then send
 * e2e_take_hello(). For {"type":"key","pub":"..."}: runs ephemeral
 * ECDH+HKDF; every successful (re)keying returns E2E_ACT_READY and the
 * caller should send the encrypted "ready" — including re-keys on an
 * already-ready session, since the browser expects a fresh confirmation
 * each handshake. */
enum { E2E_ACT_NONE = 0, E2E_ACT_HELLO = 1, E2E_ACT_READY = 2 };
int e2e_handle_text(const uint8_t *msg, size_t len);

bool e2e_ready(void);

/* Drop the session: ready=false, sequence numbers reset. Call whenever the
 * WS connection goes down. */
void e2e_reset(void);

/* Build an encrypted frame: [0x02][seq u32 LE][ciphertext][GCM tag 16].
 * dir: 0 = browser->device, 1 = device->browser (direction is encoded in
 * the nonce, not the key). Returns the frame length, 0 on failure. */
size_t e2e_encrypt(uint8_t dir, const uint8_t *pt, size_t ptlen,
                   uint8_t *out, size_t cap);

/* Decrypt a browser->device frame and extract the 8-byte HID report
 * ([0x01][modifier][k1..k6]). Returns 1 on success. Replays
 * (seq <= last good seq) and tag failures are rejected. */
int e2e_decrypt_report(const uint8_t *frame, size_t len,
                       uint8_t *modifier, uint8_t keys[6]);
