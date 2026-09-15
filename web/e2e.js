// Browser side of the Pico2KVM E2E channel (WebCrypto only; works in the
// browser and in Node >= 20 via globalThis.crypto.subtle — no Buffer).
//
//   session key: HKDF-SHA256(ECDH-P256 X-coord, salt=32*0,
//                            info="pico2kvm-e2e-v1") -> AES-256-GCM
//   frame:       [0x02][seq u32 LE][ciphertext][GCM tag 16]
//   nonce:       [dir][0 x7][seq u32 LE]; dir 0 = browser->device,
//                1 = device->browser.

const te = new TextEncoder();
const HKDF_INFO = te.encode('pico2kvm-e2e-v1');
const HKDF_SALT = new Uint8Array(32); // all zeros, per spec

export function bytesToHex(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(s) {
  if (typeof s !== 'string' || s.length % 2 || !/^[0-9a-fA-F]+$/.test(s))
    return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export async function fingerprintHex(pubBytes) {
  const d = await crypto.subtle.digest('SHA-256', pubBytes);
  return bytesToHex(new Uint8Array(d));
}

export function fpShort(fpHex) {
  return fpHex
    .slice(0, 16)
    .replace(/(.{4})/g, '$1 ')
    .trim();
}

// 16-byte random nonce for key-req, as 32 hex chars.
export function randomNonceHex() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}

// Verify the device's hello signature: ECDSA-SHA256 over
// nonce_bytes || epub_bytes, raw r||s (64 bytes), key = static pubkey.
// WebCrypto hashes the message internally, matching the device's
// SHA256(nonce || epub).
export async function verifyDeviceSig(spubHex, nonceHex, epubHex, sigHex) {
  const spub = hexToBytes(spubHex);
  const nonce = hexToBytes(nonceHex);
  const epub = hexToBytes(epubHex);
  const sig = hexToBytes(sigHex);
  if (!spub || spub.length !== 65 || spub[0] !== 0x04) return false;
  if (!nonce || nonce.length !== 16) return false;
  if (!epub || epub.length !== 65 || epub[0] !== 0x04) return false;
  if (!sig || sig.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      spub,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const msg = new Uint8Array(nonce.length + epub.length);
    msg.set(nonce, 0);
    msg.set(epub, nonce.length);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sig,
      msg,
    );
  } catch {
    return false;
  }
}

function makeNonce(dir, seq) {
  const n = new Uint8Array(12);
  n[0] = dir & 1;
  new DataView(n.buffer).setUint32(8, seq >>> 0, true);
  return n;
}

export class E2ESession {
  // rxDir: direction byte of frames this side decrypts (browser receives
  // dir=1 from the device).
  constructor(rxDir = 1) {
    this.rxDir = rxDir;
    this.txSeq = [0, 0];
    this.rxSeen = false;
    this.rxSeqMax = 0;
    this.aesKey = null;
  }

  static async create(rxDir = 1) {
    const s = new E2ESession(rxDir);
    s.kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );
    s.publicKeyRaw = new Uint8Array(
      await crypto.subtle.exportKey('raw', s.kp.publicKey),
    ); // 65 bytes, 0x04||X||Y
    return s;
  }

  publicKeyHex() {
    return bytesToHex(this.publicKeyRaw);
  }

  // devEpubHex: the device's EPHEMERAL public key from the signed hello
  // (forward secrecy) — not the long-term static key.
  async deriveSession(devEpubHex) {
    const devPub = hexToBytes(devEpubHex);
    if (!devPub || devPub.length !== 65 || devPub[0] !== 0x04)
      throw new Error('invalid device ephemeral public key');
    const peerKey = await crypto.subtle.importKey(
      'raw',
      devPub,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    const shared = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerKey },
      this.kp.privateKey,
      256,
    );
    const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, [
      'deriveKey',
    ]);
    this.aesKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: HKDF_INFO },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    this.txSeq = [0, 0];
    this.rxSeen = false;
    this.rxSeqMax = 0;
  }

  get ready() {
    return this.aesKey !== null;
  }

  async encrypt(dir, plaintext) {
    if (!this.aesKey) return null;
    dir &= 1;
    const seq = this.txSeq[dir]++;
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: makeNonce(dir, seq) },
        this.aesKey,
        plaintext,
      ),
    ); // ct || tag
    const out = new Uint8Array(5 + ct.length);
    out[0] = 0x02;
    new DataView(out.buffer).setUint32(1, seq, true);
    out.set(ct, 5);
    return out;
  }

  // Returns {seq, plaintext} or null (replay, bad tag, malformed).
  async decrypt(frame) {
    if (!this.aesKey || !frame || frame.length < 21 || frame[0] !== 0x02)
      return null;
    const f = frame instanceof Uint8Array ? frame : new Uint8Array(frame);
    const seq = new DataView(f.buffer, f.byteOffset + 1, 4).getUint32(0, true);
    if (this.rxSeen && seq <= this.rxSeqMax) return null; // replay
    let pt;
    try {
      pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: makeNonce(this.rxDir, seq) },
        this.aesKey,
        f.subarray(5),
      );
    } catch {
      return null; // tag mismatch
    }
    this.rxSeen = true;
    this.rxSeqMax = seq;
    return { seq, plaintext: new Uint8Array(pt) };
  }
}
