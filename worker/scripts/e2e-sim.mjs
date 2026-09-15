// Protocol-level E2E simulation: emulates the firmware side with
// node:crypto and exercises the real browser-side module (web/e2e.js).
// New handshake: key-req(nonce) -> hello{spub, epub, sig=ECDSA(SHA256(
// nonce||epub))} -> key -> ephemeral ECDH + HKDF -> AES-256-GCM.
// Usage: node scripts/e2e-sim.mjs
import {
  createECDH,
  generateKeyPairSync,
  sign as cryptoSign,
  hkdfSync,
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';
import {
  E2ESession,
  fingerprintHex,
  hexToBytes,
  bytesToHex,
  verifyDeviceSig,
} from '../../web/e2e.js';

const INFO = Buffer.from('pico2kvm-e2e-v1');
const SALT = Buffer.alloc(32); // 32 zero bytes, per spec

let failures = 0;
const ok = (cond, name) => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}`);
  if (!cond) failures++;
};

const b64url = (s) => Buffer.from(s, 'base64url');
const jwkPubToRaw = (jwk) =>
  Buffer.concat([Buffer.from([4]), b64url(jwk.x), b64url(jwk.y)]);

// --- device emulation (mirrors firmware/e2e.c) ---
class DeviceSim {
  constructor() {
    // Static identity key: ECDSA signing only (forward secrecy).
    this.staticPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.spub = jwkPubToRaw(
      this.staticPair.publicKey.export({ format: 'jwk' }),
    ); // 65B 0x04||X||Y
    this.eph = null; // ephemeral ECDH, per handshake
    this.resetSession();
  }
  resetSession() {
    this.key = null;
    this.eph = null;
    this.txSeq = [0, 0];
    this.rxSeen = false;
    this.rxSeqMax = 0;
  }
  fingerprint() {
    return createHash('sha256').update(this.spub).digest('hex');
  }
  // Returns a message to send back, or null.
  handleText(msg) {
    const m = JSON.parse(msg);
    if (m.type === 'key-req') {
      this.eph = createECDH('prime256v1');
      this.eph.generateKeys();
      const epub = this.eph.getPublicKey(null, 'uncompressed');
      const nonce =
        typeof m.nonce === 'string' && /^[0-9a-f]{32}$/.test(m.nonce)
          ? Buffer.from(m.nonce, 'hex')
          : Buffer.alloc(16);
      // sig = ECDSA-SHA256(static_priv, SHA256(nonce || epub)), raw r||s.
      const sig = cryptoSign('sha256', Buffer.concat([nonce, epub]), {
        key: this.staticPair.privateKey,
        dsaEncoding: 'ieee-p1363',
      });
      return JSON.stringify({
        type: 'hello',
        fw: 'pico2kvm',
        spub: this.spub.toString('hex'),
        epub: epub.toString('hex'),
        sig: sig.toString('hex'),
      });
    }
    if (m.type === 'key' && typeof m.pub === 'string' && this.eph) {
      const shared = this.eph.computeSecret(Buffer.from(m.pub, 'hex')); // X coord, 32B
      this.key = Buffer.from(hkdfSync('sha256', shared, SALT, INFO, 32));
      this.txSeq = [0, 0];
      this.rxSeen = false;
      this.rxSeqMax = 0;
      return this.encrypt(1, Buffer.from('{"type":"ready"}'));
    }
    return null;
  }
  encrypt(dir, pt) {
    const seq = this.txSeq[dir]++;
    const nonce = Buffer.alloc(12);
    nonce[0] = dir;
    nonce.writeUInt32LE(seq, 8);
    const c = createCipheriv('aes-256-gcm', this.key, nonce);
    const ct = Buffer.concat([c.update(pt), c.final()]);
    const tag = c.getAuthTag();
    const out = Buffer.alloc(5 + ct.length + 16);
    out[0] = 0x02;
    out.writeUInt32LE(seq, 1);
    ct.copy(out, 5);
    tag.copy(out, 5 + ct.length);
    return out;
  }
  decrypt(frame) {
    if (!this.key || frame.length < 21 || frame[0] !== 0x02) return null;
    const seq = frame.readUInt32LE(1);
    if (this.rxSeen && seq <= this.rxSeqMax) return null;
    const nonce = Buffer.alloc(12);
    nonce[0] = 0; // browser->device direction
    nonce.writeUInt32LE(seq, 8);
    const ctlen = frame.length - 21;
    const d = createDecipheriv('aes-256-gcm', this.key, nonce);
    d.setAuthTag(frame.subarray(5 + ctlen, 5 + ctlen + 16));
    let pt;
    try {
      pt = Buffer.concat([d.update(frame.subarray(5, 5 + ctlen)), d.final()]);
    } catch {
      return null;
    }
    this.rxSeen = true;
    this.rxSeqMax = seq;
    return pt;
  }
}

const td = new TextDecoder();
const newNonce = () => randomBytes(16).toString('hex');

// --- 1. full handshake round trip ---
const dev = new DeviceSim();
const session = await E2ESession.create();

const nonce = newNonce();
const hello = JSON.parse(
  dev.handleText(JSON.stringify({ type: 'key-req', nonce })),
);
ok(
  typeof hello.spub === 'string' && /^[0-9a-f]{130}$/.test(hello.spub),
  'hello carries static pubkey (spub) as 130 lowercase hex chars',
);
ok(
  typeof hello.epub === 'string' && /^[0-9a-f]{130}$/.test(hello.epub),
  'hello carries ephemeral pubkey (epub) as 130 lowercase hex chars',
);
ok(
  typeof hello.sig === 'string' && /^[0-9a-f]{128}$/.test(hello.sig),
  'hello carries raw r||s signature as 128 lowercase hex chars',
);
ok(
  hello.spub !== hello.epub,
  'static and ephemeral keys differ (forward secrecy)',
);
ok(
  (await fingerprintHex(hexToBytes(hello.spub))) === dev.fingerprint(),
  'browser fingerprintHex matches device SHA-256(spub)',
);
ok(
  await verifyDeviceSig(hello.spub, nonce, hello.epub, hello.sig),
  'browser verifies device signature over nonce||epub',
);

// --- 1b. bad signatures must be rejected ---
const badNonce = newNonce();
ok(
  !(await verifyDeviceSig(hello.spub, badNonce, hello.epub, hello.sig)),
  'signature over a different nonce rejected',
);
const evil = new DeviceSim();
const evilHello = JSON.parse(
  evil.handleText(JSON.stringify({ type: 'key-req', nonce })),
);
ok(
  !(await verifyDeviceSig(hello.spub, nonce, evilHello.epub, evilHello.sig)),
  'MITM signature from wrong static key rejected',
);
const tamperedSig = (hello.sig.slice(0, 126) + 'ff').slice(0, 128);
ok(
  !(await verifyDeviceSig(hello.spub, nonce, hello.epub, tamperedSig)),
  'tampered signature rejected',
);
ok(
  !(await verifyDeviceSig(
    evil.spub,
    nonce,
    hello.epub,
    hello.sig,
  )),
  'signature checked against attacker spub rejected',
);

// --- 1c. second key-req regenerates the ephemeral key ---
const hello2 = JSON.parse(
  dev.handleText(JSON.stringify({ type: 'key-req', nonce: newNonce() })),
);
ok(
  hello2.epub !== hello.epub,
  'fresh ephemeral pubkey on each key-req',
);

// browser sends key; device establishes and replies with encrypted ready
const keyMsg = JSON.stringify({ type: 'key', pub: session.publicKeyHex() });
const readyFrame = dev.handleText(keyMsg);
ok(
  readyFrame instanceof Buffer && readyFrame[0] === 0x02,
  'device replies to key with encrypted frame',
);
await session.deriveSession(hello2.epub);
ok(session.ready, 'browser session key derived');
const ready = await session.decrypt(readyFrame);
ok(
  ready && ready.seq === 0 && JSON.parse(td.decode(ready.plaintext)).type === 'ready',
  'encrypted {"type":"ready"} decrypts at seq 0',
);

// --- 2. encrypted traffic both directions ---
const report = new Uint8Array([0x01, 0x02, 0x04, 0, 0, 0, 0, 0]); // shift+a
const enc1 = await session.encrypt(0, report);
const dec1 = dev.decrypt(Buffer.from(enc1));
ok(dec1 && dec1.equals(Buffer.from(report)), 'browser->device HID report round trip');

const enc2 = await session.encrypt(0, new Uint8Array([0x01, 0, 0, 0, 0, 0, 0, 0]));
const dec2 = dev.decrypt(Buffer.from(enc2));
ok(dec2 && dec2[1] === 0 && dec2.length === 8, 'second report at seq 1 decrypts');

const statusFrame = dev.encrypt(1, Buffer.from('{"type":"status","caps":true}'));
const dec3 = await session.decrypt(statusFrame);
ok(
  dec3 && dec3.seq === 1 && JSON.parse(td.decode(dec3.plaintext)).type === 'status',
  'device->browser frame at seq 1 decrypts',
);

// --- 3. replay protection ---
ok((await session.decrypt(readyFrame)) === null, 'replayed ready frame rejected');
ok(dev.decrypt(Buffer.from(enc1)) === null, 'replayed report rejected');

// --- 4. tamper detection ---
const tampered = Buffer.from(enc2);
tampered[10] ^= 0x01;
ok(dev.decrypt(tampered) === null, 'tampered ciphertext rejected by device');
const tampered2 = Buffer.from(statusFrame);
tampered2[8] ^= 0x80;
ok((await session.decrypt(tampered2)) === null, 'tampered frame rejected by browser');

// --- 5. wrong key fails ---
const dev2 = new DeviceSim();
dev2.eph = createECDH('prime256v1');
dev2.eph.generateKeys();
dev2.key = Buffer.from(
  hkdfSync('sha256', dev2.eph.computeSecret(dev2.eph.getPublicKey()), SALT, INFO, 32),
);
const bogusFrame = dev2.encrypt(1, Buffer.from('{"type":"ready"}'));
ok(
  (await session.decrypt(bogusFrame)) === null,
  'frame encrypted under wrong key rejected',
);

// --- 6. re-handshake resets sequence numbers (device reconnect) ---
dev.resetSession();
const keyMsg2 = JSON.stringify({ type: 'key', pub: session.publicKeyHex() });
ok(
  dev.handleText(keyMsg2) === null,
  'key before key-req ignored (no ephemeral key)',
);
const hello3 = JSON.parse(
  dev.handleText(JSON.stringify({ type: 'key-req', nonce: newNonce() })),
);
const readyFrame2 = dev.handleText(keyMsg2);
ok(
  (await session.decrypt(readyFrame2)) === null,
  'stale session cannot decrypt post-rekey frame (seq reset)',
);
const session2 = await E2ESession.create();
const readyFrame3 = dev.handleText(
  JSON.stringify({ type: 'key', pub: session2.publicKeyHex() }),
);
await session2.deriveSession(hello3.epub);
const r3 = await session2.decrypt(readyFrame3);
ok(r3 && r3.seq === 0, 'fresh session accepts new ready at seq 0');

console.log(failures ? `${failures} FAILURES` : 'ALL PASS');
process.exit(failures ? 1 : 0);
