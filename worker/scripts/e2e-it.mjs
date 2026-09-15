// End-to-end integration test through a real relay (wrangler dev).
// Emulates the firmware with node:crypto and the browser with web/e2e.js,
// connected through the DeviceSession Durable Object.
// Usage: node scripts/e2e-it.mjs [baseUrl]
//   baseUrl defaults to http://localhost:8787
//   DEVICE_TOKEN / SESSION_SECRET are read from ../.dev.vars
import {
  createECDH,
  generateKeyPairSync,
  sign as cryptoSign,
  hkdfSync,
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { E2ESession, hexToBytes, verifyDeviceSig } from '../../web/e2e.js';

const here = dirname(fileURLToPath(import.meta.url));
const base = process.argv[2] || 'http://localhost:8787';
const wsBase = base.replace(/^http/, 'ws');

const vars = Object.fromEntries(
  readFileSync(join(here, '..', '.dev.vars'), 'utf8')
    .split(/\r?\n/)
    .filter((l) => l.includes('='))
    .map((l) => l.split('=').map((s) => s.trim())),
);
const DEVICE_TOKEN = vars.DEVICE_TOKEN;
const SESSION_SECRET = vars.SESSION_SECRET;
if (!DEVICE_TOKEN || !SESSION_SECRET) {
  console.error('DEVICE_TOKEN / SESSION_SECRET missing from .dev.vars');
  process.exit(1);
}

const INFO = Buffer.from('pico2kvm-e2e-v1');
const SALT = Buffer.alloc(32);
const td = new TextDecoder();

let failures = 0;
const ok = (cond, name) => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}`);
  if (!cond) failures++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function signSession(exp, secret) {
  const sig = createHmac('sha256', secret).update(String(exp)).digest('hex');
  return `${exp}.${sig}`;
}

function connect(url, headers) {
  return new Promise((resolve, reject) => {
    const w = new WebSocket(url, { headers });
    const msgs = [];
    const waiters = [];
    let cursor = 0;
    w.binaryType = 'arraybuffer';
    w.onmessage = (ev) => {
      msgs.push(ev.data);
      for (const wfn of [...waiters]) wfn();
    };
    w.next = (pred, timeout = 5000) =>
      new Promise((res, rej) => {
        const cleanup = () => {
          clearTimeout(t);
          const k = waiters.indexOf(wfn);
          if (k >= 0) waiters.splice(k, 1);
        };
        const t = setTimeout(() => {
          cleanup();
          rej(new Error('timeout waiting for message'));
        }, timeout);
        const wfn = () => {
          while (cursor < msgs.length) {
            const d = msgs[cursor++];
            Promise.resolve(pred(d)).then((hit) => {
              if (hit) {
                cleanup();
                res(d);
              }
            });
          }
        };
        waiters.push(wfn);
        wfn();
      });
    w.onopen = () => resolve(w);
    w.onerror = (e) => reject(e.error || new Error('ws error'));
  });
}

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
    this.eph = null;
    this.key = null;
    this.txSeq = [0, 0];
    this.rxSeen = false;
    this.rxSeqMax = 0;
  }
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
    if (m.type === 'key' && this.eph) {
      const shared = this.eph.computeSecret(Buffer.from(m.pub, 'hex'));
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
    const out = Buffer.alloc(5 + ct.length + 16);
    out[0] = 0x02;
    out.writeUInt32LE(seq, 1);
    ct.copy(out, 5);
    c.getAuthTag().copy(out, 5 + ct.length);
    return out;
  }
  decrypt(frame) {
    if (!this.key || frame.length < 21 || frame[0] !== 0x02) return null;
    const seq = frame.readUInt32LE(1);
    if (this.rxSeen && seq <= this.rxSeqMax) return null;
    const nonce = Buffer.alloc(12);
    nonce[0] = 0;
    nonce.writeUInt32LE(seq, 8);
    const ctlen = frame.length - 21;
    const d = createDecipheriv('aes-256-gcm', this.key, nonce);
    d.setAuthTag(frame.subarray(5 + ctlen, 5 + ctlen + 16));
    try {
      const pt = Buffer.concat([
        d.update(frame.subarray(5, 5 + ctlen)),
        d.final(),
      ]);
      this.rxSeen = true;
      this.rxSeqMax = seq;
      return pt;
    } catch {
      return null;
    }
  }
}

const toBytes = async (d) =>
  d instanceof Blob
    ? new Uint8Array(await d.arrayBuffer())
    : new Uint8Array(d);

// --- run ---
const dev = new DeviceSim();
const session = await E2ESession.create();
let devKeyEstablished = null;

// device connects first (as firmware does)
const device = await connect(`${wsBase}/device/default`, {
  Authorization: `Bearer ${DEVICE_TOKEN}`,
});
ok(true, 'device ws connected');
device.onmessage = async (ev) => {
  if (typeof ev.data !== 'string') {
    const r = dev.decrypt(Buffer.from(await toBytes(ev.data)));
    if (r) dev.lastReport = r;
    return;
  }
  const reply = dev.handleText(ev.data);
  if (reply) device.send(reply);
};
// Firmware no longer sends an unsolicited hello: it needs the browser's
// nonce to sign, so it only answers key-req.

// browser connects, runs the app.js handshake flow (fingerprint check is
// out of scope here; pin verification is covered by e2e-sim)
const cookie = `session=${signSession(Date.now() + 60000, SESSION_SECRET)}`;
const browser = await connect(`${wsBase}/device/default`, { Cookie: cookie });
ok(true, 'browser ws connected');
const nonce = randomBytes(16).toString('hex');
browser.send(JSON.stringify({ type: 'key-req', nonce }));

const browserMsgs = [];
browser.onmessage = (ev) => browserMsgs.push(ev.data);

// wait for hello (device may have sent it before browser joined; key-req
// forces a resend)
const helloText = await (async () => {
  for (let i = 0; i < 50; i++) {
    const m = browserMsgs.find(
      (d) => typeof d === 'string' && d.includes('"hello"'),
    );
    if (m) return JSON.parse(m);
    await sleep(100);
  }
  throw new Error('no hello');
})();
ok(
  /^[0-9a-f]{130}$/.test(helloText.spub) &&
    /^[0-9a-f]{130}$/.test(helloText.epub) &&
    /^[0-9a-f]{128}$/.test(helloText.sig),
  'browser received hello with spub/epub/sig',
);
ok(
  await verifyDeviceSig(helloText.spub, nonce, helloText.epub, helloText.sig),
  'device signature verified through relay',
);

browser.send(JSON.stringify({ type: 'key', pub: session.publicKeyHex() }));
await session.deriveSession(helloText.epub);

// encrypted ready arrives through the relay as binary
let ready = null;
for (let i = 0; i < 50 && !ready; i++) {
  for (const d of browserMsgs) {
    if (typeof d !== 'string') {
      const r = await session.decrypt(await toBytes(d));
      if (r && JSON.parse(td.decode(r.plaintext)).type === 'ready') ready = r;
    }
  }
  if (!ready) await sleep(100);
}
ok(!!ready, 'browser decrypted encrypted {"type":"ready"} through relay');

// browser -> device: encrypted HID report through relay
const report = new Uint8Array([0x01, 0x00, 0x04, 0, 0, 0, 0, 0]);
browser.send(await session.encrypt(0, report));
let got = null;
for (let i = 0; i < 50 && !got; i++) {
  if (dev.lastReport) got = dev.lastReport;
  else await sleep(100);
}
ok(
  got && Buffer.from(got).equals(Buffer.from(report)),
  'device decrypted HID report through relay',
);

// device -> browser: another encrypted frame
device.send(dev.encrypt(1, Buffer.from('{"type":"ping"}')));
let ping = null;
for (let i = 0; i < 50 && !ping; i++) {
  for (const d of browserMsgs) {
    if (typeof d !== 'string') {
      const r = await session.decrypt(await toBytes(d)).catch(() => null);
      if (r && JSON.parse(td.decode(r.plaintext)).type === 'ping') ping = r;
    }
  }
  if (!ping) await sleep(100);
}
ok(!!ping, 'browser decrypted device->browser frame through relay');

browser.close();
device.close();
await sleep(200);
console.log(failures ? `${failures} FAILURES` : 'ALL PASS');
process.exit(failures ? 1 : 0);
