// WebSocket relay test against local wrangler dev.
// Usage: node scripts/ws-test.mjs <baseUrl> <deviceToken> <password> <totpSecret>
// Example: node scripts/ws-test.mjs http://localhost:8787 devtoken-devtoken-devtoken testpass123 XXXX
import { createHmac } from 'node:crypto';

const [base, token, password, secret] = process.argv.slice(2);
const wsBase = base.replace(/^http/, 'ws');
let failures = 0;
const ok = (cond, name) => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}`);
  if (!cond) failures++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function b32bytes(s) {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const v = a.indexOf(c);
    if (v >= 0) bits += v.toString(2).padStart(5, '0');
  }
  const out = Buffer.alloc(Math.floor(bits.length / 8));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return out;
}

function totpCode(s) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(Date.now() / 30000), 4);
  const h = createHmac('sha1', b32bytes(s)).update(buf).digest();
  const o = h[19] & 15;
  const x = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(x % 1000000).padStart(6, '0');
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
    w.next = (pred, timeout = 3000) =>
      new Promise((res, rej) => {
        const cleanup = () => {
          clearTimeout(t);
          const k = waiters.indexOf(wfn);
          if (k >= 0) waiters.splice(k, 1);
        };
        const t = setTimeout(() => {
          cleanup();
          rej(new Error(`timeout; received so far: ${JSON.stringify(msgs.map((d) => (typeof d === 'string' ? d : '<binary>')))}`));
        }, timeout);
        const wfn = () => {
          while (cursor < msgs.length) {
            const d = msgs[cursor++];
            if (pred(d)) {
              cleanup();
              res(d);
              return;
            }
          }
        };
        waiters.push(wfn);
        wfn();
      });
    w.onopen = () => resolve(w);
    w.onerror = (e) => reject(e.error || new Error('ws error'));
  });
}

// 1. login to get a session cookie
const login = await fetch(`${base}/api/login`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ password, otp: totpCode(secret) }),
});
const cookie = login.headers.get('set-cookie')?.split(';')[0];
ok(login.ok && cookie?.startsWith('session='), `login ok, cookie=${cookie?.slice(0, 24)}...`);

const url = `${wsBase}/device/default`;

// 2. unauthenticated WS should fail
let rejected = false;
try {
  await connect(url, {});
} catch {
  rejected = true;
}
ok(rejected, 'unauthenticated ws rejected');

// 3. browser first -> peer device:false
const browser = await connect(url, { Cookie: cookie });
const peer0 = JSON.parse(await browser.next((d) => typeof d === 'string' && d.includes('"peer"')));
ok(peer0.type === 'peer' && peer0.device === false, `browser got ${JSON.stringify(peer0)} before device`);

// 4. device connects -> browser gets peer device:true
const device = await connect(url, { Authorization: `Bearer ${token}` });
const peer1 = JSON.parse(
  await browser.next((d) => typeof d === 'string' && d.includes('"peer"')).catch((e) => String(e)),
);
ok(peer1?.type === 'peer' && peer1.device === true, `browser got ${JSON.stringify(peer1)} on device join`);

// 5. device hello -> browser
device.send(JSON.stringify({ type: 'hello', fw: 'pico2kvm' }));
const hello = JSON.parse(await browser.next((d) => typeof d === 'string' && d.includes('"hello"')));
ok(hello.fw === 'pico2kvm', `browser got ${JSON.stringify(hello)}`);

// 6. browser 8-byte report -> device
const report = new Uint8Array([0x01, 0x02, 0x04, 0, 0, 0, 0, 0]);
browser.send(report);
const got = await device.next((d) => typeof d !== 'string');
const gotBytes = got instanceof Blob ? new Uint8Array(await got.arrayBuffer()) : new Uint8Array(got);
ok(Buffer.from(gotBytes).equals(Buffer.from(report)), `device got 8-byte report: ${[...gotBytes]}`);

// 7. second device replaces first (close 1000)
const closed = new Promise((r) => {
  device.onclose = (ev) => r(ev.code);
});
const device2 = await connect(url, { Authorization: `Bearer ${token}` });
const code = await closed;
ok(code === 1000, `first device closed with code ${code}`);

// 8. device disconnect -> browser peer device:false
// (device2's join already emitted a peer:true, which may still be queued)
device2.close();
const peer2 = JSON.parse(
  await browser.next((d) => typeof d === 'string' && d.includes('"device":false')),
);
ok(peer2.type === 'peer' && peer2.device === false, `browser got ${JSON.stringify(peer2)} on device disconnect`);

browser.close();
await sleep(200);
console.log(failures ? `${failures} FAILURES` : 'ALL PASS');
process.exit(failures ? 1 : 0);
