// Usage: node scripts/totp.mjs <base32-secret>
// RFC6238 TOTP (SHA-1, 30s) — same algorithm as worker/src/index.ts
import { createHmac } from 'node:crypto';

const secret = process.argv[2];
if (!secret) {
  console.error('usage: node scripts/totp.mjs <base32-secret>');
  process.exit(1);
}

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

const n = Math.floor(Date.now() / 30000);
const buf = Buffer.alloc(8);
buf.writeUInt32BE(n, 4);
const h = createHmac('sha1', b32bytes(secret)).update(buf).digest();
const o = h[19] & 15;
const x = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
console.log(String(x % 1000000).padStart(6, '0'));
