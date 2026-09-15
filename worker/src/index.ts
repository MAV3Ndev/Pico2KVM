export interface Env {
  DEVICE: DurableObjectNamespace;
  DB?: D1Database;
  DEVICE_TOKEN: string;
  SESSION_SECRET: string;
  ASSETS: Fetcher;
}

const encoder = new TextEncoder();
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_FRAME = 16384;

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function timingSafeEq(a: string, b: string): boolean {
  const ea = encoder.encode(a);
  const eb = encoder.encode(b);
  if (ea.length !== eb.length) return false;
  let diff = 0;
  for (let i = 0; i < ea.length; i++) diff |= ea[i] ^ eb[i];
  return diff === 0;
}

async function signSession(exp: number, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return `${exp}.${toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(String(exp))))}`;
}

async function verifySession(token: string, secret: string): Promise<boolean> {
  const i = token.lastIndexOf(".");
  if (i <= 0) return false;
  const exp = Number(token.slice(0, i));
  if (!Number.isSafeInteger(exp) || exp <= Date.now()) return false;
  return timingSafeEq(token, await signSession(exp, secret));
}

export class DeviceSession implements DurableObject {
  private sockets = new Map<WebSocket, "device" | "browser">();

  constructor(private state: DurableObjectState, private env: Env) {}

  private notifyBrowsers(device: boolean) {
    const msg = JSON.stringify({ type: "peer", device });
    for (const [s, role] of this.sockets) {
      if (role === "browser" && s.readyState === WebSocket.OPEN) s.send(msg);
    }
  }

  async fetch(req: Request): Promise<Response> {
    if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket")
      return json({ error: "websocket required" }, 426);
    const role: "device" | "browser" =
      req.headers.get("X-Pico2KVM-Role") === "device" ? "device" : "browser";
    for (const [s, r] of this.sockets) {
      if (r === role) {
        this.sockets.delete(s);
        try {
          s.close(1000, "replaced");
        } catch {}
      }
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    server.accept();
    this.sockets.set(server, role);
    if (role === "browser") {
      const deviceOnline = [...this.sockets.values()].includes("device");
      server.send(JSON.stringify({ type: "peer", device: deviceOnline }));
    } else {
      this.notifyBrowsers(true);
    }
    server.addEventListener("message", (ev) => {
      void (async () => {
        let data: string | ArrayBuffer;
        const raw = ev.data as unknown;
        if (typeof raw === "string" || raw instanceof ArrayBuffer) {
          data = raw;
        } else if (raw instanceof Blob) {
          data = await raw.arrayBuffer();
        } else if (ArrayBuffer.isView(raw)) {
          data = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer;
        } else {
          return;
        }
        const size = typeof data === "string" ? data.length : data.byteLength;
        if (size > MAX_FRAME) return server.close(1009, "frame too large");
        for (const p of this.sockets.keys())
          if (p !== server && p.readyState === WebSocket.OPEN) p.send(data);
      })();
    });
    const clean = () => {
      const r = this.sockets.get(server);
      if (r === undefined) return;
      this.sockets.delete(server);
      if (r === "device") this.notifyBrowsers(false);
    };
    server.addEventListener("close", clean);
    server.addEventListener("error", clean);
    return new Response(null, { status: 101, webSocket: client });
  }
}

const b32 = (n = 20) => {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const x = new Uint8Array(n);
  crypto.getRandomValues(x);
  let s = "";
  for (const v of x) s += a[v % 32];
  return s;
};

// Workers WebCrypto rejects PBKDF2 iteration counts above 100000.
const PBKDF2_ITERS = 100000;

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(Math.floor(hex.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function pbkdf2Bits(password: string, salt: Uint8Array, iterations: number) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  return crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    key,
    256,
  );
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2Bits(password, salt, PBKDF2_ITERS);
  return `pbkdf2$${PBKDF2_ITERS}$${toHex(salt.buffer as ArrayBuffer)}$${toHex(bits)}`;
}

// Returns { ok } and, for legacy unsalted SHA-256 rows that match, a newHash
// so the caller can transparently migrate the stored row to PBKDF2.
async function verifyPassword(
  password: string,
  stored: string,
): Promise<{ ok: boolean; newHash?: string }> {
  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    const iterations = Number(parts[1]);
    const saltHex = parts[2];
    const hashHex = parts[3];
    if (
      parts.length !== 4 ||
      !Number.isSafeInteger(iterations) ||
      iterations <= 0 ||
      iterations > 1_000_000 ||
      !/^[0-9a-f]{32}$/i.test(saltHex) ||
      !/^[0-9a-f]{64}$/i.test(hashHex)
    )
      return { ok: false };
    const bits = await pbkdf2Bits(password, hexToBytes(saltHex), iterations);
    return { ok: timingSafeEq(toHex(bits), hashHex.toLowerCase()) };
  }
  // Legacy format: bare unsalted SHA-256 hex.
  if (/^[0-9a-f]{64}$/i.test(stored)) {
    const d = toHex(await crypto.subtle.digest("SHA-256", encoder.encode(password)));
    if (timingSafeEq(d, stored.toLowerCase()))
      return { ok: true, newHash: await hashPassword(password) };
  }
  return { ok: false };
}

function b32bytes(s: string) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    const v = a.indexOf(c);
    if (v >= 0) bits += v.toString(2).padStart(5, "0");
  }
  const out = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return out;
}

async function totp(secret: string, code: string) {
  const n = Math.floor(Date.now() / 30000);
  const key = await crypto.subtle.importKey(
    "raw",
    b32bytes(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  for (let d = -1; d <= 1; d++) {
    const b = new ArrayBuffer(8);
    new DataView(b).setUint32(4, n + d);
    const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, b));
    const o = h[19] & 15;
    const x = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
    if (String(x % 1000000).padStart(6, "0") === String(code)) return true;
  }
  return false;
}

async function configured(env: Env): Promise<boolean> {
  const r = await env.DB?.prepare("SELECT COUNT(*) n FROM account").first<{ n: number }>();
  return (r?.n || 0) > 0;
}

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

function addSecurityHeaders(res: Response): Response {
  if (res.status === 101) return res; // WebSocket upgrade response: leave untouched
  const r = new Response(res.body, res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) r.headers.set(k, v);
  return r;
}

async function handleRequest(req: Request, env: Env): Promise<Response> {
    const u = new URL(req.url);

    if (u.pathname === "/api/setup" && req.method === "GET") {
      return json({ configured: await configured(env) });
    }

    if (u.pathname === "/api/setup" && req.method === "POST") {
      if (!env.DB) return json({ error: "D1 unavailable" }, 503);
      const b = (await req.json().catch(() => ({}))) as any;
      if (!b.password) return json({ error: "password required" }, 400);
      const secret = b.totpSecret || b32();
      const exists = await env.DB.prepare("SELECT 1 FROM account LIMIT 1").first();
      if (exists) return json({ error: "already configured" }, 409);
      await env.DB.prepare("INSERT INTO account(password_hash,totp_secret) VALUES(?,?)")
        .bind(await hashPassword(b.password), secret)
        .run();
      return json({
        ok: true,
        totpSecret: secret,
        otpauth: `otpauth://totp/Pico2KVM?secret=${secret}&issuer=Pico2KVM`,
      });
    }

    if (u.pathname === "/api/login" && req.method === "POST") {
      if (!env.SESSION_SECRET) return json({ error: "SESSION_SECRET not set" }, 503);
      if (!env.DB) return json({ error: "D1 unavailable" }, 503);
      const now = Date.now();
      const recent = await env.DB.prepare(
        "SELECT COUNT(*) n FROM login_attempt WHERE ts > ?",
      )
        .bind(now - 10 * 60 * 1000)
        .first<{ n: number }>();
      if ((recent?.n || 0) >= 10)
        return json({ error: "too many attempts, try later" }, 429);
      const fail = async () => {
        await env.DB!.prepare("INSERT INTO login_attempt(ts) VALUES(?)").bind(now).run();
        await env.DB!.prepare("DELETE FROM login_attempt WHERE ts < ?")
          .bind(now - 10 * 60 * 1000)
          .run();
        return json({ error: "invalid credentials" }, 401);
      };
      const b = (await req.json().catch(() => ({}))) as any;
      const row = await env.DB.prepare(
        "SELECT password_hash,totp_secret FROM account LIMIT 1",
      ).first<{ password_hash: string; totp_secret: string }>();
      if (!row || !b.password || !b.otp) return fail();
      const v = await verifyPassword(b.password, row.password_hash);
      if (!v.ok || !(await totp(row.totp_secret, String(b.otp)))) return fail();
      if (v.newHash)
        await env.DB.prepare("UPDATE account SET password_hash=? WHERE id=1")
          .bind(v.newHash)
          .run();
      await env.DB.prepare("DELETE FROM login_attempt").run();
      const token = await signSession(Date.now() + SESSION_TTL_MS, env.SESSION_SECRET);
      return json({ ok: true }, 200, {
        "set-cookie": `session=${token}; Max-Age=28800; Secure; HttpOnly; SameSite=Strict; Path=/`,
      });
    }

    if (u.pathname === "/api/logout" && req.method === "POST") {
      return json({ ok: true }, 200, {
        "set-cookie": "session=; Max-Age=0; Secure; HttpOnly; SameSite=Strict; Path=/",
      });
    }

    if (u.pathname === "/api/status") {
      return json({ ok: true, configured: await configured(env) });
    }

    if (u.pathname.startsWith("/device/")) {
      const id = u.pathname.slice(8);
      if (!id || id.length > 128) return json({ error: "invalid device" }, 400);
      let role: "device" | "browser" | null = null;
      const bearer = req.headers.get("Authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
      if (bearer && env.DEVICE_TOKEN && timingSafeEq(bearer, env.DEVICE_TOKEN)) role = "device";
      if (!role) {
        const token = (req.headers.get("Cookie") || "").match(/session=([^;]+)/)?.[1];
        if (token && env.SESSION_SECRET && (await verifySession(token, env.SESSION_SECRET)))
          role = "browser";
      }
      if (!role) return json({ error: "unauthorized" }, 401);
      const headers = new Headers(req.headers);
      headers.set("X-Pico2KVM-Role", role);
      return env.DEVICE.get(env.DEVICE.idFromName(id)).fetch(new Request(req, { headers }));
    }

    return env.ASSETS.fetch(req);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    return addSecurityHeaders(await handleRequest(req, env));
  },
};
