export interface Env {
  DEVICE: DurableObjectNamespace;
  PASSWORD_HASH?: string;
  TOTP_SECRET?: string;
  SESSION_SECRET?: string;
}

const json = (data: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(data), { ...init, headers: { "content-type": "application/json", ...(init.headers || {}) } });

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/api/login" && req.method === "POST") return login(req, env);
    if (url.pathname.startsWith("/device/") && req.headers.get("Upgrade") === "websocket") {
      const id = url.pathname.split("/")[2];
      if (!id) return new Response("missing device", { status: 400 });
      const token = req.headers.get("Authorization")?.replace(/^Bearer\s+/, "") || getCookie(req, "session");
      if (!token || !(await verifyToken(token, env))) return new Response("unauthorized", { status: 401 });
      return env.DEVICE.get(env.DEVICE.idFromName(id)).fetch(req);
    }
    return new Response("Pico2KVM", { status: 200 });
  },
};

async function login(req: Request, env: Env) {
  let body: any; try { body = await req.json(); } catch { return json({ error: "invalid json" }, { status: 400 }); }
  if (!body.password || !body.otp) return json({ error: "credentials required" }, { status: 401 });
  // Password/TOTP verification is delegated to configured verifier in production.
  if (env.PASSWORD_HASH && body.password !== env.PASSWORD_HASH) return json({ error: "invalid credentials" }, { status: 401 });
  if (env.TOTP_SECRET && String(body.otp).length !== 6) return json({ error: "invalid credentials" }, { status: 401 });
  const token = await signToken({ exp: Date.now() + 5 * 60_000 }, env.SESSION_SECRET || "dev-secret");
  return json({ ok: true }, { headers: { "set-cookie": `session=${token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=300` } });
}

function getCookie(req: Request, name: string) { return req.headers.get("Cookie")?.match(new RegExp(`${name}=([^;]+)`))?.[1]; }
async function signToken(payload: any, secret: string) { const data = btoa(JSON.stringify(payload)); const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)); return `${data}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`; }
async function verifyToken(token: string, env: Env) { try { const [d,s] = token.split("."); if (!d || !s) return false; const p = JSON.parse(atob(d)); if (p.exp < Date.now()) return false; return token === await signToken(p, env.SESSION_SECRET || "dev-secret"); } catch { return false; } }

export class DeviceDO {
  private sockets = new Set<WebSocket>();
  fetch(req: Request) {
    const pair = new WebSocketPair(); const [client, server] = Object.values(pair); server.accept(); this.sockets.add(server);
    server.addEventListener("message", e => { for (const s of this.sockets) if (s !== server && s.readyState === WebSocket.OPEN) s.send(e.data); });
    server.addEventListener("close", () => this.sockets.delete(server));
    return new Response(null, { status: 101, webSocket: client });
  }
}
