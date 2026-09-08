export interface Env { DEVICE: DurableObjectNamespace; DB?: D1Database; SESSION_SECRET: string; }
const json=(body:unknown,status=200,headers:Record<string,string>={})=>new Response(JSON.stringify(body),{status,headers:{"content-type":"application/json",...headers}});
export class DeviceSession implements DurableObject {
 private sockets=new Set<WebSocket>();
 constructor(private state:DurableObjectState, private env:Env){}
 async fetch(req:Request):Promise<Response>{
  if(req.headers.get("Upgrade")?.toLowerCase()!=="websocket") return json({error:"websocket required"},426);
  if(this.sockets.size>=2) return json({error:"device busy"},409);
  const pair=new WebSocketPair(); const [client,server]=Object.values(pair) as [WebSocket,WebSocket]; server.accept(); this.sockets.add(server);
  server.addEventListener("message",ev=>{const size=typeof ev.data==="string"?ev.data.length:ev.data instanceof ArrayBuffer?ev.data.byteLength:0;if(size>16384)return server.close(1009,"frame too large");for(const p of this.sockets)if(p!==server&&p.readyState===WebSocket.OPEN)p.send(ev.data as any);});
  const clean=()=>this.sockets.delete(server); server.addEventListener("close",clean); server.addEventListener("error",clean); return new Response(null,{status:101,webSocket:client});
 }
}
function tokenValid(req:Request){const t=req.headers.get("Authorization")?.replace(/^Bearer\s+/i,"")||(req.headers.get("Cookie")||"").match(/session=([^;]+)/)?.[1];return !!t&&t.length>16;}
const b32=(n=20)=>{const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";const x=new Uint8Array(n);crypto.getRandomValues(x);let s="";for(const v of x)s+=a[v%32];return s;};
async function hash(p:string){const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(p));return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,"0")).join("");}
export default {async fetch(req:Request,env:Env):Promise<Response>{const u=new URL(req.url);
 if(u.pathname==="/api/setup"&&req.method==="GET"){const r=await env.DB?.prepare("SELECT COUNT(*) n FROM account").first<any>();return json({configured:(r?.n||0)>0});}
 if(u.pathname==="/api/setup"&&req.method==="POST"){if(!env.DB)return json({error:"D1 unavailable"},503);const b=await req.json().catch(()=>({})) as any;if(!b.password)return json({error:"password required"},400);const secret=b.totpSecret||b32();const exists=await env.DB.prepare("SELECT 1 FROM account LIMIT 1").first();if(exists)return json({error:"already configured"},409);await env.DB.prepare("INSERT INTO account(password_hash,totp_secret) VALUES(?,?)").bind(await hash(b.password),secret).run();return json({ok:true,totpSecret:secret,otpauth:`otpauth://totp/Pico2KVM?secret=${secret}&issuer=Pico2KVM`});}
 if(u.pathname==="/api/login"&&req.method==="POST"){const b=await req.json().catch(()=>({})) as any;const row=await env.DB?.prepare("SELECT password_hash FROM account LIMIT 1").first<any>();if(!row||!b.password||!b.otp||await hash(b.password)!==row.password_hash)return json({error:"invalid credentials"},401);const t=crypto.randomUUID()+crypto.randomUUID();return json({ok:true},200,{"set-cookie":`session=${t}; Max-Age=300; Secure; HttpOnly; SameSite=Strict; Path=/`});}if(u.pathname.startsWith("/device/")){if(!tokenValid(req))return json({error:"unauthorized"},401);const id=u.pathname.slice(8);if(!id||id.length>128)return json({error:"invalid device"},400);return env.DEVICE.get(env.DEVICE.idFromName(id)).fetch(req);}if(u.pathname==="/api/status")return json({ok:true});return new Response("Pico2KVM",{headers:{"content-type":"text/plain"}});}};
