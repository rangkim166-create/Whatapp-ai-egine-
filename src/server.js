import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import makeWASocket, {
  DisconnectReason,
  useMultiFileAuthState,
  Browsers,
  fetchLatestBaileysVersion
} from "@whiskeysockets/baileys";

const PORT = Number(process.env.PORT || 8080);
const ENGINE_SECRET = process.env.ENGINE_SECRET || "";
const WEBHOOK_URL = process.env.ENGINE_WEBHOOK_URL || "";
const WEBHOOK_SECRET = process.env.ENGINE_WEBHOOK_SECRET || "";
const AUTH_ROOT = process.env.AUTH_ROOT || "/app/auth";
const ENGINE_NAME = "Ash WhatsApp AI Engine";

const sessions = new Map();
const rateBuckets = new Map();
const MAX_SESSIONS = Math.max(1, Math.min(25, Number(process.env.MAX_SESSIONS || 10)));
function isRateLimited(key, max, windowMs) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) { bucket = { count: 0, resetAt: now + windowMs }; rateBuckets.set(key, bucket); }
  bucket.count += 1;
  if (rateBuckets.size > 5000) for (const [k, v] of rateBuckets) if (v.resetAt <= now) rateBuckets.delete(k);
  return bucket.count > max;
}

function json(res, status, body) {
  res.writeHead(status, {
    "content-type":"application/json; charset=utf-8",
    "cache-control":"no-store, max-age=0",
    "x-content-type-options":"nosniff",
    "x-frame-options":"DENY",
    "referrer-policy":"no-referrer",
    "permissions-policy":"camera=(), microphone=(), geolocation=()"
  });
  res.end(JSON.stringify(body));
}

function authorized(req) {
  if (!ENGINE_SECRET) return process.env.NODE_ENV !== "production";
  const supplied = req.headers["x-engine-secret"];
  if (typeof supplied !== "string") return false;
  const a = Buffer.from(supplied);
  const b = Buffer.from(ENGINE_SECRET);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function readBody(req) {
  const chunks = []; let size = 0; const maxBytes = 16 * 1024;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) { const error = new Error("Request body too large"); error.statusCode = 413; throw error; }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function normalizePhone(phone) {
  return String(phone || "").replace(/[^0-9]/g, "");
}

function jidFor(phone) {
  const value = String(phone || "").trim();
  if (/^[0-9]+@(s\.whatsapp\.net|g\.us|lid)$/.test(value)) return value;
  const n = normalizePhone(value);
  return n ? `${n}@s.whatsapp.net` : null;
}

async function notifyWebhook(event) {
  if (!WEBHOOK_URL) return;
  try {
    await fetch(WEBHOOK_URL, {
      method:"POST",
      headers:{
        "content-type":"application/json",
        ...(ENGINE_SECRET ? {"x-engine-secret":ENGINE_SECRET} : {})
      },
      body:JSON.stringify(event)
    });
  } catch (error) {
    console.error("Webhook delivery failed:", error?.message || error);
  }
}

async function startSession(sessionId, phone, preserveAuth = false) {
  const existing = sessions.get(sessionId);
  if (existing?.sock) return existing;

  const sessionDir = path.join(AUTH_ROOT, sessionId);
  await fs.mkdir(sessionDir, {recursive:true});
  let auth = await useMultiFileAuthState(sessionDir);
  // A brand-new pairing attempt should start clean when there are no registered
  // credentials. During Baileys' restart-required (515) handshake, preserve the
  // updated keys: deleting them here makes phone linking fail in a loop.
  if (!auth.state.creds.registered && !preserveAuth) {
    await fs.rm(sessionDir, {recursive:true, force:true});
    await fs.mkdir(sessionDir, {recursive:true});
    auth = await useMultiFileAuthState(sessionDir);
  }
  const {state, saveCreds} = auth;

  let version;
  try {
    const latest = await fetchLatestBaileysVersion();
    version = latest.version;
  } catch {}

  const sock = makeWASocket({
    auth: state,
    version,
    browser: Browsers.macOS("Chrome"),
    printQRInTerminal: false,
    markOnlineOnConnect: false,
    syncFullHistory: false
  });

  const session = {
    sessionId,
    phone: normalizePhone(phone),
    sock,
    status: state.creds.registered ? "connecting" : "pairing",
    pairingCode: null,
    pairingRequested: false,
    connectedAt: null,
    lastError: null
  };
  sessions.set(sessionId, session);

  sock.ev.on("creds.update", saveCreds);

  // Baileys does not reliably emit a QR event for phone-number pairing.
  // Request the pairing code after the socket has had time to initialize,
  // and also use a QR event as an early trigger when one is emitted.
  let pairingTimer;
  const requestPairingCodeOnce = async () => {
    if (state.creds.registered || session.pairingCode || session.pairingRequested ||
        sessions.get(sessionId) !== session || session.sock !== sock) return;
    session.pairingRequested = true;
    session.status = "requesting_code";
    try {
      const code = await Promise.race([
        sock.requestPairingCode(session.phone),
        new Promise((_, reject) => setTimeout(() => reject(new Error("WhatsApp pairing request timed out. Please try again.")), 15000))
      ]);
      if (sessions.get(sessionId) !== session || session.sock !== sock) return;
      session.pairingCode = code;
      session.status = "pairing";
      session.lastError = null;
      console.log(`Pairing code generated for session ${sessionId}`);
    } catch (error) {
      session.pairingRequested = false;
      session.status = "error";
      session.lastError = error?.message || String(error);
      console.error("Pairing code request failed:", session.lastError);
    }
  };

  if (!state.creds.registered) {
    pairingTimer = setTimeout(() => { void requestPairingCodeOnce(); }, 6500);
  }

  sock.ev.on("connection.update", async ({connection, lastDisconnect, qr}) => {
    if (qr && !state.creds.registered) {
      clearTimeout(pairingTimer);
      void requestPairingCodeOnce();
    }

    if (connection === "open") {
      clearTimeout(pairingTimer);
      session.status = "connected";
      session.pairingCode = null;
      session.connectedAt = new Date().toISOString();
      session.lastError = null;
      console.log(`WhatsApp connected: ${sessionId}`);
      await notifyWebhook({type:"connection.open",sessionId,phone:session.phone});
    } else if (connection === "close") {
      clearTimeout(pairingTimer);
      const code = lastDisconnect?.error?.output?.statusCode;
      session.lastError = String(code || "connection_closed");
      session.sock = null;
      await notifyWebhook({type:"connection.close",sessionId,phone:session.phone,code});
      if (code === DisconnectReason.loggedOut) {
        session.status = "logged_out";
      } else if (code === DisconnectReason.restartRequired || code === 515) {
        // WhatsApp commonly closes with 515 after a successful pairing handshake.
        // This is a required socket restart, not a terminal pairing failure.
        session.status = "reconnecting";
        setTimeout(() => startSession(sessionId, session.phone, true).catch(err => {
          session.status = "error";
          session.lastError = err?.message || String(err);
          console.error("WhatsApp restart-required recovery failed:", session.lastError);
        }), 500);
      } else if (!state.creds.registered) {
        // Don't silently spin up endless fresh sockets when the phone has not
        // completed linking. Report the failure and let the user retry cleanly.
        session.status = "error";
        session.lastError = `WhatsApp closed the connection before linking completed (code: ${code || "unknown"}). Retry to request a fresh pairing code.`;
        console.error(session.lastError);
      } else {
        session.status = "reconnecting";
        setTimeout(() => startSession(sessionId, session.phone, true).catch(err => {
          session.status = "error";
          session.lastError = err?.message || String(err);
          console.error("WhatsApp reconnect failed:", session.lastError);
        }), 2000);
      }
    }
  });

  sock.ev.on("messages.upsert", async ({messages, type}) => {
    if (type !== "notify") return;
    for (const msg of messages) {
      if (!msg?.message || msg.key?.fromMe) continue;
      const remoteJid = msg.key.remoteJid;
      if (!remoteJid || remoteJid === "status@broadcast" || remoteJid.endsWith("@status")) continue;
      const body =
        msg.message.conversation ||
        msg.message.extendedTextMessage?.text ||
        msg.message.imageMessage?.caption ||
        msg.message.videoMessage?.caption ||
        "";
      if (!body) continue;
      await notifyWebhook({
        type:"message.incoming",
        sessionId,
        phone:session.phone,
        waChatId:remoteJid,
        waMessageId:msg.key.id || null,
        senderPhone:remoteJid.split("@")[0],
        body,
        timestamp:new Date().toISOString()
      });
    }
  });

  return session;
}

async function closeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return false;
  try { session.sock?.end(undefined); } catch {}
  sessions.delete(sessionId);
  return true;
}

async function restoreSavedSession(sessionId) {
  if (!/^[a-zA-Z0-9_-]{8,80}$/.test(sessionId)) return null;
  if (sessions.has(sessionId)) return sessions.get(sessionId);
  const sessionDir = path.join(AUTH_ROOT, sessionId);
  try {
    const auth = await useMultiFileAuthState(sessionDir);
    if (!auth.state.creds.registered) return null;
    const meId = String(auth.state.creds.me?.id || "");
    const phone = meId.split("@")[0].split(":")[0].replace(/[^0-9]/g, "");
    if (!phone) {
      console.warn(`Saved WhatsApp session ${sessionId} has credentials but no recoverable phone ID`);
      return null;
    }
    console.log(`Restoring saved WhatsApp session: ${sessionId}`);
    return await startSession(sessionId, phone, true);
  } catch (error) {
    if (error?.code !== "ENOENT") console.warn(`Could not restore session ${sessionId}:`, error?.message || error);
    return null;
  }
}

async function restoreSavedSessionsAtBoot() {
  try {
    await fs.mkdir(AUTH_ROOT, {recursive:true});
    const entries = await fs.readdir(AUTH_ROOT, {withFileTypes:true});
    for (const entry of entries) {
      if (!entry.isDirectory() || sessions.size >= MAX_SESSIONS) continue;
      await restoreSavedSession(entry.name);
    }
    console.log(`Saved WhatsApp session restore scan finished; restored ${sessions.size} session(s)`);
  } catch (error) {
    console.error("Saved WhatsApp session scan failed:", error?.message || error);
  }
}

async function route(req, res) {
  const pathname = new URL(req.url || "/", "http://localhost").pathname.replace(/\/+$/, "") || "/";
  if (req.method === "GET" && pathname === "/health") {
    return json(res,200,{ok:true,status:"online",timestamp:new Date().toISOString()});
  }

  if (!authorized(req)) return json(res,401,{ok:false,error:"Unauthorized"});

  if (req.method === "GET" && pathname === "/") {
    return json(res,200,{ok:true,engine:ENGINE_NAME,version:"2.0.0",whatsapp:"baileys"});
  }

  if (req.method === "GET" && pathname === "/sessions") {
    return json(res,200,{ok:true,sessions:[...sessions.values()].map(s=>({
      sessionId:s.sessionId,phone:s.phone,status:s.status,pairingCode:s.pairingCode,
      connectedAt:s.connectedAt,lastError:s.lastError
    }))});
  }

  if (req.method === "POST" && pathname === "/connect") {
    const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",")[0].trim();
    if (isRateLimited("connect:" + ip, 5, 10 * 60 * 1000)) return json(res,429,{ok:false,error:"Too many connection attempts. Wait 10 minutes before retrying."});
    let payload={};
    try { payload=JSON.parse(await readBody(req)||"{}"); } catch { return json(res,400,{ok:false,error:"Invalid JSON"}); }
    const sessionId=String(payload.sessionId||"").trim();
    const phone=normalizePhone(payload.phone);
    if (!/^[a-zA-Z0-9_-]{8,80}$/.test(sessionId) || !/^\d{8,15}$/.test(phone)) return json(res,400,{ok:false,error:"A valid session ID and international phone number are required"});
    if (!sessions.has(sessionId) && sessions.size >= MAX_SESSIONS) return json(res,429,{ok:false,error:"This engine is at its session limit. Try again later."});
    try {
      const session=await startSession(sessionId,phone);
      return json(res,200,{ok:true,sessionId,phone,status:session.status,pairingCode:session.pairingCode||null});
    } catch(error) {
      return json(res,500,{ok:false,error:error?.message||String(error)});
    }
  }

  if (req.method === "GET" && pathname.startsWith("/status/")) {
    const sessionId=decodeURIComponent(pathname.slice("/status/".length));
    let s=sessions.get(sessionId);
    if (!s) s = await restoreSavedSession(sessionId);
    if (!s) return json(res,404,{ok:false,error:"Session not found and no saved linked credentials were available to restore it. The hosting filesystem may have been reset."});
    return json(res,200,{ok:true,sessionId:s.sessionId,phone:s.phone,status:s.status,pairingCode:s.pairingCode,connectedAt:s.connectedAt,lastError:s.lastError});
  }

  if (req.method === "POST" && pathname === "/send") {
    let payload={};
    try { payload=JSON.parse(await readBody(req)||"{}"); } catch { return json(res,400,{ok:false,error:"Invalid JSON"}); }
    const sendSessionId=String(payload.sessionId||"");
    if (isRateLimited("send:" + sendSessionId, 60, 60 * 1000)) return json(res,429,{ok:false,error:"Message send rate limit reached. Try again shortly."});
    const s=sessions.get(sendSessionId);
    const to=jidFor(payload.to);
    const text=String(payload.text||"").trim();
    if (!s?.sock || s.status !== "connected") return json(res,409,{ok:false,error:"Session is not connected"});
    if (!to || !text) return json(res,400,{ok:false,error:"to and text are required"});
    try {
      const sendPromise = s.sock.sendMessage(to,{text});
      const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("WhatsApp send timed out after 25 seconds")), 25000));
      const result = await Promise.race([sendPromise, timeoutPromise]);
      return json(res,200,{ok:true,messageId:result?.key?.id||null,to});
    } catch(error) {
      return json(res,500,{ok:false,error:error?.message||String(error)});
    }
  }

  if (req.method === "POST" && pathname === "/disconnect") {
    let payload={};
    try { payload=JSON.parse(await readBody(req)||"{}"); } catch { return json(res,400,{ok:false,error:"Invalid JSON"}); }
    return json(res,200,{ok:await closeSession(String(payload.sessionId||""))});
  }

  return json(res,404,{ok:false,error:"Not found"});
}

const server=http.createServer((req,res)=>route(req,res).catch(error=>{
  if (error?.statusCode === 413) return json(res,413,{ok:false,error:"Request body too large"});
  console.error("Request failed:", error?.message || error);
  json(res,500,{ok:false,error:"Internal server error"});
}));

server.listen(PORT,"0.0.0.0",()=>{console.log(`${ENGINE_NAME} listening on ${PORT}`);void restoreSavedSessionsAtBoot();});

let shuttingDown = false;
async function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}; shutting down gracefully`);
  try {
    await Promise.all([...sessions.keys()].map(closeSession));
  } catch (error) {
    console.error("Session shutdown error:", error?.message || error);
  }
  await new Promise((resolve) => {
    server.close(() => resolve());
  }).catch(() => {});
  console.log("HTTP server closed");
  process.exit(0);
}

process.on("SIGTERM", () => { void gracefulShutdown("SIGTERM"); });
process.on("SIGINT", () => { void gracefulShutdown("SIGINT"); });
