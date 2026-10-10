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

function json(res, status, body) {
  res.writeHead(status, {"content-type":"application/json; charset=utf-8"});
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
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function normalizePhone(phone) {
  return String(phone || "").replace(/[^0-9]/g, "");
}

function jidFor(phone) {
  const value = String(phone || "").trim();
  if (/^[0-9]+@(s\\.whatsapp\\.net|g\\.us)$/.test(value)) return value;
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
        ...(WEBHOOK_SECRET ? {"x-engine-secret":WEBHOOK_SECRET} : {})
      },
      body:JSON.stringify(event)
    });
  } catch (error) {
    console.error("Webhook delivery failed:", error?.message || error);
  }
}

async function startSession(sessionId, phone) {
  const existing = sessions.get(sessionId);
  if (existing?.sock) return existing;

  const sessionDir = path.join(AUTH_ROOT, sessionId);
  await fs.mkdir(sessionDir, {recursive:true});
  const {state, saveCreds} = await useMultiFileAuthState(sessionDir);

  let version;
  try {
    const latest = await fetchLatestBaileysVersion();
    version = latest.version;
  } catch {}

  const sock = makeWASocket({
    auth: state,
    version,
    browser: Browsers.ubuntu(ENGINE_NAME),
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
    connectedAt: null,
    lastError: null
  };
  sessions.set(sessionId, session);

  sock.ev.on("creds.update", saveCreds);

  sock.ev.on("connection.update", async ({connection, lastDisconnect}) => {
    if (connection === "open") {
      session.status = "connected";
      session.pairingCode = null;
      session.connectedAt = new Date().toISOString();
      session.lastError = null;
      console.log(`WhatsApp connected: ${sessionId}`);
      await notifyWebhook({type:"connection.open",sessionId,phone:session.phone});
    } else if (connection === "close") {
      const code = lastDisconnect?.error?.output?.statusCode;
      session.lastError = String(code || "connection_closed");
      session.status = code === DisconnectReason.loggedOut ? "logged_out" : "reconnecting";
      session.sock = null;
      await notifyWebhook({type:"connection.close",sessionId,phone:session.phone,code});
      if (code !== DisconnectReason.loggedOut) {
        setTimeout(() => startSession(sessionId, session.phone).catch(err => {
          session.status = "error";
          session.lastError = err?.message || String(err);
        }), 2000);
      }
    }
  });

  sock.ev.on("messages.upsert", async ({messages, type}) => {
    if (type !== "notify") return;
    for (const msg of messages) {
      if (!msg?.message || msg.key?.fromMe) continue;
      const remoteJid = msg.key.remoteJid;
      if (!remoteJid || remoteJid.endsWith("@status")) continue;
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

  if (!state.creds.registered) {
    setTimeout(async () => {
      try {
        session.pairingCode = await sock.requestPairingCode(session.phone);
        session.status = "pairing";
        console.log(`Pairing code for ${sessionId}: ${session.pairingCode}`);
      } catch (error) {
        session.lastError = error?.message || String(error);
        console.error("Pairing code failed:", session.lastError);
      }
    }, 2500);
  }

  return session;
}

async function closeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return false;
  try { session.sock?.end(undefined); } catch {}
  sessions.delete(sessionId);
  return true;
}

async function route(req, res) {
  const pathname = new URL(req.url || "/", "http://localhost").pathname.replace(/\/+$/, "") || "/";
  if (req.method === "GET" && pathname === "/health") {
    return json(res,200,{ok:true,engine:ENGINE_NAME,status:"online",sessions:sessions.size,timestamp:new Date().toISOString()});
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
    let payload={};
    try { payload=JSON.parse(await readBody(req)||"{}"); } catch { return json(res,400,{ok:false,error:"Invalid JSON"}); }
    const sessionId=String(payload.sessionId||"").trim();
    const phone=normalizePhone(payload.phone);
    if (!sessionId || !/^\d{8,15}$/.test(phone)) return json(res,400,{ok:false,error:"sessionId and international phone number are required"});
    try {
      const session=await startSession(sessionId,phone);
      return json(res,200,{ok:true,sessionId,phone,status:session.status,pairingCode:session.pairingCode||null});
    } catch(error) {
      return json(res,500,{ok:false,error:error?.message||String(error)});
    }
  }

  if (req.method === "GET" && pathname.startsWith("/status/")) {
    const sessionId=decodeURIComponent(pathname.slice("/status/".length));
    const s=sessions.get(sessionId);
    if (!s) return json(res,404,{ok:false,error:"Session not found"});
    return json(res,200,{ok:true,sessionId:s.sessionId,phone:s.phone,status:s.status,pairingCode:s.pairingCode,connectedAt:s.connectedAt,lastError:s.lastError});
  }

  if (req.method === "POST" && pathname === "/send") {
    let payload={};
    try { payload=JSON.parse(await readBody(req)||"{}"); } catch { return json(res,400,{ok:false,error:"Invalid JSON"}); }
    const s=sessions.get(String(payload.sessionId||""));
    const to=jidFor(payload.to);
    const text=String(payload.text||"").trim();
    if (!s?.sock || s.status !== "connected") return json(res,409,{ok:false,error:"Session is not connected"});
    if (!to || !text) return json(res,400,{ok:false,error:"to and text are required"});
    try {
      const result=await s.sock.sendMessage(to,{text});
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
  console.error(error);
  json(res,500,{ok:false,error:"Internal server error"});
}));

server.listen(PORT,"0.0.0.0",()=>console.log(`${ENGINE_NAME} listening on ${PORT}`));

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
