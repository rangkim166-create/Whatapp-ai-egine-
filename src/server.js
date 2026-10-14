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

const AUTH_VAULT_BASE = (process.env.AUTH_VAULT_URL || ((process.env.SUPABASE_URL || "") + "/functions/v1/whatsapp-auth-vault")).replace(/\\/+$/, "");
const snapshotJobs = new Map();

function authVaultEnabled() {
  const raw = process.env.AUTH_VAULT_ENCRYPTION_KEY || "";
  const key = /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
  return Boolean(AUTH_VAULT_BASE && process.env.ENGINE_SECRET && key.length === 32);
}

function authVaultKey() {
  const raw = process.env.AUTH_VAULT_ENCRYPTION_KEY || "";
  const key = /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
  if (key.length !== 32) throw new Error("Auth vault encryption key is not configured");
  return key;
}

function encryptAuthSnapshot(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", authVaultKey(), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return JSON.stringify({ version: 1, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: encrypted.toString("base64") });
}

function decryptAuthSnapshot(value) {
  const envelope = JSON.parse(value);
  if (envelope?.version !== 1 || !envelope.iv || !envelope.tag || !envelope.data) throw new Error("Invalid auth snapshot envelope");
  const decipher = crypto.createDecipheriv("aes-256-gcm", authVaultKey(), Buffer.from(envelope.iv, "base64"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const clear = Buffer.concat([decipher.update(Buffer.from(envelope.data, "base64")), decipher.final()]).toString("utf8");
  const snapshot = JSON.parse(clear);
  if (snapshot?.version !== 1 || !snapshot.files || typeof snapshot.files !== "object") throw new Error("Invalid auth snapshot payload");
  return snapshot;
}

async function authVaultRequest(sessionId, method, body) {
  if (!authVaultEnabled()) throw new Error("Auth vault is not configured");
  const suffix = sessionId === null ? "/sessions" : "/session/" + encodeURIComponent(sessionId);
  const response = await fetch(AUTH_VAULT_BASE + suffix, {
    method,
    headers: { "x-engine-secret": ENGINE_SECRET, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) {
    const detail = response.status === 404 ? "not found" : "HTTP " + response.status;
    if (response.status === 404 && method === "GET") return null;
    throw new Error("Auth vault request failed: " + detail);
  }
  return response.json().catch(() => ({}));
}

async function persistAuthSnapshot(sessionId) {
  if (!authVaultEnabled()) return false;
  const previous = snapshotJobs.get(sessionId);
  if (previous) await previous.catch(() => {});
  const job = (async () => {
    const sessionDir = path.join(AUTH_ROOT, sessionId);
    const entries = await fs.readdir(sessionDir, { withFileTypes: true }).catch(() => []);
    const files = {};
    for (const entry of entries) {
      if (!entry.isFile() || !/^[A-Za-z0-9._-]+\\.json$/.test(entry.name)) continue;
      files[entry.name] = await fs.readFile(path.join(sessionDir, entry.name), "utf8");
    }
    if (!Object.keys(files).length) return false;
    const encrypted = encryptAuthSnapshot({ version: 1, files });
    await authVaultRequest(sessionId, "PUT", { encrypted });
    return true;
  })();
  snapshotJobs.set(sessionId, job);
  try { return await job; }
  finally { if (snapshotJobs.get(sessionId) === job) snapshotJobs.delete(sessionId); }
}

async function restoreAuthSnapshot(sessionId, sessionDir) {
  if (!authVaultEnabled()) return false;
  await fs.mkdir(sessionDir, { recursive: true });
  const existing = await fs.readdir(sessionDir, { withFileTypes: true }).catch(() => []);
  if (existing.some(entry => entry.isFile() && entry.name.endsWith(".json"))) return false;
  const stored = await authVaultRequest(sessionId, "GET");
  if (!stored || typeof stored.encrypted !== "string") return false;
  const snapshot = decryptAuthSnapshot(stored.encrypted);
  const names = Object.keys(snapshot.files);
  if (!names.length || names.length > 2000) return false;
  for (const name of names) {
    if (!/^[A-Za-z0-9._-]+\\.json$/.test(name) || typeof snapshot.files[name] !== "string") throw new Error("Invalid auth snapshot file");
    const target = path.join(sessionDir, name);
    const temp = target + ".restore-tmp";
    await fs.writeFile(temp, snapshot.files[name], { mode: 0o600 });
    await fs.rename(temp, target);
  }
  return true;
}

async function listAuthVaultSessions() {
  if (!authVaultEnabled()) return [];
  const result = await authVaultRequest(null, "GET");
  return Array.isArray(result?.sessions) ? result.sessions.filter(id => /^[A-Za-z0-9_-]{8,80}$/.test(id)) : [];
}

async function deleteAuthSnapshot(sessionId) {
  if (!authVaultEnabled()) return;
  try { await authVaultRequest(sessionId, "DELETE"); }
  catch (error) { console.warn("Could not remove invalid saved session", sessionId, error?.message || "vault error"); }
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
  try { await restoreAuthSnapshot(sessionId, sessionDir); }
  catch (error) { console.warn("Saved auth restore failed for session", sessionId, error?.message || "vault error"); }
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
  session.persistTimer = setInterval(() => {
    void persistAuthSnapshot(sessionId).catch(error => console.warn("Auth snapshot save failed for session", sessionId, error?.message || "vault error"));
  }, 5000);
  session.persistTimer.unref?.();

  sock.ev.on("creds.update", async () => {
    try { await saveCreds(); await persistAuthSnapshot(sessionId); }
    catch (error) { console.warn("Auth credential persistence failed for session", sessionId, error?.message || "vault error"); }
  });

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
      await persistAuthSnapshot(sessionId).catch(error => console.warn("Connected session snapshot save failed", sessionId, error?.message || "vault error"));
      await notifyWebhook({type:"connection.open",sessionId,phone:session.phone});
    } else if (connection === "close") {
      clearTimeout(pairingTimer);
      const code = lastDisconnect?.error?.output?.statusCode;
      session.lastError = String(code || "connection_closed");
      session.sock = null;
      clearInterval(session.persistTimer);
      await persistAuthSnapshot(sessionId).catch(error => console.warn("Closed session snapshot save failed", sessionId, error?.message || "vault error"));
      await notifyWebhook({type:"connection.close",sessionId,phone:session.phone,code});
      if (code === DisconnectReason.loggedOut || code === 401) {
        session.status = "logged_out";
        await deleteAuthSnapshot(sessionId);
        await fs.rm(sessionDir, {recursive:true, force:true}).catch(() => {});
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
  clearInterval(session.persistTimer);
  await persistAuthSnapshot(sessionId).catch(error => console.warn("Session shutdown snapshot save failed", sessionId, error?.message || "vault error"));
  try { session.sock?.end(undefined); } catch {}
  sessions.delete(sessionId);
  return true;
}

async function restoreSavedSession(sessionId) {
  if (!/^[a-zA-Z0-9_-]{8,80}$/.test(sessionId)) return null;
  if (sessions.has(sessionId)) return sessions.get(sessionId);
  const sessionDir = path.join(AUTH_ROOT, sessionId);
  try {
    await fs.mkdir(sessionDir, {recursive:true});
    await restoreAuthSnapshot(sessionId, sessionDir);
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
    let savedIds = [];
    try { savedIds = await listAuthVaultSessions(); }
    catch (error) { console.warn("Auth vault session listing failed:", error?.message || "vault error"); }
    for (const id of savedIds) {
      if (sessions.size >= MAX_SESSIONS) break;
      try { await restoreSavedSession(id); }
      catch (error) { console.warn("Could not restore saved session", id, error?.message || "restore error"); }
    }
    const entries = await fs.readdir(AUTH_ROOT, {withFileTypes:true});
    for (const entry of entries) {
      if (!entry.isDirectory() || sessions.size >= MAX_SESSIONS || sessions.has(entry.name)) continue;
      await restoreSavedSession(entry.name);
    }
    console.log("Saved WhatsApp session restore scan finished; restored " + sessions.size + " session(s)");
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

server.listen(PORT,"0.0.0.0",()=>{console.log(`${ENGINE_NAME} listening on ${PORT}`);if (!authVaultEnabled()) console.warn("Auth vault persistence is not configured; session recovery across restarts is disabled");void restoreSavedSessionsAtBoot();});

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
