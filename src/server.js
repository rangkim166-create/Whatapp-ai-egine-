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
const AUTH_ROOT = path.resolve(process.env.AUTH_ROOT || "/app/auth");
const ENGINE_NAME = "Ash WhatsApp AI Engine";
const sessions = new Map();
const startsInProgress = new Map();
let shuttingDown = false;

function isPaired(creds) {
  return Boolean(creds?.account && creds?.me?.id);
}

async function wipeSessionDir(dir) {
  await fs.rm(dir, { recursive: true, force: true });
}

function safeSessionId(value) {
  const id = String(value || "").trim();
  return /^[a-zA-Z0-9_-]{1,100}$/.test(id) ? id : "";
}

function json(res, status, body) {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
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
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1024 * 1024) throw Object.assign(new Error("Request body too large"), { statusCode: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function normalizePhone(phone) {
  return String(phone || "").replace(/\D/g, "");
}

function jidFor(input) {
  const value = String(input || "").trim();
  if (/^\d+(?::\d+)?@(s\.whatsapp\.net|g\.us|lid)$/.test(value)) return value;
  const n = normalizePhone(value);
  return n ? `${n}@s.whatsapp.net` : null;
}

async function notifyWebhook(event) {
  if (!WEBHOOK_URL) return;
  const headers = { "content-type": "application/json" };
  if (WEBHOOK_SECRET) headers["x-webhook-secret"] = WEBHOOK_SECRET;
  else if (ENGINE_SECRET) headers["x-engine-secret"] = ENGINE_SECRET;
  try {
    const response = await fetch(WEBHOOK_URL, {
      method: "POST",
      headers,
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) console.error("Webhook delivery returned HTTP", response.status);
  } catch (error) {
    console.error("Webhook delivery failed:", error?.message || error);
  }
}

async function startSession(sessionId, phone) {
  if (shuttingDown) throw new Error("Engine is shutting down");
  const existing = sessions.get(sessionId);
  if (existing?.sock) return existing;
  if (startsInProgress.has(sessionId)) return startsInProgress.get(sessionId);

  const task = (async () => {
    const sessionDir = path.resolve(AUTH_ROOT, sessionId);
    if (!sessionDir.startsWith(AUTH_ROOT + path.sep)) throw new Error("Invalid session ID");
    await fs.mkdir(sessionDir, { recursive: true });

    let loaded = await useMultiFileAuthState(sessionDir);
    // A pairing attempt that never completed can leave a partial identity.
    // Only reset when the credentials are clearly not a completed pairing.
    if (!isPaired(loaded.state.creds)) {
      await wipeSessionDir(sessionDir);
      await fs.mkdir(sessionDir, { recursive: true });
      loaded = await useMultiFileAuthState(sessionDir);
    }
    const { state, saveCreds } = loaded;
    const normalizedPhone = normalizePhone(phone);
    if (!/^\d{8,15}$/.test(normalizedPhone) && !isPaired(state.creds)) {
      throw new Error("Enter a valid international phone number including country code");
    }

    if (normalizedPhone) {
      await fs.writeFile(path.join(sessionDir, "meta.json"), JSON.stringify({ phone: normalizedPhone })).catch(() => {});
    }

    let version;
    try {
      const latest = await fetchLatestBaileysVersion();
      version = latest.version;
    } catch (error) {
      console.warn("Could not fetch latest WhatsApp web version; using Baileys default:", error?.message || error);
    }

    const sock = makeWASocket({
      auth: state,
      ...(version ? { version } : {}),
      browser: Browsers.ubuntu(ENGINE_NAME),
      printQRInTerminal: false,
      markOnlineOnConnect: false,
      syncFullHistory: false,
      connectTimeoutMs: 60000,
      defaultQueryTimeoutMs: 60000
    });

    const session = {
      sessionId, phone: normalizedPhone, sock,
      status: isPaired(state.creds) ? "connecting" : "pairing",
      pairingCode: null, connectedAt: null, lastError: null,
      codeRequested: false, manualClose: false
    };
    sessions.set(sessionId, session);
    sock.ev.on("creds.update", saveCreds);

    async function requestCode() {
      if (session.codeRequested || isPaired(state.creds) || !session.phone || session.manualClose) return;
      session.codeRequested = true;
      try {
        const code = await sock.requestPairingCode(session.phone);
        session.pairingCode = code;
        session.status = "pairing";
        session.lastError = null;
        // Do not log pairing codes; they can be used to link the account.
      } catch (error) {
        session.codeRequested = false;
        session.lastError = error?.message || String(error);
        session.status = "error";
        console.error("Pairing code request failed:", session.lastError);
      }
    }

    sock.ev.on("connection.update", async ({ connection, lastDisconnect, qr }) => {
      if (qr && !isPaired(state.creds)) await requestCode();

      if (connection === "open") {
        session.status = "connected";
        session.pairingCode = null;
        session.connectedAt = new Date().toISOString();
        session.lastError = null;
        await notifyWebhook({ type: "connection.open", sessionId, phone: session.phone });
      } else if (connection === "close") {
        const code = lastDisconnect?.error?.output?.statusCode;
        const paired = isPaired(state.creds);
        session.sock = null;
        session.pairingCode = null;
        await notifyWebhook({ type: "connection.close", sessionId, phone: session.phone, code });
        if (session.manualClose || shuttingDown) return;

        if (code === DisconnectReason.loggedOut) {
          session.status = "logged_out";
          session.lastError = "Logged out from WhatsApp. Connect again to relink.";
          // Keep evidence for diagnostics; the next explicit connect will reset unpaired creds.
          await wipeSessionDir(sessionDir).catch(() => {});
          return;
        }
        if (!paired) {
          session.status = "error";
          session.lastError = code === DisconnectReason.timedOut
            ? "Pairing timed out. Tap Connect WhatsApp and request a fresh code."
            : `Pairing did not complete (${code || "connection closed"}). Tap Connect WhatsApp to try again.`;
          return;
        }
        if (code === DisconnectReason.connectionReplaced) {
          session.status = "error";
          session.lastError = "This WhatsApp account was opened somewhere else.";
          return;
        }
        session.status = "reconnecting";
        session.lastError = String(code || "connection_closed");
        setTimeout(() => {
          if (shuttingDown || session.manualClose) return;
          startSession(sessionId, session.phone).catch(error => {
            session.status = "error";
            session.lastError = error?.message || String(error);
          });
        }, 2000);
      } else if (connection === "connecting" && !isPaired(state.creds) && session.phone) {
        // Pairing-code mode must be requested once the socket has begun connecting.
        // Small delay lets the websocket initialize; this is not a blind reconnect loop.
        setTimeout(() => { void requestCode(); }, 1500);
      }
    });

    sock.ev.on("messages.upsert", async ({ messages, type }) => {
      if (type !== "notify") return;
      for (const msg of messages) {
        if (!msg?.message || msg.key?.fromMe) continue;
        const remoteJid = msg.key.remoteJid;
        if (!remoteJid || remoteJid.endsWith("@status")) continue;
        const body = msg.message.conversation ||
          msg.message.extendedTextMessage?.text ||
          msg.message.imageMessage?.caption ||
          msg.message.videoMessage?.caption || "";
        if (!body) continue;
        await notifyWebhook({
          type: "message.incoming", sessionId, phone: session.phone,
          waChatId: remoteJid, waMessageId: msg.key.id || null,
          senderPhone: remoteJid.split("@")[0], body,
          timestamp: new Date().toISOString()
        });
      }
    });
    return session;
  })();

  startsInProgress.set(sessionId, task);
  try { return await task; }
  finally { startsInProgress.delete(sessionId); }
}

async function closeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return false;
  session.manualClose = true;
  try { session.sock?.end(undefined); } catch {}
  sessions.delete(sessionId);
  return true;
}

async function route(req, res) {
  const pathname = new URL(req.url || "/", "http://localhost").pathname.replace(/\/+$/, "") || "/";
  if (req.method === "GET" && pathname === "/health") {
    return json(res, 200, { ok: true, engine: ENGINE_NAME, status: "online", sessions: sessions.size, timestamp: new Date().toISOString() });
  }
  if (!authorized(req)) return json(res, 401, { ok: false, error: "Unauthorized" });

  if (req.method === "GET" && pathname === "/") {
    return json(res, 200, { ok: true, engine: ENGINE_NAME, version: "2.1.0", whatsapp: "baileys" });
  }
  if (req.method === "GET" && pathname === "/sessions") {
    return json(res, 200, { ok: true, sessions: [...sessions.values()].map(s => ({
      sessionId: s.sessionId, phone: s.phone, status: s.status,
      pairingCode: s.pairingCode, connectedAt: s.connectedAt, lastError: s.lastError
    })) });
  }
  if (req.method === "POST" && pathname === "/connect") {
    let payload = {};
    try { payload = JSON.parse(await readBody(req) || "{}"); }
    catch (error) { return json(res, error.statusCode || 400, { ok: false, error: error.statusCode === 413 ? error.message : "Invalid JSON" }); }
    const sessionId = safeSessionId(payload.sessionId);
    const phone = normalizePhone(payload.phone);
    if (!sessionId || !/^\d{8,15}$/.test(phone)) {
      return json(res, 400, { ok: false, error: "A valid sessionId and international phone number (8–15 digits, including country code) are required" });
    }
    try {
      const session = await startSession(sessionId, phone);
      return json(res, 200, { ok: true, sessionId, phone, status: session.status, pairingCode: session.pairingCode || null, lastError: session.lastError });
    } catch (error) {
      return json(res, 500, { ok: false, error: error?.message || String(error) });
    }
  }
  if (req.method === "GET" && pathname.startsWith("/status/")) {
    const sessionId = safeSessionId(decodeURIComponent(pathname.slice("/status/".length)));
    if (!sessionId) return json(res, 400, { ok: false, error: "Invalid session ID" });
    const s = sessions.get(sessionId);
    if (!s) return json(res, 404, { ok: false, error: "Session not found" });
    return json(res, 200, { ok: true, sessionId: s.sessionId, phone: s.phone, status: s.status, pairingCode: s.pairingCode, connectedAt: s.connectedAt, lastError: s.lastError });
  }
  if (req.method === "POST" && pathname === "/send") {
    let payload = {};
    try { payload = JSON.parse(await readBody(req) || "{}"); }
    catch (error) { return json(res, error.statusCode || 400, { ok: false, error: error.statusCode === 413 ? error.message : "Invalid JSON" }); }
    const s = sessions.get(safeSessionId(payload.sessionId));
    const to = jidFor(payload.to);
    const messageText = String(payload.text || "").trim();
    if (!s?.sock || s.status !== "connected") return json(res, 409, { ok: false, error: "Session is not connected" });
    if (!to || !messageText) return json(res, 400, { ok: false, error: "to and text are required" });
    try {
      const result = await s.sock.sendMessage(to, { text: messageText });
      return json(res, 200, { ok: true, messageId: result?.key?.id || null, to });
    } catch (error) {
      return json(res, 500, { ok: false, error: error?.message || String(error) });
    }
  }
  if (req.method === "POST" && pathname === "/disconnect") {
    let payload = {};
    try { payload = JSON.parse(await readBody(req) || "{}"); }
    catch (error) { return json(res, error.statusCode || 400, { ok: false, error: error.statusCode === 413 ? error.message : "Invalid JSON" }); }
    return json(res, 200, { ok: await closeSession(safeSessionId(payload.sessionId)) });
  }
  return json(res, 404, { ok: false, error: "Not found" });
}

const server = http.createServer((req, res) => {
  route(req, res).catch(error => {
    console.error("Request failed:", error?.message || error);
    json(res, error.statusCode || 500, { ok: false, error: error.statusCode === 413 ? error.message : "Internal server error" });
  });
});

async function restoreSessions() {
  let dirs = [];
  try { dirs = await fs.readdir(AUTH_ROOT, { withFileTypes: true }); }
  catch (error) {
    if (error.code !== "ENOENT") console.error("Could not scan auth storage:", error?.message || error);
    return;
  }
  for (const d of dirs) {
    if (!d.isDirectory() || !safeSessionId(d.name)) continue;
    const dir = path.join(AUTH_ROOT, d.name);
    try {
      const creds = JSON.parse(await fs.readFile(path.join(dir, "creds.json"), "utf8"));
      if (!isPaired(creds)) {
        // Don't destroy partial credentials during startup. Leave them for an explicit retry.
        console.warn("Skipping incomplete auth state for session:", d.name);
        continue;
      }
      let phone = "";
      try { phone = JSON.parse(await fs.readFile(path.join(dir, "meta.json"), "utf8")).phone || ""; } catch {}
      if (!phone) phone = String(creds.me.id).split(/[:@]/)[0];
      await startSession(d.name, phone);
      console.log("Restored WhatsApp session:", d.name);
    } catch (error) {
      // Preserve auth files on transient I/O or socket errors; never wipe on a generic failure.
      console.error("Could not restore session", d.name, error?.message || error);
    }
  }
}

server.listen(PORT, "0.0.0.0", () => {
  console.log(`${ENGINE_NAME} listening on ${PORT}`);
  void restoreSessions();
});

async function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}; shutting down gracefully`);
  try { await Promise.all([...sessions.keys()].map(closeSession)); }
  catch (error) { console.error("Session shutdown error:", error?.message || error); }
  await new Promise(resolve => server.close(() => resolve())).catch(() => {});
  console.log("HTTP server closed");
  process.exit(0);
}
process.on("SIGTERM", () => { void gracefulShutdown("SIGTERM"); });
process.on("SIGINT", () => { void gracefulShutdown("SIGINT"); });
