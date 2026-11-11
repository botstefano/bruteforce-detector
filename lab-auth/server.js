import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "public");
const PORT = Number.parseInt(process.env.PORT || "10000", 10);
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const CENTINELA_API_URL = (process.env.CENTINELA_API_URL || "").trim().replace(/\/+$/, "");
const CENTINELA_INGEST_TOKEN = (process.env.CENTINELA_INGEST_TOKEN || "").trim();
const CAMPAIGN_ID = "laboratorio-web-auth-v1";
const MAX_BODY_BYTES = 4096;
const RATE_WINDOW_MS = 60_000;
const MAX_ATTEMPTS_PER_IP = 60;
const ipBuckets = new Map();

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest();
}

function loadCredentials() {
  const raw = process.env.LAB_CREDENTIALS_JSON || "";
  if (!raw) throw new Error("Falta LAB_CREDENTIALS_JSON.");

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("LAB_CREDENTIALS_JSON no contiene un objeto JSON válido.");
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("LAB_CREDENTIALS_JSON debe ser un objeto de usuario y contraseña.");
  }

  const expectedUsers = ["lab01", "lab02", "lab03"];
  const actualUsers = Object.keys(parsed).sort();
  if (actualUsers.join(",") !== expectedUsers.join(",")) {
    throw new Error("Configura exactamente las cuentas lab01, lab02 y lab03.");
  }

  const passwordDigests = new Map();
  const distinct = new Set();

  for (const username of expectedUsers) {
    const password = parsed[username];
    if (typeof password !== "string" || password.length < 16) {
      throw new Error("Cada contraseña de laboratorio debe tener al menos 16 caracteres.");
    }
    const digest = sha256(password);
    const digestHex = digest.toString("hex");
    if (distinct.has(digestHex)) {
      throw new Error("Cada cuenta debe tener una contraseña diferente.");
    }
    distinct.add(digestHex);
    passwordDigests.set(username, digest);
  }

  return passwordDigests;
}

function validateConfiguration() {
  if (!CENTINELA_API_URL) throw new Error("Falta CENTINELA_API_URL.");
  const target = new URL(CENTINELA_API_URL);
  if (IS_PRODUCTION && target.protocol !== "https:") {
    throw new Error("CENTINELA_API_URL debe utilizar HTTPS en producción.");
  }
  if (CENTINELA_INGEST_TOKEN.length < 32) {
    throw new Error("CENTINELA_INGEST_TOKEN debe contener al menos 32 caracteres.");
  }
}

const credentialDigests = loadCredentials();
validateConfiguration();
const dummyDigest = sha256("centinela-lab-dummy-account-comparison");

function safeEqualDigest(left, right) {
  return left.length === right.length && timingSafeEqual(left, right);
}

function authenticate(username, password) {
  const expected = credentialDigests.get(username) || dummyDigest;
  const supplied = sha256(password);
  const matches = safeEqualDigest(supplied, expected);
  return credentialDigests.has(username) && matches;
}

function clientIpFromRender(req) {
  // Render routes public requests through Cloudflare. CF-Connecting-IP is set
  // by Cloudflare and is preferred over the client-controllable X-Forwarded-For chain.
  const cloudflareIp = req.headers["cf-connecting-ip"];
  const candidate = Array.isArray(cloudflareIp) ? cloudflareIp[0] : cloudflareIp;

  if (candidate && isIP(candidate.trim())) return candidate.trim();

  if (!IS_PRODUCTION) {
    const localIp = req.socket.remoteAddress || "127.0.0.1";
    return localIp.startsWith("::ffff:") ? localIp.slice(7) : localIp;
  }

  throw new Error("No se pudo verificar la IP de origen proporcionada por Render.");
}

function consumeRateLimit(ip) {
  const now = Date.now();
  const current = ipBuckets.get(ip);

  if (!current || now - current.startedAt >= RATE_WINDOW_MS) {
    ipBuckets.set(ip, { startedAt: now, count: 1 });
    return { allowed: true, remaining: MAX_ATTEMPTS_PER_IP - 1 };
  }

  if (current.count >= MAX_ATTEMPTS_PER_IP) {
    return {
      allowed: false,
      retryAfter: Math.max(1, Math.ceil((RATE_WINDOW_MS - (now - current.startedAt)) / 1000))
    };
  }

  current.count += 1;
  if (ipBuckets.size > 10_000) {
    for (const [key, bucket] of ipBuckets) {
      if (now - bucket.startedAt >= RATE_WINDOW_MS) ipBuckets.delete(key);
    }
  }
  return { allowed: true, remaining: MAX_ATTEMPTS_PER_IP - current.count };
}

function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  if (IS_PRODUCTION) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  res.end(body);
}

function originIsSame(req) {
  const origin = req.headers.origin;
  if (typeof origin !== "string") return false;

  try {
    const parsed = new URL(origin);
    const host = String(req.headers.host || "").toLowerCase();
    const secureScheme = parsed.protocol === "https:";
    const localDevelopment = !IS_PRODUCTION &&
      parsed.protocol === "http:" &&
      (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1");
    return parsed.host.toLowerCase() === host && (secureScheme || localDevelopment);
  } catch {
    return false;
  }
}

async function readJsonBody(req) {
  const contentType = String(req.headers["content-type"] || "").toLowerCase();
  if (!contentType.startsWith("application/json")) {
    const error = new Error("Content-Type no admitido.");
    error.statusCode = 415;
    throw error;
  }

  let body = "";
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const error = new Error("La solicitud supera el tamaño permitido.");
      error.statusCode = 413;
      throw error;
    }
    body += chunk.toString("utf8");
  }

  try {
    return JSON.parse(body || "{}");
  } catch {
    const error = new Error("El cuerpo JSON no es válido.");
    error.statusCode = 400;
    throw error;
  }
}

async function sendEventToCentinela(username, authenticated, ip) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);

  try {
    const response = await fetch(CENTINELA_API_URL + "/registrar_intento", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + CENTINELA_INGEST_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        usuario: username,
        exitoso: authenticated,
        ip,
        campaign_id: CAMPAIGN_ID
      }),
      signal: controller.signal
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.persisted !== true || typeof payload.event_id !== "string") {
      const error = new Error("Centinela no confirmó el registro del evento.");
      error.statusCode = 503;
      throw error;
    }
    return payload;
  } finally {
    clearTimeout(timeout);
  }
}

async function serveStatic(res, filename, contentType) {
  try {
    const content = await fs.readFile(path.join(publicDir, filename));
    res.writeHead(200, {
      "Content-Type": contentType,
      "Content-Length": content.length
    });
    res.end(content);
  } catch {
    sendJson(res, 404, { error: "Recurso no encontrado." });
  }
}

const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);

  const requestUrl = new URL(req.url || "/", "http://localhost");
  const pathname = requestUrl.pathname;

  if (req.method === "GET" && pathname === "/health") {
    return sendJson(res, 200, {
      status: "ok",
      service: "centinela-auth-lab",
      credentials_configured: credentialDigests.size === 3,
      centinela_configured: Boolean(CENTINELA_API_URL && CENTINELA_INGEST_TOKEN)
    });
  }

  if (req.method === "GET" && pathname === "/") {
    return serveStatic(res, "index.html", "text/html; charset=utf-8");
  }
  if (req.method === "GET" && pathname === "/app.js") {
    return serveStatic(res, "app.js", "text/javascript; charset=utf-8");
  }
  if (req.method === "GET" && pathname === "/styles.css") {
    return serveStatic(res, "styles.css", "text/css; charset=utf-8");
  }
  if (req.method === "GET" && pathname === "/favicon.ico") {
    res.writeHead(204);
    return res.end();
  }

  if (req.method === "POST" && pathname === "/login") {
    if (!originIsSame(req)) {
      return sendJson(res, 403, { error: "Origen de solicitud no permitido." });
    }

    let data;
    try {
      data = await readJsonBody(req);
    } catch (error) {
      return sendJson(res, error.statusCode || 400, { error: error.message });
    }

    const username = typeof data.username === "string" ? data.username.trim() : "";
    const password = typeof data.password === "string" ? data.password : "";

    if (!/^[a-zA-Z0-9_.@-]{1,64}$/.test(username) || password.length > 256) {
      return sendJson(res, 400, { error: "Introduce un usuario y una contraseña válidos." });
    }

    let ip;
    try {
      ip = clientIpFromRender(req);
    } catch (error) {
      console.error("No se pudo determinar la IP del cliente:", error.message);
      return sendJson(res, 503, { error: "No se pudo verificar el origen de la conexión. El intento no fue enviado a Centinela." });
    }

    const rate = consumeRateLimit(ip);
    if (!rate.allowed) {
      res.setHeader("Retry-After", String(rate.retryAfter));
      return sendJson(res, 429, {
        error: "Se alcanzó el límite temporal del laboratorio. Espera antes de volver a intentarlo.",
        retry_after_seconds: rate.retryAfter,
        event_recorded: false
      });
    }

    const authenticated = authenticate(username, password);

    try {
      // La contraseña se valida localmente y nunca se envía a Centinela.
      // Solo se transmite usuario, resultado e IP verificada.
      const event = await sendEventToCentinela(username, authenticated, ip);
      if (authenticated) {
        return sendJson(res, 200, {
          authenticated: true,
          event_recorded: true,
          event_id: event.event_id,
          message: "Acceso autorizado. Centinela recibió el evento."
        });
      }
      return sendJson(res, 401, {
        authenticated: false,
        event_recorded: true,
        event_id: event.event_id,
        message: "Usuario o contraseña incorrectos. Centinela recibió el evento."
      });
    } catch (error) {
      console.error("No se pudo entregar el evento a Centinela:", error.message);
      return sendJson(res, 503, {
        error: "El intento no pudo confirmarse en Centinela. No vuelvas a enviarlo hasta comprobar la captura.",
        event_recorded: false
      });
    }
  }

  if (req.method === "GET" && pathname === "/robots.txt") {
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("User-agent: *\nDisallow: /\n");
  }

  sendJson(res, 404, { error: "Ruta no encontrada." });
});

server.requestTimeout = 10_000;
server.headersTimeout = 12_000;
server.keepAliveTimeout = 5_000;

server.listen(PORT, "0.0.0.0", () => {
  console.log("Centinela Auth Lab escuchando en el puerto " + PORT);
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
