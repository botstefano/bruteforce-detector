import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "public");
const PORT = Number.parseInt(process.env.PORT || "10000", 10);
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const CENTINELA_API_URL = (process.env.CENTINELA_API_URL || "").trim().replace(/\/+$/, "");
const CENTINELA_INGEST_TOKEN = (process.env.CENTINELA_INGEST_TOKEN || "").trim();
const CAMPAIGN_ID = "laboratorio-web-auth-v2";
const EXPECTED_USERS = ["participante-01", "participante-02", "participante-03"];
const MAX_BODY_BYTES = 4096;
const RATE_WINDOW_MS = 60_000;
const MAX_ATTEMPTS_PER_IP = 60;
const ACCOUNT_FAILURE_WINDOW_MS = 15 * 60_000;
const MAX_FAILED_ATTEMPTS_PER_ACCOUNT = 5;
const ACCOUNT_LOCK_MS = 15 * 60_000;
const ipBuckets = new Map();
const accountFailures = new Map();

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest();
}

function parseJsonEnvironment(name) {
  const raw = process.env[name] || "";
  if (!raw) throw new Error(`Falta ${name}.`);
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${name} no contiene un objeto JSON válido.`);
  }
}

function validateAccountObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} debe ser un objeto JSON de cuentas.`);
  }
  const actual = Object.keys(value).sort();
  if (actual.join(",") !== [...EXPECTED_USERS].sort().join(",")) {
    throw new Error(`${name} debe contener exactamente participante-01, participante-02 y participante-03.`);
  }
}

function loadCredentials() {
  const parsed = parseJsonEnvironment("LAB_CREDENTIALS_V2_JSON");
  validateAccountObject(parsed, "LAB_CREDENTIALS_V2_JSON");
  const passwordDigests = new Map();
  const distinct = new Set();

  for (const username of EXPECTED_USERS) {
    const password = parsed[username];
    if (typeof password !== "string" || password.length < 16 || password.length > 256) {
      throw new Error("Cada contraseña de participante debe tener entre 16 y 256 caracteres.");
    }
    const digest = sha256(password);
    const digestHex = digest.toString("hex");
    if (distinct.has(digestHex)) throw new Error("Cada participante debe tener una contraseña diferente.");
    distinct.add(digestHex);
    passwordDigests.set(username, digest);
  }
  return passwordDigests;
}

function loadMfaSecrets() {
  const parsed = parseJsonEnvironment("LAB_TOTP_SECRETS_JSON");
  validateAccountObject(parsed, "LAB_TOTP_SECRETS_JSON");
  const secrets = new Map();

  for (const username of EXPECTED_USERS) {
    const secret = parsed[username];
    if (typeof secret !== "string" || !/^[A-Z2-7]{32}$/.test(secret)) {
      throw new Error("Cada semilla TOTP debe ser una clave Base32 de 32 caracteres.");
    }
    secrets.set(username, secret);
  }
  if (new Set(secrets.values()).size !== EXPECTED_USERS.length) {
    throw new Error("Cada participante debe tener una semilla TOTP diferente.");
  }
  return secrets;
}

function validateConfiguration() {
  if (!CENTINELA_API_URL) throw new Error("Falta CENTINELA_API_URL.");
  const target = new URL(CENTINELA_API_URL);
  if (IS_PRODUCTION && target.protocol !== "https:") {
    throw new Error("CENTINELA_API_URL debe utilizar HTTPS en producción.");
  }
  if (target.pathname !== "/" || target.search || target.hash || target.username || target.password) {
    throw new Error("CENTINELA_API_URL debe ser únicamente el origen del detector, sin rutas ni parámetros.");
  }
  if (CENTINELA_INGEST_TOKEN.length < 32) {
    throw new Error("CENTINELA_INGEST_TOKEN debe contener al menos 32 caracteres.");
  }
}

const credentialDigests = loadCredentials();
const totpSecrets = loadMfaSecrets();
validateConfiguration();
const dummyDigest = sha256("centinela-lab-dummy-account-comparison");

function safeEqualDigest(left, right) {
  return left.length === right.length && timingSafeEqual(left, right);
}

function authenticate(username, password) {
  const expected = credentialDigests.get(username) || dummyDigest;
  const supplied = sha256(password);
  return credentialDigests.has(username) && safeEqualDigest(supplied, expected);
}

function base32Decode(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let buffer = 0;
  const bytes = [];
  for (const character of value) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("Semilla TOTP Base32 no válida.");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totpAt(secret, timestampMs) {
  const counter = BigInt(Math.floor(timestampMs / 30_000));
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  const digest = createHmac("sha1", base32Decode(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

function verifyTotp(username, submittedCode) {
  if (!/^\d{6}$/.test(submittedCode)) return false;
  const secret = totpSecrets.get(username);
  if (!secret) return false;
  const now = Date.now();
  for (const drift of [-30_000, 0, 30_000]) {
    const expected = Buffer.from(totpAt(secret, now + drift));
    const supplied = Buffer.from(submittedCode);
    if (expected.length === supplied.length && timingSafeEqual(expected, supplied)) return true;
  }
  return false;
}

function provisioningUri(username) {
  const secret = totpSecrets.get(username);
  const label = encodeURIComponent("Centinela Auth Lab:" + username);
  const issuer = encodeURIComponent("Centinela Auth Lab");
  return `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}

function accountKey(username) {
  return sha256(username.toLowerCase()).toString("hex");
}

function accountLockStatus(username) {
  const key = accountKey(username);
  const state = accountFailures.get(key);
  if (!state) return { locked: false };
  const now = Date.now();
  if (state.lockedUntil > now) {
    return { locked: true, retryAfter: Math.max(1, Math.ceil((state.lockedUntil - now) / 1000)) };
  }
  const recent = state.failures.filter((timestamp) => now - timestamp < ACCOUNT_FAILURE_WINDOW_MS);
  if (recent.length === 0 || (state.lockedUntil && state.lockedUntil <= now)) {
    accountFailures.delete(key);
    return { locked: false };
  }
  state.failures = recent;
  return { locked: false };
}

function recordAccountFailure(username) {
  const key = accountKey(username);
  const now = Date.now();
  const state = accountFailures.get(key) || { failures: [], lockedUntil: 0 };
  state.failures = state.failures.filter((timestamp) => now - timestamp < ACCOUNT_FAILURE_WINDOW_MS);
  state.failures.push(now);

  if (state.failures.length >= MAX_FAILED_ATTEMPTS_PER_ACCOUNT) {
    state.lockedUntil = now + ACCOUNT_LOCK_MS;
    console.warn("ALERTA_SEGURIDAD: bloqueo temporal activado", {
      account_hash: key.slice(0, 16),
      failed_attempts: state.failures.length,
      lock_minutes: ACCOUNT_LOCK_MS / 60_000
    });
  }

  accountFailures.set(key, state);
  if (accountFailures.size > 10_000) {
    for (const [storedKey, storedState] of accountFailures) {
      const freshFailures = storedState.failures.filter((timestamp) => now - timestamp < ACCOUNT_FAILURE_WINDOW_MS);
      if (freshFailures.length === 0 && storedState.lockedUntil <= now) accountFailures.delete(storedKey);
    }
  }
  return accountLockStatus(username);
}

function clearAccountFailures(username) {
  accountFailures.delete(accountKey(username));
}

function clientIpFromRender(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const chain = Array.isArray(forwarded) ? forwarded.join(",") : String(forwarded || "");
  const firstAddress = chain.split(",")[0]?.trim() || "";
  if (firstAddress && isIP(firstAddress)) return firstAddress;

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

async function recordFailedAttempt(res, username, ip, reason) {
  const event = await sendEventToCentinela(username, false, ip);
  const lock = recordAccountFailure(username);
  if (lock.locked) {
    res.setHeader("Retry-After", String(lock.retryAfter));
    return sendJson(res, 423, {
      authenticated: false,
      event_recorded: true,
      event_id: event.event_id,
      retry_after_seconds: lock.retryAfter,
      message: "Cuenta bloqueada temporalmente por seguridad. El intento quedó registrado en Centinela."
    });
  }
  return sendJson(res, 401, {
    authenticated: false,
    event_recorded: true,
    event_id: event.event_id,
    message: reason || "Usuario, contraseña o código de autenticación incorrectos. Centinela recibió el evento."
  });
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
      mfa_configured: totpSecrets.size === 3,
      centinela_configured: Boolean(CENTINELA_API_URL && CENTINELA_INGEST_TOKEN),
      campaign_id: CAMPAIGN_ID
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

    const username = typeof data.username === "string" ? data.username.trim().toLowerCase() : "";
    const password = typeof data.password === "string" ? data.password : "";
    const totpCode = typeof data.totp_code === "string" ? data.totp_code.trim() : "";

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
        error: "Se alcanzó el límite temporal por IP del laboratorio. Espera antes de volver a intentarlo.",
        retry_after_seconds: rate.retryAfter,
        event_recorded: false
      });
    }

    const currentLock = accountLockStatus(username);
    if (currentLock.locked) {
      try {
        const event = await sendEventToCentinela(username, false, ip);
        res.setHeader("Retry-After", String(currentLock.retryAfter));
        return sendJson(res, 423, {
          authenticated: false,
          event_recorded: true,
          event_id: event.event_id,
          retry_after_seconds: currentLock.retryAfter,
          message: "Cuenta bloqueada temporalmente por seguridad. El intento quedó registrado en Centinela."
        });
      } catch (error) {
        console.error("No se pudo entregar a Centinela un intento durante el bloqueo:", error.message);
        return sendJson(res, 503, {
          error: "Centinela no confirmó el intento durante el bloqueo. No repitas hasta comprobar la captura.",
          event_recorded: false
        });
      }
    }

    if (!authenticate(username, password)) {
      try {
        return await recordFailedAttempt(res, username, ip);
      } catch (error) {
        console.error("No se pudo entregar el fallo de contraseña a Centinela:", error.message);
        return sendJson(res, 503, {
          error: "Centinela no confirmó el intento fallido. No repitas hasta comprobar la captura.",
          event_recorded: false
        });
      }
    }

    if (!totpCode) {
      const secret = totpSecrets.get(username);
      return sendJson(res, 202, {
        mfa_required: true,
        event_recorded: false,
        setup_secret: secret,
        provisioning_uri: provisioningUri(username),
        message: "Primer paso correcto. Añade esta clave a tu aplicación autenticadora y escribe el código de seis dígitos."
      });
    }

    if (!verifyTotp(username, totpCode)) {
      try {
        return await recordFailedAttempt(res, username, ip);
      } catch (error) {
        console.error("No se pudo entregar el fallo del segundo factor a Centinela:", error.message);
        return sendJson(res, 503, {
          error: "Centinela no confirmó el intento. No repitas hasta comprobar la captura.",
          event_recorded: false
        });
      }
    }

    try {
      const event = await sendEventToCentinela(username, true, ip);
      clearAccountFailures(username);
      return sendJson(res, 200, {
        authenticated: true,
        event_recorded: true,
        event_id: event.event_id,
        message: "Acceso autorizado con segundo factor. Centinela recibió el evento."
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
  console.log("Cuentas de laboratorio y MFA TOTP cargadas:", EXPECTED_USERS.length);
  console.log("Campaña de captura:", CAMPAIGN_ID);
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
