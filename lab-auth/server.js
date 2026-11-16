import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "public");
const PORT = Number.parseInt(process.env.PORT || "10000", 10);
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const CENTINELA_API_URL = (() => {
  let value = (process.env.CENTINELA_API_URL || "").trim();
  while (value.endsWith("/")) value = value.slice(0, -1);
  return value;
})();
const CENTINELA_INGEST_TOKEN = (process.env.CENTINELA_INGEST_TOKEN || "").trim();
const CAMPAIGN_ID = "laboratorio-web-auth-v2";
const EXPECTED_USERS = ["ronan", "andy", "stefano"];
const MAX_BODY_BYTES = 4096;
const RATE_WINDOW_MS = 60_000;
const MAX_ATTEMPTS_PER_IP = 60;
const CAPTCHA_TTL_MS = 5 * 60_000;
const MAX_PENDING_CAPTCHAS = 10_000;
const ipBuckets = new Map();
const pendingCaptchas = new Map();

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest();
}

function loadCredentials() {
  const raw = process.env.LAB_CREDENTIALS_V2_JSON || "";
  if (!raw) throw new Error("Falta LAB_CREDENTIALS_V2_JSON.");

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("LAB_CREDENTIALS_V2_JSON no contiene un objeto JSON válido.");
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("LAB_CREDENTIALS_V2_JSON debe ser un objeto JSON de usuario y contraseña.");
  }

  const actualUsers = Object.keys(parsed).sort();
  if (actualUsers.join(",") !== [...EXPECTED_USERS].sort().join(",")) {
    throw new Error("Configura exactamente las cuentas ronan, andy y stefano.");
  }

  const passwordDigests = new Map();
  const distinct = new Set();

  for (const username of EXPECTED_USERS) {
    const password = parsed[username];
    if (typeof password !== "string" || password.length < 16 || password.length > 256) {
      throw new Error("Cada contraseña debe tener entre 16 y 256 caracteres.");
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
  if (target.pathname !== "/" || target.search || target.hash || target.username || target.password) {
    throw new Error("CENTINELA_API_URL debe ser únicamente el origen del servicio detector, sin rutas ni parámetros.");
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

const CAPTCHA_GLYPHS = {
  "0": ["01110","10001","10011","10101","11001","10001","01110"],
  "1": ["00100","01100","00100","00100","00100","00100","01110"],
  "2": ["01110","10001","00001","00010","00100","01000","11111"],
  "3": ["11110","00001","00001","01110","00001","00001","11110"],
  "4": ["00010","00110","01010","10010","11111","00010","00010"],
  "5": ["11111","10000","10000","11110","00001","00001","11110"],
  "6": ["01110","10000","10000","11110","10001","10001","01110"],
  "7": ["11111","00001","00010","00100","01000","01000","01000"],
  "8": ["01110","10001","10001","01110","10001","10001","01110"],
  "9": ["01110","10001","10001","01111","00001","00001","01110"],
  "×": ["00000","10001","01010","00100","01010","10001","00000"],
  "+": ["00000","00100","00100","11111","00100","00100","00000"],
  "-": ["00000","00000","00000","11111","00000","00000","00000"],
  "=": ["00000","11111","00000","11111","00000","00000","00000"],
  "?": ["01110","10001","00001","00010","00100","00000","00100"],
  "(": ["00010","00100","01000","01000","01000","00100","00010"],
  ")": ["01000","00100","00010","00010","00010","00100","01000"],
  " ": ["00000","00000","00000","00000","00000","00000","00000"]
};

function createCaptchaSvg(expression) {
  const width = 420;
  const height = 96;
  const cell = 4;
  const advance = 26;
  const spaceAdvance = 10;
  const totalWidth = [...expression].reduce((sum, char) => sum + (char === " " ? spaceAdvance : advance), 0);
  let cursorX = (width - totalWidth) / 2;
  const parts = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`,
    '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#d7e1e5"/><stop offset="1" stop-color="#aebfc8"/></linearGradient></defs>',
    '<rect width="100%" height="100%" rx="10" fill="url(#bg)"/>'
  ];

  // Textura de fondo y trazos curvos para dificultar la lectura automática.
  for (let i = 0; i < 34; i++) {
    const x = randomInt(2, width - 2);
    const y = randomInt(2, height - 2);
    const r = randomInt(1, 3);
    parts.push(`<circle cx="${x}" cy="${y}" r="${r}" fill="#526b79" opacity="0.26"/>`);
  }
  for (let i = 0; i < 7; i++) {
    const y1 = randomInt(4, height - 4);
    const y2 = randomInt(4, height - 4);
    const bend = randomInt(55, width - 55);
    parts.push(`<path d="M-5 ${y1} Q${bend} ${randomInt(-20, height + 20)} ${width + 5} ${y2}" fill="none" stroke="#6b8490" stroke-width="${randomInt(1, 3)}" opacity="0.38"/>`);
  }

  for (const char of expression) {
    if (char === " ") {
      cursorX += spaceAdvance;
      continue;
    }
    const glyph = CAPTCHA_GLYPHS[char];
    if (!glyph) throw new Error("Carácter no admitido en el CAPTCHA.");
    let pathData = "";
    glyph.forEach((line, row) => {
      [...line].forEach((pixel, col) => {
        if (pixel === "1") {
          const jitterX = randomInt(0, 7) / 10;
          const jitterY = randomInt(0, 7) / 10;
          pathData += `M${(col * cell + jitterX).toFixed(1)} ${(row * cell + jitterY).toFixed(1)}h3.2v3.2h-3.2z`;
        }
      });
    });
    const y = randomInt(29, 42);
    const rotation = randomInt(-12, 13);
    const scaleX = (randomInt(92, 112) / 100).toFixed(2);
    const scaleY = (randomInt(94, 113) / 100).toFixed(2);
    const fill = ["#172d3d", "#203b4b", "#294555"][randomInt(0, 3)];
    parts.push(`<path d="${pathData}" fill="${fill}" transform="translate(${cursorX} ${y}) rotate(${rotation} 10 14) scale(${scaleX} ${scaleY})"/>`);
    cursorX += advance;
  }

  // Rayas finas sobre algunos trazos: visibles, pero sin tapar por completo los símbolos.
  for (let i = 0; i < 4; i++) {
    const x1 = randomInt(20, width - 20);
    const x2 = randomInt(20, width - 20);
    const y1 = randomInt(20, height - 20);
    const y2 = randomInt(20, height - 20);
    parts.push(`<path d="M${x1} ${y1} Q${randomInt(70, 350)} ${randomInt(0, 96)} ${x2} ${y2}" fill="none" stroke="#617d88" stroke-width="1.2" opacity="0.34"/>`);
  }
  parts.push("</svg>");
  return parts.join("");
}

function createCaptcha(ip) {
  const now = Date.now();
  for (const [id, item] of pendingCaptchas) {
    if (item.expiresAt <= now) pendingCaptchas.delete(id);
  }
  if (pendingCaptchas.size >= MAX_PENDING_CAPTCHAS) {
    const firstKey = pendingCaptchas.keys().next().value;
    if (firstKey) pendingCaptchas.delete(firstKey);
  }

  const left = randomInt(4, 10);
  const right = randomInt(4, 10);
  const adjustment = randomInt(2, 10);
  const useAddition = randomInt(0, 2) === 0;
  const expression = useAddition
    ? `(${left} × ${right}) + ${adjustment} = ?`
    : `(${left} × ${right}) - ${adjustment} = ?`;
  const answer = String(left * right + (useAddition ? adjustment : -adjustment));
  const challengeId = randomBytes(24).toString("hex");

  pendingCaptchas.set(challengeId, {
    answer,
    image: createCaptchaSvg(expression),
    ip,
    expiresAt: now + CAPTCHA_TTL_MS
  });
  return { challenge_id: challengeId, image_url: `/challenge/${challengeId}.svg` };
}

function verifyCaptcha(challengeId, answer, ip) {
  if (typeof challengeId !== "string" || !/^[a-f0-9]{48}$/.test(challengeId)) return false;
  const challenge = pendingCaptchas.get(challengeId);
  if (!challenge) return false;
  pendingCaptchas.delete(challengeId);
  if (challenge.expiresAt <= Date.now() || challenge.ip !== ip) return false;
  return typeof answer === "string" &&
    answer.trim().length > 0 &&
    safeEqualDigest(sha256(answer.trim()), sha256(challenge.answer));
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
      credentials_configured: credentialDigests.size === EXPECTED_USERS.length,
      captcha_configured: true,
      centinela_configured: Boolean(CENTINELA_API_URL && CENTINELA_INGEST_TOKEN),
      campaign_id: CAMPAIGN_ID,
      account_lockout_enabled: false,
      per_ip_limit_per_minute: MAX_ATTEMPTS_PER_IP
    });
  }

  if (req.method === "GET" && pathname === "/challenge") {
    let ip;
    try {
      ip = clientIpFromRender(req);
    } catch (error) {
      console.error("No se pudo determinar la IP para el CAPTCHA:", error.message);
      return sendJson(res, 503, { error: "No se pudo verificar el origen de la conexión." });
    }
    return sendJson(res, 200, createCaptcha(ip));
  }

  const captchaImageMatch = pathname.match(/^\\/challenge\\/([a-f0-9]{48})\\.svg$/);
  if (req.method === "GET" && captchaImageMatch) {
    let ip;
    try {
      ip = clientIpFromRender(req);
    } catch {
      return sendJson(res, 503, { error: "No se pudo verificar el origen de la conexión." });
    }
    const challenge = pendingCaptchas.get(captchaImageMatch[1]);
    if (!challenge || challenge.expiresAt <= Date.now() || challenge.ip !== ip) {
      return sendJson(res, 404, { error: "La comprobación ya no está disponible." });
    }
    const image = Buffer.from(challenge.image, "utf8");
    res.writeHead(200, {
      "Content-Type": "image/svg+xml; charset=utf-8",
      "Content-Length": image.length,
      "Cache-Control": "no-store, max-age=0"
    });
    return res.end(image);
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
    const challengeId = typeof data.challenge_id === "string" ? data.challenge_id : "";
    const challengeAnswer = typeof data.challenge_answer === "string" ? data.challenge_answer : "";
    const honeypot = typeof data.website === "string" ? data.website : "";

    if (honeypot) {
      console.warn("CAPTCHA_HONEYPOT: solicitud automatizada rechazada.");
      return sendJson(res, 400, { error: "No se pudo validar el formulario. Carga uno nuevo e inténtalo otra vez.", event_recorded: false });
    }

    if (!/^[a-zA-Z0-9_.@-]{1,64}$/.test(username) || password.length > 256) {
      return sendJson(res, 400, { error: "Introduce un usuario y una contraseña válidos.", event_recorded: false });
    }

    let ip;
    try {
      ip = clientIpFromRender(req);
    } catch (error) {
      console.error("No se pudo determinar la IP del cliente:", error.message);
      return sendJson(res, 503, { error: "No se pudo verificar el origen de la conexión. El intento no fue enviado a Centinela.", event_recorded: false });
    }

    const rate = consumeRateLimit(ip);
    if (!rate.allowed) {
      res.setHeader("Retry-After", String(rate.retryAfter));
      return sendJson(res, 429, {
        error: "Se alcanzó el límite temporal de solicitudes de esta IP. Espera un minuto antes de continuar.",
        retry_after_seconds: rate.retryAfter,
        event_recorded: false
      });
    }

    if (!verifyCaptcha(challengeId, challengeAnswer, ip)) {
      console.warn("CAPTCHA_FAILED: comprobación humana no superada.");
      return sendJson(res, 400, {
        error: "La comprobación CAPTCHA no es correcta o ha caducado. Resuelve la nueva comprobación.",
        captcha_failed: true,
        event_recorded: false
      });
    }

    const authenticated = authenticate(username, password);

    try {
      // La contraseña se valida localmente y nunca se envía a Centinela.
      // Se registran los fallos de credenciales y los éxitos después del CAPTCHA.
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
  console.log("Cuentas de laboratorio cargadas:", EXPECTED_USERS.join(", "));
  console.log("Campaña de captura:", CAMPAIGN_ID);
  console.log("Bloqueo por cuenta desactivado; CAPTCHA y límite por IP activos.");
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
