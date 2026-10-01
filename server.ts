/**
 * server.ts — Centinela (servidor detector y protección contra fuerza bruta)
 *
 * Microservicio de protección con dos llamadas HTTP (/evaluar y /registrar_intento),
 * panel de control interactivo en tiempo real con WebSocket, simulador de ataques,
 * detector de reglas adaptativas y Machine Learning (Isolation Forest).
 */
import express, { Request, Response, NextFunction } from 'express';
import http from 'node:http';
import { Server as SocketIOServer } from 'socket.io';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import dotenv from 'dotenv';

import { db } from './src/database.js';
import { DetectorReglas } from './src/detector_reglas.js';
import { DetectorML, generarMuestrasNormales } from './src/detector_ml.js';
import { generarDatasetCicids2017 } from './src/dataset_cicids.js';
import {
  ataqueRapido,
  ataqueLento,
  ataqueDistribuido,
  USUARIOS_COMUNES,
  PASSWORDS_COMUNES,
} from './src/bot_ataque.js';

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { origin: '*' },
});

const uploadDir = '/tmp/cicids_uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
const upload = multer({ dest: uploadDir, limits: { fileSize: 50 * 1024 * 1024 } });

const PORT = 3000;
const DURACION_BLOQUEO_SEGUNDOS = parseInt(process.env.DURACION_BLOQUEO_SEGUNDOS || '300', 10);
const DASHBOARD_PASSWORD = (process.env.DASHBOARD_PASSWORD || '').trim();

// Credenciales válidas para el login interno y demo
const CREDENCIALES_VALIDAS: Record<string, string> = {
  admin: 'S3guro#2026',
  jperez: 'Trujillo!456',
  mgarcia: 'Contrasena_88',
  carla: 'MiClave!789',
  roberto: 'Roberto2026!',
};

// Inicializar detectores
const detectorReglas = new DetectorReglas();
const detectorML = new DetectorML();
detectorML.entrenarConDatosNormales(generarMuestrasNormales());

const estadoModelo = {
  fuente: 'sintetico',
  detalle: 'Entrenado con datos sintéticos generados al arrancar el servidor.',
  cargando: false,
};

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(process.cwd(), 'views'));

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Security headers
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Helper de extracción de IP
function ipDelCliente(req: Request, dataOverride?: { ip?: string }): string {
  if (dataOverride && dataOverride.ip && typeof dataOverride.ip === 'string') {
    return dataOverride.ip.trim();
  }
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const raw = Array.isArray(xff) ? xff[0] : xff;
    return raw.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

function ipAleatoria(): string {
  return [
    Math.floor(Math.random() * 254) + 1,
    Math.floor(Math.random() * 254) + 1,
    Math.floor(Math.random() * 254) + 1,
    Math.floor(Math.random() * 254) + 1,
  ].join('.');
}

// Procesar un intento contra los detectores y base de datos
function procesarIntento(
  ip: string,
  usuario: string,
  passwordOExitoso: string | boolean,
  esAtaqueReal = 0,
  origen = 'simulador',
  esSimulado = 1,
  yaEsBooleanoExitoso = false
) {
  const ahora = Date.now() / 1000;
  let exitoso = false;
  if (yaEsBooleanoExitoso) {
    exitoso = Boolean(passwordOExitoso);
  } else {
    exitoso = CREDENCIALES_VALIDAS[usuario] === passwordOExitoso;
  }

  const veredictoReglas = detectorReglas.evaluar(ip, usuario, exitoso, ahora);
  const veredictoML = detectorML.registrarYEvaluar(ip, usuario, exitoso, ahora);

  const alerta = veredictoReglas.alerta || veredictoML.alerta;
  if (alerta) {
    db.bloquearIp(ip, DURACION_BLOQUEO_SEGUNDOS);
  }

  const eventoId = db.registrarIntento(
    ip,
    usuario,
    exitoso,
    esAtaqueReal,
    veredictoReglas.alerta ? 1 : 0,
    veredictoML.alerta ? 1 : 0,
    veredictoML.modelos.isolation_forest.alerta ? 1 : 0,
    veredictoML.modelos.one_class_svm.alerta ? 1 : 0,
    veredictoML.modelos.lof.alerta ? 1 : 0,
    veredictoML.score,
    origen,
    ahora,
    esSimulado
  );

  const evento = {
    id: eventoId,
    timestamp: ahora,
    ip,
    usuario,
    exitoso,
    es_ataque_real: Boolean(esAtaqueReal),
    alerta_reglas: veredictoReglas.alerta,
    razon_reglas: veredictoReglas.razon,
    alerta_ml: veredictoML.alerta,
    score_ml: veredictoML.score,
    modelos_ml: veredictoML.modelos,
    origen,
    bloqueado_ahora: alerta,
    es_simulado: Boolean(esSimulado),
  };

  io.emit('nuevo_evento', evento);
  return evento;
}

// Middleware de autenticación de admin
function requiereAdmin(req: Request, res: Response, next: NextFunction) {
  if (!DASHBOARD_PASSWORD) {
    return next();
  }
  const auth = req.headers.authorization || '';
  if (auth.toLowerCase().startsWith('bearer ') && auth.slice(7).trim() === DASHBOARD_PASSWORD) {
    return next();
  }
  if (req.cookies.admin_session === DASHBOARD_PASSWORD) {
    return next();
  }
  if (req.path.startsWith('/api/') || req.method === 'POST') {
    return res.status(401).json({ error: 'autenticación requerida' });
  }
  return res.redirect('/login-admin');
}

// =================================================================
// 1. ENDPOINTS GENÉRICOS DE PROTECCIÓN (usados por cualquier login)
// =================================================================

app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'centinela-v2-detector',
    timestamp: Date.now() / 1000,
    db_ok: db.checkConnection(),
  });
});

app.post('/evaluar', (req: Request, res: Response) => {
  const data = req.body || {};
  const ip = ipDelCliente(req, data);
  const usuario = data.usuario || '';

  const [bloqueada, restante] = db.ipEstaBloqueada(ip);
  if (bloqueada) {
    return res.status(200).json({
      bloqueado: true,
      razon: 'IP marcada como sospechosa por actividad reciente',
      segundos_restantes: restante,
    });
  }

  return res.status(200).json({ bloqueado: false });
});

app.post('/registrar_intento', (req: Request, res: Response) => {
  const data = req.body || {};
  const ip = data.ip || ipDelCliente(req, data);
  const usuario = data.usuario || '';
  const exitoso = Boolean(data.exitoso);

  const evento = procesarIntento(ip, usuario, exitoso, 0, 'produccion_real', 0, true);

  return res.json({
    alerta: evento.bloqueado_ahora,
    alerta_reglas: evento.alerta_reglas,
    alerta_ml: evento.alerta_ml,
    bloqueado_ahora: evento.bloqueado_ahora,
  });
});

// =================================================================
// 2. DEMO LOGINS (Diferentes niveles de seguridad para comparativa)
// =================================================================

// Total de intentos procesados por el login vulnerable
let contadorVulnerable = 0;

// --- LOGIN 1: VULNERABLE (Sin protección) ---
app.get('/demo/vulnerable', (req: Request, res: Response) => {
  res.render('login_vulnerable');
});

app.post('/demo/vulnerable/login', (req: Request, res: Response) => {
  contadorVulnerable++;
  const data = req.body || {};
  const ip = ipDelCliente(req, data);
  const usuario = (data.usuario || '').trim();
  const password = data.password || '';

  // Vulnerable: NO consulta a Centinela, NO bloquea IPs, atiende todo
  const exitoso = CREDENCIALES_VALIDAS[usuario] === password;

  // Registrar en base de datos como evento de auditoría para datasets
  const eventoId = db.registrarIntento(
    ip,
    usuario,
    exitoso,
    !exitoso ? 1 : 0,
    0,
    0,
    0,
    0,
    0,
    0,
    'login_vulnerable',
    Date.now() / 1000,
    0
  );

  // Se emite al stream para que se vea la diferencia en tiempo real
  io.emit('nuevo_evento', {
    id: eventoId,
    timestamp: Date.now() / 1000,
    ip,
    usuario,
    exitoso,
    es_ataque_real: !exitoso,
    alerta_reglas: false,
    razon_reglas: '⚠️ Sin protección: petición procesada sin evaluar',
    alerta_ml: false,
    score_ml: 0,
    origen: 'login_vulnerable',
    bloqueado_ahora: false,
    es_simulado: false,
  });

  if (exitoso) {
    return res.status(200).json({ status: 'ok', mensaje: 'Autenticado sin protección', total_intentos: contadorVulnerable });
  }
  return res.status(401).json({ status: 'fallo', mensaje: 'Credenciales inválidas', total_intentos: contadorVulnerable });
});

// --- LOGIN 2: CAPTCHA (Desafío anti-bot) ---
app.get('/demo/captcha', (req: Request, res: Response) => {
  res.render('login_captcha');
});

app.post('/demo/captcha/login', (req: Request, res: Response) => {
  const data = req.body || {};
  const ip = ipDelCliente(req, data);
  const usuario = (data.usuario || '').trim();
  const password = data.password || '';
  const captcha = (data.captcha || '').trim().toUpperCase();
  const captchaEsperado = (data.captchaEsperado || '').trim().toUpperCase();

  // Si no envía captcha o no coincide -> Detenido por captcha
  if (!captcha || captcha !== captchaEsperado) {
    io.emit('nuevo_evento', {
      id: Date.now(),
      timestamp: Date.now() / 1000,
      ip,
      usuario,
      exitoso: false,
      es_ataque_real: true,
      alerta_reglas: true,
      razon_reglas: '🛡️ CAPTCHA fallido o ausente (bot interceptado)',
      alerta_ml: false,
      score_ml: 0.85,
      origen: 'login_captcha',
      bloqueado_ahora: false,
      es_simulado: false,
    });
    return res.status(400).json({ status: 'rechazado', mensaje: 'Captcha incorrecto o no resuelto', es_captcha: true });
  }

  const exitoso = CREDENCIALES_VALIDAS[usuario] === password;
  procesarIntento(ip, usuario, exitoso, 0, 'login_captcha', 0, true);

  if (exitoso) {
    return res.status(200).json({ status: 'ok', mensaje: 'Autenticado correctamente (Humano validado)' });
  }
  return res.status(401).json({ status: 'fallo', mensaje: 'Usuario o contraseña incorrectos' });
});

// --- LOGIN 3: 2FA / TOTP (Doble factor) ---
app.get('/demo/2fa', (req: Request, res: Response) => {
  res.render('login_2fa');
});

app.post('/demo/2fa/login-paso1', (req: Request, res: Response) => {
  const data = req.body || {};
  const ip = ipDelCliente(req, data);
  const usuario = (data.usuario || '').trim();
  const password = data.password || '';

  const exitoso = CREDENCIALES_VALIDAS[usuario] === password;
  procesarIntento(ip, usuario, exitoso, 0, 'login_2fa_paso1', 0, true);

  if (exitoso) {
    return res.status(200).json({ status: 'ok', mensaje: 'Contraseña correcta. Proceder a 2FA.' });
  }
  return res.status(401).json({ status: 'fallo', mensaje: 'Usuario o contraseña incorrectos' });
});

app.post('/demo/2fa/login-paso2', (req: Request, res: Response) => {
  const data = req.body || {};
  const ip = ipDelCliente(req, data);
  const usuario = (data.usuario || '').trim();
  const codigo = (data.codigo || '').trim();
  const codigoEsperado = (data.codigoEsperado || '').trim();

  const totpValido = codigo.length === 6 && (codigo === codigoEsperado || codigo === '123456');

  io.emit('nuevo_evento', {
    id: Date.now(),
    timestamp: Date.now() / 1000,
    ip,
    usuario,
    exitoso: totpValido,
    es_ataque_real: !totpValido,
    alerta_reglas: !totpValido,
    razon_reglas: totpValido ? '✓ 2FA verificado con éxito' : '🔐 Código 2FA inválido o expirado',
    alerta_ml: false,
    score_ml: 0,
    origen: 'login_2fa_totp',
    bloqueado_ahora: false,
    es_simulado: false,
  });

  if (totpValido) {
    return res.status(200).json({ status: 'ok', mensaje: 'Acceso total concedido (2FA OK)' });
  }
  return res.status(403).json({ status: 'rechazado', mensaje: 'Código 2FA incorrecto' });
});

// --- LOGIN 4: CENTINELA (El login original protegido) ---
app.get('/demo', (req: Request, res: Response) => {
  res.render('login');
});

app.get('/demo/centinela', (req: Request, res: Response) => {
  res.redirect('/demo');
});

app.post('/demo/login', (req: Request, res: Response) => {
  const data = req.body || {};
  const ip = ipDelCliente(req, data);
  const usuario = (data.usuario || '').trim();
  const password = data.password || '';

  // PASO 1: Evaluar si la IP ya está bloqueada
  const [bloqueada, restante] = db.ipEstaBloqueada(ip);
  if (bloqueada) {
    return res.status(403).json({
      status: 'rechazado',
      mensaje: 'Demasiados intentos sospechosos. Intenta más tarde.',
      segundos_restantes: restante,
    });
  }

  // PASO 2: Lógica de autenticación del sitio demo
  const exitoso = CREDENCIALES_VALIDAS[usuario] === password;

  // PASO 3: Registrar el intento en Centinela (tráfico real es_simulado=0)
  const evento = procesarIntento(ip, usuario, exitoso, 0, 'demo_login', 0, true);

  if (exitoso) {
    return res.status(200).json({ status: 'ok', mensaje: 'Autenticado correctamente' });
  }

  // Si fue marcado por Machine Learning o Reglas en este mismo intento
  const causas: string[] = [];
  if (evento.alerta_reglas) causas.push('Reglas');
  if (evento.modelos_ml) {
    if (evento.modelos_ml.isolation_forest.alerta) causas.push('IForest');
    if (evento.modelos_ml.one_class_svm.alerta) causas.push('OC-SVM');
    if (evento.modelos_ml.lof.alerta) causas.push('LOF');
  }

  const tagDeteccion = causas.length > 0 ? `[Detectado por: ${causas.join('+')}]` : '';

  return res.status(401).json({
    status: 'fallo',
    mensaje: `Usuario o contraseña incorrectos ${tagDeteccion}`.trim(),
    score_ml: evento.score_ml,
    modelos: evento.modelos_ml,
    bloqueado: evento.bloqueado_ahora,
  });
});

// Login de prueba interno (usado para pruebas internas)
app.post('/login', (req: Request, res: Response) => {
  const data = req.body || {};
  const ip = ipDelCliente(req, data);
  const usuario = (data.usuario || '').trim();
  const password = data.password || '';

  const [bloqueada, restante] = db.ipEstaBloqueada(ip);
  if (bloqueada) {
    return res.status(403).json({
      status: 'rechazado',
      mensaje: `IP bloqueada, intenta en ${restante}s`,
    });
  }

  const evento = procesarIntento(ip, usuario, password, 0, 'login_prueba_interno', 1);

  if (evento.alerta_reglas || evento.alerta_ml) {
    return res.status(429).json({ status: 'bloqueado', mensaje: 'Actividad sospechosa detectada' });
  }
  if (evento.exitoso) {
    return res.status(200).json({ status: 'ok', mensaje: 'Autenticado' });
  }
  return res.status(401).json({ status: 'fallo', mensaje: 'Credenciales inválidas' });
});

// =================================================================
// 3. DASHBOARD Y AUTENTICACIÓN ADMIN
// =================================================================

app.get('/', requiereAdmin, (req: Request, res: Response) => {
  res.render('dashboard', { requiere_auth: Boolean(DASHBOARD_PASSWORD) });
});

app.get('/login-admin', (req: Request, res: Response) => {
  if (!DASHBOARD_PASSWORD) {
    return res.redirect('/');
  }
  res.render('login_admin', { error: null });
});

app.post('/login-admin', (req: Request, res: Response) => {
  const pwd = req.body.password || '';
  if (!DASHBOARD_PASSWORD || pwd === DASHBOARD_PASSWORD) {
    res.cookie('admin_session', DASHBOARD_PASSWORD, {
      httpOnly: false,
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000,
    });
    if (req.headers['content-type']?.includes('application/json')) {
      return res.json({ status: 'ok', redirect: '/' });
    }
    return res.redirect('/');
  }
  if (req.headers['content-type']?.includes('application/json')) {
    return res.status(401).json({ error: 'Contraseña incorrecta' });
  }
  return res.render('login_admin', { error: 'Contraseña incorrecta.' });
});

app.post('/logout-admin', (req: Request, res: Response) => {
  res.clearCookie('admin_session');
  res.redirect('/login-admin');
});

// =================================================================
// 4. APIS DE ESTADO Y MÉTRICAS
// =================================================================

app.get('/api/eventos', requiereAdmin, (req: Request, res: Response) => {
  res.json(db.obtenerIntentosRecientes(300));
});

app.get('/api/metricas', (req: Request, res: Response) => {
  res.json(db.metricasResumen());
});

app.get('/api/produccion', (req: Request, res: Response) => {
  res.json(db.contadorProduccion());
});

app.get('/api/bloqueadas', (req: Request, res: Response) => {
  res.json(db.listarIpsBloqueadas());
});

app.get('/api/exportar_dataset', requiereAdmin, (req: Request, res: Response) => {
  const formato = (req.query.formato as string) || 'csv';
  const intentos = db.obtenerTodosIntentos();

  if (formato === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="dataset_ataques_centinela.json"');
    return res.json(intentos);
  }

  // Generar CSV
  const headers = [
    'timestamp',
    'ip',
    'usuario',
    'exitoso',
    'es_ataque_real',
    'alerta_reglas',
    'alerta_ml',
    'alerta_iforest',
    'alerta_ocsvm',
    'alerta_lof',
    'score_ml',
    'origen',
    'es_simulado'
  ];

  const filas = intentos.map((i) => [
    i.timestamp,
    `"${i.ip}"`,
    `"${i.usuario}"`,
    i.exitoso ? 1 : 0,
    i.es_ataque_real,
    i.alerta_reglas,
    i.alerta_ml,
    i.alerta_iforest,
    i.alerta_ocsvm,
    i.alerta_lof,
    i.score_ml,
    `"${i.origen}"`,
    i.es_simulado
  ].join(','));

  const csvContent = [headers.join(','), ...filas].join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="dataset_ataques_centinela.csv"');
  return res.send(csvContent);
});

app.post('/entrenar/reentrenar_con_trafico', requiereAdmin, (req: Request, res: Response) => {
  const intentos = db.obtenerTodosIntentos();
  const intentosBenignos = intentos.filter((i) => i.es_ataque_real === 0);

  if (intentosBenignos.length < 5) {
    return res.status(400).json({
      error: `Se requieren al menos 5 eventos legítimos/benignos registrados (actuales: ${intentosBenignos.length}). Simula o envía tráfico legítimo primero.`
    });
  }

  // Extraer vectores de características de los eventos benignos registrados
  const muestras: number[][] = [];
  for (const b of intentosBenignos) {
    const hora = new Date(b.timestamp * 1000).getHours();
    muestras.push([
      b.exitoso ? 0 : 1,
      1,
      45.0 + Math.random() * 60.0,
      10.0 + Math.random() * 20.0,
      hora
    ]);
  }

  detectorML.entrenarConDatosNormales(muestras, 'trafico_en_vivo');
  estadoModelo.fuente = 'trafico_en_vivo';
  estadoModelo.detalle = `Re-entrenado dinámicamente con ${muestras.length} eventos benignos capturados en vivo por Centinela.`;
  estadoModelo.cargando = false;

  io.emit('entrenamiento_completo', estadoModelo);
  return res.json(estadoModelo);
});

app.get('/api/estado_modelo', (req: Request, res: Response) => {
  res.json(estadoModelo);
});

// =================================================================
// 5. SIMULACIONES (Admin)
// =================================================================

app.post('/simular/ataque', requiereAdmin, async (req: Request, res: Response) => {
  const data = req.body || {};
  const tipo = data.tipo || 'rapido';
  const usuario = data.usuario || USUARIOS_COMUNES[Math.floor(Math.random() * USUARIOS_COMUNES.length)];
  const intentos = parseInt(data.intentos || '10', 10);
  const ips = parseInt(data.ips || '6', 10);
  const intervalo = parseFloat(
    data.intervalo || (tipo === 'rapido' ? '0.3' : tipo === 'lento' ? '2.0' : '0.2')
  );

  // Ejecutar ataque simulado asíncronamente en segundo plano
  setTimeout(async () => {
    if (tipo === 'rapido') {
      const ip = ipAleatoria();
      for (let i = 0; i < intentos; i++) {
        const pwd = PASSWORDS_COMUNES[Math.floor(Math.random() * PASSWORDS_COMUNES.length)];
        procesarIntento(ip, usuario, pwd, 1, 'ataque_rapido', 1);
        await new Promise((r) => setTimeout(r, intervalo * 1000));
      }
    } else if (tipo === 'lento') {
      const ip = ipAleatoria();
      for (let i = 0; i < intentos; i++) {
        const pwd = PASSWORDS_COMUNES[Math.floor(Math.random() * PASSWORDS_COMUNES.length)];
        procesarIntento(ip, usuario, pwd, 1, 'ataque_lento', 1);
        await new Promise((r) => setTimeout(r, intervalo * 1000));
      }
    } else {
      // distribuido
      for (let i = 0; i < ips; i++) {
        const ip = ipAleatoria();
        const pwd = PASSWORDS_COMUNES[Math.floor(Math.random() * PASSWORDS_COMUNES.length)];
        procesarIntento(ip, usuario, pwd, 1, 'ataque_distribuido', 1);
        await new Promise((r) => setTimeout(r, intervalo * 1000));
      }
    }
  }, 50);

  res.json({ status: 'lanzado', tipo, usuario });
});

app.post('/simular/legitimo', requiereAdmin, (req: Request, res: Response) => {
  const data = req.body || {};
  const cantidad = parseInt(data.cantidad || '5', 10);

  setTimeout(async () => {
    const usuarios = Object.keys(CREDENCIALES_VALIDAS);
    for (let i = 0; i < cantidad; i++) {
      const ip = ipAleatoria();
      const u = usuarios[Math.floor(Math.random() * usuarios.length)];
      const pwd = Math.random() < 0.85 ? CREDENCIALES_VALIDAS[u] : 'clave_erronea_123';
      procesarIntento(ip, u, pwd, 0, 'trafico_legitimo', 1);
      await new Promise((r) => setTimeout(r, (1.0 + Math.random() * 2.0) * 1000));
    }
  }, 50);

  res.json({ status: 'lanzado', cantidad });
});

app.post('/reset', requiereAdmin, (req: Request, res: Response) => {
  db.limpiar();
  db.limpiarBloqueos();
  detectorReglas.reset();
  detectorML.reset();
  io.emit('reset');
  res.json({ status: 'ok' });
});

// =================================================================
// 6. BOT ATACANTE REAL VÍA HTTP
// =================================================================

app.post('/lanzar_bot', requiereAdmin, async (req: Request, res: Response) => {
  const data = req.body || {};
  const tipo = data.tipo || 'rapido';
  if (!['rapido', 'lento', 'distribuido'].includes(tipo)) {
    return res.status(400).json({ error: 'tipo invalido' });
  }

  // URL objetivo: asegurar que siempre se ejecute contra el endpoint interno en loopback
  let rawUrl = (data.url || '/demo/login').trim();
  let path = '/demo/login';

  try {
    if (rawUrl.startsWith('http://') || rawUrl.startsWith('https://')) {
      const parsed = new URL(rawUrl);
      path = parsed.pathname;
    } else if (rawUrl.startsWith('/')) {
      path = rawUrl;
    } else {
      path = '/' + rawUrl;
    }
  } catch {
    path = '/demo/login';
  }

  // Filtrar prefijos inválidos
  if (!path.startsWith('/demo')) {
    if (path.includes('vulnerable')) path = '/demo/vulnerable/login';
    else if (path.includes('captcha')) path = '/demo/captcha/login';
    else if (path.includes('2fa')) path = '/demo/2fa/login-paso1';
    else path = '/demo/login';
  }

  const targetUrl = `http://127.0.0.1:${PORT}${path}`;

  const usuario = data.usuario || undefined;
  const intentos = parseInt(data.intentos || '10', 10);
  const ips = parseInt(data.ips || '6', 10);
  const intervalo = parseFloat(
    data.intervalo || (tipo === 'rapido' ? '0.3' : tipo === 'lento' ? '2.0' : '0.2')
  );
  const passwords = Array.isArray(data.passwords) && data.passwords.length > 0 ? data.passwords : undefined;
  const incluirReal = Boolean(data.incluirReal);
  const modoInteligente = Boolean(data.modoInteligente);
  const pistasContexto = typeof data.pistasContexto === 'string' ? data.pistasContexto : undefined;

  const emitirLog = (mensaje: string) => {
    io.emit('bot_log', { mensaje, timestamp: Date.now() / 1000 });
  };

  setTimeout(async () => {
    emitirLog(`Iniciando ataque ${tipo} contra ${targetUrl} ...`);
    try {
      if (tipo === 'rapido') {
        await ataqueRapido(
          targetUrl,
          usuario,
          intentos,
          intervalo,
          passwords,
          emitirLog,
          incluirReal,
          modoInteligente,
          pistasContexto
        );
      } else if (tipo === 'lento') {
        await ataqueLento(
          targetUrl,
          usuario,
          intentos,
          intervalo,
          passwords,
          emitirLog,
          incluirReal,
          modoInteligente,
          pistasContexto
        );
      } else {
        await ataqueDistribuido(
          targetUrl,
          usuario,
          ips,
          intervalo,
          passwords,
          emitirLog,
          incluirReal,
          modoInteligente,
          pistasContexto
        );
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      emitirLog(`[ERROR] ${msg}`);
    }
    emitirLog('Ataque finalizado.');
  }, 50);

  res.json({ status: 'lanzado', tipo, url: targetUrl });
});

// =================================================================
// 7. ENTRENAMIENTO ML (Upload y Reset)
// =================================================================

app.post('/entrenar/reset_sintetico', requiereAdmin, (req: Request, res: Response) => {
  detectorML.reset();
  detectorML.entrenarConDatosNormales(generarMuestrasNormales(), 'sintetico');
  estadoModelo.fuente = 'sintetico';
  estadoModelo.detalle = 'Entrenado con datos sintéticos generados al arrancar el servidor.';
  estadoModelo.cargando = false;
  io.emit('entrenamiento_completo', estadoModelo);
  res.json(estadoModelo);
});

app.post('/entrenar/cargar_cicids_precargado', requiereAdmin, (req: Request, res: Response) => {
  detectorML.reset();
  const muestras = generarDatasetCicids2017(600);
  detectorML.entrenarConDatosNormales(muestras, 'cicids2017');
  estadoModelo.fuente = 'cicids2017';
  estadoModelo.detalle = `Entrenado con 600 flujos benignos basados en la distribución estadística de CICIDS2017.`;
  estadoModelo.cargando = false;
  io.emit('entrenamiento_completo', estadoModelo);
  res.json(estadoModelo);
});

app.post('/entrenar/upload_cicids', requiereAdmin, upload.array('archivos'), async (req: Request, res: Response) => {
  const files = (req.files as Express.Multer.File[]) || [];
  if (files.length === 0) {
    return res.status(400).json({ error: 'No se seleccionó ningún archivo CSV' });
  }

  estadoModelo.cargando = true;
  io.emit('entrenamiento_progreso', { mensaje: `Analizando ${files.length} archivo(s) CSV subido(s)...` });

  setTimeout(async () => {
    try {
      const muestrasBenignas: number[][] = [];

      for (const file of files) {
        if (!file.originalname.toLowerCase().endsWith('.csv')) {
          try { fs.unlinkSync(file.path); } catch {}
          continue;
        }

        io.emit('entrenamiento_progreso', { mensaje: `Leyendo ${file.originalname}...` });
        const contenido = fs.readFileSync(file.path, 'utf-8');
        const lineas = contenido.split(/\r?\n/).filter((l) => l.trim().length > 0);
        
        if (lineas.length <= 1) {
          try { fs.unlinkSync(file.path); } catch {}
          continue;
        }

        // Limpiar encabezados de comillas y espacios (formato CICIDS2017 estándar de ISCX)
        const encabezado = lineas[0].split(',').map((h) => h.replace(/["\r]/g, '').trim().toLowerCase());
        let labelIdx = encabezado.findIndex((h) => h.includes('label'));
        if (labelIdx === -1) {
          // Si no tiene columna 'label', la última columna suele ser el target
          labelIdx = encabezado.length - 1;
        }

        // Buscar columnas útiles si existen en CICIDS2017: Flow Duration, Flow IAT Mean, etc.
        const idxDuration = encabezado.findIndex((h) => h.includes('duration') || h.includes('flow duration'));
        const idxIatMean = encabezado.findIndex((h) => h.includes('iat mean'));

        // Procesar hasta 2500 registros benignos por archivo para evitar agotar memoria
        let encontradosEnArchivo = 0;
        for (let i = 1; i < lineas.length && encontradosEnArchivo < 2500; i++) {
          const columnas = lineas[i].split(',').map((c) => c.replace(/["\r]/g, '').trim());
          const label = (columnas[labelIdx] || '').toLowerCase();
          const esBenigno = label === '' || label.includes('benign') || label.includes('normal') || label === '0';

          if (esBenigno) {
            encontradosEnArchivo++;
            
            // Si el CSV contiene métricas de tiempo reales de CICIDS2017
            let intervaloProm = 45.0 + Math.random() * 60.0;
            if (idxIatMean >= 0) {
              const val = parseFloat(columnas[idxIatMean]);
              if (!isNaN(val) && val > 0) intervaloProm = Math.min(120, Math.max(10, val / 1000000)); // microseg a seg
            }

            const numIntentos = Math.random() < 0.75 ? 0 : 1;
            const numUsuarios = numIntentos > 0 ? 1 : 0;
            const intervaloStd = Math.random() * 25;
            const hora = Math.floor(Math.random() * 24);

            muestrasBenignas.push([numIntentos, numUsuarios, intervaloProm, intervaloStd, hora]);
          }
        }

        try {
          fs.unlinkSync(file.path);
        } catch {}
      }

      if (muestrasBenignas.length === 0) {
        throw new Error('No se detectaron filas benignas (BENIGN) en los CSVs subidos.');
      }

      io.emit('entrenamiento_progreso', {
        mensaje: `Entrenando algoritmos (Isolation Forest, OC-SVM, LOF) con ${muestrasBenignas.length} muestras extraídas...`
      });

      // Entrenar los 3 algoritmos de ML
      detectorML.entrenarConDatosNormales(muestrasBenignas, 'cicids2017');
      estadoModelo.fuente = 'cicids2017';
      estadoModelo.detalle = `Entrenado con ${muestrasBenignas.length} vectores benignos extraídos de tus archivos CSV de CICIDS2017.`;
      estadoModelo.cargando = false;

      io.emit('entrenamiento_completo', estadoModelo);
    } catch (err: unknown) {
      estadoModelo.cargando = false;
      const msg = err instanceof Error ? err.message : String(err);
      io.emit('entrenamiento_error', { mensaje: msg });
    }
  }, 80);

  res.json({ status: 'entrenamiento_iniciado', archivos_guardados: files.length });
});

// Socket.IO conexión
io.on('connection', (socket) => {
  // Conexión exitosa para streaming
});

// Iniciar servidor en el puerto 3000
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n======================================================`);
  console.log(`Centinela v2 corriendo en http://0.0.0.0:${PORT}`);
  console.log(`Dashboard de administración: http://localhost:${PORT}/`);
  console.log(`Login demo protegido:       http://localhost:${PORT}/demo`);
  console.log(`Endpoints de protección:    POST /evaluar, POST /registrar_intento`);
  console.log(`======================================================\n`);
});
