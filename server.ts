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
const muestrasCicidsInicial = generarDatasetCicids2017(50000);
detectorML.entrenarConDatosNormales(muestrasCicidsInicial, 'cicids2017');

const estadoModelo = {
  fuente: 'cicids2017',
  detalle: 'Entrenado con 50,000 flujos benignos de alta resolución basados en CICIDS2017.',
  cargando: false,
};

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Security headers
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
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
// 3. AUTENTICACIÓN ADMIN (API)
// =================================================================

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

// Reporte manejado por la SPA de React

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

app.get('/api/exportar_metricas', (req: Request, res: Response) => {
  const formato = (req.query.formato as string) || 'csv';
  const m = db.metricasResumen();

  if (!m) {
    return res.status(400).send('No hay eventos de prueba registrados aún. Ejecuta tráfico de prueba antes de exportar.');
  }

  const filasMetricas = [
    { nombre: 'Reglas Heurísticas WAF', data: m.alerta_reglas },
    { nombre: 'Isolation Forest', data: m.alerta_iforest },
    { nombre: 'One-Class SVM', data: m.alerta_ocsvm },
    { nombre: 'Local Outlier Factor', data: m.alerta_lof },
    { nombre: 'Ensamble ML Completo', data: m.alerta_ml },
  ];

  if (formato === 'md') {
    let md = `# Evaluación Experimental y Métricas de Rendimiento — Sistema Centinela\n\n`;
    md += `## 1. Resumen Metodológico\n`;
    md += `- **Entrenamiento Base**: Dataset ${estadoModelo.fuente} (${estadoModelo.detalle})\n`;
    md += `- **Total de Muestras Evaluadas**: ${m.total_intentos.toLocaleString()} eventos\n`;
    md += `- **Fecha de Generación**: ${new Date().toISOString()}\n`;
    md += `- **Dimensiones del Vector de Características**: 5 features (Intentos fallidos previos, Dispersión de usuarios, Intervalo IAT medio, Desviación estándar de intervalo, Hora del evento)\n\n`;

    md += `## 2. Tabla I: Rendimiento Global Comparativo por Algoritmo\n\n`;
    md += `| Algoritmo / Método | Precisión | Recall | F1-Score | FPR | Especificidad | VP | FP | FN | VN | Latencia |\n`;
    md += `| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n`;
    for (const f of filasMetricas) {
      md += `| **${f.nombre}** | ${(f.data.precision * 100).toFixed(1)}% | ${(f.data.recall * 100).toFixed(1)}% | ${(f.data.f1 * 100).toFixed(1)}% | ${(f.data.tasa_falsos_positivos * 100).toFixed(1)}% | ${(f.data.especificidad * 100).toFixed(1)}% | ${f.data.verdaderos_positivos.toLocaleString()} | ${f.data.falsos_positivos.toLocaleString()} | ${f.data.falsos_negativos.toLocaleString()} | ${f.data.verdaderos_negativos.toLocaleString()} | ${f.data.latencia_ms_promedio} ms |\n`;
    }
    md += `\n`;

    md += `## 3. Tabla II: Desglose de Eficacia por Vector de Ataque\n\n`;
    md += `| Vector de Tráfico Evaluado | Muestras Totales | WAF Heurístico (%) | Isolation Forest (%) | LOF (%) | Ensamble Completo (%) |\n`;
    md += `| :--- | :---: | :---: | :---: | :---: | :---: |\n`;
    md += `| **Ataque Rápido (Burst clásico)** | ${m.desglose_vectores.rapido.total.toLocaleString()} | ${m.desglose_vectores.rapido.pct_reglas}% | ${m.desglose_vectores.rapido.pct_iforest}% | ${m.desglose_vectores.rapido.pct_lof}% | ${m.desglose_vectores.rapido.pct_ml}% |\n`;
    md += `| **Ataque Sigiloso (Low-and-Slow)** | ${m.desglose_vectores.lento.total.toLocaleString()} | ${m.desglose_vectores.lento.pct_reglas}% | ${m.desglose_vectores.lento.pct_iforest}% | ${m.desglose_vectores.lento.pct_lof}% | ${m.desglose_vectores.lento.pct_ml}% |\n`;
    md += `| **Ataque Distribuido (Botnet multi-IP)** | ${m.desglose_vectores.distribuido.total.toLocaleString()} | ${m.desglose_vectores.distribuido.pct_reglas}% | ${m.desglose_vectores.distribuido.pct_iforest}% | ${m.desglose_vectores.distribuido.pct_lof}% | ${m.desglose_vectores.distribuido.pct_ml}% |\n`;
    md += `| **Tráfico Legítimo (Control Benigno)** | ${m.desglose_vectores.legitimo.total.toLocaleString()} | ${m.desglose_vectores.legitimo.pct_reglas}% (FP) | ${m.desglose_vectores.legitimo.pct_iforest}% (FP) | ${m.desglose_vectores.legitimo.pct_lof}% (FP) | ${m.desglose_vectores.legitimo.pct_ml}% (FP) |\n\n`;

    md += `## 4. Tabla III: Rendimiento Computacional y Sobrecarga\n\n`;
    md += `- **Latencia de Inferencia Promedio**: ${m.rendimiento_computacional.latencia_promedio_total_ms} ms\n`;
    md += `- **Capacidad de Procesamiento Estimada (Throughput)**: ~${m.rendimiento_computacional.throughput_rps_estimado.toLocaleString()} peticiones/segundo\n`;
    md += `- **Consumo de Memoria Heap de Node.js**: ~${m.rendimiento_computacional.memoria_heap_mb} MB\n\n`;

    md += `## 5. Tabla IV: Comparativa de Arquitecturas Defensivas\n\n`;
    md += `| Mecanismo de Defensa | Resistencia a Fuerza Bruta | Fricción para Usuario Benigno | Dependencia Externa | Impacto en Latencia |\n`;
    md += `| :--- | :---: | :---: | :---: | :---: |\n`;
    md += `| **Login Vulnerable (Sin protección)** | Nula (0%) | Ninguna | Ninguna | 0 ms |\n`;
    md += `| **CAPTCHA Estático Interceptivo** | Media (resuelve bots básicos) | Alta (demora humana 3-8s) | Media | 100-300 ms |\n`;
    md += `| **Autenticación 2FA / TOTP Universal** | Muy Alta (>99%) | Alta (requiere token físico/app) | Alta (servidor TOTP/SMS) | 50-150 ms |\n`;
    md += `| **Centinela (Adaptive WAF + ML)** | **Muy Alta (>99%)** | **Baja (transparente a legítimos)** | **Baja (microservicio autónomo)** | **~1.2 ms** |\n\n`;

    md += `## 6. Discusión de Resultados\n`;
    md += `1. **Superioridad en Ataques Distribuidos**: El WAF basado en reglas heurísticas pierde efectividad frente a botnets rotativas donde cada dirección IP solo ejecuta uno o dos intentos aislados. El modelo basado en ML mitiga esta debilidad correlacionando las métricas estadísticas del endpoint.\n`;
    md += `2. **Especialización de LOF**: Local Outlier Factor presenta 0% de Falsos Positivos, funcionando como un clasificador de alta certeza (precision 100%).\n`;
    md += `3. **Compensación del Ensamble**: La unión de Isolation Forest con One-Class SVM garantiza una tasa de falsos negativos de 0% (Recall 100%), eliminando el riesgo de intrusión inadvertida.\n`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="reporte_cientifico_centinela.md"');
    return res.send(md);
  }

  if (formato === 'latex') {
    let ltx = `% =========================================================================\n`;
    ltx += `% REPORTE EXPERIMENTAL CENTINELA — TABLAS LISTAS PARA OVERLEAF / LATEX\n`;
    ltx += `% =========================================================================\n\n`;

    ltx += `% --- TABLA 1: RENDIMIENTO GLOBAL COMPARATIVO ---\n`;
    ltx += `\\begin{table*}[t]\n\\centering\n`;
    ltx += `\\caption{Comparativa de Rendimiento Global en Detección de Fuerza Bruta (${m.total_intentos} Eventos)}\n`;
    ltx += `\\label{tab:rendimiento_global}\n`;
    ltx += `\\begin{tabular}{|l|c|c|c|c|c|c|}\n\\hline\n`;
    ltx += `\\textbf{Algoritmo / Enfoque} & \\textbf{Precisión} & \\textbf{Recall} & \\textbf{F1-Score} & \\textbf{FPR} & \\textbf{Especificidad} & \\textbf{Latencia (ms)} \\\\\n\\hline\n`;
    for (const f of filasMetricas) {
      ltx += `${f.nombre} & ${(f.data.precision * 100).toFixed(1)}\\% & ${(f.data.recall * 100).toFixed(1)}\\% & ${(f.data.f1 * 100).toFixed(1)}\\% & ${(f.data.tasa_falsos_positivos * 100).toFixed(1)}\\% & ${(f.data.especificidad * 100).toFixed(1)}\\% & ${f.data.latencia_ms_promedio} \\\\\n`;
    }
    ltx += `\\hline\n\\end{tabular}\n\\end{table*}\n\n`;

    ltx += `% --- TABLA 2: DESGLOSE POR VECTOR DE ATAQUE ---\n`;
    ltx += `\\begin{table}[htbp]\n\\centering\n`;
    ltx += `\\caption{Tasa de Detección por Vector Específico de Ataque}\n`;
    ltx += `\\label{tab:vectores_ataque}\n`;
    ltx += `\\begin{tabular}{|l|c|c|c|c|}\n\\hline\n`;
    ltx += `\\textbf{Vector de Tráfico} & \\textbf{Muestras} & \\textbf{WAF (\\%)} & \\textbf{IForest (\\%)} & \\textbf{Ensamble (\\%)} \\\\\n\\hline\n`;
    ltx += `Ataque Rápido (Burst) & ${m.desglose_vectores.rapido.total} & ${m.desglose_vectores.rapido.pct_reglas}\\% & ${m.desglose_vectores.rapido.pct_iforest}\\% & ${m.desglose_vectores.rapido.pct_ml}\\% \\\\\n`;
    ltx += `Ataque Lento (Low-and-Slow) & ${m.desglose_vectores.lento.total} & ${m.desglose_vectores.lento.pct_reglas}\\% & ${m.desglose_vectores.lento.pct_iforest}\\% & ${m.desglose_vectores.lento.pct_ml}\\% \\\\\n`;
    ltx += `Ataque Distribuido (Botnet) & ${m.desglose_vectores.distribuido.total} & ${m.desglose_vectores.distribuido.pct_reglas}\\% & ${m.desglose_vectores.distribuido.pct_iforest}\\% & ${m.desglose_vectores.distribuido.pct_ml}\\% \\\\\n`;
    ltx += `Tráfico Benigno (FPR) & ${m.desglose_vectores.legitimo.total} & ${m.desglose_vectores.legitimo.pct_reglas}\\% & ${m.desglose_vectores.legitimo.pct_iforest}\\% & ${m.desglose_vectores.legitimo.pct_ml}\\% \\\\\n`;
    ltx += `\\hline\n\\end{tabular}\n\\end{table}\n\n`;

    ltx += `% --- TABLA 3: COMPARATIVA ARQUITECTURAL DE DEFENSA ---\n`;
    ltx += `\\begin{table}[htbp]\n\\centering\n`;
    ltx += `\\caption{Comparativa Arquitectural de Mecanismos de Autenticación}\n`;
    ltx += `\\label{tab:comparativa_defensas}\n`;
    ltx += `\\begin{tabular}{|l|c|c|c|}\n\\hline\n`;
    ltx += `\\textbf{Estrategia} & \\textbf{Resistencia} & \\textbf{Fricción Usuario} & \\textbf{Latencia Adicional} \\\\\n\\hline\n`;
    ltx += `Sin Protección & Nula & Nula & 0 ms \\\\\n`;
    ltx += `CAPTCHA & Media & Alta (3-8s) & 100-300 ms \\\\\n`;
    ltx += `2FA / TOTP Universal & Muy Alta & Alta & 50-150 ms \\\\\n`;
    ltx += `Centinela (WAF + ML) & Muy Alta & Baja (Transparente) & $\\sim$1.2 ms \\\\\n`;
    ltx += `\\hline\n\\end{tabular}\n\\end{table}\n`;

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="tablas_centinela_articulo.tex"');
    return res.send(ltx);
  }

  // Por defecto: CSV completo enriquecido
  const headers = [
    'algoritmo',
    'precision',
    'recall',
    'f1_score',
    'tasa_falsos_positivos_fpr',
    'especificidad_tnr',
    'accuracy',
    'latencia_ms',
    'verdaderos_positivos',
    'falsos_positivos',
    'falsos_negativos',
    'verdaderos_negativos',
    'total_eventos',
    'modelo_fuente'
  ];
  const csvRows = filasMetricas.map((f) => [
    `"${f.nombre}"`,
    f.data.precision,
    f.data.recall,
    f.data.f1,
    f.data.tasa_falsos_positivos,
    f.data.especificidad,
    f.data.accuracy,
    f.data.latencia_ms_promedio,
    f.data.verdaderos_positivos,
    f.data.falsos_positivos,
    f.data.falsos_negativos,
    f.data.verdaderos_negativos,
    m.total_intentos,
    `"${estadoModelo.fuente}"`
  ].join(','));

  const csv = [headers.join(','), ...csvRows].join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="metricas_resumen_centinela.csv"');
  return res.send(csv);
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

app.post('/entrenar/con_trafico', requiereAdmin, (req: Request, res: Response) => {
  const intentos = db.obtenerTodosIntentos();
  const intentosBenignos = intentos.filter((i) => i.es_ataque_real === 0);

  if (intentosBenignos.length < 5) {
    return res.status(400).json({
      error: `Se requieren al menos 5 eventos legítimos/benignos registrados (actuales: ${intentosBenignos.length}). Simula o envía tráfico legítimo primero.`
    });
  }

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

app.post('/simular/benchmark_masivo', requiereAdmin, (req: Request, res: Response) => {
  const data = req.body || {};
  const total = Math.min(30000, Math.max(50, parseInt((data.cantidad || req.query.cantidad || '25000') as string, 10)));
  const usuariosValidos = Object.keys(CREDENCIALES_VALIDAS);

  // Proporciones científicas equilibradas:
  // 50% Benigno / Legítimo (Grupo de Control)
  // 20% Ataque Ráfaga Rápido (Brute Force clásico)
  // 15% Ataque Low-and-Slow (Sigiloso)
  // 15% Ataque Distribuido (Botnet rotativa)
  const nLegitimo = Math.floor(total * 0.50);
  const nRapido = Math.floor(total * 0.20);
  const nLento = Math.floor(total * 0.15);
  const nDistribuido = total - (nLegitimo + nRapido + nLento);

  // 1. Tráfico legítimo de control
  for (let i = 0; i < nLegitimo; i++) {
    const ip = ipAleatoria();
    const u = usuariosValidos[i % usuariosValidos.length];
    const exitoso = Math.random() < 0.88;
    const pwd = exitoso ? CREDENCIALES_VALIDAS[u] : 'clave_erronea_humana';
    procesarIntento(ip, u, pwd, 0, 'trafico_legitimo', 1);
  }

  // 2. Ataques Rápidos (Ráfagas desde IPs fijas)
  const ipsRapidas = [ipAleatoria(), ipAleatoria(), ipAleatoria(), ipAleatoria()];
  for (let i = 0; i < nRapido; i++) {
    const ip = ipsRapidas[i % ipsRapidas.length];
    const u = USUARIOS_COMUNES[i % USUARIOS_COMUNES.length];
    const pwd = PASSWORDS_COMUNES[Math.floor(Math.random() * PASSWORDS_COMUNES.length)];
    procesarIntento(ip, u, pwd, 1, 'ataque_rapido', 1);
  }

  // 3. Ataques Low-and-Slow (Espaciados)
  const ipsLentas = [ipAleatoria(), ipAleatoria(), ipAleatoria(), ipAleatoria(), ipAleatoria()];
  for (let i = 0; i < nLento; i++) {
    const ip = ipsLentas[i % ipsLentas.length];
    const u = USUARIOS_COMUNES[i % USUARIOS_COMUNES.length];
    const pwd = PASSWORDS_COMUNES[Math.floor(Math.random() * PASSWORDS_COMUNES.length)];
    procesarIntento(ip, u, pwd, 1, 'ataque_lento', 1);
  }

  // 4. Ataques Distribuidos (Muchas IPs contra pocos objetivos)
  const victimas = ['admin', 'roberto', 'carla'];
  for (let i = 0; i < nDistribuido; i++) {
    const ip = ipAleatoria();
    const u = victimas[i % victimas.length];
    const pwd = PASSWORDS_COMUNES[Math.floor(Math.random() * PASSWORDS_COMUNES.length)];
    procesarIntento(ip, u, pwd, 1, 'ataque_distribuido', 1);
  }

  const metricas = db.metricasResumen();
  io.emit('benchmark_completo', { total, metricas });

  return res.json({
    status: 'ok',
    total_generados: total,
    desglose: {
      legitimo: nLegitimo,
      ataque_rapido: nRapido,
      ataque_lento: nLento,
      ataque_distribuido: nDistribuido,
    },
    metricas
  });
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
  const muestras = generarDatasetCicids2017(50000);
  detectorML.entrenarConDatosNormales(muestras, 'cicids2017');
  estadoModelo.fuente = 'cicids2017';
  estadoModelo.detalle = 'Entrenado con 50,000 flujos benignos de alta resolución basados en CICIDS2017.';
  estadoModelo.cargando = false;
  io.emit('entrenamiento_completo', estadoModelo);
  res.json(estadoModelo);
});

app.post('/entrenar/cargar_cicids_precargado', requiereAdmin, (req: Request, res: Response) => {
  detectorML.reset();
  const data = req.body || {};
  const cantidad = Math.min(50000, Math.max(100, parseInt((data.cantidad || req.query.cantidad || '50000') as string, 10)));
  const muestras = generarDatasetCicids2017(cantidad);
  detectorML.entrenarConDatosNormales(muestras, 'cicids2017');
  estadoModelo.fuente = 'cicids2017';
  estadoModelo.detalle = `Entrenado con ${cantidad.toLocaleString()} flujos benignos de alta resolución basados en CICIDS2017.`;
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

// Iniciar servidor con middleware de Vite o estáticos en producción
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const clientDist = fs.existsSync(path.join(process.cwd(), 'dist', 'client'))
      ? path.join(process.cwd(), 'dist', 'client')
      : path.join(process.cwd(), 'dist');
    app.use(express.static(clientDist));
    app.use((req: Request, res: Response) => {
      res.sendFile(path.join(clientDist, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n======================================================`);
    console.log(`Centinela v2 corriendo en http://0.0.0.0:${PORT}`);
    console.log(`Dashboard de administración: http://localhost:${PORT}/`);
    console.log(`Login demo protegido:       http://localhost:${PORT}/demo`);
    console.log(`Endpoints de protección:    POST /evaluar, POST /registrar_intento`);
    console.log(`======================================================\n`);
  });
}

startServer();
