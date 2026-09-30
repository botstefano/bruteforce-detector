/**
 * bot_ataque.ts — Bot de prueba de fuerza bruta para atacar el login demo
 * y verificar la protección de Centinela de punta a punta.
 */

export const USUARIOS_COMUNES = ['admin', 'carla', 'roberto', 'root', 'test'];
export const PASSWORDS_COMUNES = [
  '123456',
  'password',
  'admin123',
  'qwerty',
  'letmein',
  '12345678',
  'root',
  'changeme',
];

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
): Promise<{ status: number | null; mensaje: string }> {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': ip,
      },
      body: JSON.stringify({ usuario, password, ip }),
    });
    const data = (await res.json().catch(() => ({}))) as { mensaje?: string; error?: string };
    const mensaje = data.mensaje || data.error || '';
    return { status: res.status, mensaje };
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
  onProgreso?: (msg: string) => void
): Promise<{ bloqueado: boolean; intentosRealizados: number }> {
  const reportar = onProgreso || console.log;
  const pwList = passwords && passwords.length > 0 ? passwords : PASSWORDS_COMUNES;
  const targetUser = usuario || USUARIOS_COMUNES[Math.floor(Math.random() * USUARIOS_COMUNES.length)];
  const ip = ipAleatoria();

  reportar(`[ATAQUE RÁPIDO] ip=${ip} usuario=${targetUser} (${numIntentos} intentos, ${intervalo}s entre cada uno)`);
  let realizados = 0;
  let bloqueado = false;

  for (let i = 1; i <= numIntentos; i++) {
    const pwd = pwList[Math.floor(Math.random() * pwList.length)];
    const { status, mensaje } = await intentar(url, ip, targetUser, pwd);
    realizados = i;
    reportar(`  intento ${String(i).padStart(2, ' ')}: password='${pwd.padEnd(12, ' ')}' -> HTTP ${status}  ${mensaje}`);

    if (status === 403) {
      reportar(`  >>> BLOQUEADO en el intento ${i}. Deteniendo ataque.`);
      bloqueado = true;
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
  onProgreso?: (msg: string) => void
): Promise<{ bloqueado: boolean; intentosRealizados: number }> {
  const reportar = onProgreso || console.log;
  const pwList = passwords && passwords.length > 0 ? passwords : PASSWORDS_COMUNES;
  const targetUser = usuario || USUARIOS_COMUNES[Math.floor(Math.random() * USUARIOS_COMUNES.length)];
  const ip = ipAleatoria();

  reportar(`[ATAQUE LENTO] ip=${ip} usuario=${targetUser} (${numIntentos} intentos, ${intervalo}s entre cada uno)`);
  let realizados = 0;
  let bloqueado = false;

  for (let i = 1; i <= numIntentos; i++) {
    const pwd = pwList[Math.floor(Math.random() * pwList.length)];
    const { status, mensaje } = await intentar(url, ip, targetUser, pwd);
    realizados = i;
    reportar(`  intento ${String(i).padStart(2, ' ')}: password='${pwd.padEnd(12, ' ')}' -> HTTP ${status}  ${mensaje}`);

    if (status === 403) {
      reportar(`  >>> BLOQUEADO en el intento ${i}. Deteniendo ataque.`);
      bloqueado = true;
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
  onProgreso?: (msg: string) => void
): Promise<{ ipsBloqueadas: number; totalIntentos: number }> {
  const reportar = onProgreso || console.log;
  const pwList = passwords && passwords.length > 0 ? passwords : PASSWORDS_COMUNES;
  const targetUser = usuario || USUARIOS_COMUNES[Math.floor(Math.random() * USUARIOS_COMUNES.length)];

  reportar(`[ATAQUE DISTRIBUIDO] usuario=${targetUser} (${numIps} IPs distintas, 1 intento cada una)`);
  let ipsBloqueadas = 0;

  for (let i = 1; i <= numIps; i++) {
    const ip = ipAleatoria();
    const pwd = pwList[Math.floor(Math.random() * pwList.length)];
    const { status, mensaje } = await intentar(url, ip, targetUser, pwd);
    reportar(`  IP ${i}/${numIps} (${ip}): password='${pwd.padEnd(12, ' ')}' -> HTTP ${status}  ${mensaje}`);

    if (status === 403) {
      ipsBloqueadas++;
      reportar('  >>> Esta IP fue bloqueada, pero el ataque sigue con nuevas IPs (intento de evasión distribuida)');
    }
    if (i < numIps) {
      await sleep(intervalo * 1000);
    }
  }

  return { ipsBloqueadas, totalIntentos: numIps };
}
