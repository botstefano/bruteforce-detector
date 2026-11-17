import { setTimeout as sleep } from 'node:timers/promises';

type AgentCommand = 'continue' | 'pause' | 'cancel';

interface LabJob {
  job_id: string;
  campaign_id: string;
  run_id: string;
  scenario_id: string;
  agent_id: string;
  target_account: 'ronan' | 'andy' | 'stefano';
  start_at: string;
  interval_ms: number;
  outcomes: boolean[];
  max_attempts: number;
  attempts_completed?: number;
  event_ids?: string[];
}

interface AgentCredentials {
  ronan: string;
  andy: string;
  stefano: string;
}

const REQUIRED_USERS = ['ronan', 'andy', 'stefano'] as const;
const coordinatorUrl = requireOrigin('CENTINELA_LAB_COORDINATOR_URL', 'bruteforce-detector-2uv4.onrender.com');
const portalUrl = requireOrigin('CENTINELA_LAB_PORTAL_URL', 'centinela-auth-lab.onrender.com');
const agentToken = requiredEnv('CENTINELA_LAB_AGENT_TOKEN');
const agentId = requiredEnv('CENTINELA_LAB_AGENT_ID');
const version = process.env.CENTINELA_LAB_AGENT_VERSION || 'centinela-v3-agent/1.0.0';
const invalidPassword = process.env.CENTINELA_LAB_INVALID_PASSWORD || 'Centinela-lab-invalid-credential-DO-NOT-LOGIN';
const credentials = parseCredentials(requiredEnv('CENTINELA_LAB_CREDENTIALS_JSON'));

if (agentToken.length < 32) throw new Error('CENTINELA_LAB_AGENT_TOKEN debe tener al menos 32 caracteres.');
if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(agentId)) throw new Error('CENTINELA_LAB_AGENT_ID debe tener entre 3 y 64 caracteres.');
if (invalidPassword.length < 16 || invalidPassword.length > 240) {
  throw new Error('CENTINELA_LAB_INVALID_PASSWORD debe tener entre 16 y 240 caracteres.');
}
if (REQUIRED_USERS.some((username) => credentials[username] === invalidPassword)) {
  throw new Error('La credencial inválida coincide con una contraseña de prueba; cambia CENTINELA_LAB_INVALID_PASSWORD.');
}

function requiredEnv(key: string): string {
  const value = process.env[key]?.trim();
  if (!value) throw new Error(`Falta la variable requerida ${key}.`);
  return value;
}

function requireOrigin(key: string, allowedHost: string): string {
  const raw = requiredEnv(key);
  const url = new URL(raw);
  if (url.protocol !== 'https:' || url.hostname.toLowerCase() !== allowedHost || url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
    throw new Error(`${key} debe ser el origen HTTPS permitido https://${allowedHost}.`);
  }
  return url.origin;
}

function parseCredentials(raw: string): AgentCredentials {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('CENTINELA_LAB_CREDENTIALS_JSON no contiene JSON válido.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('CENTINELA_LAB_CREDENTIALS_JSON debe ser un objeto con las tres cuentas del testbed.');
  }
  const record = parsed as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== [...REQUIRED_USERS].sort().join(',')) {
    throw new Error('CENTINELA_LAB_CREDENTIALS_JSON debe contener exactamente ronan, andy y stefano.');
  }
  for (const username of REQUIRED_USERS) {
    if (typeof record[username] !== 'string' || record[username].length < 16 || record[username].length > 256) {
      throw new Error(`La contraseña de ${username} debe tener entre 16 y 256 caracteres.`);
    }
  }
  return record as unknown as AgentCredentials;
}

async function requestJson(
  base: string,
  pathname: string,
  options: RequestInit = {},
): Promise<{ response: Response; body: any }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25_000);
  try {
    const response = await fetch(base + pathname, {
      ...options,
      redirect: 'error',
      cache: 'no-store',
      signal: controller.signal,
    });
    const body = await response.json().catch(() => ({}));
    return { response, body };
  } finally {
    clearTimeout(timeout);
  }
}

async function coordinator(pathname: string, method = 'GET', body?: Record<string, unknown>) {
  const { response, body: payload } = await requestJson(coordinatorUrl, pathname, {
    method,
    headers: {
      Authorization: `Bearer ${agentToken}`,
      'Content-Type': 'application/json',
      'X-Centinela-Agent-Id': agentId,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) throw new Error(`Coordinador respondió HTTP ${response.status}: ${String(payload.error || 'error').slice(0, 180)}`);
  return payload;
}

async function log(message: string) {
  try {
    await coordinator('/api/lab/agent/log', 'POST', {
      agent_id: agentId,
      message: message.slice(0, 220),
    });
  } catch {
    // Los logs de observabilidad no deben ocultar un error real de captura.
  }
  console.log(`[${new Date().toISOString()}] ${message}`);
}

async function checkCommand(jobId: string): Promise<AgentCommand> {
  const result = await coordinator('/api/lab/agent/heartbeat', 'POST', {
    agent_id: agentId,
    job_id: jobId,
  });
  return result.command === 'pause' || result.command === 'cancel' ? result.command : 'continue';
}

async function waitUntilAndCheck(job: LabJob): Promise<AgentCommand> {
  const startAt = Date.parse(job.start_at);
  while (Number.isFinite(startAt) && Date.now() < startAt) {
    const command = await checkCommand(job.job_id);
    if (command !== 'continue') return command;
    await sleep(Math.min(2_000, Math.max(250, startAt - Date.now())));
  }
  return checkCommand(job.job_id);
}

async function pauseUntilResumed(job: LabJob): Promise<AgentCommand> {
  for (;;) {
    await sleep(3_000);
    const command = await checkCommand(job.job_id);
    if (command !== 'pause') return command;
  }
}

async function executeJob(job: LabJob): Promise<void> {
  const eventIds: string[] = Array.isArray(job.event_ids) ? job.event_ids.filter((id) => typeof id === 'string') : [];
  const httpStatuses: number[] = [];
  let attemptsCompleted = Number.isInteger(job.attempts_completed) ? Number(job.attempts_completed) : 0;
  let finalStatus: 'completed' | 'failed' | 'cancelled' = 'completed';
  let failureReason: string | null = null;

  try {
    if (!REQUIRED_USERS.includes(job.target_account)) throw new Error('La tarea contiene una cuenta objetivo fuera del testbed.');
    if (!Array.isArray(job.outcomes) || job.outcomes.length === 0 || job.outcomes.length > 12 || job.max_attempts !== job.outcomes.length) {
      throw new Error('La tarea supera los límites de intentos permitidos.');
    }
    if (job.interval_ms < 1_000 || job.interval_ms > 120_000) throw new Error('El intervalo de la tarea está fuera del rango permitido.');

    await log(`Tarea ${job.job_id.slice(0, 8)} iniciada: ${job.scenario_id}, ${job.outcomes.length} intentos.`);
    let command = await waitUntilAndCheck(job);
    if (command === 'cancel') finalStatus = 'cancelled';

    for (let index = attemptsCompleted; index < job.outcomes.length && finalStatus === 'completed'; index += 1) {
      while (command === 'pause') {
        command = await pauseUntilResumed(job);
      }
      if (command === 'cancel') {
        finalStatus = 'cancelled';
        break;
      }

      const expectedAuthSuccess = Boolean(job.outcomes[index]);
      const invalidCandidate = `${invalidPassword}-${index + 1}`;
      if (!expectedAuthSuccess && Object.values(credentials).includes(invalidCandidate)) {
        throw new Error('La credencial inválida generada coincide con una contraseña del testbed; cancela la tarea y cambia el secreto base.');
      }
      const password = expectedAuthSuccess ? credentials[job.target_account] : invalidCandidate;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 25_000);
      try {
        const response = await fetch(portalUrl + '/agent/login', {
          method: 'POST',
          redirect: 'error',
          headers: {
            Authorization: `Bearer ${agentToken}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
            'X-Centinela-Campaign-Id': job.campaign_id,
            'X-Centinela-Run-Id': job.run_id,
            'X-Centinela-Agent-Id': agentId,
            'X-Centinela-Scenario-Id': job.scenario_id,
          },
          body: JSON.stringify({ job_id: job.job_id, attempt_index: index, campaign_id: job.campaign_id, run_id: job.run_id, scenario_id: job.scenario_id, username: job.target_account, password }),
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        httpStatuses.push(response.status);
        if ((expectedAuthSuccess ? response.status !== 200 : response.status !== 401) || payload.event_recorded !== true || typeof payload.event_id !== 'string') {
          throw new Error(`El portal no confirmó el evento (HTTP ${response.status}); se detiene la tarea para no producir datos incompletos.`);
        }
        eventIds.push(payload.event_id);
        attemptsCompleted = index + 1;
        await coordinator('/api/lab/agent/progress', 'POST', {
          agent_id: agentId,
          job_id: job.job_id,
          attempts_completed: attemptsCompleted,
          event_id: payload.event_id,
        });
        await log(`Evento ${attemptsCompleted}/${job.outcomes.length} confirmado: ${payload.event_id.slice(0, 8)} · HTTP ${response.status}.`);
      } finally {
        clearTimeout(timeout);
      }

      if (index < job.outcomes.length - 1) {
        const endAt = Date.now() + job.interval_ms;
        while (Date.now() < endAt) {
          command = await checkCommand(job.job_id);
          if (command !== 'continue') break;
          await sleep(Math.min(3_000, Math.max(250, endAt - Date.now())));
        }
      }
    }

    if (attemptsCompleted !== job.outcomes.length && finalStatus === 'completed') {
      finalStatus = 'cancelled';
    }
  } catch (error) {
    finalStatus = 'failed';
    failureReason = error instanceof Error ? error.message : String(error);
    await log(`Tarea fallida: ${failureReason.slice(0, 180)}`);
  }

  // Siempre informar un estado terminal. El coordinador rechazará etiquetar una tarea
  // fallida, cancelada o con IDs de eventos incompletos.
  await coordinator('/api/lab/agent/complete', 'POST', {
    agent_id: agentId,
    job_id: job.job_id,
    status: finalStatus,
    attempts_completed: attemptsCompleted,
    summary: { event_ids: eventIds, http_statuses: httpStatuses, failure_reason: failureReason },
  });
  await log(`Tarea ${job.job_id.slice(0, 8)} finalizada: ${finalStatus}, ${attemptsCompleted}/${job.outcomes.length} eventos confirmados.`);
}

async function registerAgent() {
  const registration = await coordinator('/api/lab/agent/register', 'POST', {
    agent_id: agentId,
    version,
  });
  console.log(`Agente ${agentId} registrado. IP HMAC observado por el coordinador: ${registration.egress_ip_hash_prefix}.`);
  await log('Runner conectado y listo.');
}

async function main() {
  await registerAgent();

  for (;;) {
    try {
      const result = await coordinator('/api/lab/agent/jobs/next');
      const job = result.job as LabJob | null;
      if (!job) {
        await sleep(5_000);
        continue;
      }
      await executeJob(job);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      await log(`Error de ejecución: ${detail.slice(0, 180)}`);
      // El coordinador guarda su cola en memoria. Si Render reinicia el servicio,
      // volver a registrar el runner permite que se recupere como agente disponible.
      try {
        await registerAgent();
      } catch (registrationError) {
        const registrationDetail = registrationError instanceof Error ? registrationError.message : String(registrationError);
        await log(`No se pudo recuperar el registro: ${registrationDetail.slice(0, 160)}`);
      }
      await sleep(8_000);
    }
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
