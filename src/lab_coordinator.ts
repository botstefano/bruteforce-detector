import { randomUUID } from 'node:crypto';

export type LabScenarioId =
  | 'benign_mixed'
  | 'attack_rapid'
  | 'attack_low_frequency'
  | 'attack_distributed';

type JobStatus = 'queued' | 'assigned' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
export type ExperimentPhase = 'train' | 'validation' | 'test';

interface LabAgent {
  agentId: string;
  egressIpHash: string;
  registeredAt: number;
  lastSeenAt: number;
  status: 'ready' | 'running' | 'paused' | 'offline' | 'error';
  currentJobId: string | null;
  version: string;
  nextJobAvailableAt: number;
}

interface LabJob {
  jobId: string;
  campaignId: string;
  runId: string;
  scenarioId: LabScenarioId;
  agentId: string | null;
  targetAccount: string;
  startAt: number;
  deadlineAt: number | null;
  sessionGapAfterMs: number;
  intervalMs: number;
  interAttemptDelaysMs: number[];
  outcomes: boolean[];
  sessionProfile: Record<string, unknown>;
  seed: number;
  expectedLabel: 'benign' | 'attack';
  actorType: 'benign_agent' | 'attack_agent';
  generationMethod: 'automated_http_agent';
  status: JobStatus;
  attemptsCompleted: number;
  createdAt: number;
  startedAt: number | null;
  finishedAt: number | null;
  pauseRequested: boolean;
  cancelRequested: boolean;
  summary: Record<string, unknown>;
}

export interface LabAutomationPlan {
  enabled: boolean;
  experimentId: string;
  batchSize: number;
  accounts: Array<'ronan' | 'andy' | 'stefano'>;
  targets: Record<ExperimentPhase, Partial<Record<LabScenarioId, number>>>;
  status: 'running' | 'paused' | 'completed';
  updatedAt: string;
  lastError: string | null;
}

interface LabCampaign {
  campaignId: string;
  experimentId: string;
  createdAt: number;
  status: 'queued' | 'running' | 'paused' | 'completed' | 'failed' | 'stopped';
  targetAccount: string;
  scenarioIds: LabScenarioId[];
  repetitions: number;
  phase: ExperimentPhase;
  jobIds: string[];
  manifestPersisted: boolean;
  manifest: Record<string, unknown>;
  scheduledByAutomation: boolean;
  labelsAppliedAt: string | null;
}

const agents = new Map<string, LabAgent>();
const jobs = new Map<string, LabJob>();
const campaigns = new Map<string, LabCampaign>();
let labAutomationPlan: LabAutomationPlan | null = null;
const AGENT_STALE_MS = 90_000;

/** Resets module state for isolated unit tests; never exposed by the HTTP API. */
export function resetLabCoordinatorForTesting(): void {
  agents.clear();
  jobs.clear();
  campaigns.clear();
  labAutomationPlan = null;
}

export function serializeLabCoordinatorState(experimentId?: string | null): Record<string, unknown> {
  const selectedCampaigns = [...campaigns.values()].filter((campaign) =>
    !experimentId || campaign.experimentId === experimentId
  );
  const campaignIds = new Set(selectedCampaigns.map((campaign) => campaign.campaignId));
  const selectedJobs = [...jobs.values()].filter((job) => campaignIds.has(job.campaignId));
  // Persist every registered runner, including idle runners. After a service
  // restart their next authenticated poll can safely move them from offline to ready.
  const selectedAgents = [...agents.values()];
  return {
    version: 2,
    saved_at: new Date().toISOString(),
    automation_plan: labAutomationPlan ? { ...labAutomationPlan, accounts: [...labAutomationPlan.accounts], targets: structuredClone(labAutomationPlan.targets) } : null,
    agents: selectedAgents.map((agent) => ({ ...agent })),
    campaigns: selectedCampaigns.map((campaign) => ({ ...campaign, jobIds: [...campaign.jobIds], scenarioIds: [...campaign.scenarioIds] })),
    jobs: selectedJobs.map((job) => ({ ...job, outcomes: [...job.outcomes], summary: { ...job.summary } })),
  };
}

export function restoreLabCoordinatorState(value: unknown): { agents: number; campaigns: number; jobs: number } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('El estado persistido del laboratorio no tiene un formato válido.');
  }
  const state = value as Record<string, unknown>;
  if (![1, 2].includes(Number(state.version)) || !Array.isArray(state.agents) || !Array.isArray(state.campaigns) || !Array.isArray(state.jobs)) {
    throw new Error('La versión del estado persistido del laboratorio no es compatible.');
  }
  resetLabCoordinatorForTesting();
  const rawPlan = state.automation_plan;
  if (rawPlan && typeof rawPlan === 'object' && !Array.isArray(rawPlan)) {
    const candidate = rawPlan as LabAutomationPlan;
    if (typeof candidate.experimentId === 'string' && typeof candidate.enabled === 'boolean' &&
        Number.isInteger(candidate.batchSize) && Array.isArray(candidate.accounts) &&
        candidate.targets && typeof candidate.targets === 'object') {
      labAutomationPlan = { ...candidate, accounts: [...candidate.accounts], targets: structuredClone(candidate.targets) };
    }
  }

  for (const raw of state.agents) {
    if (!raw || typeof raw !== 'object') continue;
    const agent = raw as LabAgent;
    if (typeof agent.agentId !== 'string' || !/^[a-f0-9]{64}$/i.test(agent.egressIpHash || '')) continue;
    // Give runners a 90-second reconnection window after coordinator restart.
    // A live runner's next authenticated poll will restore its ready/running state.
    agent.status = 'offline';
    agent.lastSeenAt = Date.now();
    if (!Number.isFinite(agent.nextJobAvailableAt)) agent.nextJobAvailableAt = 0;
    agents.set(agent.agentId, { ...agent });
  }
  for (const raw of state.campaigns) {
    if (!raw || typeof raw !== 'object') continue;
    const campaign = raw as LabCampaign;
    if (typeof campaign.campaignId !== 'string' || typeof campaign.experimentId !== 'string' || !Array.isArray(campaign.jobIds)) continue;
    // Any coordinator snapshot is written only after the independent manifest is
    // persisted, so a restart can safely re-enable job claiming.
    campaigns.set(campaign.campaignId, {
      ...campaign,
      manifestPersisted: true,
      jobIds: [...campaign.jobIds],
      scenarioIds: [...campaign.scenarioIds],
      scheduledByAutomation: campaign.scheduledByAutomation === true,
      labelsAppliedAt: typeof campaign.labelsAppliedAt === 'string' ? campaign.labelsAppliedAt : null,
    });
  }
  for (const raw of state.jobs) {
    if (!raw || typeof raw !== 'object') continue;
    const job = raw as LabJob;
    if (typeof job.jobId !== 'string' || typeof job.campaignId !== 'string' || !Array.isArray(job.outcomes)) continue;
    if (!Array.isArray(job.interAttemptDelaysMs)) {
      job.interAttemptDelaysMs = Array.from({ length: Math.max(0, job.outcomes.length - 1) }, () => job.intervalMs);
    }
    if (!job.sessionProfile || typeof job.sessionProfile !== 'object') job.sessionProfile = { profile_version: 'legacy-fixed-v1' };
    if (!Number.isInteger(job.seed)) job.seed = 0;
    if (typeof job.deadlineAt !== 'number' || !Number.isFinite(job.deadlineAt)) job.deadlineAt = null;
    if (!Number.isFinite(job.sessionGapAfterMs)) job.sessionGapAfterMs = 0;
    const eventIds = Array.isArray(job.summary?.event_ids)
      ? (job.summary.event_ids as unknown[]).filter((item): item is string => typeof item === 'string')
      : [];
    if (!Number.isInteger(job.attemptsCompleted) || job.attemptsCompleted < 0 ||
        job.attemptsCompleted > job.outcomes.length || eventIds.length !== job.attemptsCompleted) {
      throw new Error(`La tarea persistida ${job.jobId} tiene progreso e IDs de eventos inconsistentes.`);
    }
    if (job.status === 'running' || job.status === 'assigned') job.status = 'assigned';
    jobs.set(job.jobId, { ...job, outcomes: [...job.outcomes], summary: { ...(job.summary ?? {}), event_ids: eventIds } });
  }
  for (const campaign of campaigns.values()) refreshCampaignStatus(campaign);
  return { agents: agents.size, campaigns: campaigns.size, jobs: jobs.size };
}


export const LAB_SCENARIO_CATALOG: Record<LabScenarioId, {
  label: string;
  description: string;
  expectedLabel: 'benign' | 'attack';
  actorType: 'benign_agent' | 'attack_agent';
  requiredAgents: number;
}> = {
  benign_mixed: {
    label: 'Sesión legítima con errores ocasionales',
    description: 'Sesiones controladas de 3–8 autenticaciones, con 0–2 errores ocasionales y pausas reproducibles variables de 8–180 segundos.',
    expectedLabel: 'benign',
    actorType: 'benign_agent',
    requiredAgents: 1,
  },
  attack_rapid: {
    label: 'Fuerza bruta desde un origen',
    description: 'Entre 6 y 10 autenticaciones fallidas controladas desde un único agente y origen de red.',
    expectedLabel: 'attack',
    actorType: 'attack_agent',
    requiredAgents: 1,
  },
  attack_low_frequency: {
    label: 'Intentos de baja frecuencia',
    description: 'Entre 8 y 12 autenticaciones fallidas con intervalos variables desde un único origen.',
    expectedLabel: 'attack',
    actorType: 'attack_agent',
    requiredAgents: 1,
  },
  attack_distributed: {
    label: 'Fuerza bruta distribuida',
    description: 'Entre 2 y 4 intentos fallidos por agente, desde cuatro IP observadas distintas y verificadas.',
    expectedLabel: 'attack',
    actorType: 'attack_agent',
    requiredAgents: 4,
  },
};



function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4_294_967_296;
  };
}

function randomBetween(random: () => number, min: number, max: number): number {
  return Math.floor(min + random() * (max - min + 1));
}

function shuffle<T>(items: T[], random: () => number): T[] {
  const result = [...items];
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

function buildScenarioProfile(scenarioId: LabScenarioId, seed: number): {
  outcomes: boolean[];
  delaysMs: number[];
  profile: Record<string, unknown>;
} {
  const random = seededRandom(seed);
  let outcomes: boolean[];
  let delaysMs: number[];
  let profileId: string;

  if (scenarioId === 'benign_mixed') {
    const attempts = randomBetween(random, 3, 8);
    const errors = randomBetween(random, 0, Math.min(2, attempts - 1));
    outcomes = shuffle([...Array(errors).fill(false), ...Array(attempts - errors).fill(true)], random);
    delaysMs = Array.from({ length: attempts - 1 }, () => randomBetween(random, 8_000, 180_000));
    profileId = 'benign_session_v2';
  } else if (scenarioId === 'attack_rapid') {
    const attempts = randomBetween(random, 6, 10);
    outcomes = Array(attempts).fill(false);
    delaysMs = Array.from({ length: attempts - 1 }, () => randomBetween(random, 1_000, 4_000));
    profileId = 'rapid_bruteforce_v2';
  } else if (scenarioId === 'attack_low_frequency') {
    const attempts = randomBetween(random, 8, 12);
    outcomes = Array(attempts).fill(false);
    delaysMs = Array.from({ length: attempts - 1 }, () => randomBetween(random, 45_000, 150_000));
    profileId = 'low_frequency_bruteforce_v2';
  } else {
    const attempts = randomBetween(random, 2, 4);
    outcomes = Array(attempts).fill(false);
    delaysMs = Array.from({ length: attempts - 1 }, () => randomBetween(random, 6_000, 20_000));
    profileId = 'distributed_bruteforce_v2';
  }

  return {
    outcomes,
    delaysMs,
    profile: {
      profile_id: profileId,
      profile_version: 2,
      planned_attempts: outcomes.length,
      planned_failures: outcomes.filter((success) => !success).length,
      inter_attempt_delays_ms: [...delaysMs],
      reproducibility: 'seeded_prng_v1',
    },
  };
}

function isScenarioId(value: unknown): value is LabScenarioId {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(LAB_SCENARIO_CATALOG, value);
}

function activeAgents(now = Date.now()): LabAgent[] {
  return [...agents.values()].filter((agent) => now - agent.lastSeenAt <= AGENT_STALE_MS);
}

function refreshCampaignStatus(campaign: LabCampaign): void {
  const campaignJobs = campaign.jobIds.map((id) => jobs.get(id)).filter((job): job is LabJob => Boolean(job));
  if (campaign.status === 'stopped') return;
  if (campaignJobs.length > 0 && campaignJobs.every((job) => ['completed', 'failed', 'cancelled'].includes(job.status))) {
    campaign.status = campaignJobs.some((job) => job.status === 'failed' || job.status === 'cancelled') ? 'failed' : 'completed';
  } else if (campaignJobs.some((job) => job.status === 'running' || job.status === 'assigned')) {
    campaign.status = 'running';
  } else if (campaignJobs.some((job) => job.status === 'paused' || job.pauseRequested)) {
    campaign.status = 'paused';
  }
}

export function registerLabAgent(input: {
  agentId: string;
  egressIpHash: string;
  version?: string;
}): LabAgent {
  const agentId = input.agentId.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(agentId)) {
    throw new Error('agent_id debe tener entre 3 y 64 caracteres alfanuméricos, punto, guion o guion bajo.');
  }
  if (!/^[a-f0-9]{64}$/i.test(input.egressIpHash)) {
    throw new Error('No se pudo verificar y seudonimizar la IP de salida del agente.');
  }
  const existing = agents.get(agentId);
  if (existing && existing.egressIpHash !== input.egressIpHash) {
    throw new Error('Este agent_id ya está registrado desde otro origen de red. Usa un identificador distinto por runner.');
  }
  const agent: LabAgent = existing ?? {
    agentId,
    egressIpHash: input.egressIpHash.toLowerCase(),
    registeredAt: Date.now(),
    lastSeenAt: Date.now(),
    status: 'ready',
    currentJobId: null,
    version: input.version || 'unknown',
    nextJobAvailableAt: 0,
  };
  agent.lastSeenAt = Date.now();
  if (!Number.isFinite(agent.nextJobAvailableAt)) agent.nextJobAvailableAt = 0;
  agent.version = input.version || agent.version;
  if (agent.status === 'offline' || agent.status === 'error') agent.status = 'ready';
  agents.set(agentId, agent);
  return { ...agent };
}

export function verifyLabAgentOrigin(agentId: string, egressIpHash: string): boolean {
  const agent = agents.get(agentId);
  return Boolean(agent && agent.egressIpHash === egressIpHash.toLowerCase());
}

export function getLabJobCaptureContext(agentId: string, jobId: string, attemptIndex: number): {
  campaignId: string;
  runId: string;
  scenarioId: LabScenarioId;
  targetAccount: string;
  expectedSuccess: boolean;
  egressIpHash: string;
  deadlineAt: number | null;
  deadlineExpired: boolean;
} {
  const job = jobs.get(jobId);
  const agent = agents.get(agentId);
  if (!job || !agent || job.agentId !== agentId || agent.currentJobId !== jobId) {
    throw new Error('La tarea no está asignada al agente autenticado.');
  }
  if (!['assigned', 'running'].includes(job.status)) {
    throw new Error('La tarea no está activa para capturar eventos.');
  }

  if (!Number.isInteger(attemptIndex) || attemptIndex !== job.attemptsCompleted ||
      attemptIndex < 0 || attemptIndex >= job.outcomes.length) {
    throw new Error('El índice de intento no coincide con el progreso confirmado de la tarea.');
  }
  return {
    campaignId: job.campaignId,
    runId: job.runId,
    scenarioId: job.scenarioId,
    targetAccount: job.targetAccount,
    expectedSuccess: job.outcomes[attemptIndex],
    egressIpHash: agent.egressIpHash,
    deadlineAt: job.deadlineAt,
    deadlineExpired: job.deadlineAt !== null && Date.now() >= job.deadlineAt,
  };
}

export function heartbeatLabAgent(agentId: string): {
  agent: LabAgent;
  command: 'continue' | 'pause' | 'cancel';
} {
  const agent = agents.get(agentId);
  if (!agent) throw new Error('Agente no registrado.');
  agent.lastSeenAt = Date.now();
  const job = agent.currentJobId ? jobs.get(agent.currentJobId) : null;
  if (!job) {
    if (agent.status !== 'error') agent.status = 'ready';
    return { agent: { ...agent }, command: 'continue' };
  }
  if (job.cancelRequested) return { agent: { ...agent }, command: 'cancel' };
  if (job.pauseRequested) {
    job.status = 'paused';
    agent.status = 'paused';
    refreshCampaignStatus(campaigns.get(job.campaignId)!);
    return { agent: { ...agent }, command: 'pause' };
  }
  if (job.status === 'paused') job.status = 'running';
  agent.status = 'running';
  return { agent: { ...agent }, command: 'continue' };
}


function buildLegacyScenarioProfile(scenarioId: LabScenarioId): {
  outcomes: boolean[];
  delaysMs: number[];
  profile: Record<string, unknown>;
} {
  const definitions: Record<LabScenarioId, { outcomes: boolean[]; intervalMs: number; profileId: string }> = {
    benign_mixed: {
      outcomes: [true, true, false, true, false, true, true],
      intervalMs: 4_000,
      profileId: 'legacy_benign_mixed_v1',
    },
    attack_rapid: {
      outcomes: [false, false, false, false, false, false],
      intervalMs: 2_000,
      profileId: 'legacy_attack_rapid_v1',
    },
    attack_low_frequency: {
      outcomes: [false, false, false, false, false, false, false, false],
      intervalMs: 75_000,
      profileId: 'legacy_attack_low_frequency_v1',
    },
    attack_distributed: {
      outcomes: [false, false],
      intervalMs: 12_000,
      profileId: 'legacy_attack_distributed_v1',
    },
  };
  const definition = definitions[scenarioId];
  const delaysMs = Array.from({ length: Math.max(0, definition.outcomes.length - 1) }, () => definition.intervalMs);
  return {
    outcomes: [...definition.outcomes],
    delaysMs,
    profile: {
      profile_id: definition.profileId,
      profile_version: 1,
      planned_attempts: definition.outcomes.length,
      planned_failures: definition.outcomes.filter((success) => !success).length,
      inter_attempt_delays_ms: [...delaysMs],
      reproducibility: 'legacy_fixed_v1',
    },
  };
}

export function createLabCampaign(input: {
  experimentId: string;
  targetAccount: string;
  targetAccounts?: string[];
  scenarioIds: unknown[];
  phase: ExperimentPhase;
  repetitions?: number;
  scheduledByAutomation?: boolean;
  phaseEndAtMs?: number | null;
}): { campaign: LabCampaign; manifest: Record<string, unknown> } {
  const now = Date.now();
  const scenarioIds = [...new Set(input.scenarioIds.filter(isScenarioId))];
  const repetitions = input.repetitions ?? 1;
  if (!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 5) {
    throw new Error('repetitions debe ser un entero entre 1 y 5.');
  }
  if (!input.experimentId) throw new Error('Se requiere un experimento activo.');
  const targetAccounts = [...new Set(input.targetAccounts?.length ? input.targetAccounts : [input.targetAccount])];
  if (!targetAccounts.length || targetAccounts.some((account) => !/^(ronan|andy|stefano)$/.test(account))) {
    throw new Error('Las cuentas objetivo deben ser cuentas de laboratorio autorizadas.');
  }
  if (scenarioIds.length === 0 || scenarioIds.length !== input.scenarioIds.length) {
    throw new Error('Selecciona uno o más escenarios válidos del catálogo experimental.');
  }
  if (!['train', 'validation', 'test'].includes(input.phase)) {
    throw new Error('La fase experimental no es válida.');
  }
  if (input.phase === 'train' && scenarioIds.some((scenarioId) => scenarioId !== 'benign_mixed')) {
    throw new Error('Durante entrenamiento solo se permite el escenario benigno mixto.');
  }
  const activeCampaign = [...campaigns.values()].find((campaign) =>
    campaign.experimentId === input.experimentId && ['queued', 'running', 'paused'].includes(campaign.status)
  );
  if (activeCampaign) {
    throw new Error(`La campaña ${activeCampaign.campaignId} todavía no ha finalizado. Complétala, páusala o detenla antes de iniciar otra.`);
  }

  const readyAgents = activeAgents(now).filter((agent) => agent.status === 'ready' && agent.currentJobId === null);
  const distributedRuns = scenarioIds.filter((id) => id === 'attack_distributed').length * repetitions;
  const distinctEgress = new Set(readyAgents.map((agent) => agent.egressIpHash));
  if (distributedRuns > 0 && distinctEgress.size < 4) {
    throw new Error(`El escenario distribuido necesita cuatro agentes activos con IP de salida independientes; ahora hay ${distinctEgress.size}.`);
  }
  if (readyAgents.length === 0) {
    throw new Error('No hay agentes conectados. Registra al menos un runner antes de crear una campaña.');
  }

  const campaignId = `${input.scheduledByAutomation ? 'v4' : 'v3'}-${randomUUID()}`;
  const jobIds: string[] = [];
  const manifestRuns: Record<string, unknown>[] = [];
  // Ejecutar primero los escenarios que necesitan sincronización distribuida
  // y dejar los low-frequency largos para el final.
  const orderedScenarioIds: LabScenarioId[] = [
    ...scenarioIds.filter((id) => id === 'attack_distributed'),
    ...scenarioIds.filter((id) => id !== 'attack_distributed' && id !== 'attack_low_frequency'),
    ...scenarioIds.filter((id) => id === 'attack_low_frequency'),
  ];
  let nextSingleAgent = 0;
  let nextSessionStart = now + 25_000;

  for (const scenarioId of orderedScenarioIds) {
    const definition = LAB_SCENARIO_CATALOG[scenarioId];
    for (let repetition = 1; repetition <= repetitions; repetition += 1) {
      const runTargetAccount = targetAccounts[(repetition - 1) % targetAccounts.length];
      const runId = randomUUID();
      const runSeed = Number.parseInt(randomUUID().replace(/-/g, '').slice(0, 8), 16) >>> 0;
      const profile = input.scheduledByAutomation
        ? buildScenarioProfile(scenarioId, runSeed)
        : buildLegacyScenarioProfile(scenarioId);
      let startAt = nextSessionStart;
      const sessionGapMs = randomBetween(seededRandom(runSeed ^ 0x9e3779b9), 8 * 60_000, 25 * 60_000);
      const plannedActiveDurationMs = profile.delaysMs.reduce((sum, delay) => sum + delay, 0) + profile.outcomes.length * 2_000;
      const assignedAgents = scenarioId === 'attack_distributed'
        ? readyAgents.filter((agent, index, all) =>
            all.findIndex((candidate) => candidate.egressIpHash === agent.egressIpHash) === index
          ).slice(0, 4)
        : [readyAgents[nextSingleAgent++ % readyAgents.length]];
      // Sessions cannot start until every assigned runner has completed its
      // previously scheduled rest. For distributed runs this synchronizes
      // all four origins to the latest available start time.
      startAt = Math.max(startAt, ...assignedAgents.map((agent) => agent.nextJobAvailableAt || 0));
      nextSessionStart = startAt + plannedActiveDurationMs + sessionGapMs;
      const runJobIds: string[] = [];

      for (const agent of assignedAgents) {
        const jobId = randomUUID();
        const job: LabJob = {
          jobId,
          campaignId,
          runId,
          scenarioId,
          agentId: agent.agentId,
          targetAccount: runTargetAccount,
          startAt,
          deadlineAt: Number.isFinite(input.phaseEndAtMs) ? Number(input.phaseEndAtMs) : null,
          sessionGapAfterMs: input.scheduledByAutomation ? sessionGapMs : 0,
          intervalMs: profile.delaysMs.length ? Math.round(profile.delaysMs.reduce((sum, delay) => sum + delay, 0) / profile.delaysMs.length) : 0,
          interAttemptDelaysMs: [...profile.delaysMs],
          outcomes: [...profile.outcomes],
          sessionProfile: { ...profile.profile },
          seed: runSeed,
          expectedLabel: definition.expectedLabel,
          actorType: definition.actorType,
          generationMethod: 'automated_http_agent',
          status: 'queued',
          attemptsCompleted: 0,
          createdAt: now,
          startedAt: null,
          finishedAt: null,
          pauseRequested: false,
          cancelRequested: false,
          summary: {},
        };
        jobs.set(jobId, job);
        jobIds.push(jobId);
        runJobIds.push(jobId);
      }

      manifestRuns.push({
        run_id: runId,
        scenario_id: scenarioId,
        repetition,
        expected_label: definition.expectedLabel,
        actor_type: definition.actorType,
        generation_method: 'automated_http_agent',
        target_account: runTargetAccount,
        required_independent_egress_ips: definition.requiredAgents,
        planned_agent_ids: assignedAgents.map((agent) => agent.agentId),
        planned_agent_origins: assignedAgents.map((agent) => ({
          agent_id: agent.agentId,
          egress_ip_hash: agent.egressIpHash,
        })),
        planned_start_at: new Date(startAt).toISOString(),
        planned_attempts_per_agent: profile.outcomes.length,
        planned_outcomes: [...profile.outcomes],
        planned_active_duration_ms: plannedActiveDurationMs,
        planned_inter_attempt_delays_ms: [...profile.delaysMs],
        session_profile: profile.profile,
        reproducibility_seed: runSeed,
        planned_session_gap_after_ms: sessionGapMs,
        planned_session_gap_profile: 'uniform_random_8_to_25_minutes',
        job_ids: runJobIds,
      });
    }
  }

  const campaign: LabCampaign = {
    campaignId,
    experimentId: input.experimentId,
    createdAt: now,
    status: 'queued',
    targetAccount: targetAccounts[0],
    scenarioIds,
    repetitions,
    phase: input.phase,
    jobIds,
    manifestPersisted: false,
    scheduledByAutomation: input.scheduledByAutomation === true,
    labelsAppliedAt: null,
    manifest: {
      protocol: input.scheduledByAutomation ? 'centinela-auth-study-v4-empirical' : 'centinela-auth-study-v3-compatible',
      campaign_id: campaignId,
      experiment_id: input.experimentId,
      phase: input.phase,
      created_at: new Date(now).toISOString(),
      target_account: targetAccounts[0],
      target_accounts: [...targetAccounts],
      scenarios: manifestRuns,
      truth_source: 'predefined_authorized_campaign_manifest',
      generation_profile_version: input.scheduledByAutomation ? 2 : 1,
      scheduling_mode: input.scheduledByAutomation ? 'automatic_phase_scheduler' : 'manual_campaign',
      note: 'Cada sesión tiene semilla reproducible, secuencia de resultados e intervalos planificados registrados en este manifiesto. La etiqueta esperada se conserva fuera del detector y nunca se envía en las solicitudes de autenticación. Los eventos son transacciones HTTP ejecutadas por agentes en un testbed controlado, no sesiones humanas espontáneas.',
    },
  };
  campaigns.set(campaignId, campaign);
  return { campaign: { ...campaign }, manifest: campaign.manifest };
}

function serializeJobForAgent(job: LabJob, agentId: string): Record<string, unknown> {
  const eventIds = Array.isArray(job.summary.event_ids)
    ? (job.summary.event_ids as unknown[]).filter((item): item is string => typeof item === 'string')
    : [];
  const agent = agents.get(agentId);
  const effectiveStartAt = Math.max(job.startAt, agent?.nextJobAvailableAt ?? 0);
  return {
    job_id: job.jobId,
    campaign_id: job.campaignId,
    run_id: job.runId,
    scenario_id: job.scenarioId,
    agent_id: agentId,
    target_account: job.targetAccount,
    start_at: new Date(effectiveStartAt).toISOString(),
    deadline_at: job.deadlineAt !== null ? new Date(job.deadlineAt).toISOString() : null,
    interval_ms: job.intervalMs,
    inter_attempt_delays_ms: [...job.interAttemptDelaysMs],
    session_profile: { ...job.sessionProfile },
    seed: job.seed,
    outcomes: [...job.outcomes],
    max_attempts: job.outcomes.length,
    attempts_completed: job.attemptsCompleted,
    event_ids: eventIds,
  };
}



export function configureLabAutomation(input: {
  experimentId: string;
  batchSize?: number;
  accounts?: string[];
  targets: Record<string, Record<string, number>>;
}): LabAutomationPlan {
  if (!input.experimentId) throw new Error('Se requiere un experimento para automatizar la recolección.');
  if (labAutomationPlan) throw new Error('El plan V4 ya fue configurado. No se pueden cambiar cuotas, cuentas ni tamaño de lote durante el experimento; usa pausar/reanudar.');
  const batchSize = input.batchSize ?? 5;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 5) {
    throw new Error('El tamaño de lote automático debe estar entre 1 y 5 sesiones.');
  }
  const allowedAccounts = ['ronan', 'andy', 'stefano'] as const;
  const accounts = [...new Set((input.accounts ?? [...allowedAccounts]).filter(
    (account): account is typeof allowedAccounts[number] => allowedAccounts.includes(account as typeof allowedAccounts[number])
  ))];
  if (!accounts.length) throw new Error('Configura al menos una cuenta de laboratorio autorizada.');
  const targets: LabAutomationPlan['targets'] = { train: {}, validation: {}, test: {} };
  for (const phase of ['train', 'validation', 'test'] as const) {
    const phaseTargets = input.targets[phase] ?? {};
    for (const [scenario, rawCount] of Object.entries(phaseTargets)) {
      if (!isScenarioId(scenario) || !Number.isInteger(rawCount) || rawCount < 0 || rawCount > 10_000) {
        throw new Error('Los objetivos de recolección contienen un escenario o una cantidad inválida.');
      }
      if (phase === 'train' && scenario !== 'benign_mixed') {
        throw new Error('El entrenamiento solo admite sesiones benignas.');
      }
      targets[phase][scenario] = rawCount;
    }
  }
  if (!targets.train.benign_mixed || targets.train.benign_mixed < 1) {
    throw new Error('Define un objetivo de al menos una sesión benigna para entrenamiento.');
  }
  const evaluationScenarios: LabScenarioId[] = ['benign_mixed', 'attack_rapid', 'attack_low_frequency', 'attack_distributed'];
  for (const phase of ['validation', 'test'] as const) {
    for (const scenarioId of evaluationScenarios) {
      const minimum = scenarioId === 'attack_distributed' ? 0 : 1;
      if (!Number.isInteger(targets[phase][scenarioId]) || (targets[phase][scenarioId] ?? -1) < minimum) {
        throw new Error(`La fase ${phase} debe incluir al menos ${minimum} sesiones de ${scenarioId}; los escenarios de un solo origen siguen siendo obligatorios.`);
      }
    }
  }

  labAutomationPlan = {
    enabled: true,
    experimentId: input.experimentId,
    batchSize,
    accounts,
    targets,
    status: 'running',
    updatedAt: new Date().toISOString(),
    lastError: null,
  };
  return { ...labAutomationPlan, accounts: [...accounts], targets: structuredClone(targets) };
}


export function discardUnpersistedLabAutomationPlan(experimentId: string): boolean {
  if (!labAutomationPlan || labAutomationPlan.experimentId !== experimentId) return false;
  const hasAutomaticCampaign = [...campaigns.values()].some(
    (campaign) => campaign.experimentId === experimentId && campaign.scheduledByAutomation
  );
  if (hasAutomaticCampaign) return false;
  labAutomationPlan = null;
  return true;
}

export function stopLabAutomation(): LabAutomationPlan | null {
  if (!labAutomationPlan) return null;
  labAutomationPlan = { ...labAutomationPlan, enabled: false, status: 'paused', updatedAt: new Date().toISOString() };
  return { ...labAutomationPlan, accounts: [...labAutomationPlan.accounts], targets: structuredClone(labAutomationPlan.targets) };
}

export function updateLabAutomationStatus(input: {
  status?: LabAutomationPlan['status'];
  enabled?: boolean;
  lastError?: string | null;
}): LabAutomationPlan | null {
  if (!labAutomationPlan) return null;
  labAutomationPlan = {
    ...labAutomationPlan,
    ...(input.status ? { status: input.status } : {}),
    ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
    ...(input.lastError !== undefined ? { lastError: input.lastError } : {}),
    updatedAt: new Date().toISOString(),
  };
  return { ...labAutomationPlan, accounts: [...labAutomationPlan.accounts], targets: structuredClone(labAutomationPlan.targets) };
}


export function resumeLabAutomation(experimentId: string): LabAutomationPlan {
  if (!labAutomationPlan || labAutomationPlan.experimentId !== experimentId) {
    throw new Error('No existe un plan V4 persistido para este experimento.');
  }
  if (labAutomationPlan.status === 'completed') {
    throw new Error('El plan V4 ya completó todas sus cuotas y no puede reanudarse.');
  }
  labAutomationPlan = {
    ...labAutomationPlan,
    enabled: true,
    status: 'running',
    lastError: null,
    updatedAt: new Date().toISOString(),
  };
  return {
    ...labAutomationPlan,
    accounts: [...labAutomationPlan.accounts],
    targets: structuredClone(labAutomationPlan.targets),
  };
}

export function getLabAutomationPlan(): LabAutomationPlan | null {
  return labAutomationPlan
    ? { ...labAutomationPlan, accounts: [...labAutomationPlan.accounts], targets: structuredClone(labAutomationPlan.targets) }
    : null;
}

export function getNextLabAutomationBatch(experimentId: string, phase: ExperimentPhase): {
  scenarioId: LabScenarioId;
  repetitions: number;
  targetAccount: string;
  targetAccounts: string[];
  completed: number;
  target: number;
} | null {
  const plan = labAutomationPlan;
  if (!plan || !plan.enabled || plan.status !== 'running' || plan.experimentId !== experimentId) return null;
  const phaseTargets = plan.targets[phase] ?? {};
  const phaseCampaigns = [...campaigns.values()].filter(
    (campaign) => campaign.experimentId === experimentId &&
      campaign.phase === phase && campaign.scheduledByAutomation
  );
  const counts = new Map<LabScenarioId, { completed: number; failed: number }>();
  for (const scenarioId of Object.keys(phaseTargets) as LabScenarioId[]) counts.set(scenarioId, { completed: 0, failed: 0 });
  for (const campaign of phaseCampaigns) {
    const runs = new Map<string, LabJob[]>();
    for (const jobId of campaign.jobIds) {
      const job = jobs.get(jobId);
      if (!job) continue;
      const runJobs = runs.get(job.runId) ?? [];
      runJobs.push(job);
      runs.set(job.runId, runJobs);
    }
    for (const runJobs of runs.values()) {
      const scenarioId = runJobs[0]?.scenarioId;
      const count = scenarioId ? counts.get(scenarioId) : undefined;
      if (!count) continue;
      if (runJobs.every((job) => job.status === 'completed')) count.completed += 1;
      if (runJobs.some((job) => job.status === 'failed' || job.status === 'cancelled')) count.failed += 1;
    }
  }

  const ordered = (['benign_mixed', 'attack_rapid', 'attack_low_frequency', 'attack_distributed'] as LabScenarioId[])
    .filter((scenarioId) => phaseTargets[scenarioId] !== undefined);
  for (const scenarioId of ordered) {
    const target = phaseTargets[scenarioId] ?? 0;
    const count = counts.get(scenarioId) ?? { completed: 0, failed: 0 };
    if (count.completed >= target) continue;
    if (count.failed >= 3) {
      updateLabAutomationStatus({ status: 'paused', enabled: false, lastError: `Se pausó la automatización: ${scenarioId} acumula tres ejecuciones fallidas.` });
      return null;
    }
    const remaining = target - count.completed;
    const startAccountIndex = (count.completed + count.failed) % plan.accounts.length;
    const orderedAccounts = plan.accounts.map((_, index) => plan.accounts[(startAccountIndex + index) % plan.accounts.length]);
    return {
      scenarioId,
      repetitions: Math.min(plan.batchSize, remaining),
      targetAccount: orderedAccounts[0],
      targetAccounts: orderedAccounts,
      completed: count.completed,
      target,
    };
  }
  return null;
}

export function isLabAutomationPhaseComplete(experimentId: string, phase: ExperimentPhase): boolean {
  const plan = labAutomationPlan;
  if (!plan || plan.experimentId !== experimentId) return false;
  const targets = plan.targets[phase] ?? {};
  for (const [scenarioId, target] of Object.entries(targets) as Array<[LabScenarioId, number]>) {
    let completed = 0;
    const phaseCampaigns = [...campaigns.values()].filter(
      (campaign) => campaign.experimentId === experimentId &&
        campaign.phase === phase && campaign.scheduledByAutomation
    );
    for (const campaign of phaseCampaigns) {
      if (!campaign.labelsAppliedAt || campaign.status !== 'completed') continue;
      const runs = new Map<string, LabJob[]>();
      for (const jobId of campaign.jobIds) {
        const job = jobs.get(jobId);
        if (!job || job.scenarioId !== scenarioId) continue;
        const runJobs = runs.get(job.runId) ?? [];
        runJobs.push(job);
        runs.set(job.runId, runJobs);
      }
      for (const runJobs of runs.values()) {
        if (runJobs.length > 0 && runJobs.every((job) => job.status === 'completed')) completed += 1;
      }
    }
    if (completed < target) return false;
  }
  return true;
}

export function completeLabAutomation(): LabAutomationPlan | null {
  if (!labAutomationPlan) return null;
  labAutomationPlan = {
    ...labAutomationPlan,
    enabled: false,
    status: 'completed',
    lastError: null,
    updatedAt: new Date().toISOString(),
  };
  return { ...labAutomationPlan, accounts: [...labAutomationPlan.accounts], targets: structuredClone(labAutomationPlan.targets) };
}

export function markLabCampaignLabeled(campaignId: string): LabCampaign {
  const campaign = campaigns.get(campaignId);
  if (!campaign) throw new Error('Campaña no encontrada.');
  campaign.labelsAppliedAt = campaign.labelsAppliedAt ?? new Date().toISOString();
  return { ...campaign };
}

export function activateLabCampaign(campaignId: string): LabCampaign {
  const campaign = campaigns.get(campaignId);
  if (!campaign) throw new Error('Campaña no encontrada.');
  campaign.manifestPersisted = true;
  return { ...campaign };
}

export function claimNextLabJob(agentId: string): Record<string, unknown> | null {
  const agent = agents.get(agentId);
  if (!agent) throw new Error('Agente no registrado.');
  agent.lastSeenAt = Date.now();

  // A runner that reconnects after a detector restart resumes its existing task.
  if (agent.currentJobId) {
    const activeJob = jobs.get(agent.currentJobId);
    if (activeJob && activeJob.agentId === agentId &&
        ['assigned', 'running', 'paused'].includes(activeJob.status)) {
      if (activeJob.status === 'assigned') activeJob.status = 'running';
      agent.status = activeJob.status === 'paused' ? 'paused' : 'running';
      return serializeJobForAgent(activeJob, agentId);
    }
    agent.currentJobId = null;
  }

  const job = [...jobs.values()].find((candidate) =>
    candidate.status === 'queued' &&
    campaigns.get(candidate.campaignId)?.manifestPersisted === true &&
    (candidate.agentId === null || candidate.agentId === agentId) &&
    (!candidate.agentId || candidate.agentId === agentId)
  );
  if (!job) {
    if (agent.status === 'offline' || agent.status === 'error') agent.status = 'ready';
    return null;
  }

  if (job.scenarioId === 'attack_distributed') {
    const matching = [...agents.values()].filter((item) =>
      item.egressIpHash === agent.egressIpHash && Date.now() - item.lastSeenAt <= AGENT_STALE_MS
    );
    if (matching.length > 1) {
      throw new Error('Se detectaron varios agent_id detrás de la misma IP de salida. No se asignará una tarea distribuida a un origen duplicado.');
    }
  }

  job.agentId = agentId;
  job.status = 'assigned';
  job.startedAt = job.startedAt ?? Date.now();
  agent.currentJobId = job.jobId;
  agent.status = 'running';
  const campaign = campaigns.get(job.campaignId);
  if (campaign) campaign.status = 'running';

  // No se devuelve expectedLabel ni ningún otro campo de verdad de referencia.
  return serializeJobForAgent(job, agentId);
}

export function reportLabJobProgress(agentId: string, jobId: string, attemptsCompleted: number, eventId: string): void {
  const job = jobs.get(jobId);
  if (!job || job.agentId !== agentId) throw new Error('La tarea no pertenece a este agente.');
  if (!/^[a-f0-9-]{36}$/i.test(eventId)) throw new Error('El identificador del evento confirmado no es válido.');
  const currentIds = Array.isArray(job.summary.event_ids)
    ? (job.summary.event_ids as unknown[]).filter((item): item is string => typeof item === 'string')
    : [];
  if (attemptsCompleted === job.attemptsCompleted && currentIds.includes(eventId)) return;
  if (!Number.isInteger(attemptsCompleted) || attemptsCompleted !== job.attemptsCompleted + 1 ||
      attemptsCompleted > job.outcomes.length) {
    throw new Error('El progreso informado no corresponde al siguiente intento confirmado.');
  }
  if (currentIds.includes(eventId)) throw new Error('El evento ya está asociado a otro avance de la tarea.');
  job.attemptsCompleted = attemptsCompleted;
  job.summary = { ...job.summary, event_ids: [...currentIds, eventId] };
  const agent = agents.get(agentId);
  if (agent) agent.lastSeenAt = Date.now();
}


export function expireStaleLabJobs(now = Date.now()): number {
  let expired = 0;
  for (const job of jobs.values()) {
    if (!['assigned', 'running', 'paused'].includes(job.status) || !job.agentId) continue;
    const agent = agents.get(job.agentId);
    if (agent && now - agent.lastSeenAt <= AGENT_STALE_MS) continue;
    job.status = 'failed';
    job.finishedAt = now;
    job.pauseRequested = false;
    job.cancelRequested = false;
    job.summary = {
      ...job.summary,
      failure_reason: 'agent_heartbeat_timeout',
      failure_message: 'El runner dejó de enviar heartbeats durante más de 90 segundos.',
    };
    if (agent) {
      agent.currentJobId = null;
      agent.status = 'offline';
    }
    const campaign = campaigns.get(job.campaignId);
    if (campaign) refreshCampaignStatus(campaign);
    expired++;
  }
  return expired;
}

export function completeLabJob(input: {
  agentId: string;
  jobId: string;
  status: 'completed' | 'failed' | 'cancelled';
  attemptsCompleted: number;
  summary?: Record<string, unknown>;
}): LabJob {
  const job = jobs.get(input.jobId);
  if (!job || job.agentId !== input.agentId) throw new Error('La tarea no pertenece a este agente.');
  if (!['completed', 'failed', 'cancelled'].includes(input.status)) throw new Error('Estado de finalización no válido.');
  if (!Number.isInteger(input.attemptsCompleted) || input.attemptsCompleted < 0 || input.attemptsCompleted > job.outcomes.length) {
    throw new Error('El número final de intentos no es válido.');
  }
  const persistedEventIds = Array.isArray(job.summary.event_ids)
    ? (job.summary.event_ids as unknown[]).filter((item): item is string => typeof item === 'string')
    : [];
  const suppliedEventIds = Array.isArray(input.summary?.event_ids)
    ? (input.summary!.event_ids as unknown[]).filter((item): item is string => typeof item === 'string')
    : persistedEventIds;
  if (suppliedEventIds.length !== persistedEventIds.length ||
      suppliedEventIds.some((eventId, index) => eventId !== persistedEventIds[index])) {
    throw new Error('Los IDs de eventos informados no coinciden con el progreso confirmado por el coordinador.');
  }
  if (input.status === 'completed' &&
      (input.attemptsCompleted !== job.outcomes.length || persistedEventIds.length !== job.outcomes.length)) {
    throw new Error('Una tarea solo se completa cuando todos sus intentos tienen un evento persistido y confirmado.');
  }
  if (input.attemptsCompleted !== job.attemptsCompleted || persistedEventIds.length !== job.attemptsCompleted) {
    throw new Error('El estado final no coincide con los intentos y eventos confirmados.');
  }
  job.status = input.status;
  job.attemptsCompleted = input.attemptsCompleted;
  job.finishedAt = Date.now();
  job.summary = { ...(input.summary ?? {}), event_ids: [...persistedEventIds] };
  const agent = agents.get(input.agentId);
  if (agent) {
    agent.lastSeenAt = Date.now();
    agent.currentJobId = null;
    agent.status = input.status === 'failed' ? 'error' : 'ready';
    agent.nextJobAvailableAt = input.status === 'completed'
      ? Date.now() + job.sessionGapAfterMs
      : Date.now();
  }
  const campaign = campaigns.get(job.campaignId);
  if (campaign) refreshCampaignStatus(campaign);
  return { ...job };
}

export function updateLabCampaign(campaignId: string, action: 'pause' | 'resume' | 'stop'): LabCampaign {
  const campaign = campaigns.get(campaignId);
  if (!campaign) throw new Error('Campaña no encontrada en esta instancia.');
  if (action === 'stop') {
    campaign.status = 'stopped';
    for (const jobId of campaign.jobIds) {
      const job = jobs.get(jobId);
      if (!job) continue;
      if (job.status === 'queued' || job.status === 'assigned') {
        job.status = 'cancelled';
        job.finishedAt = Date.now();
      } else if (job.status === 'running' || job.status === 'paused') {
        job.cancelRequested = true;
      }
    }
  } else if (action === 'pause') {
    campaign.status = 'paused';
    for (const jobId of campaign.jobIds) {
      const job = jobs.get(jobId);
      if (!job) continue;
      if (job.status === 'queued') job.status = 'paused';
      if (job.status === 'running' || job.status === 'assigned') job.pauseRequested = true;
    }
  } else {
    if (campaign.status === 'stopped') throw new Error('Una campaña detenida no puede reanudarse; crea una nueva campaña.');
    campaign.status = 'running';
    for (const jobId of campaign.jobIds) {
      const job = jobs.get(jobId);
      if (!job) continue;
      if (job.status === 'paused' && !job.cancelRequested) job.status = 'queued';
      job.pauseRequested = false;
    }
  }
  return { ...campaign };
}

export function getLabCampaignForLabeling(campaignId: string): {
  campaign: LabCampaign;
  jobs: Array<{
    jobId: string;
    runId: string;
    scenarioId: LabScenarioId;
    agentId: string;
    targetAccount: string;
    egressIpHash: string;
    expectedLabel: 'benign' | 'attack';
    status: JobStatus;
    attemptsCompleted: number;
    attemptsPlanned: number;
    eventIds: string[];
  }>;
} {
  const campaign = campaigns.get(campaignId);
  if (!campaign) throw new Error('Campaña no encontrada en esta instancia.');
  const campaignJobs = campaign.jobIds.map((id) => jobs.get(id)).filter((job): job is LabJob => Boolean(job));
  if (!campaignJobs.length || campaignJobs.some((job) => job.status !== 'completed')) {
    throw new Error('Solo se pueden etiquetar campañas cuyas tareas hayan finalizado correctamente.');
  }
  const normalizedJobs = campaignJobs.map((job) => ({
    jobId: job.jobId,
    runId: job.runId,
    scenarioId: job.scenarioId,
    agentId: job.agentId || '',
    targetAccount: job.targetAccount,
    egressIpHash: job.agentId ? agents.get(job.agentId)?.egressIpHash || '' : '',
    expectedLabel: job.expectedLabel,
    status: job.status,
    attemptsCompleted: job.attemptsCompleted,
    attemptsPlanned: job.outcomes.length,
    eventIds: Array.isArray(job.summary.event_ids)
      ? (job.summary.event_ids as unknown[]).filter((value): value is string => typeof value === 'string')
      : [],
  }));
  if (normalizedJobs.some((job) => !job.agentId ||
      job.attemptsCompleted !== job.attemptsPlanned || job.eventIds.length !== job.attemptsPlanned)) {
    throw new Error('La campaña tiene tareas con solicitudes faltantes o sin IDs de evento confirmados; no se aplicarán etiquetas automáticamente.');
  }
  return { campaign: { ...campaign }, jobs: normalizedJobs };
}


export function getLabAutomationProgress(experimentId: string): Record<string, Record<string, { completed: number; target: number }>> | null {
  const plan = labAutomationPlan;
  if (!plan || plan.experimentId !== experimentId) return null;

  const result: Record<string, Record<string, { completed: number; target: number }>> = {};
  for (const phase of ['train', 'validation', 'test'] as const) {
    result[phase] = {};
    const targets = plan.targets[phase] ?? {};
    const phaseCampaigns = [...campaigns.values()].filter(
      (campaign) => campaign.experimentId === experimentId &&
        campaign.phase === phase && campaign.scheduledByAutomation &&
        campaign.status === 'completed' && Boolean(campaign.labelsAppliedAt)
    );
    for (const [scenarioId, target] of Object.entries(targets) as Array<[LabScenarioId, number]>) {
      const runIds = new Set<string>();
      for (const campaign of phaseCampaigns) {
        const byRun = new Map<string, LabJob[]>();
        for (const jobId of campaign.jobIds) {
          const job = jobs.get(jobId);
          if (!job || job.scenarioId !== scenarioId) continue;
          const runJobs = byRun.get(job.runId) ?? [];
          runJobs.push(job);
          byRun.set(job.runId, runJobs);
        }
        for (const [runId, runJobs] of byRun) {
          if (runJobs.length > 0 && runJobs.every((job) =>
            job.status === 'completed' && job.attemptsCompleted === job.outcomes.length
          )) runIds.add(runId);
        }
      }
      result[phase][scenarioId] = { completed: Math.min(runIds.size, target), target };
    }
  }
  return result;
}

export function getLabSnapshot(experimentId?: string | null): Record<string, unknown> {
  const now = Date.now();
  const agentList = [...agents.values()].map((agent) => ({
    agent_id: agent.agentId,
    egress_ip_hash_prefix: agent.egressIpHash.slice(0, 12),
    registered_at: new Date(agent.registeredAt).toISOString(),
    last_seen_at: new Date(agent.lastSeenAt).toISOString(),
    status: now - agent.lastSeenAt > AGENT_STALE_MS ? 'offline' : agent.status,
    current_job_id: agent.currentJobId,
    version: agent.version,
  }));
  const campaignList = [...campaigns.values()]
    .filter((campaign) => !experimentId || campaign.experimentId === experimentId)
    .map((campaign) => {
      refreshCampaignStatus(campaign);
      const campaignJobs = campaign.jobIds.map((id) => jobs.get(id)).filter((job): job is LabJob => Boolean(job));
      return {
        campaign_id: campaign.campaignId,
        experiment_id: campaign.experimentId,
        created_at: new Date(campaign.createdAt).toISOString(),
        status: campaign.status,
        target_account: campaign.targetAccount,
        scenario_ids: campaign.scenarioIds,
        repetitions: campaign.repetitions,
        phase: campaign.phase,
        manifest_persisted: campaign.manifestPersisted,
        scheduled_by_automation: campaign.scheduledByAutomation,
        labels_applied_at: campaign.labelsAppliedAt,
        jobs: campaignJobs.map((job) => ({
          job_id: job.jobId,
          run_id: job.runId,
          scenario_id: job.scenarioId,
          agent_id: job.agentId,
          status: job.status,
          attempts_completed: job.attemptsCompleted,
          attempts_planned: job.outcomes.length,
          planned_inter_attempt_delays_ms: [...job.interAttemptDelaysMs],
          planned_session_gap_after_ms: job.sessionGapAfterMs,
          session_profile: { ...job.sessionProfile },
          start_at: new Date(Math.max(job.startAt, job.agentId ? agents.get(job.agentId)?.nextJobAvailableAt ?? 0 : 0)).toISOString(),
          deadline_at: job.deadlineAt !== null ? new Date(job.deadlineAt).toISOString() : null,
          started_at: job.startedAt ? new Date(job.startedAt).toISOString() : null,
          finished_at: job.finishedAt ? new Date(job.finishedAt).toISOString() : null,
          expected_label: job.expectedLabel,
          summary: job.summary,
        })),
      };
    });
  return {
    generated_at: new Date(now).toISOString(),
    agent_stale_after_ms: AGENT_STALE_MS,
    automation: getLabAutomationPlan(),
    automation_progress: experimentId ? getLabAutomationProgress(experimentId) : null,
    agents: agentList,
    campaigns: campaignList,
    scenarios: Object.entries(LAB_SCENARIO_CATALOG).map(([id, value]) => ({
      scenario_id: id,
      label: value.label,
      description: value.description,
      required_agents: value.requiredAgents,
    })),
  };
}

export function getLabJobControl(agentId: string, jobId: string): 'continue' | 'pause' | 'cancel' {
  const job = jobs.get(jobId);
  if (!job || job.agentId !== agentId) return 'cancel';
  if (job.cancelRequested || job.status === 'cancelled') return 'cancel';
  if (job.pauseRequested || job.status === 'paused') return 'pause';
  return 'continue';
}
