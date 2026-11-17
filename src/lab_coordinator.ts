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
}

interface LabJob {
  jobId: string;
  campaignId: string;
  runId: string;
  scenarioId: LabScenarioId;
  agentId: string | null;
  targetAccount: string;
  startAt: number;
  intervalMs: number;
  outcomes: boolean[];
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
  manifest: Record<string, unknown>;
}

const agents = new Map<string, LabAgent>();
const jobs = new Map<string, LabJob>();
const campaigns = new Map<string, LabCampaign>();
const AGENT_STALE_MS = 90_000;

/** Resets module state for isolated unit tests; never exposed by the HTTP API. */
export function resetLabCoordinatorForTesting(): void {
  agents.clear();
  jobs.clear();
  campaigns.clear();
}


export const LAB_SCENARIO_CATALOG: Record<LabScenarioId, {
  label: string;
  description: string;
  expectedLabel: 'benign' | 'attack';
  actorType: 'benign_agent' | 'attack_agent';
  outcomes: boolean[];
  intervalMs: number;
  requiredAgents: number;
}> = {
  benign_mixed: {
    label: 'Sesión legítima con errores ocasionales',
    description: 'Autenticaciones correctas intercaladas con errores aislados de contraseña.',
    expectedLabel: 'benign',
    actorType: 'benign_agent',
    outcomes: [true, true, false, true, false, true, true],
    intervalMs: 4_000,
    requiredAgents: 1,
  },
  attack_rapid: {
    label: 'Fuerza bruta desde un origen',
    description: 'Seis intentos fallidos controlados desde un único agente y origen de red.',
    expectedLabel: 'attack',
    actorType: 'attack_agent',
    outcomes: [false, false, false, false, false, false],
    intervalMs: 2_000,
    requiredAgents: 1,
  },
  attack_low_frequency: {
    label: 'Intentos de baja frecuencia',
    description: 'Ocho intentos fallidos espaciados desde un único origen.',
    expectedLabel: 'attack',
    actorType: 'attack_agent',
    outcomes: [false, false, false, false, false, false, false, false],
    intervalMs: 75_000,
    requiredAgents: 1,
  },
  attack_distributed: {
    label: 'Fuerza bruta distribuida',
    description: 'Cuatro agentes desde cuatro IP observadas distintas, coordinados contra una cuenta de laboratorio.',
    expectedLabel: 'attack',
    actorType: 'attack_agent',
    outcomes: [false, false],
    intervalMs: 12_000,
    requiredAgents: 4,
  },
};

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
  };
  agent.lastSeenAt = Date.now();
  agent.version = input.version || agent.version;
  if (agent.status === 'offline' || agent.status === 'error') agent.status = 'ready';
  agents.set(agentId, agent);
  return { ...agent };
}

export function verifyLabAgentOrigin(agentId: string, egressIpHash: string): boolean {
  const agent = agents.get(agentId);
  return Boolean(agent && agent.egressIpHash === egressIpHash.toLowerCase());
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

export function createLabCampaign(input: {
  experimentId: string;
  targetAccount: string;
  scenarioIds: unknown[];
  phase: ExperimentPhase;
  repetitions?: number;
}): { campaign: LabCampaign; manifest: Record<string, unknown> } {
  const now = Date.now();
  const scenarioIds = [...new Set(input.scenarioIds.filter(isScenarioId))];
  const repetitions = input.repetitions ?? 1;
  if (!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 5) {
    throw new Error('repetitions debe ser un entero entre 1 y 5.');
  }
  if (!input.experimentId) throw new Error('Se requiere un experimento activo.');
  if (!/^(ronan|andy|stefano)$/.test(input.targetAccount)) {
    throw new Error('La cuenta objetivo debe ser una cuenta de laboratorio autorizada.');
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

  const campaignId = `v3-${randomUUID()}`;
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

  for (const scenarioId of orderedScenarioIds) {
    const definition = LAB_SCENARIO_CATALOG[scenarioId];
    for (let repetition = 1; repetition <= repetitions; repetition += 1) {
      const runId = randomUUID();
      const startAt = now + 25_000 + (repetition - 1) * 5_000;
      const assignedAgents = scenarioId === 'attack_distributed'
        ? readyAgents.slice(0, 4)
        : [readyAgents[nextSingleAgent++ % readyAgents.length]];
      const runJobIds: string[] = [];

      for (const agent of assignedAgents) {
        const jobId = randomUUID();
        const job: LabJob = {
          jobId,
          campaignId,
          runId,
          scenarioId,
          agentId: agent.agentId,
          targetAccount: input.targetAccount,
          startAt,
          intervalMs: definition.intervalMs,
          outcomes: [...definition.outcomes],
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
        target_account: input.targetAccount,
        required_independent_egress_ips: definition.requiredAgents,
        planned_agent_ids: assignedAgents.map((agent) => agent.agentId),
        planned_start_at: new Date(startAt).toISOString(),
        planned_attempts_per_agent: definition.outcomes.length,
        planned_interval_ms: definition.intervalMs,
        job_ids: runJobIds,
      });
    }
  }

  const campaign: LabCampaign = {
    campaignId,
    experimentId: input.experimentId,
    createdAt: now,
    status: 'queued',
    targetAccount: input.targetAccount,
    scenarioIds,
    repetitions,
    phase: input.phase,
    jobIds,
    manifest: {
      protocol: 'centinela-auth-study-v3',
      campaign_id: campaignId,
      experiment_id: input.experimentId,
      phase: input.phase,
      created_at: new Date(now).toISOString(),
      target_account: input.targetAccount,
      scenarios: manifestRuns,
      truth_source: 'predefined_authorized_campaign_manifest',
      note: 'La etiqueta esperada se conserva en el manifiesto independiente del detector y nunca se envía en las solicitudes de autenticación.',
    },
  };
  campaigns.set(campaignId, campaign);
  return { campaign: { ...campaign }, manifest: campaign.manifest };
}

export function claimNextLabJob(agentId: string): Record<string, unknown> | null {
  const agent = agents.get(agentId);
  if (!agent) throw new Error('Agente no registrado.');
  agent.lastSeenAt = Date.now();
  if (agent.currentJobId) return null;

  const job = [...jobs.values()].find((candidate) =>
    candidate.status === 'queued' &&
    (candidate.agentId === null || candidate.agentId === agentId) &&
    (!candidate.agentId || candidate.agentId === agentId)
  );
  if (!job) return null;

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
  job.startedAt = Date.now();
  agent.currentJobId = job.jobId;
  agent.status = 'running';
  const campaign = campaigns.get(job.campaignId);
  if (campaign) campaign.status = 'running';

  // No se devuelve expectedLabel ni ningún otro campo de verdad de referencia.
  return {
    job_id: job.jobId,
    campaign_id: job.campaignId,
    run_id: job.runId,
    scenario_id: job.scenarioId,
    agent_id: agentId,
    target_account: job.targetAccount,
    start_at: new Date(job.startAt).toISOString(),
    interval_ms: job.intervalMs,
    outcomes: [...job.outcomes],
    max_attempts: job.outcomes.length,
  };
}

export function getLabJobCaptureContext(agentId: string, jobId: string, attemptIndex: number): {
  campaignId: string;
  runId: string;
  scenarioId: LabScenarioId;
  targetAccount: string;
  expectedSuccess: boolean;
  egressIpHash: string;
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
  };
}

export function reportLabJobProgress(agentId: string, jobId: string, attemptsCompleted: number): void {
  const job = jobs.get(jobId);
  if (!job || job.agentId !== agentId) throw new Error('La tarea no pertenece a este agente.');
  if (!Number.isInteger(attemptsCompleted) || attemptsCompleted < job.attemptsCompleted || attemptsCompleted > job.outcomes.length) {
    throw new Error('El progreso informado no es válido.');
  }
  job.attemptsCompleted = attemptsCompleted;
  const agent = agents.get(agentId);
  if (agent) agent.lastSeenAt = Date.now();
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
  job.status = input.status;
  job.attemptsCompleted = Math.max(0, Math.min(job.outcomes.length, Math.floor(input.attemptsCompleted)));
  job.finishedAt = Date.now();
  job.summary = input.summary ?? {};
  const agent = agents.get(input.agentId);
  if (agent) {
    agent.lastSeenAt = Date.now();
    agent.currentJobId = null;
    agent.status = input.status === 'failed' ? 'error' : 'ready';
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
    expectedLabel: job.expectedLabel,
    status: job.status,
    attemptsCompleted: job.attemptsCompleted,
    attemptsPlanned: job.outcomes.length,
    eventIds: Array.isArray(job.summary.event_ids)
      ? (job.summary.event_ids as unknown[]).filter((value): value is string => typeof value === 'string')
      : [],
  }));
  if (normalizedJobs.some((job) => job.attemptsCompleted !== job.attemptsPlanned || job.eventIds.length !== job.attemptsPlanned)) {
    throw new Error('La campaña tiene tareas con solicitudes faltantes o sin IDs de evento confirmados; no se aplicarán etiquetas automáticamente.');
  }
  return { campaign: { ...campaign }, jobs: normalizedJobs };
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
        jobs: campaignJobs.map((job) => ({
          job_id: job.jobId,
          run_id: job.runId,
          scenario_id: job.scenarioId,
          agent_id: job.agentId,
          status: job.status,
          attempts_completed: job.attemptsCompleted,
          attempts_planned: job.outcomes.length,
          start_at: new Date(job.startAt).toISOString(),
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
