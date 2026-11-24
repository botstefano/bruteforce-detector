import { randomUUID } from 'node:crypto';
import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  activateLabCampaign,
  claimNextLabJob,
  configureLabAutomation,
  configureLabTestExtension,
  getLabJobCaptureContext,
  completeLabJob,
  createLabCampaign,
  getLabCampaignForLabeling,
  registerLabAgent,
  reportLabJobProgress,
  resetLabCoordinatorForTesting,
} from '../src/lab_coordinator.js';

const unique = () => `test-${randomUUID()}`;

beforeEach(() => resetLabCoordinatorForTesting());

function registerAgents(prefix: string, count: number) {
  const ids: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const agentId = `${prefix}-${index + 1}`;
    const egressIpHash = (index + 1).toString(16).padStart(2, '0').repeat(32);
    registerLabAgent({ agentId, egressIpHash, version: 'unit-test' });
    ids.push(agentId);
  }
  return ids;
}

test('el escenario distribuido exige cuatro salidas de red independientes', () => {
  const prefix = unique();
  registerAgents(prefix, 3);
  assert.throws(() => createLabCampaign({
    experimentId: unique(),
    targetAccount: 'ronan',
    scenarioIds: ['attack_distributed'],
    phase: 'validation',
  }), /necesita cuatro agentes activos con IP de salida independientes/);
});

test('el manifiesto no se filtra al agente y el etiquetado exige eventos completos', () => {
  const prefix = unique();
  const agentIds = registerAgents(prefix, 4);
  const experimentId = unique();
  const { campaign } = createLabCampaign({
    experimentId,
    targetAccount: 'ronan',
    scenarioIds: ['attack_distributed'],
    phase: 'validation',
  });
  activateLabCampaign(campaign.campaignId);

  const taskEvents = new Map<string, string[]>();
  for (const agentId of agentIds) {
    const task = claimNextLabJob(agentId);
    assert.ok(task);
    assert.equal(task.agent_id, agentId);
    assert.equal('expected_label' in task, false);
    assert.equal('actor_type' in task, false);
    const jobId = String(task.job_id);
    const eventIds = [randomUUID(), randomUUID()];
    taskEvents.set(jobId, eventIds);
    reportLabJobProgress(agentId, jobId, 1, eventIds[0]);
    reportLabJobProgress(agentId, jobId, 2, eventIds[1]);
    completeLabJob({
      agentId,
      jobId,
      status: 'completed',
      attemptsCompleted: 2,
      summary: { event_ids: eventIds },
    });
  }

  const result = getLabCampaignForLabeling(campaign.campaignId);
  assert.equal(result.jobs.length, 4);
  assert.ok(result.jobs.every((job) => job.expectedLabel === 'attack'));
  assert.ok(result.jobs.every((job) => job.eventIds.length === 2));
});

test('una campaña fallida solo expone sesiones completas para etiquetado', () => {
  const prefix = unique();
  const [agentId] = registerAgents(prefix, 1);
  const { campaign } = createLabCampaign({
    experimentId: unique(),
    targetAccount: 'andy',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
    repetitions: 2,
  });
  activateLabCampaign(campaign.campaignId);

  const completedTask = claimNextLabJob(agentId);
  assert.ok(completedTask);
  const completedJobId = String(completedTask.job_id);
  const completedEventIds = (completedTask.outcomes as boolean[]).map(() => randomUUID());
  completedEventIds.forEach((eventId, index) => reportLabJobProgress(agentId, completedJobId, index + 1, eventId));
  completeLabJob({
    agentId,
    jobId: completedJobId,
    status: 'completed',
    attemptsCompleted: completedEventIds.length,
    summary: { event_ids: completedEventIds },
  });

  // The next session is intentionally unclaimable during its long rest.
  // Advance the test clock to the final minute of its scheduled start window.
  const realNow = Date.now;
  let failedTask;
  try {
    Date.now = () => realNow() + 60 * 60_000;
    failedTask = claimNextLabJob(agentId);
  } finally {
    Date.now = realNow;
  }
  assert.ok(failedTask);
  const failedJobId = String(failedTask.job_id);
  const partialEventIds = [randomUUID()];
  reportLabJobProgress(agentId, failedJobId, 1, partialEventIds[0]);
  completeLabJob({
    agentId,
    jobId: failedJobId,
    status: 'failed',
    attemptsCompleted: 1,
    summary: { event_ids: partialEventIds },
  });

  const result = getLabCampaignForLabeling(campaign.campaignId);
  assert.equal(result.campaign.status, 'failed');
  assert.equal(result.jobs.length, 1);
  assert.deepEqual(result.jobs[0]?.eventIds, completedEventIds);
  assert.equal(result.jobs.some((job) => job.eventIds.includes(partialEventIds[0])), false);
});

test('una campaña sin ninguna sesión completa no puede etiquetarse', () => {
  const prefix = unique();
  const [agentId] = registerAgents(prefix, 1);
  const { campaign } = createLabCampaign({
    experimentId: unique(),
    targetAccount: 'andy',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
  });
  activateLabCampaign(campaign.campaignId);
  const task = claimNextLabJob(agentId);
  assert.ok(task);
  const jobId = String(task.job_id);
  const eventIds = [randomUUID()];
  reportLabJobProgress(agentId, jobId, 1, eventIds[0]);
  completeLabJob({
    agentId,
    jobId,
    status: 'failed',
    attemptsCompleted: 1,
    summary: { event_ids: eventIds },
  });
  assert.throws(() => getLabCampaignForLabeling(campaign.campaignId), /Solo se pueden etiquetar campañas/);
});

test('no acepta repeticiones fuera del rango preregistrado', () => {
  const prefix = unique();
  registerAgents(prefix, 1);
  assert.throws(() => createLabCampaign({
    experimentId: unique(),
    targetAccount: 'stefano',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
    repetitions: 0,
  }), /repetitions debe ser un entero entre 1 y 5/);
});


test('la extensión complementaria conserva una fase y un manifiesto independientes', () => {
  const prefix = unique();
  const [agentId] = registerAgents(prefix, 1);
  const experimentId = unique();
  const extensionId = randomUUID();
  const { campaign, manifest } = createLabCampaign({
    experimentId,
    targetAccount: 'ronan',
    scenarioIds: ['attack_rapid'],
    phase: 'test_extension',
    extensionId,
    scheduledByAutomation: true,
    repetitions: 1,
    phaseEndAtMs: Date.now() + 6 * 60 * 60_000,
  });
  assert.equal(campaign.phase, 'test_extension');
  assert.equal(campaign.extensionId, extensionId);
  assert.equal(manifest.phase, 'test_extension');
  assert.equal(manifest.extension_id, extensionId);
  assert.equal(manifest.protocol, 'centinela-auth-study-v4-supplementary-test-extension');

  activateLabCampaign(campaign.campaignId);
  const task = claimNextLabJob(agentId);
  assert.ok(task);
  const context = getLabJobCaptureContext(agentId, String(task.job_id), 0);
  assert.equal(context.phase, 'test_extension');
  assert.equal(context.extensionId, extensionId);
});

test('la configuración de extensión añade cuotas separadas sin cambiar objetivos originales', () => {
  const experimentId = unique();
  const originalPlan = configureLabAutomation({
    experimentId,
    batchSize: 5,
    targets: {
      train: { benign_mixed: 55 },
      validation: { benign_mixed: 8, attack_rapid: 8, attack_low_frequency: 7, attack_distributed: 0 },
      test: { benign_mixed: 5, attack_rapid: 5, attack_low_frequency: 4, attack_distributed: 0 },
    },
  });
  const extensionId = randomUUID();
  const plan = configureLabTestExtension({
    experimentId,
    extensionId,
    targets: { attack_rapid: 5, attack_low_frequency: 4 },
  });
  assert.equal(plan.enabled, true);
  assert.equal(plan.status, 'running');
  assert.deepEqual(plan.targets.test, originalPlan.targets.test);
  assert.deepEqual(plan.targets.test_extension, { attack_rapid: 5, attack_low_frequency: 4 });
  assert.throws(() => configureLabTestExtension({
    experimentId,
    extensionId: randomUUID(),
    targets: { attack_rapid: 5, attack_low_frequency: 4 },
  }), /Ya existe un plan de extensión/);
});
