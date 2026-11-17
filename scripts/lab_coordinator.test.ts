import { randomUUID } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  claimNextLabJob,
  completeLabJob,
  createLabCampaign,
  getLabCampaignForLabeling,
  registerLabAgent,
  reportLabJobProgress,
} from '../src/lab_coordinator.js';

const unique = () => `test-${randomUUID()}`;

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
    reportLabJobProgress(agentId, jobId, 2);
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

test('una campaña que no completó todas las solicitudes no puede etiquetarse', () => {
  const prefix = unique();
  const [agentId] = registerAgents(prefix, 1);
  const { campaign } = createLabCampaign({
    experimentId: unique(),
    targetAccount: 'andy',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
  });
  const task = claimNextLabJob(agentId);
  assert.ok(task);
  const jobId = String(task.job_id);
  const eventIds = [randomUUID()];
  reportLabJobProgress(agentId, jobId, 1);
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
