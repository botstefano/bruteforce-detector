import assert from 'node:assert/strict';
import test from 'node:test';
import {
  claimNextLabJob,
  createLabCampaign,
  getLabJobCaptureContext,
  registerLabAgent,
  resetLabCoordinatorForTesting,
} from '../src/lab_coordinator.js';

test('capture context is bound to the assigned agent and exact next attempt', () => {
  resetLabCoordinatorForTesting();
  registerLabAgent({
    agentId: 'runner-test-01',
    egressIpHash: 'a'.repeat(64),
    version: 'test',
  });
  const { campaign } = createLabCampaign({
    experimentId: 'experiment-test',
    targetAccount: 'ronan',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
  });
  const job = claimNextLabJob('runner-test-01');
  assert.ok(job);
  const jobId = String(job.job_id);

  const context = getLabJobCaptureContext('runner-test-01', jobId, 0);
  assert.equal(context.campaignId, campaign.campaignId);
  assert.equal(context.targetAccount, 'ronan');
  assert.equal(context.expectedSuccess, true);
  assert.equal(context.egressIpHash, 'a'.repeat(64));

  assert.throws(
    () => getLabJobCaptureContext('another-runner', jobId, 0),
    /no está asignada al agente autenticado/i,
  );
  assert.throws(
    () => getLabJobCaptureContext('runner-test-01', jobId, 1),
    /índice de intento/i,
  );
  resetLabCoordinatorForTesting();
});
