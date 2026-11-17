import assert from 'node:assert/strict';
import test from 'node:test';
import {
  activateLabCampaign,
  claimNextLabJob,
  createLabCampaign,
  getLabJobCaptureContext,
  registerLabAgent,
  reportLabJobProgress,
  serializeLabCoordinatorState,
  restoreLabCoordinatorState,
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
  activateLabCampaign(campaign.campaignId);
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


test('a runner cannot claim a job until its independent manifest is activated', () => {
  resetLabCoordinatorForTesting();
  registerLabAgent({ agentId: 'runner-manifest-01', egressIpHash: 'c'.repeat(64), version: 'test' });
  const { campaign } = createLabCampaign({
    experimentId: 'experiment-manifest',
    targetAccount: 'andy',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
  });
  assert.equal(claimNextLabJob('runner-manifest-01'), null);
  activateLabCampaign(campaign.campaignId);
  const job = claimNextLabJob('runner-manifest-01');
  assert.ok(job);
  assert.equal(job.campaign_id, campaign.campaignId);
  resetLabCoordinatorForTesting();
});

test('a runner resumes a partially completed task after coordinator state restoration', () => {
  resetLabCoordinatorForTesting();
  const egress = 'b'.repeat(64);
  registerLabAgent({ agentId: 'runner-resume-01', egressIpHash: egress, version: 'test' });
  const { campaign } = createLabCampaign({
    experimentId: 'experiment-resume',
    targetAccount: 'ronan',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
  });
  activateLabCampaign(campaign.campaignId);
  const firstJob = claimNextLabJob('runner-resume-01');
  assert.ok(firstJob);
  const jobId = String(firstJob.job_id);
  const eventId = '11111111-1111-4111-8111-111111111111';
  reportLabJobProgress('runner-resume-01', jobId, 1, eventId);
  // A retry after a lost HTTP response is idempotent; a different event cannot
  // occupy the same attempt number.
  assert.doesNotThrow(() => reportLabJobProgress('runner-resume-01', jobId, 1, eventId));
  assert.throws(
    () => reportLabJobProgress('runner-resume-01', jobId, 1, '22222222-2222-4222-8222-222222222222'),
    /progreso informado no corresponde/i,
  );

  const persisted = serializeLabCoordinatorState('experiment-resume');
  resetLabCoordinatorForTesting();
  const restored = restoreLabCoordinatorState(persisted);
  assert.equal(restored.agents, 1);
  assert.equal(restored.campaigns, 1);
  assert.equal(restored.jobs, 1);

  registerLabAgent({ agentId: 'runner-resume-01', egressIpHash: egress, version: 'test-restarted' });
  const resumed = claimNextLabJob('runner-resume-01');
  assert.ok(resumed);
  assert.equal(resumed.job_id, jobId);
  assert.equal(resumed.attempts_completed, 1);
  assert.deepEqual(resumed.event_ids, [eventId]);
  assert.equal(resumed.campaign_id, campaign.campaignId);
  resetLabCoordinatorForTesting();
});
