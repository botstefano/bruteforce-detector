import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  activateLabCampaign,
  claimNextLabJob,
  completeLabJob,
  configureLabAutomation,
  createLabCampaign,
  getNextLabAutomationBatch,
  getLabAutomationPlan,
  getLabSnapshot,
  isLabAutomationPhaseComplete,
  markLabCampaignLabeled,
  registerLabAgent,
  reportLabJobProgress,
  resetLabCoordinatorForTesting,
  resumeLabAutomation,
  stopLabAutomation,
  restoreLabCoordinatorState,
  serializeLabCoordinatorState,
} from '../src/lab_coordinator.js';

function registerRunner(agentId = 'runner-test-01'): void {
  registerLabAgent({
    agentId,
    egressIpHash: 'a'.repeat(64),
    version: 'test-runner',
  });
}

test('benign sessions have variable, bounded and reproducible manifest parameters', () => {
  resetLabCoordinatorForTesting();
  registerRunner();

  const { manifest } = createLabCampaign({
    experimentId: 'experiment-v4-test',
    targetAccount: 'ronan',
    targetAccounts: ['ronan', 'andy', 'stefano'],
    scenarioIds: ['benign_mixed'],
    phase: 'train',
    repetitions: 5,
    scheduledByAutomation: true,
  });

  const runs = manifest.scenarios as Array<Record<string, unknown>>;
  assert.equal(runs.length, 5);
  const seeds = new Set<number>();

  for (const run of runs) {
    const attempts = Number(run.planned_attempts_per_agent);
    const delays = run.planned_inter_attempt_delays_ms as number[];
    const profile = run.session_profile as Record<string, unknown>;
    const seed = Number(run.reproducibility_seed);

    assert.ok(attempts >= 3 && attempts <= 8);
    assert.equal(delays.length, attempts - 1);
    assert.ok(delays.every((delay) => delay >= 8_000 && delay <= 180_000));
    assert.equal(profile.profile_version, 2);
    assert.equal(profile.planned_attempts, attempts);
    const restMs = Number(run.planned_session_gap_after_ms);
    assert.ok(restMs >= 8 * 60_000 && restMs <= 25 * 60_000);
    assert.ok(seed > 0);
    seeds.add(seed);
  }

  assert.equal(seeds.size, runs.length);
  assert.notEqual(runs[0].planned_start_at, runs[1].planned_start_at);
  assert.deepEqual(runs.map((run) => run.target_account), ['ronan', 'andy', 'stefano', 'ronan', 'andy']);
  assert.match(String(manifest.note), /no sesiones humanas espontáneas/);
});

test('automation plan persists and only schedules benign activity during training', () => {
  resetLabCoordinatorForTesting();
  registerRunner();

  configureLabAutomation({
    experimentId: 'experiment-v4-test',
    batchSize: 5,
    accounts: ['ronan', 'andy', 'stefano'],
    targets: {
      train: { benign_mixed: 12 },
      validation: { benign_mixed: 10, attack_rapid: 5, attack_low_frequency: 5, attack_distributed: 0 },
      test: { benign_mixed: 20, attack_rapid: 10, attack_low_frequency: 10, attack_distributed: 0 },
    },
  });

  assert.equal(getLabAutomationPlan()?.targets.validation.attack_distributed, 0);
  assert.equal(getLabAutomationPlan()?.targets.test.attack_distributed, 0);

  const next = getNextLabAutomationBatch('experiment-v4-test', 'train');
  assert.deepEqual(next && {
    scenarioId: next.scenarioId,
    repetitions: next.repetitions,
    targetAccount: next.targetAccount,
  }, {
    scenarioId: 'benign_mixed',
    repetitions: 5,
    targetAccount: 'ronan',
  });

  const saved = serializeLabCoordinatorState('experiment-v4-test');
  resetLabCoordinatorForTesting();
  restoreLabCoordinatorState(saved);
  const restored = getLabAutomationPlan();

  assert.equal(restored?.enabled, true);
  assert.equal(restored?.experimentId, 'experiment-v4-test');
  assert.equal(getNextLabAutomationBatch('experiment-v4-test', 'train')?.scenarioId, 'benign_mixed');
});



test('resume after three failed sessions schedules a bounded replacement batch', () => {
  resetLabCoordinatorForTesting();
  registerRunner('runner-recovery-01');
  registerRunner('runner-recovery-02');
  registerRunner('runner-recovery-03');

  configureLabAutomation({
    experimentId: 'experiment-v4-recovery',
    batchSize: 5,
    accounts: ['ronan', 'andy', 'stefano'],
    targets: {
      train: { benign_mixed: 12 },
      validation: { benign_mixed: 10, attack_rapid: 5, attack_low_frequency: 5, attack_distributed: 0 },
      test: { benign_mixed: 20, attack_rapid: 10, attack_low_frequency: 10, attack_distributed: 0 },
    },
  });

  const { campaign } = createLabCampaign({
    experimentId: 'experiment-v4-recovery',
    targetAccount: 'ronan',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
    repetitions: 3,
    scheduledByAutomation: true,
  });
  activateLabCampaign(campaign.campaignId);

  const realNow = Date.now;
  let fakeNow = realNow() + 60_000;
  try {
    // Campaign sessions are sequential and include up to 25 minutes of rest.
    // Advance one hour per planned session so every runner is inside its
    // permitted final-minute claim window.
    Date.now = () => fakeNow;
    for (const agentId of ['runner-recovery-01', 'runner-recovery-02', 'runner-recovery-03']) {
      const task = claimNextLabJob(agentId);
      assert.ok(task);
      completeLabJob({
        agentId,
        jobId: String(task.job_id),
        status: 'failed',
        attemptsCompleted: 0,
        summary: { event_ids: [] },
      });
      fakeNow += 60 * 60_000;
    }
  } finally {
    Date.now = realNow;
  }

  assert.equal(getNextLabAutomationBatch('experiment-v4-recovery', 'train'), null);
  assert.equal(getLabAutomationPlan()?.status, 'paused');

  // Model a later successful session in the same experiment. It clears the
  // consecutive-failure streak but must not erase the three failed quota slots.
  registerRunner('runner-recovery-04');
  const { campaign: successfulCampaign } = createLabCampaign({
    experimentId: 'experiment-v4-recovery',
    targetAccount: 'ronan',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
    repetitions: 1,
    scheduledByAutomation: true,
  });
  activateLabCampaign(successfulCampaign.campaignId);
  try {
    Date.now = () => realNow() + 60_000;
    const successfulTask = claimNextLabJob('runner-recovery-04');
    assert.ok(successfulTask);
    const jobId = String(successfulTask.job_id);
    const outcomes = successfulTask.outcomes as boolean[];
    const eventIds = outcomes.map((_, index) =>
      `10000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`
    );
    eventIds.forEach((eventId, index) => reportLabJobProgress('runner-recovery-04', jobId, index + 1, eventId));
    completeLabJob({
      agentId: 'runner-recovery-04',
      jobId,
      status: 'completed',
      attemptsCompleted: outcomes.length,
      summary: { event_ids: eventIds },
    });
  } finally {
    Date.now = realNow;
  }

  const resumed = resumeLabAutomation('experiment-v4-recovery');
  assert.equal(resumed.recoveryPending, true);

  const recoveryBatch = getNextLabAutomationBatch('experiment-v4-recovery', 'train');
  assert.equal(recoveryBatch?.repetitions, 3);
  assert.equal(recoveryBatch?.scenarioId, 'benign_mixed');
  assert.equal(getLabAutomationPlan()?.targets.train.benign_mixed, 12);
});

test('legacy manual campaigns remain on the original V3 fixed profile', () => {
  resetLabCoordinatorForTesting();
  registerRunner();

  const { manifest } = createLabCampaign({
    experimentId: 'experiment-v3-compatibility',
    targetAccount: 'ronan',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
    repetitions: 1,
  });

  const run = (manifest.scenarios as Array<Record<string, unknown>>)[0];
  assert.equal(run.planned_attempts_per_agent, 7);
  assert.deepEqual(run.planned_inter_attempt_delays_ms, [4_000, 4_000, 4_000, 4_000, 4_000, 4_000]);
  assert.equal(run.session_profile && (run.session_profile as Record<string, unknown>).profile_version, 1);
  assert.equal(manifest.generation_profile_version, 1);
});

test('a preregistered plan cannot be reconfigured; it can only be paused and resumed', () => {
  resetLabCoordinatorForTesting();
  configureLabAutomation({
    experimentId: 'experiment-v4-lock',
    batchSize: 5,
    accounts: ['ronan', 'andy', 'stefano'],
    targets: {
      train: { benign_mixed: 12 },
      validation: { benign_mixed: 10, attack_rapid: 5, attack_low_frequency: 5, attack_distributed: 2 },
      test: { benign_mixed: 20, attack_rapid: 10, attack_low_frequency: 10, attack_distributed: 4 },
    },
  });

  assert.throws(() => configureLabAutomation({
    experimentId: 'experiment-v4-lock',
    batchSize: 1,
    accounts: ['ronan'],
    targets: {
      train: { benign_mixed: 1 },
      validation: { benign_mixed: 1, attack_rapid: 1, attack_low_frequency: 1, attack_distributed: 1 },
      test: { benign_mixed: 1, attack_rapid: 1, attack_low_frequency: 1, attack_distributed: 1 },
    },
  }), /ya fue configurado/i);

  const paused = stopLabAutomation();
  assert.equal(paused?.status, 'paused');
  assert.equal(paused?.enabled, false);
  const resumed = resumeLabAutomation('experiment-v4-lock');
  assert.equal(resumed.status, 'running');
  assert.equal(resumed.enabled, true);
  assert.equal(resumed.batchSize, 5);
  assert.equal(resumed.targets.train.benign_mixed, 12);
});

test('labelled failed campaign still contributes fully completed independent sessions to quota', () => {
  resetLabCoordinatorForTesting();
  registerRunner('runner-complete-01');
  registerRunner('runner-failed-02');

  configureLabAutomation({
    experimentId: 'experiment-v4-partial-campaign',
    batchSize: 5,
    accounts: ['ronan', 'andy', 'stefano'],
    targets: {
      train: { benign_mixed: 1 },
      validation: {},
      test: {},
    },
  });

  const { campaign } = createLabCampaign({
    experimentId: 'experiment-v4-partial-campaign',
    targetAccount: 'ronan',
    scenarioIds: ['benign_mixed'],
    phase: 'train',
    repetitions: 2,
    scheduledByAutomation: true,
  });
  activateLabCampaign(campaign.campaignId);

  const realNow = Date.now;
  let fakeNow = realNow() + 60_000;
  try {
    Date.now = () => fakeNow;
    const completedTask = claimNextLabJob('runner-complete-01');
    assert.ok(completedTask);
    const outcomes = completedTask.outcomes as boolean[];
    const eventIds = outcomes.map((_, index) =>
      `20000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`
    );
    eventIds.forEach((eventId, index) =>
      reportLabJobProgress('runner-complete-01', String(completedTask.job_id), index + 1, eventId)
    );
    completeLabJob({
      agentId: 'runner-complete-01',
      jobId: String(completedTask.job_id),
      status: 'completed',
      attemptsCompleted: outcomes.length,
      summary: { event_ids: eventIds },
    });

    // The second run is scheduled after the first run's active duration and rest.
    fakeNow += 60 * 60_000;
    const failedTask = claimNextLabJob('runner-failed-02');
    assert.ok(failedTask);
    completeLabJob({
      agentId: 'runner-failed-02',
      jobId: String(failedTask.job_id),
      status: 'failed',
      attemptsCompleted: 0,
      summary: { event_ids: [] },
    });

    assert.equal(isLabAutomationPhaseComplete('experiment-v4-partial-campaign', 'train'), false);
    markLabCampaignLabeled(campaign.campaignId);
    assert.equal(isLabAutomationPhaseComplete('experiment-v4-partial-campaign', 'train'), true);

    const snapshot = getLabSnapshot('experiment-v4-partial-campaign') as {
      automation_progress: Record<string, Record<string, { completed: number; target: number }>>;
      campaigns: Array<{ status: string }>;
    };
    assert.equal(snapshot.campaigns[0].status, 'failed');
    assert.deepEqual(snapshot.automation_progress.train.benign_mixed, {
      completed: 1,
      target: 1,
    });
  } finally {
    Date.now = realNow;
  }
});

