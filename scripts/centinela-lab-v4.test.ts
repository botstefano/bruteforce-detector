import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  configureLabAutomation,
  createLabCampaign,
  getNextLabAutomationBatch,
  getLabAutomationPlan,
  registerLabAgent,
  resetLabCoordinatorForTesting,
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
      validation: { benign_mixed: 10, attack_rapid: 5, attack_low_frequency: 5, attack_distributed: 2 },
      test: { benign_mixed: 20, attack_rapid: 10, attack_low_frequency: 10, attack_distributed: 4 },
    },
  });

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
