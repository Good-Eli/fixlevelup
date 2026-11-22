import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { RegisteredQuarantineStorage, StorageTarget } from '../storage/index.js';
import { issueRegisteredQuarantineProbe } from '../storage/registered-proof.js';
import { isUploadError, refuse } from './contract.js';
import type { Observation, UploadOperationalPolicy, UploadReconcileCommand, UploadReconcileSummary } from './contract.js';
import { assertNotAborted, deadline, reconcileCommand, signalAborted, uploadOperationalPolicy } from './input.js';
import type { RuntimeEpoch } from '../file-lifecycle/contract.js';
import { ATTEMPTS, SHA256, audit, hasProbeCapacity, leaseDeadline, lockTechnicalAttempt, lockUploadRuntime, retireExpired } from './registry.js';
import type { AttemptRow } from './registry.js';
import { CommitUncertain, inUploadTransaction } from './transaction.js';
import { ownerBudgetSql } from './accounting.js';

export type { UploadReconcileCommand, UploadReconcileSummary } from './contract.js';

type Candidate = Pick<AttemptRow, 'id' | 'intent_id'>;
interface Claim {
  readonly attempt: AttemptRow;
  readonly id: string;
  readonly generation: number;
  readonly until: number;
}

function targetOf(row: AttemptRow): StorageTarget {
  return Object.freeze({ endpoint: row.storage_endpoint, bucket: row.storage_bucket, region: row.storage_region });
}

function matchesTarget(row: AttemptRow, target: StorageTarget): boolean {
  return row.storage_endpoint === target.endpoint && row.storage_bucket === target.bucket && row.storage_region === target.region;
}

/** Listing is only a hint. Recheck eligibility and all quota/lease predicates under the owner lock. */
async function candidates(client: PoolClient, target: StorageTarget, policy: UploadOperationalPolicy, limit: number): Promise<Candidate[]> {
  const { rows } = await client.query<Candidate>(`WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now)
    SELECT a.id,a.intent_id FROM ${ATTEMPTS} a CROSS JOIN t
    LEFT JOIN foundation.file_privacy_controls privacy ON privacy.intent_id=a.intent_id
    JOIN LATERAL (${ownerBudgetSql('a.owner_request_session_id')}) owner_budget ON true
    WHERE a.storage_endpoint=$2 AND a.storage_bucket=$3 AND a.storage_region=$4
      -- 016 uses access_epoch=1; every irreversible 017 delete freeze raises it.
      -- Filter before LIMIT, including retirement rows, so a frozen oldest row
      -- cannot consume every bounded batch without making progress.
      AND (privacy.intent_id IS NULL OR privacy.access_epoch=1)
      AND ((a.state IN ('REGISTERED','IN_FLIGHT') AND a.upload_lease_expires_at <= t.now)
       OR (a.state='UNKNOWN' AND (a.probe_lease_expires_at IS NULL OR a.probe_lease_expires_at <= t.now)
         AND a.probe_generation < 2147483647 AND a.probe_held_slots < 2147483647
         -- Match the locked claim check across raw and sanitized attempts, C read
         -- and unregistered processing claims. Expiry never releases occupied debt.
         AND owner_budget.slots::numeric < $1::numeric))
    ORDER BY (a.state='UNKNOWN'), a.observed_at NULLS FIRST, a.created_at,a.id LIMIT $5`,
  [policy.maxLiveOperationsPerOwner, target.endpoint, target.bucket, target.region, limit]);
  return rows;
}

async function claimProbe(client: PoolClient, candidate: Candidate, target: StorageTarget, policy: UploadOperationalPolicy,
  signal: AbortSignal, epoch: RuntimeEpoch | null,
): Promise<{ retired?: 'FAILED_NOBYTES' | 'UNKNOWN'; claim?: Claim }> {
  const row = await lockTechnicalAttempt(client, candidate, { epoch, requireOpen: true });
  if (row === undefined) {
    return {};
  }
  assertNotAborted(signal);
  const retired = await retireExpired(client, row);
  if ((row.state !== 'UNKNOWN' && retired !== 'UNKNOWN') || !matchesTarget(row, target)
    || !await hasProbeCapacity(client, row.owner_request_session_id, policy)) {
    return retired === undefined ? {} : { retired };
  }
  const id = randomUUID();
  const { rows: [claim] } = await client.query<{ probe_generation: number }>(`UPDATE ${ATTEMPTS} SET
    probe_generation=probe_generation+1,probe_held_slots=probe_held_slots+1,probe_lease_id=$2,
    probe_lease_expires_at=clock_timestamp()+$3::integer * interval '1 millisecond'
    WHERE id=$1 AND state='UNKNOWN' AND (probe_lease_expires_at IS NULL OR probe_lease_expires_at<=clock_timestamp())
      AND probe_generation < 2147483647 AND probe_held_slots < 2147483647
    RETURNING probe_generation`, [row.id, id, policy.leaseMs]);
  if (claim === undefined) {
    return retired === undefined ? {} : { retired };
  }
  const result = { attempt: row, id, generation: claim.probe_generation, until: await leaseDeadline(client, row.id, 'probe') };
  return retired === undefined ? { claim: result } : { retired, claim: result };
}

async function finishProbe(client: PoolClient, claim: Claim, observation: Observation, transportSettled: boolean,
  epoch: RuntimeEpoch | null,
): Promise<boolean> {
  const row = await lockTechnicalAttempt(client, claim.attempt, { epoch });
  if (!row || row.state !== 'UNKNOWN' || row.object_key !== claim.attempt.object_key
    || !matchesTarget(row, targetOf(claim.attempt))) {
    return false;
  }
  const { rows: [matched] } = await client.query<{ expires_at: string }>(`WITH prior AS MATERIALIZED (
      SELECT probe_lease_expires_at AS expires_at FROM ${ATTEMPTS} WHERE id=$1
    ) UPDATE ${ATTEMPTS} SET
    probe_lease_id=NULL,probe_lease_expires_at=NULL,probe_held_slots=probe_held_slots-$5::integer,
    observation=$4,observed_bytes=$6,observed_sha256=$7 FROM prior
    WHERE id=$1 AND state='UNKNOWN' AND probe_lease_id=$2 AND probe_generation=$3
      AND probe_lease_expires_at > clock_timestamp() RETURNING prior.expires_at::text AS expires_at`,
  [row.id, claim.id, claim.generation, observation.kind, transportSettled ? 1 : 0,
    observation.kind === 'PRESENT' ? observation.actualBytes : null, observation.kind === 'PRESENT' ? observation.sha256 : null]);
  if (matched === undefined) {
    return false;
  }
  await audit(client, 'OBSERVED', row, observation.kind);
  // The locked attempt keeps this generation stable, but audit itself can wait
  // past the claim's expiry. Roll back the observation and release together.
  const { rows: [gate] } = await client.query<{ live: boolean }>(
    'SELECT clock_timestamp() < $1::timestamptz AS live', [matched.expires_at]);
  if (gate?.live !== true) {
    refuse('STALE_ATTEMPT');
  }
  return true;
}

async function observe(storage: RegisteredQuarantineStorage, claim: Claim, caller: AbortSignal,
): Promise<{ observation: Observation; transportSettled: boolean } | undefined> {
  const remaining = Math.floor(claim.until - performance.now());
  if (remaining < 1 || signalAborted(caller)) {
    return undefined;
  }
  const signal = deadline(caller, remaining);
  try {
    const row = claim.attempt;
    const maxBytes = Number(row.charged_bytes);
    const proof = issueRegisteredQuarantineProbe({
      attemptId: row.id, objectKey: row.object_key, target: targetOf(row), claimId: claim.id, claimGeneration: claim.generation,
    });
    if (signalAborted(signal.signal) || performance.now() >= claim.until) {
      return undefined;
    }
    const read = await storage.inspectRegisteredQuarantineObject(proof, { maxBytes, signal: signal.signal });
    const transportSettled = read.transportSettled;
    if (read.observation === 'PRESENT' && Number.isSafeInteger(read.actualBytes)
      && read.actualBytes >= 0 && read.actualBytes <= maxBytes && SHA256.test(read.sha256)) {
      return { observation: { kind: 'PRESENT', actualBytes: read.actualBytes, sha256: read.sha256 }, transportSettled };
    }
    return { observation: { kind: read.observation === 'NOT_OBSERVED' ? 'NOT_OBSERVED' : 'INDETERMINATE' }, transportSettled };
  } catch {
    // No raw exception or digest is returned. Without a transport settlement fact,
    // the claimed slot remains charged even if an eligible observation commits.
    return { observation: { kind: 'INDETERMINATE' }, transportSettled: false };
  } finally {
    signal.close();
  }
}

/** Operator-only bounded sweep: no request proof, selected UUID, old PUT, delete, or publication. */
export async function reconcileUploadAttempts(pool: Pool, storage: RegisteredQuarantineStorage,
  operationalPolicy: UploadOperationalPolicy, command: UploadReconcileCommand,
): Promise<UploadReconcileSummary> {
  const policy = uploadOperationalPolicy(operationalPolicy);
  const { limit, signal } = reconcileCommand(command);
  assertNotAborted(signal);
  let target: StorageTarget;
  try {
    const prepared = storage.prepareRegisteredQuarantineAttempt();
    if (policy.maxSourceChunkBytes > prepared.maxChunkBytes) {
      refuse('NOT_CONFIGURED');
    }
    target = prepared.target;
  } catch {
    refuse('NOT_CONFIGURED');
  }
  const result = { retiredWithoutPut: 0, retiredUnknown: 0, present: 0, notObserved: 0, indeterminate: 0, skipped: 0 };
  try {
    const { selected, epoch } = await inUploadTransaction(pool, async (client) => {
      const runtime = await lockUploadRuntime(client);
      return { selected: await candidates(client, target, policy, limit), epoch: runtime ?? null };
    });
    for (const candidate of selected) {
      if (signalAborted(signal)) {
        break;
      }
      let claimed;
      try {
        claimed = await inUploadTransaction(pool, (client) => claimProbe(client, candidate, target, policy, signal, epoch));
      } catch (error) {
        if (error instanceof CommitUncertain) {
          // Never start a GET using an unacknowledged claim.
          result.skipped += 1;
          continue;
        }
        throw error;
      }
      if (claimed.retired === 'FAILED_NOBYTES') {
        result.retiredWithoutPut += 1;
      } else if (claimed.retired === 'UNKNOWN') {
        result.retiredUnknown += 1;
      }
      if (!claimed.claim) {
        if (claimed.retired === undefined) {
          result.skipped += 1;
        }
        continue;
      }
      const claim = claimed.claim;
      const observed = await observe(storage, claim, signal);
      if (!observed) {
        result.skipped += 1;
        continue;
      }
      let committed: boolean;
      try {
        committed = await inUploadTransaction(pool,
          (client) => finishProbe(client, claim, observed.observation, observed.transportSettled, epoch));
      } catch (error) {
        if (error instanceof CommitUncertain || (isUploadError(error) && error.code === 'STALE_ATTEMPT')) {
          result.skipped += 1;
          continue;
        }
        throw error;
      }
      if (!committed) {
        result.skipped += 1;
      } else if (observed.observation.kind === 'PRESENT') {
        result.present += 1;
      } else if (observed.observation.kind === 'NOT_OBSERVED') {
        result.notObserved += 1;
      } else {
        result.indeterminate += 1;
      }
    }
    return Object.freeze(result);
  } catch (error) {
    if (isUploadError(error)) {
      throw error;
    }
    refuse('CONFLICT');
  }
}
