import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { auditLifecycle } from '../file-lifecycle/audit.js';
import {
  checkFileAuthorization, CONTROLS, INTENTS, lockFileAuthorization, lockOrCreateControl, lockTechnicalFile,
} from '../file-lifecycle/authorization.js';
import type { FileAuthorization, PrivacyControl } from '../file-lifecycle/authorization.js';
import { requireOwnerReadCapacity } from '../file-lifecycle/budget.js';
import type { FFile, RuntimeEpoch } from '../file-lifecycle/contract.js';
import { refuseLifecycle } from '../file-lifecycle/errors.js';
import { selectPublication, toReadyFileView } from '../file-lifecycle/publication.js';
import type { Publication } from '../file-lifecycle/publication.js';
import { withLifecycleTransaction } from '../file-lifecycle/transaction.js';
import { MAX_PG_INT, reserveRead } from './budget.js';
import type { ReadReservation } from './budget.js';
import type { ReadContext } from './input.js';

export interface ReadClaim {
  readonly runtime: RuntimeEpoch;
  readonly publication: Publication;
  readonly accessEpoch: bigint;
  readonly id: string;
  readonly generation: number;
  readonly deadline: number;
}

/** The part of the access policy that bounds the original READY window. */
export type ReadyWindowPolicy = {
  readonly expiresAt: string;
  readonly maxAccessAgeMs: number;
};

type ReadLimits = Pick<ReadContext['policy'], 'expiresAt' | 'maxAccessAgeMs' | 'maxChunkBytes'>;
export type ReadAuthority = { readonly pool: ReadContext['pool']; readonly epoch: RuntimeEpoch; readonly policy: ReadLimits };

export function assertReadSignal(signal: AbortSignal): void {
  if (signal.aborted) {
    refuseLifecycle('ABORTED');
  }
}

/**
 * The exact immutable publication has already been read under the enclosing intent lock.
 * Sample only after all prior row/relation/audit waits, at PostgreSQL's precision. The
 * returned local deadline is conservative: project remaining DB time onto the pre-query
 * monotonic instant, not onto the later receipt of the reply.
 */
async function accessWindow(client: PoolClient, auth: FileAuthorization, policy: ReadyWindowPolicy,
  publication: Publication | undefined, readExpiresAt: string | null = null,
): Promise<{ localDeadlineMs: number; expiresAtMs: number | null }> {
  const { mime } = await checkFileAuthorization(client, auth);
  const sampleStarted = performance.now();
  const { rows: [gate] } = await client.query<{
    policy_live: boolean; ready_live: boolean | null; lease_live: boolean; remaining_ms: number | null;
    session_live: boolean; intent_live: boolean; original_policy_live: boolean; expires_at_ms: number | null;
  }>(`WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now)
    SELECT $3::timestamptz > t.now AS policy_live,
      ($4::timestamptz + $5::integer * interval '1 millisecond') > t.now AS ready_live,
      ($6::timestamptz IS NULL OR $6::timestamptz > t.now) AS lease_live,
      s.expires_at > t.now AS session_live,i.expires_at > t.now AS intent_live,
      i.policy_expires_at > t.now AS original_policy_live,
      CASE WHEN $6::timestamptz IS NOT NULL THEN greatest(0,floor(extract(epoch FROM
        (least(s.expires_at,i.expires_at,i.policy_expires_at,$3::timestamptz,
          $4::timestamptz + $5::integer * interval '1 millisecond',$6::timestamptz) - t.now)) * 1000))::float8
      END AS remaining_ms,
       CASE WHEN $4::timestamptz IS NOT NULL THEN floor(extract(epoch FROM least(
         s.expires_at,i.expires_at,i.policy_expires_at,$3::timestamptz,
         $4::timestamptz + $5::integer * interval '1 millisecond')) * 1000)::float8 END AS expires_at_ms
    FROM ${INTENTS} i JOIN foundation.request_sessions s ON s.id=i.owner_request_session_id CROSS JOIN t
    WHERE i.id=$1 AND s.id=$2`, [auth.intent.id, auth.owner, policy.expiresAt, publication?.published_at ?? null,
    policy.maxAccessAgeMs, readExpiresAt]);
  if (gate === undefined) {
    refuseLifecycle('CONFLICT');
  }
  if (!gate.session_live) {
    refuseLifecycle('SESSION_EXPIRED');
  }
  if (!gate.policy_live || !gate.original_policy_live) {
    refuseLifecycle('NOT_CONFIGURED');
  }
  if (!gate.intent_live) {
    refuseLifecycle('INTENT_EXPIRED');
  }
  if (gate.ready_live !== true || publication?.mime !== mime) {
    refuseLifecycle('NOT_READY');
  }
  if (readExpiresAt === null) {
    return { localDeadlineMs: 0, expiresAtMs: gate.expires_at_ms };
  }
  if (!gate.lease_live || gate.remaining_ms === null || !Number.isSafeInteger(gate.remaining_ms) || gate.remaining_ms < 1) {
    refuseLifecycle('STALE_CLAIM');
  }
  return { localDeadlineMs: sampleStarted + gate.remaining_ms, expiresAtMs: gate.expires_at_ms };
}

export async function authorizeMetadata(client: PoolClient, ctx: ReadAuthority, cmd: FFile) {
  const auth = await lockFileAuthorization(client, cmd, ctx.epoch);
  const publication = await selectPublication(client, auth.intent.id);
  await accessWindow(client, auth, ctx.policy, publication);
  if (publication === undefined) {
    refuseLifecycle('NOT_READY');
  }
  return toReadyFileView(publication);
}

/**
 * Read-only proof of the original READY access window, for P05 attachment admission.
 *
 * No claim, no ticket and no byte access: it re-runs exactly the same
 * `checkFileAuthorization` + window statement the read path uses, so the attach
 * decision cannot drift from the access policy. `publication` must be the exact
 * immutable publication already read under the enclosing intent lock.
 */
export async function proveReadyWindow(client: PoolClient, auth: FileAuthorization, policy: ReadyWindowPolicy,
  publication: Publication | undefined,
): Promise<number> {
  const { expiresAtMs } = await accessWindow(client, auth, policy, publication);
  if (expiresAtMs === null || !Number.isSafeInteger(expiresAtMs)) { return refuseLifecycle('NOT_READY'); }
  return expiresAtMs;
}

async function claimControl(client: PoolClient, auth: FileAuthorization, control: PrivacyControl,
  policy: ReadContext['policy'], publication: Publication,
): Promise<{ readonly id: string; readonly expires: string; readonly generation: number }> {
  if (control.read_lease_id !== null || control.read_generation >= MAX_PG_INT) {
    // Expiry alone is not evidence that the exact prior holder has settled.
    refuseLifecycle('ACCESS_LIMIT');
  }
  const id = randomUUID();
  const { rows: [row] } = await client.query<{ read_expires_at: string; read_generation: number }>(
    `WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now), limits AS (
       SELECT least(t.now + $5::integer * interval '1 millisecond', i.expires_at, i.policy_expires_at, s.expires_at,
         $6::timestamptz, $7::timestamptz + $8::integer * interval '1 millisecond') AS expires, t.now
       FROM ${INTENTS} i JOIN foundation.request_sessions s ON s.id=i.owner_request_session_id CROSS JOIN t
       WHERE i.id=$1 AND s.id=$9
     ) UPDATE ${CONTROLS} c SET read_generation=c.read_generation+1,read_lease_id=$4,read_expires_at=limits.expires
       FROM limits WHERE c.intent_id=$1 AND c.access_epoch=$2::bigint AND c.read_generation=$3
         AND c.read_lease_id IS NULL AND limits.expires > limits.now
       RETURNING c.read_expires_at::text,c.read_generation`,
    [auth.intent.id, control.access_epoch, control.read_generation, id, policy.ticketMs, policy.expiresAt,
      publication.published_at, policy.maxAccessAgeMs, auth.owner],
  );
  if (row === undefined) {
    refuseLifecycle('STALE_CLAIM');
  }
  return { id, expires: row.read_expires_at, generation: row.read_generation };
}

/** No object IO in this transaction. RAM and a stream slot are held before creating the durable claim. */
export async function claimRead(client: PoolClient, ctx: ReadContext, cmd: FFile & { readonly signal: AbortSignal },
  hold: (reservation: ReadReservation) => void,
): Promise<ReadClaim> {
  const auth = await lockFileAuthorization(client, cmd, ctx.epoch);
  const publication = await selectPublication(client, auth.intent.id);
  await accessWindow(client, auth, ctx.policy, publication);
  assertReadSignal(cmd.signal);
  if (publication === undefined) {
    refuseLifecycle('NOT_READY');
  }
  const bytes = toReadyFileView(publication).bytes;
  if (auth.control?.read_lease_id !== undefined && auth.control.read_lease_id !== null) {
    refuseLifecycle('ACCESS_LIMIT');
  }
  await requireOwnerReadCapacity(client, auth.owner, ctx.maxLiveOperationsPerOwner);
  const control = await lockOrCreateControl(client, auth.intent.id, auth.control);
  await accessWindow(client, auth, ctx.policy, publication);
  assertReadSignal(cmd.signal);
  hold(reserveRead(ctx.budget, auth.runtime.namespace, bytes, ctx.policy));
  const claim = await claimControl(client, auth, control, ctx.policy, publication);
  await auditLifecycle(client, 'READ_CLAIM', auth.intent.id, claim.id);
  const { localDeadlineMs: deadline } = await accessWindow(client, auth, ctx.policy, publication, claim.expires);
  assertReadSignal(cmd.signal);
  return { runtime: auth.runtime, publication, accessEpoch: BigInt(control.access_epoch),
    id: claim.id, generation: claim.generation, deadline };
}

function samePublication(left: Publication, right: Publication): boolean {
  return left.id === right.id && left.intent_id === right.intent_id && left.quarantine_id === right.quarantine_id
    && left.sanitized_attempt_id === right.sanitized_attempt_id && left.mime === right.mime
    && left.served_bytes === right.served_bytes && left.served_sha256 === right.served_sha256
    && left.raw_bytes === right.raw_bytes && left.raw_sha256 === right.raw_sha256 && left.published_at === right.published_at
    && left.object_key === right.object_key && left.storage_endpoint === right.storage_endpoint
    && left.storage_bucket === right.storage_bucket && left.storage_region === right.storage_region;
}

/** Read-only admission: no durable mutation and therefore no transition audit/outbox pair per chunk. */
export async function admitRead(client: PoolClient, ctx: ReadAuthority, cmd: FFile, claim: ReadClaim,
  signal: AbortSignal,
): Promise<void> {
  assertReadSignal(signal);
  const auth = await lockFileAuthorization(client, cmd, claim.runtime);
  const publication = await selectPublication(client, auth.intent.id);
  const control = auth.control;
  await accessWindow(client, auth, ctx.policy, publication, control?.read_expires_at ?? null);
  if (publication === undefined || !samePublication(publication, claim.publication)
    || control === undefined || BigInt(control.access_epoch) !== claim.accessEpoch
    || control.read_lease_id !== claim.id || control.read_generation !== claim.generation
    || control.read_expires_at === null) {
    refuseLifecycle('STALE_CLAIM');
  }
  assertReadSignal(signal);
}

/** For this locally settled holder only; expiry, later claims and a new runtime never authorize release. */
export async function releaseReadClaim(pool: ReadContext['pool'], claim: ReadClaim): Promise<void> {
  await withLifecycleTransaction(pool, async (client) => {
    const intentId = claim.publication.intent_id;
    const current = await lockTechnicalFile(client, intentId, claim.runtime);
    if (current?.control?.read_lease_id !== claim.id || current.control.read_generation !== claim.generation) {
      return;
    }
    const { rowCount } = await client.query(`UPDATE ${CONTROLS} SET read_lease_id=NULL,read_expires_at=NULL
      WHERE intent_id=$1 AND read_lease_id=$2 AND read_generation=$3`, [intentId, claim.id, claim.generation]);
    if (rowCount === 1) {
      await auditLifecycle(client, 'READ_RELEASE', intentId, claim.id);
    }
  });
}
