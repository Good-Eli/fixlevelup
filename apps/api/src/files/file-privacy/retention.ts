import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { ledgerGraphSha256 } from '../file-ledger/index.js';
import type { LedgerGraph, LedgerItem, LedgerScope } from '../file-ledger/index.js';
import { probeAttachmentInterlock } from '../file-lifecycle/authorization.js';
import type { AttachmentInterlock } from '../file-lifecycle/authorization.js';
import { refusePrivacy } from './contract.js';
import type { AggregateOnly, DatabaseContext, HoldContext, HoldGrant, PrivacyContext, RetentionContext } from './contract.js';
import { lockDecision, lockPrivacyRuntime, privacyAudit, privacyTx, requireFreshPolicy, T } from './db.js';
import { readHoldGrant, requireOperator } from './grants.js';
import { checkSignal, contextSnapshot, nativeSignal, scopeSnapshot } from './input.js';

export async function changeFileHold(input: HoldContext, token: HoldGrant): Promise<{ readonly applied: boolean; readonly rowVersion: bigint }> {
  const ctx = contextSnapshot(input, [], true);
  const hold = readHoldGrant(token, ctx.epoch.namespace);
  return await privacyTx(ctx.pool, async (client) => {
    const row = await lockDecision(client, ctx, hold.intentId, 'ACTIVE', true);
    if (row === undefined) { return refusePrivacy('NOT_FOUND'); }
    if (row.delete_state !== 'OPEN') { return refusePrivacy('TOO_LATE'); }
    const version = BigInt(row.row_version);
    if (version !== hold.expectedRowVersion) { return refusePrivacy('STALE_VERSION'); }
    const placed = hold.action === 'PLACE';
    if (row.hold_active === placed) {
      await requireFreshPolicy(client, ctx);
      return { applied: false, rowVersion: version };
    }
    await privacyAudit(client, hold.intentId, randomUUID(), placed ? 'HOLD_PLACED' : 'HOLD_RELEASED');
    const { rowCount } = await client.query(`UPDATE ${T.controls} SET hold_active=$3::boolean,
      hold_actor_id=$4,hold_reason=$5
      WHERE intent_id=$1 AND row_version=$2 AND access_epoch=1 AND delete_state='OPEN' AND clock_timestamp() < $6::timestamptz`,
    [hold.intentId, row.row_version, placed, placed ? hold.operator.actorId : null, placed ? hold.reason : null, ctx.policy.expiresAt]);
    if (rowCount !== 1) { return refusePrivacy('NOT_CONFIGURED'); }
    await requireFreshPolicy(client, ctx);
    return { applied: true, rowVersion: version + 1n };
  });
}

const INTERVAL = `interval '1 millisecond'`;
// Cheap candidate filter only, then all rows are locked and due-ness is re-evaluated. Exclude empty intents,
// oversized complete graphs and immutably held decisions so they cannot starve other eligible work.
const DUE = `NOT EXISTS (SELECT 1 FROM ${T.raw} a LEFT JOIN ${T.binding} q ON q.attempt_id=a.id
    LEFT JOIN ${T.pubs} p ON p.quarantine_id=q.id WHERE a.intent_id=i.id AND
    (CASE WHEN q.id IS NULL THEN coalesce(a.dispatched_at,a.created_at) + $1::bigint * ${INTERVAL}
          WHEN p.id IS NULL THEN q.created_at + greatest($2::bigint,$3::bigint) * ${INTERVAL}
          ELSE greatest(q.created_at + $2::bigint * ${INTERVAL}, p.published_at + $4::bigint * ${INTERVAL}) END) > now.t)
  AND NOT EXISTS (SELECT 1 FROM ${T.sanitized} a LEFT JOIN ${T.pubs} p ON p.sanitized_attempt_id=a.id
    WHERE a.intent_id=i.id AND p.id IS NULL AND coalesce(a.dispatched_at,a.created_at) + $1::bigint * ${INTERVAL} > now.t)`;
function ages(ctx: PrivacyContext): readonly number[] {
  return [ctx.policy.orphanMs, ctx.policy.rawBoundMs, ctx.policy.quarantinedMs, ctx.policy.readyMs];
}

interface Attempt {
  readonly id: string; readonly storage_endpoint: string; readonly storage_bucket: string; readonly storage_region: string;
  readonly object_key: string; readonly dispatched: boolean; readonly state: string;
}
async function lockAttempts(client: PoolClient, intentId: string, cap: number): Promise<readonly LedgerItem[] | undefined> {
  const items: LedgerItem[] = [];
  for (const kind of ['RAW', 'SANITIZED'] as const) {
    const { rows } = await client.query<Attempt>(`SELECT id,storage_endpoint,storage_bucket,storage_region,object_key,
      dispatched_at IS NOT NULL AS dispatched,state FROM ${kind === 'RAW' ? T.raw : T.sanitized}
      WHERE intent_id=$1 ORDER BY id LIMIT $2 FOR UPDATE`, [intentId, cap + 1 - items.length]);
    for (const row of rows) {
      items.push({ kind, attemptId: row.id, objectKey: row.object_key,
        target: { endpoint: row.storage_endpoint, bucket: row.storage_bucket, region: row.storage_region },
        writeProof: !row.dispatched ? 'NEVER_DISPATCHED' : row.state === 'VERIFIED' ? 'VERIFIED_SETTLED' : 'UNKNOWN' });
    }
    if (items.length > cap) { return undefined; }
  }
  // No CAS/retirement of an already-dispatched PUT implies remote termination. For an undispatched
  // REGISTERED row the intent privacy fence and its forward lock are what prohibit future dispatch.
  return items;
}

/**
 * P05 §5.2 attach/delete interlock: an attached intent is excluded from aging.
 *
 * `DRIFTED` (an intermediate schema, a missing FK/CHECK/UNIQUE, a deferrable
 * interlock or a same-prefixed artifact) is never treated as "no attachments":
 * the whole retention run fails closed with `NOT_CONFIGURED` instead of using the
 * legacy query on a schema whose interlock cannot be proven.
 */
export function requireRetentionInterlock(mode: AttachmentInterlock): 'S3' | 'PRE_S3' {
  if (mode === 'DRIFTED') {
    return refusePrivacy('NOT_CONFIGURED');
  }
  return mode;
}

const ATTACHMENT_EXCLUSION = `NOT EXISTS (SELECT 1 FROM foundation.request_files rf WHERE rf.intent_id=i.id)`;

/**
 * Candidate selection. On the exact S3 profile an attached intent is excluded
 * before the `LIMIT`, so it cannot consume a batch slot; on the exact pre-S3
 * profile the reviewed relation does not exist and the legacy query is unchanged.
 */
export function retentionCandidateSql(mode: AttachmentInterlock): string {
  const interlock = requireRetentionInterlock(mode);
  return `WITH now AS MATERIALIZED (SELECT clock_timestamp() AS t)
      SELECT i.id FROM ${T.intents} i CROSS JOIN now LEFT JOIN ${T.controls} c ON c.intent_id=i.id
      WHERE (c.intent_id IS NULL OR (c.delete_state='OPEN' AND NOT c.hold_active))
        AND (EXISTS (SELECT 1 FROM ${T.raw} a WHERE a.intent_id=i.id) OR EXISTS (SELECT 1 FROM ${T.sanitized} a WHERE a.intent_id=i.id))
        AND (SELECT count(*) FROM (SELECT 1 FROM ${T.raw} a WHERE a.intent_id=i.id
          UNION ALL SELECT 1 FROM ${T.sanitized} a WHERE a.intent_id=i.id LIMIT ($5::integer + 1)) bounded) <= $5::integer
        ${interlock === 'S3' ? `AND ${ATTACHMENT_EXCLUSION}` : ''}
        AND ${DUE} ORDER BY i.id LIMIT $6`;
}

/**
 * Second, irreversible check after the intent/control locks: an attachment that
 * committed while this planner waited must defer the decision. The S3 FK is the
 * database backstop for the reverse order (a decision that wins must make a later
 * attach refuse), this read is the application-side half of the same interlock.
 */
export function retentionAttachmentGuardSql(mode: AttachmentInterlock): string | undefined {
  return requireRetentionInterlock(mode) === 'S3'
    ? `SELECT rf.intent_id FROM foundation.request_files rf WHERE rf.intent_id=$1 LIMIT 1`
    : undefined;
}

async function decide(ctx: DatabaseContext, scope: LedgerScope, intentId: string, signal: AbortSignal,
  mode: AttachmentInterlock,
): Promise<boolean> {
  return await privacyTx(ctx.pool, async (client) => {
    const row = await lockDecision(client, ctx, intentId, 'ACTIVE', true);
    if (row === undefined || row.delete_state !== 'OPEN' || row.hold_active) { return false; }
    const attachmentGuard = retentionAttachmentGuardSql(mode);
    if (attachmentGuard !== undefined) {
      const { rows } = await client.query(attachmentGuard, [intentId]);
      if (rows.length > 0) { return false; }
    }
    const items = await lockAttempts(client, intentId, ctx.policy.maxItemsPerIntent);
    if (items === undefined || items.length === 0) { return false; }
    const { rows: [due] } = await client.query<{ due: boolean }>(`WITH now AS MATERIALIZED (SELECT clock_timestamp() AS t)
      SELECT ${DUE} AS due FROM ${T.intents} i CROSS JOIN now WHERE i.id=$5`, [...ages(ctx), intentId]);
    if (due?.due !== true) { return false; }
    await requireFreshPolicy(client, ctx);
    checkSignal(signal);
    const graph: LedgerGraph = { ...scope, intentId, eventId: randomUUID(), accessEpoch: BigInt(row.access_epoch) + 1n, items };
    const digest = ledgerGraphSha256(graph, ctx.policy.maxItemsPerIntent);
    await privacyAudit(client, intentId, graph.eventId, 'DELETE_DECIDED');
    const { rowCount } = await client.query(`UPDATE ${T.controls} SET
      delete_state='PENDING_LEDGER',delete_event_id=$3,delete_policy_id=$4,delete_graph_sha256=$5
      WHERE intent_id=$1 AND row_version=$2 AND access_epoch=1 AND NOT hold_active AND delete_state='OPEN' AND clock_timestamp() < $6::timestamptz`,
    [intentId, row.row_version, graph.eventId, ctx.policy.versionId, digest, ctx.policy.expiresAt]);
    if (rowCount !== 1) { return refusePrivacy('NOT_CONFIGURED'); }
    await client.query(`INSERT INTO ${T.items} (event_id,intent_id,attempt_kind,attempt_id,target_endpoint,target_bucket,target_region,
      object_key,write_proof) SELECT $1,$2,x.kind,x.id,x.endpoint,x.bucket,x.region,x.key,x.proof
      FROM jsonb_to_recordset($3::jsonb) AS x(kind text,id uuid,endpoint text,bucket text,region text,key text,proof text)`,
    [graph.eventId, intentId, JSON.stringify(items.map((item) => ({ kind: item.kind, id: item.attemptId, ...item.target,
      key: item.objectKey, proof: item.writeProof })))]);
    // Force the deferred complete-graph check before sampling the final DB clock.
    await client.query('SET CONSTRAINTS foundation.file_delete_graph_complete IMMEDIATE');
    await requireFreshPolicy(client, ctx);
    checkSignal(signal);
    return true;
  });
}

export async function planRetention(input: RetentionContext, abort: AbortSignal): Promise<AggregateOnly> {
  const ctx = contextSnapshot(input, ['grant','scope'], true);
  requireOperator(ctx.fields['grant'], ctx.epoch.namespace, 'RETENTION');
  const scope = scopeSnapshot(ctx.fields['scope'], ctx.epoch);
  const signal = nativeSignal(abort);
  checkSignal(signal);
  const planned = await privacyTx(ctx.pool, async (client) => {
    await lockPrivacyRuntime(client, ctx, 'ACTIVE');
    // Explicit interlock probe: catalog facts only, never a caught SQL error.
    const mode = await probeAttachmentInterlock(client);
    const { rows } = await client.query<{ id: string }>(retentionCandidateSql(mode),
      [...ages(ctx), ctx.policy.maxItemsPerIntent, ctx.policy.maxBatch]);
    await requireFreshPolicy(client, ctx);
    return { mode, rows };
  });
  let advanced = 0;
  for (const { id } of planned.rows) {
    checkSignal(signal);
    if (await decide(ctx, scope, id, signal, planned.mode)) { advanced++; }
  }
  return { examined: planned.rows.length, advanced, deferred: planned.rows.length - advanced };
}
