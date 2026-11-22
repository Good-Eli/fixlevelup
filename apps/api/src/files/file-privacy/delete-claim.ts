import { randomUUID } from 'node:crypto';
import { readLedgerMembership } from '../file-ledger/index.js';
import type { LedgerGraph, LedgerItem, LedgerMembership } from '../file-ledger/index.js';
import { refusePrivacy } from './contract.js';
import type { CommittedDeleteGrant, DatabaseContext, DeleteBroker } from './contract.js';
import { lockDecision, privacyAudit, privacyTx, T } from './db.js';
import type { Decision } from './db.js';
import { checkSignal } from './input.js';

interface ItemRow {
  readonly attempt_kind: LedgerItem['kind']; readonly attempt_id: string; readonly target_endpoint: string;
  readonly target_bucket: string; readonly target_region: string; readonly object_key: string; readonly write_proof: LedgerItem['writeProof'];
  readonly state: 'AUTHORIZED' | 'DELETE_ATTEMPTED' | 'VERIFY_PENDING' | 'CONFIRMED_ABSENT';
  readonly claim_generation: number; readonly claim_id: string | null;
}
export const ITEM = `attempt_kind,attempt_id,target_endpoint,target_bucket,target_region,object_key,write_proof,state,claim_generation,claim_id`;
export function toLedgerItem(row: ItemRow): LedgerItem {
  return { kind: row.attempt_kind, attemptId: row.attempt_id, writeProof: row.write_proof, objectKey: row.object_key,
    target: { endpoint: row.target_endpoint, bucket: row.target_bucket, region: row.target_region } };
}
export function sameDecision(row: Decision | undefined, graph: LedgerGraph, digest: string): row is Decision {
  return row !== undefined && !row.hold_active && row.delete_event_id === graph.eventId && row.access_epoch === graph.accessEpoch.toString()
    && row.delete_graph_sha256 === digest && row.delete_writer_epoch === graph.writerEpoch.toString() && row.delete_state !== 'OPEN';
}

interface Claim {
  readonly namespace: string;
  readonly runtimeEpoch: bigint;
  readonly broker: DeleteBroker;
  readonly intentId: string;
  readonly item: LedgerItem;
  readonly deadline: number;
  readonly id: string;
  readonly generation: number;
}
const grants = new WeakMap<object, Claim>();
export function consumeCommittedDeleteGrant(token: unknown, broker: DeleteBroker): Claim {
  const claim = typeof token === 'object' && token !== null ? grants.get(token) : undefined;
  if (claim === undefined || claim.broker !== broker) { return refusePrivacy('NOT_CONFIGURED'); }
  grants.delete(token as object);
  return claim;
}

export async function claimExactItem(ctx: DatabaseContext, broker: DeleteBroker, signal: AbortSignal,
  graph: LedgerGraph, membership: LedgerMembership, allowed: (item: LedgerItem) => boolean,
): Promise<{ readonly grant: CommittedDeleteGrant; readonly claim: Claim } | undefined> {
  const proof = readLedgerMembership(membership);
  if (proof.namespace !== ctx.epoch.namespace || proof.incarnation !== graph.incarnation || proof.writerEpoch !== graph.writerEpoch ||
    proof.head.writerEpoch !== ctx.epoch.epoch || proof.eventId !== graph.eventId || proof.intentId !== graph.intentId ||
    proof.accessEpoch !== graph.accessEpoch) { return refusePrivacy('CONFLICT'); }
  const claim = await privacyTx(ctx.pool, async (client) => {
    const row = await lockDecision(client, ctx, graph.intentId, 'ACTIVE');
    if (!sameDecision(row, graph, proof.graphSha256) || row.ledger_seq !== proof.seq.toString() || row.ledger_hash !== proof.hash ||
      (row.delete_state !== 'LEDGERED' && row.delete_state !== 'VERIFY_PENDING')) { return undefined; }
    const { rows: candidates } = await client.query<ItemRow>(`SELECT ${ITEM} FROM ${T.items} WHERE event_id=$1 AND intent_id=$2
      AND (state IN ('AUTHORIZED','VERIFY_PENDING') OR (state='DELETE_ATTEMPTED' AND claim_expires_at <= clock_timestamp()))
      ORDER BY CASE state WHEN 'AUTHORIZED' THEN 0 ELSE 1 END,claim_generation,attempt_kind,attempt_id LIMIT $3`,
    [graph.eventId, graph.intentId, ctx.policy.maxItemsPerIntent]);
    const chosen = candidates.find((candidate) => allowed(toLedgerItem(candidate)));
    if (chosen === undefined) { return undefined; }
    const { rows: [exact] } = await client.query<ItemRow>(`SELECT ${ITEM} FROM ${T.items}
      WHERE event_id=$1 AND intent_id=$2 AND attempt_kind=$3 AND attempt_id=$4 FOR UPDATE`,
    [graph.eventId, graph.intentId, chosen.attempt_kind, chosen.attempt_id]);
    if (exact === undefined) { return refusePrivacy('CONFLICT'); }
    const item = toLedgerItem(exact);
    if (!graph.items.some((entry) => entry.kind === item.kind && entry.attemptId === item.attemptId && entry.objectKey === item.objectKey &&
      entry.writeProof === item.writeProof && entry.target.endpoint === item.target.endpoint && entry.target.bucket === item.target.bucket &&
      entry.target.region === item.target.region)) { return refusePrivacy('CONFLICT'); }
    const id = randomUUID();
    if (row.delete_state === 'LEDGERED') {
      const pending = await client.query(`UPDATE ${T.controls} SET delete_state='VERIFY_PENDING'
        WHERE intent_id=$1 AND delete_state='LEDGERED' AND delete_event_id=$2`, [graph.intentId, graph.eventId]);
      if (pending.rowCount !== 1) { return refusePrivacy('CONFLICT'); }
    }
    await privacyAudit(client, graph.intentId, id, 'DELETE_CLAIMED');
    checkSignal(signal);
    // Monotonic process budget starts before writing the PG claim. Any DB/COMMIT wait consumes it.
    const started = performance.now();
    const { rows: [committing] } = await client.query<{ claim_generation: number }>(`WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now)
      UPDATE ${T.items} SET state='DELETE_ATTEMPTED',claim_id=$6,claim_generation=claim_generation+1,
        claim_expires_at=least(t.now + $7::bigint * interval '1 millisecond',$8::timestamptz)
      FROM t WHERE event_id=$1 AND intent_id=$2 AND attempt_kind=$3 AND attempt_id=$4 AND claim_generation=$5
        AND t.now < $8::timestamptz
        AND (state IN ('AUTHORIZED','VERIFY_PENDING') OR (state='DELETE_ATTEMPTED' AND claim_expires_at <= t.now))
      RETURNING claim_generation`, [graph.eventId, graph.intentId, item.kind, item.attemptId, exact.claim_generation,
      id, ctx.policy.claimMs, ctx.policy.expiresAt]);
    if (committing === undefined) { return refusePrivacy('CONFLICT'); }
    const checkpoint = performance.now();
    const { rows: [fresh] } = await client.query<{ left_ms: number }>(`SELECT floor(extract(epoch FROM
        (claim_expires_at-clock_timestamp())) * 1000)::integer AS left_ms FROM ${T.items}
      WHERE event_id=$1 AND attempt_kind=$2 AND attempt_id=$3 AND claim_id=$4 AND claim_generation=$5`,
    [graph.eventId, item.kind, item.attemptId, id, committing.claim_generation]);
    if (fresh === undefined || fresh.left_ms <= 0) { return refusePrivacy('NOT_CONFIGURED'); }
    checkSignal(signal);
    return { namespace: ctx.epoch.namespace, runtimeEpoch: ctx.epoch.epoch, broker, intentId: graph.intentId, item, id, generation: committing.claim_generation,
      deadline: Math.min(started + ctx.policy.claimMs, checkpoint + fresh.left_ms) };
  });
  if (claim === undefined) { return undefined; }
  // Never mint on COMMIT ambiguity; a later call can reconcile only the same immutable target/key.
  const grant = Object.freeze({}) as CommittedDeleteGrant;
  grants.set(grant, claim);
  return { grant, claim };
}

export async function finishExactItem(ctx: DatabaseContext, graph: LedgerGraph, digest: string, claim: Claim,
  result: 'AUTHENTICATED_404' | 'VERIFY_PENDING',
): Promise<void> {
  await privacyTx(ctx.pool, async (client) => {
    const row = await lockDecision(client, ctx, graph.intentId, 'ACTIVE');
    if (!sameDecision(row, graph, digest) || row.delete_state !== 'VERIFY_PENDING') { return; }
    const { item } = claim;
    const keys = [graph.eventId, item.kind, item.attemptId, claim.id, claim.generation];
    const { rows: [picked] } = await client.query<{ claim_expires_at: string }>(`SELECT claim_expires_at::text FROM ${T.items}
      WHERE event_id=$1 AND attempt_kind=$2 AND attempt_id=$3
      AND claim_id=$4 AND claim_generation=$5 AND state='DELETE_ATTEMPTED' FOR UPDATE`, keys);
    if (picked === undefined) { return; }
    const absent = result === 'AUTHENTICATED_404' && item.writeProof !== 'UNKNOWN';
    await privacyAudit(client, graph.intentId, claim.id, absent ? 'DELETE_ITEM_ABSENT' : 'DELETE_VERIFY_PENDING');
    const updated = await client.query(`UPDATE ${T.items} SET state=$6,claim_id=NULL,claim_expires_at=NULL
      WHERE event_id=$1 AND attempt_kind=$2 AND attempt_id=$3 AND claim_id=$4 AND claim_generation=$5
        AND clock_timestamp() < least(claim_expires_at,$7::timestamptz)`,
    [...keys, absent ? 'CONFIRMED_ABSENT' : 'VERIFY_PENDING', ctx.policy.expiresAt]);
    if (updated.rowCount !== 1) { return refusePrivacy('CONFLICT'); }
    if (absent) {
      await client.query(`UPDATE ${T.controls} c SET delete_state='CONFIRMED_ABSENT'
        WHERE c.intent_id=$1 AND c.delete_event_id=$2 AND c.delete_state='VERIFY_PENDING'
          AND NOT EXISTS (SELECT 1 FROM ${T.items} WHERE event_id=$2 AND state <> 'CONFIRMED_ABSENT')`, [graph.intentId, graph.eventId]);
    }
    // The group UPDATE can wait even after the item update cleared its lease. Never commit
    // absence/audit on an expired generation: use the original, precision-preserved DB stamp.
    const { rows: [fresh] } = await client.query<{ live: boolean }>(`SELECT clock_timestamp()
      < least($1::timestamptz,$2::timestamptz) AS live`, [picked.claim_expires_at, ctx.policy.expiresAt]);
    if (fresh?.live !== true) { refusePrivacy('CONFLICT'); }
  });
}
