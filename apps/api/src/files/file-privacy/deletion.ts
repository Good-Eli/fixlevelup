import { ledgerGraphSha256, readLedgerMembership } from '../file-ledger/index.js';
import type { FileLedger, FileLedgerVerifier, LedgerGraph, LedgerMembership, LedgerPosition, LedgerScope } from '../file-ledger/index.js';
import { brokerDatabase, brokerSchedule, executeCommittedDelete, hasDeleteTarget, requireDeleteBroker } from './broker.js';
import { refusePrivacy } from './contract.js';
import type { AggregateOnly, DatabaseContext, DeleteContext, FencedDrainContext } from './contract.js';
import { lockDecision, lockPrivacyRuntime, privacyAudit, privacyTx, requireFreshPolicy, T } from './db.js';
import { claimExactItem, finishExactItem, ITEM, sameDecision, toLedgerItem } from './delete-claim.js';
import { requireOperator } from './grants.js';
import { checkSignal, contextSnapshot, nativeSignal, safeFailure, scopeSnapshot } from './input.js';

type Mode = 'ACTIVE' | 'FENCED';
interface LedgerContext extends DatabaseContext {
  readonly scope: LedgerScope; readonly ledger: FileLedger; readonly verifier: FileLedgerVerifier;
}
interface Work {
  readonly graph: LedgerGraph; readonly digest: string; readonly position?: LedgerPosition;
}
async function readCommittedWork(ctx: LedgerContext, intentId: string, mode: Mode): Promise<Work | undefined> {
  return await privacyTx(ctx.pool, async (client) => {
    const row = await lockDecision(client, ctx, intentId, mode);
    if (row === undefined || row.delete_event_id === null || row.hold_active || row.delete_state === 'OPEN' ||
      row.delete_state === 'CONFIRMED_ABSENT' || (mode === 'FENCED' && row.delete_state !== 'PENDING_LEDGER')) { return undefined; }
    const { rows } = await client.query<Parameters<typeof toLedgerItem>[0]>(`SELECT ${ITEM} FROM ${T.items}
      WHERE event_id=$1 AND intent_id=$2 ORDER BY attempt_kind,attempt_id LIMIT $3`,
    [row.delete_event_id, intentId, ctx.policy.maxItemsPerIntent + 1]);
    if (rows.length === 0 || rows.length > ctx.policy.maxItemsPerIntent || row.delete_writer_epoch === null) { return refusePrivacy('CONFLICT'); }
    const writerEpoch = BigInt(row.delete_writer_epoch);
    if (writerEpoch > ctx.scope.writerEpoch || (row.delete_state === 'PENDING_LEDGER' && writerEpoch !== ctx.scope.writerEpoch)) {
      return refusePrivacy('CONFLICT'); // A historical pending decision had to be drained before handoff.
    }
    const graph: LedgerGraph = { ...ctx.scope, writerEpoch, intentId, eventId: row.delete_event_id,
      accessEpoch: BigInt(row.access_epoch), items: rows.map(toLedgerItem) };
    const digest = ledgerGraphSha256(graph, ctx.policy.maxItemsPerIntent);
    if (digest !== row.delete_graph_sha256) { return refusePrivacy('CONFLICT'); }
    await requireFreshPolicy(client, ctx);
    if (row.delete_state === 'PENDING_LEDGER') { return { graph, digest }; }
    if (row.ledger_seq === null || row.ledger_hash === null) { return refusePrivacy('CONFLICT'); }
    return { graph, digest, position: { seq: BigInt(row.ledger_seq), hash: row.ledger_hash } };
  });
}

async function authorizeLedger(ctx: LedgerContext, work: Work, mode: Mode, signal: AbortSignal): Promise<LedgerMembership | undefined> {
  checkSignal(signal);
  const { graph, digest } = work;
  // No checked-out main DB connection here. A failed/ambiguous append authorizes nothing;
  // a later invocation retries this immutable event id and requires independent membership.
  const position = work.position ?? await ctx.ledger.append(graph);
  checkSignal(signal);
  const membership = await ctx.verifier.verifyMembership(graph, position.seq, ctx.scope);
  const facts = readLedgerMembership(membership);
  if (facts.namespace !== ctx.scope.namespace || facts.incarnation !== ctx.scope.incarnation ||
    facts.writerEpoch !== graph.writerEpoch || facts.head.writerEpoch !== ctx.scope.writerEpoch ||
    facts.seq !== position.seq || facts.hash !== position.hash || facts.eventId !== graph.eventId || facts.intentId !== graph.intentId ||
    facts.accessEpoch !== graph.accessEpoch || facts.graphSha256 !== digest) { return refusePrivacy('CONFLICT'); }
  checkSignal(signal);
  if (work.position !== undefined) { return membership; }
  // The local stamp is also a separate, acknowledged commit. Its loss does not mint a grant.
  const ack = await privacyTx(ctx.pool, async (client) => {
    const row = await lockDecision(client, ctx, graph.intentId, mode);
    if (!sameDecision(row, graph, digest)) { return false; }
    if (row.delete_state !== 'PENDING_LEDGER') { return row.ledger_seq === position.seq.toString() && row.ledger_hash === position.hash; }
    await privacyAudit(client, graph.intentId, graph.eventId, 'DELETE_LEDGERED');
    checkSignal(signal);
    const result = await client.query(`UPDATE ${T.controls} SET delete_state='LEDGERED',ledger_seq=$3,ledger_hash=$4
      WHERE intent_id=$1 AND delete_event_id=$2 AND delete_state='PENDING_LEDGER' AND access_epoch=$5
        AND clock_timestamp() < $6::timestamptz`,
    [graph.intentId, graph.eventId, position.seq.toString(), position.hash, graph.accessEpoch.toString(), ctx.policy.expiresAt]);
    if (result.rowCount !== 1) { return refusePrivacy('NOT_CONFIGURED'); }
    await requireFreshPolicy(client, ctx);
    return true;
  });
  return ack ? membership : undefined;
}

async function dueWork(ctx: LedgerContext, mode: Mode, broker: DeleteContext['broker'] | undefined): Promise<readonly { intent_id: string }[]> {
  return await privacyTx(ctx.pool, async (client) => {
    await lockPrivacyRuntime(client, ctx, mode);
    // An unacknowledged decision must reach the ledger even when this broker cannot touch its keys.
    // Afterwards, select only groups with an available exact tuple BEFORE the batch cap. No scan in JS.
    const schedule = broker === undefined ? '[]' : brokerSchedule(broker);
    const { rows } = await client.query<{ intent_id: string }>(`WITH allowed AS MATERIALIZED (
        SELECT * FROM jsonb_to_recordset($2::jsonb) AS x(endpoint text,bucket text,region text,intent uuid,kind text,attempt uuid,key text)
      ) SELECT c.intent_id FROM ${T.controls} c LEFT JOIN LATERAL (
        SELECT min(a.claim_generation) AS generation FROM ${T.items} a
        WHERE c.delete_state IN ('LEDGERED','VERIFY_PENDING') AND a.event_id=c.delete_event_id AND a.intent_id=c.intent_id
          AND (a.state IN ('AUTHORIZED','VERIFY_PENDING') OR (a.state='DELETE_ATTEMPTED' AND a.claim_expires_at <= clock_timestamp()))
          AND EXISTS (SELECT 1 FROM allowed x WHERE
            (a.target_endpoint,a.target_bucket,a.target_region)=(x.endpoint,x.bucket,x.region)
            AND (($4::boolean AND a.write_proof='VERIFIED_SETTLED'
                  AND (a.intent_id,a.attempt_kind,a.attempt_id,a.object_key)=(x.intent,x.kind,x.attempt,x.key))
              OR (NOT $4::boolean AND x.intent IS NULL)))
      ) eligible ON true
      WHERE c.delete_state='PENDING_LEDGER' OR eligible.generation IS NOT NULL
      ORDER BY (c.delete_writer_epoch = $3::bigint) DESC,
        CASE c.delete_state WHEN 'PENDING_LEDGER' THEN 0 WHEN 'LEDGERED' THEN 1 ELSE 2 END,
        eligible.generation,c.delete_at,c.intent_id LIMIT $1`,
    [ctx.policy.maxBatch, schedule, ctx.scope.writerEpoch.toString(), ctx.database !== undefined]);
    await requireFreshPolicy(client, ctx);
    return rows;
  });
}
function readContext(input: FencedDrainContext | DeleteContext, mode: Mode): LedgerContext & { readonly broker?: DeleteContext['broker'] } {
  const ctx = contextSnapshot(input, ['grant','scope','ledger','verifier', ...(mode === 'ACTIVE' ? ['broker'] : [])]);
  requireOperator(ctx.fields['grant'], ctx.epoch.namespace, mode === 'ACTIVE' ? 'DELETE' : 'SOURCE_DRAIN');
  const scope = scopeSnapshot(ctx.fields['scope'], ctx.epoch);
  // The two infrastructure ports are trusted capabilities. They are never accepted in command/grant DTOs.
  const ledger = ctx.fields['ledger'] as FileLedger;
  const verifier = ctx.fields['verifier'] as FileLedgerVerifier;
  const trusted = { pool: ctx.pool, epoch: ctx.epoch, policy: ctx.policy, scope, ledger, verifier };
  if (mode !== 'ACTIVE') { return trusted; }
  const broker = requireDeleteBroker(ctx.fields['broker'], ctx.epoch.namespace, ctx.epoch.epoch);
  const database = brokerDatabase(broker);
  return database === undefined ? { ...trusted, broker } : { ...trusted, broker, database };
}
async function run(input: FencedDrainContext | DeleteContext, abort: AbortSignal, mode: Mode): Promise<AggregateOnly> {
  const ctx = readContext(input, mode);
  const signal = nativeSignal(abort);
  checkSignal(signal);
  try {
    const jobs = await dueWork(ctx, mode, ctx.broker);
    let advanced = 0;
    for (const { intent_id: intentId } of jobs) {
      checkSignal(signal);
      const work = await readCommittedWork(ctx, intentId, mode);
      if (work === undefined) { continue; }
      const membership = await authorizeLedger(ctx, work, mode, signal);
      if (membership === undefined) { continue; }
      const broker = ctx.broker;
      if (broker === undefined) { advanced++; continue; }
      const claimed = await claimExactItem(ctx, broker, signal, work.graph, membership,
        (item) => hasDeleteTarget(broker, work.graph.intentId, item));
      if (claimed === undefined) { if (work.position === undefined) { advanced++; } continue; }
      const result = await executeCommittedDelete(broker, claimed.grant, signal);
      await finishExactItem(ctx, work.graph, work.digest, claimed.claim, result);
      advanced++;
    }
    return { examined: jobs.length, advanced, deferred: jobs.length - advanced };
  } catch (error: unknown) {
    return safeFailure(error);
  }
}

export async function reconcileFileDeletion(ctx: DeleteContext, signal: AbortSignal): Promise<AggregateOnly> {
  return await run(ctx, signal, 'ACTIVE');
}
/** Ledger-only writer drain on the matching FENCED source. Cannot claim or reach object storage. */
export async function drainFencedFileDecisions(ctx: FencedDrainContext, signal: AbortSignal): Promise<AggregateOnly> {
  return await run(ctx, signal, 'FENCED');
}
