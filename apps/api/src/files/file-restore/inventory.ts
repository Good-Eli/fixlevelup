import type { Pool } from 'pg';
import { ledgerGraphSha256 } from '../file-ledger/codec.js';
import type { FileLedgerVerifier, LedgerEvent, LedgerGraph, LedgerHead, LedgerItem, LedgerScope } from '../file-ledger/contract.js';
import { canonicalRegistryTarget } from '../storage/config.js';
import { refuseRestore } from './contract.js';
import type { RestoreKind, RestoreLimits, RestoreObject } from './contract.js';
import { inventoryJson, objectId, sha256, targetId } from './records.js';

type Query = Pick<Pool, 'query'>;
export const AUTHORITY_TABLES = Object.freeze([
  ['request_sessions', 'id'], ['legal_documents', 'id'], ['legal_document_versions', 'id'], ['consent_records', 'id'],
  ['file_upload_intents', 'id'], ['file_upload_attempts', 'id'], ['file_sanitized_attempts', 'id'], ['file_privacy_controls', 'intent_id'],
  ['file_delete_items', 'event_id,attempt_kind,attempt_id'], ['file_quarantine_objects', 'id'], ['file_publications', 'id'],
  ['audit_logs', 'id'], ['outbox_events', 'id'],
] as const);

/** Exact current rows, including microseconds, immutable evidence, current pointers and per-intent hold/cancel generations.
 * Only digests cross this connection boundary; no raw F proof is ever stored or exported. */
export async function readAuthorityInventory(pool: Query, limits: RestoreLimits): Promise<string> {
  const hashes: unknown[] = [];
  for (const [table, order] of AUTHORITY_TABLES) {
    const maxRows = Math.min(65_536, table === 'file_delete_items' ? limits.maxObjects : limits.maxIntents * 16);
    const { rows } = await pool.query<{ digest: string }>(`SELECT encode(sha256(convert_to(row_to_json(t)::text,'UTF8')),'hex') AS digest
      FROM foundation.${table} t ORDER BY ${order} LIMIT $1`, [maxRows + 1]);
    if (rows.length > maxRows) {refuseRestore('RESTORE_AUTHORITY');}
    hashes.push([table, rows.map(row => row.digest)]);
  }
  const { rows: [status] } = await pool.query<{ count: number; pending: boolean; held: boolean }>(`SELECT
    (SELECT count(*)::int FROM foundation.file_upload_intents) AS count,
    EXISTS(SELECT 1 FROM foundation.file_privacy_controls WHERE delete_state='PENDING_LEDGER') AS pending,
    EXISTS(SELECT 1 FROM foundation.file_privacy_controls WHERE processing_lease_id IS NOT NULL OR read_lease_id IS NOT NULL) AS held`);
  // A persisted old lease is not proof its holder's RAM/get/worker ever settled. No lease reset.
  if (status === undefined || status.count > limits.maxIntents || status.pending || status.held) {refuseRestore('RESTORE_AUTHORITY');}
  return sha256(JSON.stringify(hashes));
}

interface AttemptRow {
  kind: RestoreKind;
  id: string;
  intent_id: string;
  endpoint: string;
  bucket: string;
  region: string;
  object_key: string;
  state: string;
  size: string | null;
  sha: string | null;
  tombstoned: boolean;
}
export async function readRestoreInventory(pool: Query, limits: RestoreLimits): Promise<readonly RestoreObject[]> {
  const { rows } = await pool.query<AttemptRow>(`WITH attempts AS (
    SELECT 'RAW' AS kind,id,intent_id,storage_endpoint AS endpoint,storage_bucket AS bucket,storage_region AS region,
      object_key,state,verified_bytes::text AS size,verified_sha256 AS sha FROM foundation.file_upload_attempts
    UNION ALL
    SELECT 'SANITIZED',id,intent_id,storage_endpoint,storage_bucket,storage_region,object_key,state,
      verified_bytes::text,verified_sha256 FROM foundation.file_sanitized_attempts)
    SELECT a.*,coalesce(c.delete_state NOT IN ('OPEN','PENDING_LEDGER'),false) AS tombstoned
    FROM attempts a LEFT JOIN foundation.file_privacy_controls c USING (intent_id)
    ORDER BY a.kind COLLATE "C",a.id LIMIT $1`, [limits.maxObjects + 1]);
  if (rows.length > limits.maxObjects) {refuseRestore('RESTORE_INPUT');}
  let total = 0;
  return Object.freeze(rows.map(row => {
    const target = canonicalRegistryTarget(row.endpoint, row.bucket, row.region);
    if (target === undefined) {return refuseRestore('RESTORE_INPUT');}
    const disposition = row.tombstoned ? 'TOMBSTONED' : row.state === 'VERIFIED' ? 'COPY'
      : row.state === 'FAILED_NOBYTES' || row.state === 'REGISTERED' ? 'NEVER_DISPATCHED' : 'UNRESOLVED';
    const bytes = disposition === 'COPY' ? Number(row.size) : null;
    const digest = disposition === 'COPY' ? row.sha : null;
    if (bytes !== null) {
      total += bytes;
      if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > limits.maxObjectBytes || total > limits.maxTotalObjectBytes
        || digest === null || !/^[a-f0-9]{64}$/.test(digest)) {return refuseRestore('RESTORE_INPUT');}
    }
    return Object.freeze({ kind: row.kind, attemptId: row.id, intentId: row.intent_id, target,
      key: row.object_key, disposition, bytes, sha256: digest });
  }));
}

export function requireMatchingInventory(snapshot: readonly RestoreObject[], current: readonly RestoreObject[]): void {
  // Old COPY may be deliberately suppressed by a fresh tombstone, never by absence/reclassification.
  if (snapshot.length !== current.length) {refuseRestore('RESTORE_AUTHORITY');}
  const expected = snapshot.map((a, index) => current[index]?.disposition === 'TOMBSTONED'
    ? { ...a, disposition: 'TOMBSTONED' as const, bytes: null, sha256: null } : a);
  if (inventoryJson(expected) !== inventoryJson(current)) {refuseRestore('RESTORE_AUTHORITY');}
}

interface DecisionRow { intent_id: string; event_id: string; access_epoch: string; ledger_seq: string; ledger_hash: string; graph_sha: string; writer_epoch: string }
interface DeleteItemRow { event_id: string; intent_id: string; attempt_kind: RestoreKind; attempt_id: string;
  target_endpoint: string; target_bucket: string; target_region: string; object_key: string; write_proof: LedgerItem['writeProof'] }
export async function requireExactTombstones(pool: Query, limits: RestoreLimits, verifier: FileLedgerVerifier, oldScope: LedgerScope,
  base: LedgerHead, head: LedgerHead, events: readonly LedgerEvent[], inventory: readonly RestoreObject[]): Promise<void> {
  const { rows: decisions } = await pool.query<DecisionRow>(`SELECT intent_id,delete_event_id AS event_id,access_epoch::text,
    ledger_seq::text,ledger_hash,delete_graph_sha256 AS graph_sha,delete_writer_epoch::text AS writer_epoch FROM foundation.file_privacy_controls
    WHERE delete_state IN ('LEDGERED','VERIFY_PENDING','CONFIRMED_ABSENT') ORDER BY intent_id LIMIT $1`, [limits.maxIntents + 1]);
  const { rows: items } = await pool.query<DeleteItemRow>(`SELECT event_id,intent_id,attempt_kind,attempt_id,target_endpoint,target_bucket,
    target_region,object_key,write_proof FROM foundation.file_delete_items ORDER BY event_id,attempt_kind,attempt_id LIMIT $1`, [limits.maxObjects + 1]);
  if (decisions.length > limits.maxIntents || items.length > limits.maxObjects) {refuseRestore('RESTORE_LEDGER');}
  const local = new Map(decisions.map(row => [row.intent_id, row]));
  const verified = new Map(events.map(event => [event.graph.intentId, event]));
  // Every post-snapshot ledger entry must exist in the current handoff; no filtering unknown intents/events.
  if (verified.size !== events.length || events.some(event => !local.has(event.graph.intentId))) {refuseRestore('RESTORE_LEDGER');}
  const itemsByEvent = new Map<string, DeleteItemRow[]>();
  for (const item of items) {
    if (local.get(item.intent_id)?.event_id !== item.event_id) {refuseRestore('RESTORE_LEDGER');}
    const group = itemsByEvent.get(item.event_id) ?? [];
    group.push(item);
    itemsByEvent.set(item.event_id, group);
  }
  const grouped = new Map<string, RestoreObject[]>();
  for (const entry of inventory) {
    if ((entry.disposition === 'TOMBSTONED') !== local.has(entry.intentId)) {refuseRestore('RESTORE_LEDGER');}
    const group = grouped.get(entry.intentId) ?? [];
    group.push(entry);
    grouped.set(entry.intentId, group);
  }
  for (const decision of decisions) {
    const event = verified.get(decision.intent_id);
    const seq = BigInt(decision.ledger_seq);
    if (seq > head.seq || (seq > base.seq && event === undefined) || (event !== undefined && (event.seq !== seq || event.hash !== decision.ledger_hash))) {
      refuseRestore('RESTORE_LEDGER');
    }
    const entries = grouped.get(decision.intent_id) ?? [];
    const graphItems = itemsByEvent.get(decision.event_id) ?? [];
    if (entries.length !== graphItems.length) {refuseRestore('RESTORE_LEDGER');}
    const byId = new Map(entries.map(o => [objectId(o), o]));
    const graph: LedgerGraph = { ...oldScope, writerEpoch: BigInt(decision.writer_epoch),
      eventId: decision.event_id, intentId: decision.intent_id, accessEpoch: BigInt(decision.access_epoch), items: graphItems.map(item => {
        const entry = byId.get(`${item.attempt_kind}/${item.attempt_id}`);
        const target = canonicalRegistryTarget(item.target_endpoint, item.target_bucket, item.target_region);
        if (entry === undefined || target === undefined || entry.key !== item.object_key || targetId(entry.target) !== targetId(target)) {return refuseRestore('RESTORE_LEDGER');}
        return { kind: item.attempt_kind, attemptId: item.attempt_id, objectKey: item.object_key, target, writeProof: item.write_proof };
      }) };
    const hash = ledgerGraphSha256(graph, Math.min(limits.maxObjects, 2048));
    if (hash !== decision.graph_sha || (event !== undefined && hash !== ledgerGraphSha256(event.graph, Math.min(limits.maxObjects, 2048)))) {
      refuseRestore('RESTORE_LEDGER');
    }
    if (event === undefined) {
      const { namespace, incarnation, writerEpoch } = head;
      await verifier.verifyMembership(graph, seq, { namespace, incarnation, writerEpoch });
    }
  }
}