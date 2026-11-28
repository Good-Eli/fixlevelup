import { createHash, randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { KeyringConfig } from '../crypto/keyring.js';
import { idempotencyHmac, verifyIdempotencyHmac } from '../crypto/payload-cipher.js';
import { canonicalJson } from '../../infrastructure/admission/proof.js';
import { REQUEST_PHONE_HISTORY_COMPLETE } from '../../infrastructure/database/request-phone-history.js';
import type { CommandName, RequestStatus } from '../workflow/registry.js';
import type { RequestRow } from './store.js';
import { deny } from './errors.js';

export interface Actor { readonly kind: 'F' | 'STAFF'; readonly id: string }
export interface CommandIdentity { readonly actor: Actor; readonly command: CommandName; readonly key: string;
  readonly target: string | null; readonly match: string | null; readonly body: unknown }
export interface EffectReceipt { readonly eventId: string; readonly requestId: string; readonly version: number;
  readonly status: RequestStatus; readonly publicNumber: string; readonly applied: true }
interface Event { readonly id: string; readonly request_id: string }

const principal = (actor: Actor) => `${actor.kind}:${actor.id}`;
export const eventTypeOf = (command: CommandName) => command === 'CreateCallback' ? 'REQUEST_CALLBACK_INTENT'
  : command === 'ReadyForDispatch' ? 'REQUEST_READY_FOR_ASSIGNMENT' : 'REQUEST_EFFECT_RECORDED';

function intentOf(cmd: CommandIdentity): string {
  return canonicalJson({ operation: cmd.command, key: cmd.key, target: cmd.target, ifMatch: cmd.match, body: cmd.body });
}

export async function lockStaffCommandKey(client: PoolClient, actor: Actor, operation: CommandName | 'CreateManualRequest', key: string): Promise<void> {
  await client.query(`SELECT pg_catalog.pg_advisory_xact_lock(705024,hashtext($1))`,
    [canonicalJson([principal(actor),operation,key])]);
}

export async function findManualEvent(client: PoolClient, cmd: Pick<CommandIdentity,'actor'|'key'>): Promise<Event | undefined> {
  const { rows } = await client.query<Event>(`SELECT id,request_id FROM foundation.request_events
    WHERE principal=$1 AND operation IN ('CreateCallback','CreateRepair') AND idempotency_key=$2 LIMIT 2`,
  [principal(cmd.actor),cmd.key]);
  // A historical split-key double effect is an inconsistent state, never a replay.
  if (rows.length > 1) { return deny('NOT_READY'); }
  return rows[0];
}
export async function findEvent(client: PoolClient, cmd: Pick<CommandIdentity,'actor'|'command'|'key'>): Promise<Event | undefined> {
  const { rows: [row] } = await client.query<Event>(`SELECT id,request_id FROM foundation.request_events
    WHERE principal=$1 AND operation=$2 AND idempotency_key=$3`, [principal(cmd.actor),cmd.command,cmd.key]);
  return row;
}

interface PersistedReceipt {
  readonly event_id: string; readonly request_id: string; readonly version: number; readonly status: RequestStatus;
  readonly key_id: string; readonly fingerprint: Buffer; readonly command: CommandName; readonly key: string;
  readonly principal: string; readonly complete: boolean; readonly good_audit: boolean;
  readonly good_outbox: boolean; readonly good_phone: boolean; readonly public_number: string;
}

/** Independent predicates are intentionally projected as well as the combined gate:
 * they let the failure-injection proof damage one persisted edge at a time without
 * weakening the production decision. Requires aliases r/e/a/o. */
const REQUEST_RECEIPT_AUDIT_COMPLETE_SQL = `coalesce(
    a.operation=e.command AND a.correlation_id=e.correlation_id AND a.details->>'requestId'=e.request_id::text,
    false)`;
const REQUEST_RECEIPT_OUTBOX_COMPLETE_SQL = `coalesce(
    o.event_id=e.id AND o.event_type=CASE e.command WHEN 'CreateCallback' THEN 'REQUEST_CALLBACK_INTENT'
      WHEN 'ReadyForDispatch' THEN 'REQUEST_READY_FOR_ASSIGNMENT' ELSE 'REQUEST_EFFECT_RECORDED' END
    AND o.payload->>'requestId'=e.request_id::text AND o.payload->>'version'=e.resulting_version::text,
    false)`;
const REQUEST_RECEIPT_PHONE_COMPLETE_SQL = `coalesce(${REQUEST_PHONE_HISTORY_COMPLETE},false)`;
export const REQUEST_RECEIPT_COMPLETE_SQL = `(${REQUEST_RECEIPT_AUDIT_COMPLETE_SQL}
    AND ${REQUEST_RECEIPT_OUTBOX_COMPLETE_SQL} AND ${REQUEST_RECEIPT_PHONE_COMPLETE_SQL})`;

export async function checkedReceipt(client: PoolClient, request: RequestRow, eventId: string): Promise<PersistedReceipt> {
  const { rows: [row] } = await client.query<PersistedReceipt>(`SELECT r.event_id,r.request_id,r.version,r.resulting_status AS status,
    r.key_id,r.fingerprint,r.command,e.idempotency_key AS key,e.principal,q.public_number::text,
    ${REQUEST_RECEIPT_AUDIT_COMPLETE_SQL} AS good_audit,
    ${REQUEST_RECEIPT_OUTBOX_COMPLETE_SQL} AS good_outbox,
    ${REQUEST_RECEIPT_PHONE_COMPLETE_SQL} AS good_phone,
    ${REQUEST_RECEIPT_COMPLETE_SQL} AS complete
    FROM foundation.request_events e JOIN foundation.request_command_receipts r ON r.event_id=e.id AND r.request_id=e.request_id
      AND r.version=e.resulting_version AND r.correlation_id=e.correlation_id AND r.command=e.command AND r.resulting_status=e.details->>'status'
    JOIN foundation.requests q ON q.id=e.request_id
    LEFT JOIN foundation.audit_logs a ON a.id=r.audit_id LEFT JOIN foundation.outbox_events o ON o.id=r.outbox_id
    WHERE e.id=$1 AND e.request_id=$2`, [eventId,request.id]);
  if (!row || !row.complete || !row.good_audit || !row.good_outbox || !row.good_phone
    || row.version > request.row_version || !Buffer.isBuffer(row.fingerprint)
    || row.fingerprint.length !== 32) { return deny('NOT_READY'); }
  return row;
}

export function replayReceipt(ring: KeyringConfig, cmd: CommandIdentity, receipt: PersistedReceipt): EffectReceipt {
  if (receipt.principal !== principal(cmd.actor)) { return deny('NOT_READY'); }
  if (receipt.command !== cmd.command || receipt.key !== cmd.key) { return deny('FORM_ALREADY_SUBMITTED'); }
  let equal: boolean;
  try { equal = verifyIdempotencyHmac({ ring, keyId: receipt.key_id, namespace: principal(cmd.actor),
    canonicalIntent: intentOf(cmd), digest: receipt.fingerprint }); } catch { return deny('NOT_READY'); }
  if (!equal) { return deny('IDEMPOTENCY_KEY_REUSED'); }
  return { eventId: receipt.event_id, requestId: receipt.request_id, status: receipt.status, publicNumber: receipt.public_number,
    version: receipt.version, applied: true };
}

export async function writeEffect(client: PoolClient, ring: KeyringConfig, row: RequestRow, cmd: CommandIdentity, eventId: string,
  correlation: string, extra: Readonly<Record<string,string>> = {}): Promise<EffectReceipt> {
  const auditId = randomUUID();
  const outboxId = randomUUID();
  const { keyId, digest } = idempotencyHmac({ ring, namespace: principal(cmd.actor), canonicalIntent: intentOf(cmd) });
  const info = { requestId: row.id, status: row.status, version: row.row_version, ...extra };
  await client.query(`INSERT INTO foundation.request_events(id,request_id,command,principal,operation,idempotency_key,
    actor_type,actor_session_id,actor_staff_id,resulting_version,correlation_id,details)
    VALUES ($1,$2,$3,$4,$3,$5,$6,$7,$8,$9,$10,$11::jsonb)`, [eventId,row.id,cmd.command,principal(cmd.actor),cmd.key,
    cmd.actor.kind,cmd.actor.kind === 'F' ? cmd.actor.id : null,cmd.actor.kind === 'STAFF' ? cmd.actor.id : null,
    row.row_version,correlation,JSON.stringify(info)]);
  await client.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id,details) VALUES ($1,$2,$3,$4::jsonb)',
    [auditId,cmd.command,correlation,JSON.stringify({ ...info, actorId: cmd.actor.id, actorKind: cmd.actor.kind })]);
  await client.query('INSERT INTO foundation.outbox_events(id,event_id,event_type,payload) VALUES ($1,$2,$3,$4::jsonb)',
    [outboxId,eventId,eventTypeOf(cmd.command),JSON.stringify({ requestId: row.id, version: row.row_version })]);
  await client.query(`INSERT INTO foundation.request_command_receipts
    (event_id,request_id,version,correlation_id,command,key_id,fingerprint,resulting_status,audit_id,outbox_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [eventId,row.id,row.row_version,correlation,cmd.command,keyId,digest,row.status,auditId,outboxId]);
  return { eventId, requestId: row.id, status: row.status, publicNumber: row.public_number, version: row.row_version, applied: true };
}

export function requestRepresentation(actor: Actor['kind'], row: RequestRow, full: boolean) {
  const data = !full ? { version: row.row_version } : actor === 'F'
    ? { publicNumber: row.public_number, status: row.status, version: row.row_version }
    : { id: row.id, publicNumber: row.public_number, type: row.type, status: row.status, version: row.row_version };
  const bytes = Buffer.from(JSON.stringify({ data }), 'utf8');
  const hash = createHash('sha256');
  for (const value of [Buffer.from('p05-r1'), Buffer.from(actor), Buffer.from(row.id), bytes]) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(value.byteLength);
    hash.update(length).update(value);
  }
  return Object.freeze({ bytes, etag: `"p05-r1-${hash.digest('hex')}"` });
}
