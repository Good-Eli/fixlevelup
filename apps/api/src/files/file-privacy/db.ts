import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { assertCallerTransaction, beginLegalTransaction } from '../../settings/legal/index.js';
import { lockLegacyTechnicalFile, lockOrCreateControl, lockTechnicalFile } from '../file-lifecycle/authorization.js';
import { refusePrivacy } from './contract.js';
import type { DatabaseContext, PrivacyContext } from './contract.js';
import { safeFailure } from './input.js';

export const T = {
  runtimes: 'foundation.file_runtime_epochs', intents: 'foundation.file_upload_intents',
  controls: 'foundation.file_privacy_controls', raw: 'foundation.file_upload_attempts',
  binding: 'foundation.file_quarantine_objects', sanitized: 'foundation.file_sanitized_attempts',
  pubs: 'foundation.file_publications', items: 'foundation.file_delete_items',
} as const;
export const CONTROL = `row_version::text,access_epoch::text,hold_active,delete_state,delete_event_id,
  delete_policy_id,delete_graph_sha256,delete_writer_epoch::text,ledger_seq::text,ledger_hash`;
export type State = 'OPEN' | 'PENDING_LEDGER' | 'LEDGERED' | 'VERIFY_PENDING' | 'CONFIRMED_ABSENT';
export interface Decision {
  readonly row_version: string;
  readonly access_epoch: string;
  readonly hold_active: boolean;
  readonly delete_state: State;
  readonly delete_event_id: string | null;
  readonly delete_policy_id: string | null;
  readonly delete_graph_sha256: string | null;
  readonly delete_writer_epoch: string | null;
  readonly ledger_seq: string | null;
  readonly ledger_hash: string | null;
}

export async function privacyTx<TValue>(pool: Pool, run: (client: PoolClient) => Promise<TValue>): Promise<TValue> {
  let client: PoolClient;
  try { client = await pool.connect(); } catch { return refusePrivacy('CONFLICT'); }
  let committing = false;
  let discard = true;
  try {
    await beginLegalTransaction(client);
    await assertCallerTransaction(client);
    const value = await run(client);
    committing = true;
    if ((await client.query('COMMIT')).command !== 'COMMIT') { return refusePrivacy('CONFLICT'); }
    discard = false;
    return value;
  } catch (error: unknown) {
    if (!committing) {
      try { await client.query('ROLLBACK'); discard = false; } catch { /* Discard failed connection. */ }
    }
    return safeFailure(error);
  } finally {
    try { client.release(discard); } catch { /* Never return a pool error or raw diagnostics. */ }
  }
}

export async function lockPrivacyRuntime(client: PoolClient, ctx: DatabaseContext, mode: 'ACTIVE' | 'FENCED'): Promise<void> {
  const { rowCount } = await client.query(`SELECT singleton FROM ${T.runtimes}
    WHERE singleton AND namespace_id=$1 AND epoch=$2 AND mode=$3 AND ($4::text IS NULL OR current_database()=$4) FOR SHARE`,
  [ctx.epoch.namespace, ctx.epoch.epoch.toString(), mode, ctx.database ?? null]);
  if (rowCount !== 1) { refusePrivacy('NOT_CONFIGURED'); }
}

export async function lockDecision(client: PoolClient, ctx: DatabaseContext, intentId: string,
  mode: 'ACTIVE' | 'FENCED', create = false,
): Promise<Decision | undefined> {
  await lockPrivacyRuntime(client, ctx, mode);
  const locked = mode === 'ACTIVE' ? await lockLegacyTechnicalFile(client, intentId, ctx.epoch)
    : await lockTechnicalFile(client, intentId, ctx.epoch);
  if (locked === undefined) { return undefined; }
  if (locked.control === undefined && create) { await lockOrCreateControl(client, intentId, undefined); }
  const { rows: [decision] } = await client.query<Decision>(`SELECT ${CONTROL} FROM ${T.controls} WHERE intent_id=$1`, [intentId]);
  return decision;
}

export async function requireFreshPolicy(client: PoolClient, ctx: PrivacyContext): Promise<void> {
  const { rows: [clock] } = await client.query<{ live: boolean }>('SELECT clock_timestamp() < $1::timestamptz AS live', [ctx.policy.expiresAt]);
  if (clock?.live !== true) { refusePrivacy('NOT_CONFIGURED'); }
}

const PHASES = {
  HOLD_PLACED: 'FILE_HOLD_PLACED', HOLD_RELEASED: 'FILE_HOLD_RELEASED', DELETE_DECIDED: 'FILE_DELETE_DECIDED',
  DELETE_LEDGERED: 'FILE_DELETE_LEDGERED', DELETE_CLAIMED: 'FILE_DELETE_CLAIMED',
  DELETE_VERIFY_PENDING: 'FILE_DELETE_VERIFY_PENDING', DELETE_ITEM_ABSENT: 'FILE_DELETE_ITEM_ABSENT',
} as const;
export async function privacyAudit(client: PoolClient, intentId: string, operationId: string, phase: keyof typeof PHASES): Promise<void> {
  const event = randomUUID();
  const payload = JSON.stringify({ intentId, operationId, phase });
  const operation = PHASES[phase];
  await client.query('INSERT INTO foundation.audit_logs (id,operation,correlation_id,details) VALUES ($1,$2,$3,$4::jsonb)',
    [randomUUID(), operation, event, payload]);
  await client.query('INSERT INTO foundation.outbox_events (id,event_id,event_type,payload) VALUES ($1,$2,$3,$4::jsonb)',
    [randomUUID(), event, operation, payload]);
}
