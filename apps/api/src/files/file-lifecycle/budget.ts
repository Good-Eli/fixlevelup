import type { PoolClient } from 'pg';
import type { UploadOperationalPolicy } from '../upload-coordinator/contract.js';
import { ownerBudgetSql } from '../upload-coordinator/accounting.js';
import { refuseLifecycle } from './errors.js';

export const RAW_ATTEMPTS = 'foundation.file_upload_attempts';
export const SANITIZED_ATTEMPTS = 'foundation.file_sanitized_attempts';

/** The caller holds the request-session owner lock. None of these debts vanish on lease expiry or when changing targets. */
export async function ownerBudget(client: PoolClient, owner: string): Promise<{ attempts: bigint; bytes: bigint; slots: bigint }> {
  const { rows: [row] } = await client.query<{ attempts: string; bytes: string; slots: string }>(ownerBudgetSql('$1'), [owner]);
  if (row === undefined) {
    refuseLifecycle('CONFLICT');
  }
  return { attempts: BigInt(row.attempts), bytes: BigInt(row.bytes), slots: BigInt(row.slots) };
}

/** Slot delta is zero when a claimed processing job becomes its own registered write. */
export async function checkOwnerWriteBudget(client: PoolClient, owner: string, policy: UploadOperationalPolicy,
  add: { readonly bytes?: bigint; readonly slots?: 0n | 1n } = {},
): Promise<void> {
  const { attempts, bytes, slots } = await ownerBudget(client, owner);
  if (attempts + (add.bytes === undefined ? 0n : 1n) > BigInt(policy.maxAttemptsPerOwner)) {
    refuseLifecycle('ATTEMPT_BUDGET_EXCEEDED');
  }
  if (bytes + (add.bytes ?? 0n) > BigInt(policy.maxPhysicalBytesPerOwner)) {
    refuseLifecycle('PHYSICAL_BUDGET_EXCEEDED');
  }
  if (slots + (add.slots ?? 0n) > BigInt(policy.maxLiveOperationsPerOwner)) {
    refuseLifecycle('LIVE_OPERATION_LIMIT');
  }
}

export async function requireOwnerReadCapacity(client: PoolClient, owner: string, maximum: number): Promise<void> {
  if ((await ownerBudget(client, owner)).slots >= BigInt(maximum)) {
    refuseLifecycle('LIVE_OPERATION_LIMIT');
  }
}
