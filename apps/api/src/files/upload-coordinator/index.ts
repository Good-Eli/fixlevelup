import type { Pool } from 'pg';
import type { QuarantineReceipt, RegisteredQuarantineAttempt, RegisteredQuarantineStorage } from '../storage/index.js';
import { isUploadError, refuse } from './contract.js';
import type { UploadOperationalPolicy, UploadQuarantineReceipt, UploadReservedFileCommand, VerifiedContent } from './contract.js';
import { assertNotAborted, deadline, uploadCommand, uploadOperationalPolicy } from './input.js';
import { prepareUploadBody } from './prefix.js';
import {
  SHA256, authorizeUploadDispatch, finalizeUploadAttempt, leaseDeadline, recordAttemptOutcome,
  registerUploadAttempt, verifyFinalCommit, verifyRegistration,
} from './registry.js';
import type { Registration, UploadGrant } from './registry.js';
import { CommitUncertain, inUploadTransaction } from './transaction.js';

export { UploadCoordinatorError } from './contract.js';
export type {
  UploadCoordinatorErrorCode, UploadOperationalPolicy, UploadQuarantineReceipt, UploadReservedFileCommand,
} from './contract.js';

async function register(pool: Pool, prepared: RegisteredQuarantineAttempt, policy: UploadOperationalPolicy,
  command: UploadReservedFileCommand,
): Promise<{ readonly result: Registration; readonly until: number }> {
  // The in-memory origin retains its own immutable descriptor and exact row. A later
  // invocation knows only the command key and can never use this recovery branch.
  const captured: { result?: Registration } = {};
  try {
    return await inUploadTransaction(pool, async (client) => {
      const result = await registerUploadAttempt(client, command, policy, prepared.attempt, prepared.target);
      captured.result = result;
      const until = result.kind === 'new' ? await leaseDeadline(client, result.grant.row.id, 'upload') : 0;
      return { result, until };
    });
  } catch (error) {
    if (!(error instanceof CommitUncertain)) {
      throw error;
    }
    const result = captured.result;
    if (result === undefined || result.kind !== 'new') {
      refuse('CONFLICT');
    }
    return await inUploadTransaction(pool, async (client) => {
      await verifyRegistration(client, command, policy, result.grant);
      return { result, until: await leaseDeadline(client, result.grant.row.id, 'upload') };
    });
  }
}

function verifiedContent(receipt: QuarantineReceipt, grant: UploadGrant): VerifiedContent {
  const { actualBytes, sha256, attemptId, objectKey } = receipt;
  if (attemptId !== grant.row.id || objectKey !== grant.row.object_key || actualBytes !== grant.bytes || !SHA256.test(sha256)) {
    refuse('WRITE_OUTCOME_UNKNOWN');
  }
  return { actualBytes, sha256 };
}

function remaining(until: number, signal: AbortSignal): number {
  assertNotAborted(signal);
  const ms = Math.floor(until - performance.now());
  if (ms < 1) {
    refuse('STALE_ATTEMPT');
  }
  return ms;
}

/** The only F-facing coordinator port; no route or general metadata access. */
export async function uploadReservedFile(pool: Pool, storage: RegisteredQuarantineStorage,
  operationalPolicy: UploadOperationalPolicy, command: UploadReservedFileCommand,
): Promise<UploadQuarantineReceipt> {
  const policy = uploadOperationalPolicy(operationalPolicy);
  const parsed = uploadCommand(command);
  assertNotAborted(parsed.signal);
  let prepared: RegisteredQuarantineAttempt;
  try {
    prepared = storage.prepareRegisteredQuarantineAttempt();
    if (policy.maxSourceChunkBytes > prepared.maxChunkBytes) {
      refuse('NOT_CONFIGURED');
    }
  } catch {
    refuse('NOT_CONFIGURED');
  }

  let grant: UploadGrant | undefined;
  let stop: (() => void) | undefined;
  let closeSource: (() => void) | undefined;
  let phase: 'PRE_DISPATCH' | 'AFTER_DISPATCH' = 'PRE_DISPATCH';
  let verified: VerifiedContent | undefined;
  let attemptedPut = false;
  try {
    const { result, until } = await register(pool, prepared, policy, parsed);
    if (result.kind === 'existing') {
      assertNotAborted(parsed.signal);
      return result.receipt;
    }
    grant = result.grant;
    const registered = grant;
    const operation = deadline(parsed.signal, remaining(until, parsed.signal));
    stop = operation.close;
    const call = { ...parsed, signal: operation.signal };
    const source = await prepareUploadBody(parsed.body, operation.signal, grant.mime, grant.bytes, policy.maxSourceChunkBytes,
      Math.min(policy.prefixTimeoutMs, remaining(until, operation.signal)));
    closeSource = source.close;
    await inUploadTransaction(pool, (client) => authorizeUploadDispatch(client, call, policy, registered));
    phase = 'AFTER_DISPATCH';
    remaining(until, operation.signal);
    attemptedPut = true;
    const written = verifiedContent(await storage.putQuarantined(prepared.attempt, {
      body: source.body, expectedBytes: grant.bytes, maxBytes: grant.bytes, signal: operation.signal,
    }), grant);
    remaining(until, operation.signal);
    const read = verifiedContent(await storage.verifyQuarantined(prepared.attempt, {
      expectedBytes: grant.bytes, maxBytes: grant.bytes, sha256: written.sha256, signal: operation.signal,
    }), grant);
    if (read.sha256 !== written.sha256) {
      refuse('WRITE_OUTCOME_UNKNOWN');
    }
    verified = read;
    remaining(until, operation.signal);
    let receipt: UploadQuarantineReceipt;
    try {
      receipt = await inUploadTransaction(pool, (client) => finalizeUploadAttempt(client, call, policy, registered, read));
    } catch (error) {
      if (!(error instanceof CommitUncertain)) {
        throw error;
      }
      // Replaying a committed binding is a new authorization decision, not a new
      // attempt. This is a read: it does not need the old lease to remain live.
      receipt = await inUploadTransaction(pool, (client) => verifyFinalCommit(client, parsed, policy, registered));
    }
    // If the caller aborted while COMMIT was already travelling, do not return a
    // receipt. A committed binding is still durable and only an authorized replay
    // can recover it; do not claim the database rolled it back.
    assertNotAborted(parsed.signal);
    return receipt;
  } catch (error) {
    // Stop source work before entering a cleanup transaction. The attempt continues
    // to be charged if cleanup cannot reach a trusted conclusive state.
    stop?.();
    closeSource?.();
    stop = undefined;
    closeSource = undefined;
    if (grant !== undefined) {
      const captured = grant;
      try {
        await inUploadTransaction(pool, (client) => recordAttemptOutcome(client, captured, phase, verified));
      } catch {
        // The earlier durable marker remains the conservative recovery source.
      }
    }
    if (isUploadError(error)) {
      throw error;
    }
    if (attemptedPut || error instanceof CommitUncertain) {
      refuse('WRITE_OUTCOME_UNKNOWN');
    }
    return refuse('CONFLICT');
  } finally {
    stop?.();
    closeSource?.();
  }
}
