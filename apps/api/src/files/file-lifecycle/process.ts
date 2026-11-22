import { randomUUID } from 'node:crypto';
import { isLifecycleStorageOperationSettled } from '../storage/errors.js';
import type { QuarantineReceipt } from '../storage/index.js';
import { issueRawGetGrant } from '../storage/lifecycle-proof.js';
import { deadline, signalAborted } from '../upload-coordinator/input.js';
import type { ContentDigest, FFile, ProcessingContext, ProcessQuarantineReceipt, WorkerResult } from './contract.js';
import { isLifecycleError, refuseLifecycle } from './errors.js';
import { parseFileCommand, snapshotProcessingContext } from './input.js';
import { assertCurrentEvidence, copyAndCheckBytes, prepareSanitized, snapshotClean } from './processing-evidence.js';
import { admitProcessing, authorizeVerify, authorizeWorker, checkLocalLifetime, dispatchSanitized, publishVerified, registerSanitized,
  replayFinalPublication, settleProcessing } from './processing-registry.js';
import type { ProcessCommand, ProcessingClaim, SanitizedRow } from './processing-registry.js';
import { isLifecycleCommitUnknown, withLifecycleTransaction } from './transaction.js';

function assertReceipt(receipt: QuarantineReceipt, row: SanitizedRow, digest: ContentDigest): void {
  // Storage result, not an authorization or policy verdict. Never echo it.
  try {
    if (receipt.attemptId !== row.id || receipt.objectKey !== row.object_key
      || receipt.actualBytes !== digest.bytes || receipt.sha256 !== digest.sha256) {
      refuseLifecycle('WRITE_OUTCOME_UNKNOWN');
    }
  } catch {
    refuseLifecycle('WRITE_OUTCOME_UNKNOWN');
  }
}

function rawGrant(ctx: ProcessingContext, claim: ProcessingClaim) {
  try {
    const raw = claim.raw;
    return issueRawGetGrant({ intentId: claim.intentId, quarantineId: raw.id, attemptId: raw.attempt_id, objectKey: raw.object_key,
      target: { endpoint: raw.storage_endpoint, bucket: raw.storage_bucket, region: raw.storage_region },
      expectedBytes: claim.digest.bytes, expectedSha256: claim.digest.sha256,
      namespaceId: ctx.epoch.namespace, runtimeEpoch: ctx.epoch.epoch, accessEpoch: BigInt(claim.accessEpoch),
      claimId: claim.id, claimGeneration: claim.generation });
  } catch {
    return refuseLifecycle('CONFLICT');
  }
}

// eslint-disable-next-line @typescript-eslint/require-await -- bounded async-iterable storage port needs no work between copies
async function* boundedOutput(bytes: Uint8Array, chunk: number, command: ProcessCommand, wallUntil: number,
  claim: ProcessingClaim,
): AsyncGenerator<Uint8Array> {
  for (let offset = 0; offset < bytes.byteLength; offset += chunk) {
    checkLocalLifetime(command, wallUntil, claim);
    // Adapter is trusted and independently validates size/hash; send only bounded copies.
    yield bytes.slice(offset, offset + chunk);
  }
}

/** Internal F command; never returns READY metadata. No transaction spans storage or worker waits. */
export async function processQuarantine(context: ProcessingContext,
  input: FFile & { readonly signal: AbortSignal },
): Promise<ProcessQuarantineReceipt> {
  const command = parseFileCommand(input, true);
  const ctx = snapshotProcessingContext(context);
  const wallUntil = performance.now() + ctx.policy.wallMs;
  const captured: { claim?: ProcessingClaim } = {};
  let attemptId: string | undefined;
  let locallySettled = true;
  let writePossible = false;
  let stop: (() => void) | undefined;
  try {
    checkLocalLifetime(command, wallUntil);
    const admission = await withLifecycleTransaction(ctx.pool, async (client) => {
      const result = await admitProcessing(client, ctx, command, wallUntil);
      if (result.kind === 'claimed') {
        captured.claim = result.claim;
      }
      return result;
    });
    if (admission.kind === 'existing') {
      checkLocalLifetime(command, wallUntil);
      return admission.receipt;
    }
    const claim = admission.claim;
    checkLocalLifetime(command, wallUntil, claim);
    const remaining = Math.floor(Math.min(claim.until, wallUntil) - performance.now());
    if (remaining < 1) {
      refuseLifecycle('STALE_CLAIM');
    }
    const operation = deadline(command.signal, remaining);
    stop = operation.close;
    const call = { session: command.session, intentId: command.intentId, signal: operation.signal };
    const proof = rawGrant(ctx, claim);
    checkLocalLifetime(call, wallUntil, claim);
    let raw: Uint8Array;
    try {
      locallySettled = false;
      raw = await ctx.storage.fetchRawBytes(proof, { maxBytes: claim.digest.bytes, signal: call.signal });
      locallySettled = true;
    } catch (error) {
      locallySettled = isLifecycleStorageOperationSettled(error);
      return refuseLifecycle(signalAborted(call.signal) ? 'ABORTED' : 'PROCESSING_DENIED');
    }
    const workerInput = copyAndCheckBytes(raw, claim.digest, claim.mime);
    // Before calling the first scan, freshly reauthorize after the raw GET wait.
    await withLifecycleTransaction(ctx.pool, (client) => authorizeWorker(client, ctx, call, claim, wallUntil));
    checkLocalLifetime(call, wallUntil, claim);
    let result: WorkerResult;
    try {
      locallySettled = false;
      result = await ctx.processor.process({ mime: claim.mime, bytes: workerInput, raw: claim.digest,
        policy: Object.freeze({ ...ctx.policy, expiresAt: new Date(ctx.policy.expiresAt.getTime()) }) }, call.signal);
      // The trusted orchestration contract resolves only after actual local exit.
      locallySettled = true;
    } catch {
      return refuseLifecycle(signalAborted(call.signal) ? 'ABORTED' : 'PROCESSING_DENIED');
    }
    const clean = snapshotClean(result, claim.digest, claim.mime, ctx.policy);
    const prepared = prepareSanitized(ctx);
    attemptId = prepared.id;
    const row = await withLifecycleTransaction(ctx.pool,
      (client) => registerSanitized(client, ctx, call, claim, prepared, clean, wallUntil));
    try {
      await withLifecycleTransaction(ctx.pool, (client) => dispatchSanitized(client, ctx, call, claim, row, clean, wallUntil));
    } catch (error) {
      // No PUT after uncertain dispatch. If the marker committed, it remains
      // pessimistic UNKNOWN until proven terminal by private technical accounting.
      writePossible = isLifecycleCommitUnknown(error);
      throw error;
    }
    writePossible = true;
    checkLocalLifetime(call, wallUntil, claim);
    const putInput = { body: boundedOutput(clean.output, prepared.maxChunkBytes, call, wallUntil, claim),
      expectedBytes: clean.served.bytes, maxBytes: clean.served.bytes, signal: call.signal };
    try {
      locallySettled = false;
      const wrote = await ctx.storage.putSanitized(prepared.descriptor, putInput);
      locallySettled = true;
      assertReceipt(wrote, row, clean.served);
    } catch (error) {
      locallySettled ||= isLifecycleStorageOperationSettled(error);
      return refuseLifecycle('WRITE_OUTCOME_UNKNOWN');
    }
    // Do not issue the independent GET under authorization cached before the PUT.
    await withLifecycleTransaction(ctx.pool, (client) => authorizeVerify(client, ctx, call, claim, row, clean, wallUntil));
    checkLocalLifetime(call, wallUntil, claim);
    try {
      locallySettled = false;
      const verified = await ctx.storage.verifySanitized(prepared.descriptor, { expectedBytes: clean.served.bytes,
        maxBytes: clean.served.bytes, sha256: clean.served.sha256, signal: call.signal });
      locallySettled = true;
      assertReceipt(verified, row, clean.served);
    } catch (error) {
      locallySettled ||= isLifecycleStorageOperationSettled(error);
      return refuseLifecycle('WRITE_OUTCOME_UNKNOWN');
    }
    const publicationId = randomUUID();
    let receipt: ProcessQuarantineReceipt;
    try {
      const published = await withLifecycleTransaction(ctx.pool,
        (client) => publishVerified(client, ctx, call, claim, row, clean, wallUntil, publicationId),
        ({ dbNow }) => {
          // No await between this process-local epoch check and sending COMMIT.
          checkLocalLifetime(call, wallUntil, claim);
          assertCurrentEvidence(ctx, clean, dbNow);
        });
      receipt = published.receipt;
    } catch (error) {
      if (!isLifecycleCommitUnknown(error)) {
        throw error;
      }
      // Read the exact committed publication once, under fresh authority; never
      // attempt another publish or send object bytes on an uncertain acknowledgement.
      receipt = await withLifecycleTransaction(ctx.pool,
        (client) => replayFinalPublication(client, ctx, command, claim, row, publicationId, wallUntil));
    }
    delete captured.claim;
    checkLocalLifetime(command, wallUntil);
    return receipt;
  } catch (error) {
    if (isLifecycleError(error)) {
      throw error;
    }
    return refuseLifecycle(writePossible ? 'WRITE_OUTCOME_UNKNOWN' : 'CONFLICT');
  } finally {
    stop?.();
    if (captured.claim !== undefined) {
      const claim = captured.claim;
      try {
        await withLifecycleTransaction(ctx.pool, (client) => settleProcessing(client, ctx, claim, attemptId, locallySettled));
      } catch {
        // The durable reservation remains conservative. No claim is released
        // based on expiry, an unproved transport exit or an ambiguous DB result.
      }
    }
  }
}
