import { createHash } from 'node:crypto';
import { types } from 'node:util';
import type { AccessContext, FFile, ReadyFileView } from '../file-lifecycle/contract.js';
import { isLifecycleError, lifecycleError, refuseLifecycle } from '../file-lifecycle/errors.js';
import { toReadyFileView } from '../file-lifecycle/publication.js';
import { isLifecycleCommitUnknown, withLifecycleTransaction } from '../file-lifecycle/transaction.js';
import { isLifecycleStorageOperationSettled } from '../storage/errors.js';
import { issueReadyGetGrant } from '../storage/lifecycle-proof.js';
import type { ReadReservation } from './budget.js';
import { readCommand, readContext } from './input.js';
import type { ReadContext } from './input.js';
import { admitRead, assertReadSignal, authorizeMetadata, claimRead, releaseReadClaim } from './registry.js';
import type { ReadAuthority, ReadClaim } from './registry.js';

declare const ticketBrand: unique symbol;
export type ReadyReadTicket = { readonly [ticketBrand]: true };
export type ReadyReadResult = { readonly kind: 'CHUNK'; readonly bytes: Uint8Array } | { readonly kind: 'EOF' };

interface LiveRead {
  readonly ctx: ReadAuthority;
  readonly cmd: FFile;
  readonly claim: ReadClaim;
  readonly reservation: ReadReservation;
  readonly controller: AbortController;
  readonly signal: AbortSignal;
  bytes: Uint8Array | undefined;
  cursor: number;
}
interface TicketState {
  live?: LiveRead | undefined;
  pull?: Promise<ReadyReadResult> | undefined;
  closing?: Promise<void>;
  onAbort?: (() => void) | undefined;
}

// WeakMap membership, not any property on the object, is the runtime ticket brand.
const tickets = new WeakMap<object, TicketState>();

function ticketState(ticket: unknown): TicketState {
  const state = typeof ticket === 'object' && ticket !== null ? tickets.get(ticket) : undefined;
  if (state === undefined) {
    refuseLifecycle('TICKET_CLOSED');
  }
  return state;
}

function issueReadTicket(live: LiveRead): ReadyReadTicket {
  const ticket = Object.freeze(Object.create(null) as ReadyReadTicket);
  const state: TicketState = { live };
  // Once caller cancellation is observed, even an idle ticket can be locally
  // settled. Mere expiry does not trigger automatic takeover or debt clearing.
  const onAbort = (): void => { void requestClose(state).catch(() => undefined); };
  state.onAbort = onAbort;
  live.signal.addEventListener('abort', onAbort, { once: true });
  tickets.set(ticket, state);
  return ticket;
}

export async function readReadyMetadata(ctx: AccessContext, cmd: FFile): Promise<ReadyFileView> {
  const snapshot = readContext(ctx);
  const command = readCommand(cmd);
  try {
    return await withLifecycleTransaction(snapshot.pool, (client) => authorizeMetadata(client, snapshot, command));
  } catch (error) {
    if (isLifecycleError(error)) {
      throw error;
    }
    refuseLifecycle('CONFLICT');
  }
}

function assertDeadline(claim: ReadClaim): void {
  if (performance.now() >= claim.deadline) {
    refuseLifecycle('STALE_CLAIM');
  }
}

interface GetState { settled: boolean }

/** Only this opening can establish whether it is safe to retire its slot/claim. */
async function getPrivateBytes(ctx: ReadContext, claim: ReadClaim, lifeSignal: AbortSignal, io: GetState): Promise<Uint8Array> {
  const publication = claim.publication;
  const expectedBytes = toReadyFileView(publication).bytes;
  const getGrant = issueReadyGetGrant({
    intentId: publication.intent_id, quarantineId: publication.quarantine_id,
    publicationId: publication.id, attemptId: publication.sanitized_attempt_id, objectKey: publication.object_key,
    target: { endpoint: publication.storage_endpoint, bucket: publication.storage_bucket, region: publication.storage_region },
    expectedBytes, expectedSha256: publication.served_sha256,
    namespaceId: claim.runtime.namespace, runtimeEpoch: claim.runtime.epoch, accessEpoch: claim.accessEpoch,
    claimId: claim.id, claimGeneration: claim.generation,
  });
  const deadlineController = new AbortController();
  const signal = AbortSignal.any([lifeSignal, deadlineController.signal]);
  assertReadSignal(lifeSignal);
  assertDeadline(claim);
  const timer = setTimeout(() => { deadlineController.abort(); }, Math.max(1, Math.floor(claim.deadline - performance.now())));
  timer.unref();
  let staged: Uint8Array;
  try {
    io.settled = false;
    staged = await ctx.fetchReadyBytes(getGrant, { maxBytes: expectedBytes, signal });
    // Success of the trusted port means the transport and staging work actually settled.
    io.settled = true;
  } catch (error) {
    // Generic promise rejection/abort does not prove the request/body actually stopped.
    // Unknown settlement deliberately leaves both the process and durable debt occupied.
    io.settled = isLifecycleStorageOperationSettled(error);
    assertReadSignal(lifeSignal);
    assertDeadline(claim);
    refuseLifecycle('NOT_READY');
  } finally {
    clearTimeout(timer);
  }
  assertReadSignal(lifeSignal);
  assertDeadline(claim);
  if (!types.isUint8Array(staged) || staged.byteLength !== expectedBytes) {
    refuseLifecycle('NOT_READY');
  }
  // Never store an adapter-owned alias. Independently verify the exact bytes we will serve.
  const bytes = new Uint8Array(expectedBytes);
  bytes.set(staged);
  if (createHash('sha256').update(bytes).digest('hex') !== publication.served_sha256) {
    refuseLifecycle('NOT_READY');
  }
  return bytes;
}

export async function openReadyStream(ctx: AccessContext, cmd: FFile & { readonly signal: AbortSignal }): Promise<ReadyReadTicket> {
  const snapshot = readContext(ctx);
  const command = readCommand(cmd, true);
  const controller = new AbortController();
  const signal = AbortSignal.any([command.signal, controller.signal]);
  const authority: FFile = { session: command.session, intentId: command.intentId };
  const io: GetState = { settled: true };
  let reservation: ReadReservation | undefined;
  let claim: ReadClaim | undefined;
  try {
    assertReadSignal(signal);
    claim = await withLifecycleTransaction(snapshot.pool, (client) => claimRead(client, snapshot, { ...authority, signal }, (held) => {
      reservation = held;
    }));
    if (reservation === undefined) {
      refuseLifecycle('CONFLICT');
    }
    // Claim transaction is confirmed committed and the connection is released before GET.
    const bytes = await getPrivateBytes(snapshot, claim, signal, io);
    assertReadSignal(signal);
    assertDeadline(claim);
    return issueReadTicket({ ctx: { pool: snapshot.pool, epoch: snapshot.epoch, policy: snapshot.policy },
      cmd: authority, claim, reservation, controller, signal, bytes, cursor: 0 });
  } catch (error) {
    controller.abort();
    if (io.settled) {
      reservation?.release();
      // If COMMIT acknowledgement was lost, `claim` is still undefined and no
      // GET has begun. Drop the RAM hold, but leave any durable claim untouched.
      if (claim !== undefined) {
        await releaseReadClaim(snapshot.pool, claim).catch(() => undefined);
      }
    }
    if (isLifecycleError(error)) {
      throw error;
    }
    refuseLifecycle('CONFLICT');
  }
}

function discardPrivateRead(state: TicketState): {
  readonly pool: ReadAuthority['pool']; readonly claim: ReadClaim; readonly reservation: ReadReservation;
} | undefined {
  const live = state.live;
  state.live = undefined;
  state.pull = undefined;
  if (live !== undefined) {
    live.bytes?.fill(0);
    live.bytes = undefined;
    return { pool: live.ctx.pool, claim: live.claim, reservation: live.reservation };
  }
}

function requestClose(state: TicketState): Promise<void> {
  if (state.closing !== undefined) {
    return state.closing;
  }
  let pending = state.pull;
  state.closing = Promise.resolve().then(async () => {
    // Never await close from inside the pull itself. `pending` is the internal
    // pull (not the outward call that may await this finalizer after settlement).
    await pending?.catch(() => undefined);
    pending = undefined;
    const cleanup = discardPrivateRead(state);
    if (cleanup === undefined) {
      return;
    }
    cleanup.reservation.release();
    try {
      await releaseReadClaim(cleanup.pool, cleanup.claim);
    } catch {
      // The local resources have settled; the durable claim remains blocked
      // if release did not commit. Do not export DB failure diagnostics.
      refuseLifecycle('CONFLICT');
    }
  });
  const live = state.live;
  if (live !== undefined) {
    if (state.onAbort !== undefined) {
      live.signal.removeEventListener('abort', state.onAbort);
      state.onAbort = undefined;
    }
    live.controller.abort();
  }
  return state.closing;
}

async function pullRead(live: LiveRead): Promise<ReadyReadResult> {
  try {
    assertReadSignal(live.signal);
    await withLifecycleTransaction(live.ctx.pool, (client) => admitRead(client, live.ctx, live.cmd, live.claim, live.signal));
    assertReadSignal(live.signal);
    // Consent/epoch/storage changes *after* confirmed admission may not retract
    // this one admitted chunk. No further pull is admitted without a new tx.
    const bytes = live.bytes;
    if (bytes === undefined) {
      refuseLifecycle('TICKET_CLOSED');
    }
    if (live.cursor === bytes.length) {
      return { kind: 'EOF' };
    }
    const length = Math.min(live.ctx.policy.maxChunkBytes, bytes.length - live.cursor);
    const result = new Uint8Array(length);
    result.set(bytes.subarray(live.cursor, live.cursor + length));
    live.cursor += length;
    return { kind: 'CHUNK', bytes: result };
  } catch (error) {
    if (isLifecycleError(error)) {
      throw error;
    }
    // COMMIT may have taken effect but not been confirmed; never retry that pull.
    if (isLifecycleCommitUnknown(error)) {
      throw lifecycleError('TICKET_CLOSED');
    }
    refuseLifecycle('CONFLICT');
  }
}

export async function readReadyChunk(ticket: ReadyReadTicket): Promise<ReadyReadResult> {
  const state = ticketState(ticket);
  const live = state.live;
  if (state.closing !== undefined || state.pull !== undefined || live === undefined) {
    refuseLifecycle('TICKET_CLOSED');
  }
  // Set the in-flight flag synchronously before even a pool-connect microtask.
  const pull = Promise.resolve().then(() => pullRead(live));
  state.pull = pull;
  try {
    const result = await pull;
    if (result.kind === 'EOF') {
      await requestClose(state).catch(() => undefined);
    }
    return result;
  } catch (error) {
    await requestClose(state).catch(() => undefined);
    throw error;
  } finally {
    state.pull = undefined;
  }
}

export async function closeReadyStream(ticket: ReadyReadTicket): Promise<void> {
  await requestClose(ticketState(ticket));
}
