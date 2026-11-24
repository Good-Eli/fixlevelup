/**
 * Child-side process admission (docs/P05-PLAN.md §7, «Однократный допуск у
 * launcher»): the child NEVER consumes its own proof. The private launcher
 * does. The child's part is exactly the plan's sequence:
 *
 *   1. live verification of its physical binding on a REAL connection to the
 *      configured database (exact database/OID/role/schema + the live witness
 *      granted to the pinned launcher pid) and of the exact PHYSICAL PROFILE
 *      (S1 readiness fingerprint for S1 proofs, legacy readiness for S0);
 *   2. a runtime handshake sent to the launcher over the private IPC channel
 *      (`process.send`) — the launcher alone holds the control credentials,
 *      runs the single-winner ISSUED→CONSUMED CAS bound to this verified
 *      token, and re-checks witness/expiry after its COMMIT;
 *   3. the ONE approval signal from the launcher, accepted once from the same
 *      channel, followed by a FINAL live witness + DB-clock check immediately
 *      before the process starts, and an activation acknowledgement.
 *
 * Without a launcher channel a child can never be admitted (fail closed):
 * there is no in-process fallback and no way to start DB-backed work alone.
 */
import { createRequire } from 'node:module';
import { ConfigurationError } from '../../runtime/config.js';
import type { RuntimeAdmission } from './runtime-admission.js';

const apiRequire = createRequire(new URL('../../../package.json', import.meta.url));
const { Client } = apiRequire('pg') as typeof import('pg');

/** The private IPC channel to the launcher (Node child_process IPC). */
export interface LauncherChannel {
  send(message: unknown): boolean;
  on(event: 'message', listener: (message: unknown) => void): unknown;
}

export type AdmissionRefusal = 'ADMISSION_MISSING' | 'ADMISSION_NO_CHANNEL' | 'ADMISSION_DENIED';

export class ProcessAdmissionError extends Error {
  readonly kind: AdmissionRefusal;
  constructor(kind: AdmissionRefusal) {
    super(kind);
    this.name = 'ProcessAdmissionError';
    this.kind = kind;
  }
}

/** Typed child→launcher handshake: the child's verified identity facts. */
export interface ChildHandshake {
  readonly type: 'p05/launch/handshake';
  readonly pid: number;
  readonly database: string;
  readonly databaseOid: number;
  readonly role: string;
  readonly witnessHolderPid: number;
  readonly consumerKind: string;
  readonly instanceId: string;
  readonly channelId: string;
  readonly issuerGeneration: number;
  readonly launchNonce: string;
  /** SHA-256 of the canonical verified payload (the registry's digest key). */
  readonly proofDigest: string;
  readonly profile: string;
}

/** Typed launcher→child messages: exactly one `approve` for the winner. */
export type LauncherMessage =
  | { readonly type: 'p05/launch/approve'; readonly instanceId: string; readonly launchNonce: string }
  | { readonly type: 'p05/launch/reject'; readonly instanceId: string };

export type ChildAck = { readonly type: 'p05/launch/active'; readonly instanceId: string };

/**
 * The authorization a factory/module requires (round-6 audit MUST 1): the
 * PROOF of a completed process admission. Constructed exclusively inside
 * admitProcess after the launcher's single approval, the final live check and
 * the activation acknowledgement. The `completed` marker is IDENTITY-BOUND:
 * a runtime WeakSet pairs each marker with the exact RuntimeAdmission it was
 * issued for, and the module's validateAuthorization() (called by every
 * DB-consumer boundary) rejects a marker paired with a DIFFERENT admission —
 * mixing one genuine completion with another offline loader output cannot
 * authorize anything (round-7 audit MUST 1).
 */
export interface ProcessAuthorization {
  readonly admission: RuntimeAdmission;
  /** Module-private identity-bound marker; only admitProcess creates it. */
  readonly completed: ProcessAdmissionCompleted;
}

/** Opaque brand carrier (structurally unconstructable outside this module). */
export interface ProcessAdmissionCompleted { readonly __p05ProcessAdmissionCompleted: unique symbol }

declare const completedBrand: unique symbol;

/** The identity pairing: each issued marker is bound to its exact admission. */
const issuedFor = new WeakMap<ProcessAdmissionCompleted, RuntimeAdmission>();

function issue(admission: RuntimeAdmission): ProcessAdmissionCompleted {
  const marker: ProcessAdmissionCompleted = { __p05ProcessAdmissionCompleted: Symbol() } as unknown as ProcessAdmissionCompleted;
  issuedFor.set(marker, admission);
  return marker;
}

/**
 * Boundary validation (round-7 MUST 1, round-8 gap): the marker must have
 * been issued for EXACTLY the admission it is presented with. Any other
 * pairing — including a reused marker from a different, offline admission —
 * throws. The admission is read ONCE and returned FROM THE PRIVATE MAP (never
 * a second accessor read of the presented object), and an absent binding is
 * rejected explicitly, so a JS caller with getter side effects cannot swap
 * the object between the check and the use. DB-consumer boundaries
 * (requireAdmission in the modules) call this before unwrapping.
 */
export function validateAuthorization(authorization: ProcessAuthorization): RuntimeAdmission {
  const presented = authorization.admission;
  const bound = issuedFor.get(authorization.completed);
  if (presented === undefined || bound !== presented) {
    throw new Error('Invalid process authorization: marker is not bound to this admission');
  }
  return bound;
}

export interface ProcessAdmissionDeps {
  /** The configured APPLICATION database connection facts (runtime role). */
  readonly database: { readonly host: string; readonly port: number; readonly user: string; readonly password: string };
  /** The private channel to the launcher (absent for a standalone process → refusal). */
  readonly channel: LauncherChannel | undefined;
  /** Exact physical-profile check on a guarded connection (S1: readiness fingerprint; S0: legacy readiness). */
  readonly verifyProfile: (admission: RuntimeAdmission) => Promise<boolean>;
  /** Bounds the wait for the launcher's single approval. */
  readonly approvalTimeoutMs: number;
}

function refusal(error: unknown): ProcessAdmissionError {
  return error instanceof ProcessAdmissionError ? error : new ProcessAdmissionError('ADMISSION_DENIED');
}

/** Live verification on a fresh real connection; the client is always closed. */
async function verifyLive(admission: RuntimeAdmission, deps: ProcessAdmissionDeps,
  extra?: (client: import('pg').Client) => Promise<void>): Promise<void> {
  const client = new Client({ host: deps.database.host, port: deps.database.port,
    database: admission.binding.database, user: deps.database.user, password: deps.database.password,
    connectionTimeoutMillis: 5000, statement_timeout: 5000 });
  try {
    await client.connect();
    await admission.gate.verifyConnection(client, new Date());
    if (extra) { await extra(client); }
  } catch (error) {
    throw refusal(error);
  } finally {
    await client.end().catch(() => undefined);
  }
}

/**
 * Child-side admission. Resolves ONLY after the launcher's single approval and
 * the final pre-start re-check — the resolved value is the factory-bound
 * ProcessAuthorization. Rejects with ProcessAdmissionError otherwise (typed
 * `kind`, no values logged). The caller MUST NOT start before it resolves,
 * and DB-backed factories accept only its result, never the loader's
 * RuntimeAdmission.
 */
export async function admitProcess(admission: RuntimeAdmission, deps: ProcessAdmissionDeps): Promise<ProcessAuthorization> {
  const channel = deps.channel;
  if (channel === undefined) { throw new ProcessAdmissionError('ADMISSION_NO_CHANNEL'); }
  // 1. Live binding + physical profile on a real connection.
  await verifyLive(admission, deps);
  if (!await deps.verifyProfile(admission)) { throw new ProcessAdmissionError('ADMISSION_DENIED'); }
  // 2. Handshake to the launcher; await exactly one decision for this instance.
  const binding = admission.binding;
  const handshake: ChildHandshake = Object.freeze({
    type: 'p05/launch/handshake', pid: process.pid, database: binding.database,
    databaseOid: binding.databaseOid, role: binding.role, witnessHolderPid: binding.witnessHolderPid,
    consumerKind: binding.expected.consumerKind, instanceId: binding.expected.instanceId,
    channelId: binding.expected.channelId, issuerGeneration: binding.expected.issuerGeneration,
    launchNonce: binding.expected.launchNonce, proofDigest: admission.proofDigest, profile: binding.profile,
  });
  const decision = await new Promise<LauncherMessage>((resolve, reject) => {
    let settled = false;
    const finish = (message: LauncherMessage | undefined): void => {
      if (settled) { return; }
      settled = true;
      if (message === undefined) { reject(new ProcessAdmissionError('ADMISSION_DENIED')); }
      else { resolve(message); }
    };
    const timer = setTimeout(() => { finish(undefined); }, deps.approvalTimeoutMs);
    timer.unref();
    channel.on('message', (message: unknown) => {
      if (message === null || typeof message !== 'object' || !('type' in message)) { return; }
      const typed = message as LauncherMessage;
      if (typed.type !== 'p05/launch/approve' && typed.type !== 'p05/launch/reject') { return; }
      // Only a decision bound to THIS instance is accepted; anything else is ignored.
      if (typed.instanceId !== binding.expected.instanceId) { return; }
      clearTimeout(timer);
      finish(typed);
    });
    try {
      channel.send(handshake);
    } catch {
      clearTimeout(timer);
      finish(undefined);
    }
  });
  if (decision.type !== 'p05/launch/approve' || decision.launchNonce !== binding.expected.launchNonce) {
    throw new ProcessAdmissionError('ADMISSION_DENIED');
  }
  // 3. Final live witness + DB-clock check immediately before start, then the
  //    activation acknowledgement on the same channel.
  await verifyLive(admission, deps, async (client) => {
    const clock = await client.query<{ db_now: Date }>('SELECT clock_timestamp() AS db_now');
    const dbNow = clock.rows[0]?.db_now;
    if (!(dbNow instanceof Date) || dbNow.getTime() >= Date.parse(admission.payload.expiresAt)) {
      throw new ProcessAdmissionError('ADMISSION_DENIED');
    }
  });
  const ack: ChildAck = { type: 'p05/launch/active', instanceId: binding.expected.instanceId };
  try {
    channel.send(ack);
  } catch {
    throw new ProcessAdmissionError('ADMISSION_DENIED');
  }
  // The private channel has carried its one handshake, decision and ack; a
  // lingering IPC handle would keep a real child alive after shutdown, so the
  // child disconnects once the acknowledgement is out. In-process test doubles
  // (a plain object channel) never touch process.disconnect.
  if (typeof process.disconnect === 'function' && typeof process.send === 'function' && channel === (process as unknown as LauncherChannel)) {
    process.disconnect();
  }
  return { admission, completed: issue(admission) };
}

/** Maps a refusal to the operator-visible startup event name (no values). */
export function admissionEvent(error: unknown): 'admission_missing' | 'admission_denied' | 'startup_failed' {
  if (error instanceof ConfigurationError) { return 'admission_missing'; }
  if (error instanceof ProcessAdmissionError) { return 'admission_denied'; }
  return 'startup_failed';
}
