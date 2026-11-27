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
 *   3. the launcher's one prepare approval, a final profile/witness check,
 *      a bound child ACK, and the launcher's explicit activation. The child
 *      never starts on prepare alone and retains live IPC supervision.
 *
 * Without a launcher channel a child can never be admitted (fail closed):
 * there is no in-process fallback and no way to start DB-backed work alone.
 */
import { createRequire } from 'node:module';
import { ConfigurationError } from '../../runtime/config.js';
import { isVerifiedRuntimeAdmission, matchesRuntimeTarget } from './runtime-admission.js';
import type { RuntimeAdmission } from './runtime-admission.js';
import type { DatabaseConfig } from '../database/runtime-database.js';
import { physicalProfileVerifier } from './physical-profile.js';
import { createPrivateLaunchChannel } from './private-launch-channel.js';

const apiRequire = createRequire(new URL('../../../package.json', import.meta.url));
const { Client } = apiRequire('pg') as typeof import('pg');


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

export type LaunchBinding = Pick<ChildHandshake, 'instanceId' | 'launchNonce' | 'channelId'
  | 'consumerKind' | 'issuerGeneration' | 'proofDigest' | 'witnessHolderPid' | 'pid' | 'database' | 'databaseOid'
  | 'role' | 'profile'>;

export function launchBindingOf(binding: LaunchBinding): LaunchBinding {
  return {
    instanceId: binding.instanceId, launchNonce: binding.launchNonce, channelId: binding.channelId,
    consumerKind: binding.consumerKind, issuerGeneration: binding.issuerGeneration, proofDigest: binding.proofDigest,
    witnessHolderPid: binding.witnessHolderPid, pid: binding.pid, database: binding.database,
    databaseOid: binding.databaseOid, role: binding.role, profile: binding.profile,
  };
}

export function matchesLaunchBinding(message: unknown, expected: LaunchBinding): boolean {
  if (typeof message !== 'object' || message === null) { return false; }
  const actual = message as Partial<LaunchBinding>;
  return actual.instanceId === expected.instanceId && actual.launchNonce === expected.launchNonce
    && actual.channelId === expected.channelId && actual.consumerKind === expected.consumerKind
    && actual.issuerGeneration === expected.issuerGeneration && actual.proofDigest === expected.proofDigest
    && actual.witnessHolderPid === expected.witnessHolderPid && actual.pid === expected.pid
    && actual.database === expected.database && actual.databaseOid === expected.databaseOid
    && actual.role === expected.role && actual.profile === expected.profile;
}

export type LauncherMessage = LaunchBinding & {
  readonly type: 'p05/launch/approve' | 'p05/launch/reject' | 'p05/launch/activate';
};
export type ChildAck = LaunchBinding & { readonly type: 'p05/launch/active' };
export type ChildActivationReceipt = LaunchBinding & { readonly type: 'p05/launch/activated' };

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
  if (bound === undefined || bound !== presented) {
    throw new Error('Invalid process authorization: marker is not bound to this admission');
  }
  return bound;
}

/** Validates the branded authorization and pins it to one runtime consumer kind. */
export function requireAuthorizationKind(authorization: ProcessAuthorization, kind: 'API' | 'WORKER' | 'TEST'): RuntimeAdmission {
  const admission = validateAuthorization(authorization);
  if (admission.binding.expected.consumerKind !== kind) {
    throw new Error('Invalid process authorization: consumer kind mismatch');
  }
  return admission;
}

export interface ProcessAdmissionDeps {
  /** The configured APPLICATION database connection facts (runtime role). */
  readonly database: DatabaseConfig;
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
    connectionTimeoutMillis: 5000, statement_timeout: 5000, query_timeout: 5000,
    options: '-c default_transaction_read_only=on' });
  client.on('error', () => { /* The failed probe never leaks driver details. */ });
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
  const channel = createPrivateLaunchChannel();
  if (!channel) { throw new ProcessAdmissionError('ADMISSION_NO_CHANNEL'); }
  const database = Object.freeze({ ...deps.database });
  const approvalTimeoutMs = deps.approvalTimeoutMs;
  if (!isVerifiedRuntimeAdmission(admission) || !matchesRuntimeTarget(admission, database) || !Number.isSafeInteger(approvalTimeoutMs)
    || approvalTimeoutMs <= 0 || approvalTimeoutMs > 2_147_483_647) {
    throw new ProcessAdmissionError('ADMISSION_DENIED');
  }
  const verify = physicalProfileVerifier(database);
  const probe = (extra: (client: import('pg').Client) => Promise<void>) =>
    verifyLive(admission, { database, approvalTimeoutMs }, extra);
  const bound = admission.binding;
  const binding = Object.freeze(launchBindingOf({
    pid: process.pid, database: bound.database, databaseOid: bound.databaseOid, role: bound.role,
    witnessHolderPid: bound.witnessHolderPid, consumerKind: bound.expected.consumerKind,
    instanceId: bound.expected.instanceId, channelId: bound.expected.channelId,
    issuerGeneration: bound.expected.issuerGeneration, launchNonce: bound.expected.launchNonce,
    proofDigest: admission.proofDigest, profile: bound.profile,
  }));
  let lost = false;
  let cancelWait: (() => void) | undefined;
  let completed: ProcessAdmissionCompleted | undefined;
  const onLost = (): void => {
    if (lost) { return; }
    lost = true;
    cancelWait?.();
    if (!completed) { return; }
    issuedFor.delete(completed);
    channel.stopAfterLoss();
  };
  const detachLoss = channel.onLoss(onLost);
  const requireChannel = (): void => {
    if (lost || !channel.live()) { throw new ProcessAdmissionError('ADMISSION_DENIED'); }
  };
  const verifyProfile = async (client: import('pg').Client): Promise<void> => {
    if (!await verify(admission, client)) { throw new ProcessAdmissionError('ADMISSION_DENIED'); }
  };
  const verifyExpiry = async (client: import('pg').Client): Promise<void> => {
    const { rows } = await client.query<{ db_now: Date }>('SELECT clock_timestamp() AS db_now');
    const dbNow = rows[0]?.db_now;
    if (!(dbNow instanceof Date) || !Number.isFinite(dbNow.getTime())
      || dbNow.getTime() >= Date.parse(admission.payload.expiresAt)) {
      throw new ProcessAdmissionError('ADMISSION_DENIED');
    }
  };
  const waitFor = (target: 'p05/launch/approve' | 'p05/launch/activate', outgoing: ChildHandshake | ChildAck): Promise<void> => {
    requireChannel();
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const listener = (message: unknown): void => {
        if (typeof message !== 'object' || message === null || !('type' in message)
          || !matchesLaunchBinding(message, binding)) { return; }
        if (message.type === target) { finish(true); }
        else if (message.type === 'p05/launch/reject') { finish(false); }
      };
      const finish = (ok: boolean): void => {
        if (settled) { return; }
        settled = true;
        clearTimeout(timer);
        detachMessage();
        cancelWait = undefined;
        if (ok) { resolve(); }
        else { reject(new ProcessAdmissionError('ADMISSION_DENIED')); }
      };
      const timer = setTimeout(() => { finish(false); }, approvalTimeoutMs);
      const detachMessage = channel.onMessage(listener);
      cancelWait = () => { finish(false); };
      try { channel.send(outgoing, (error) => { if (error) { onLost(); } }); }
      catch { finish(false); }
    });
  };
  try {
    await probe(verifyProfile);
    await waitFor('p05/launch/approve', { ...binding, type: 'p05/launch/handshake' });
    await probe(async (client) => {
      await verifyProfile(client);
      await verifyExpiry(client);
    });
    await waitFor('p05/launch/activate', { ...binding, type: 'p05/launch/active' });
    requireChannel();
    await probe(verifyExpiry);
    requireChannel();
    const receipt: ChildActivationReceipt = { ...binding, type: 'p05/launch/activated' };
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const finish = (ok: boolean): void => {
        if (settled) { return; }
        settled = true;
        clearTimeout(timer);
        cancelWait = undefined;
        if (ok) { resolve(); }
        else { reject(new ProcessAdmissionError('ADMISSION_DENIED')); }
      };
      const timer = setTimeout(() => { finish(false); }, approvalTimeoutMs);
      cancelWait = () => { finish(false); };
      try { channel.send(receipt, (error) => { finish(!error); }); }
      catch { finish(false); }
    });
    requireChannel();
    completed = issue(admission);
    channel.unref();
    return { admission, completed };
  } catch (error) {
    detachLoss();
    throw refusal(error);
  }
}

/** Maps a refusal to the operator-visible startup event name (no values). */
export function admissionEvent(error: unknown): 'admission_missing' | 'admission_denied' | 'startup_failed' {
  if (error instanceof ConfigurationError) { return 'admission_missing'; }
  if (error instanceof ProcessAdmissionError) { return 'admission_denied'; }
  return 'startup_failed';
}
