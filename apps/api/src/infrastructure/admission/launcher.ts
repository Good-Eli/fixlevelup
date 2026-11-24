/**
 * Launcher-side supervisor (docs/P05-PLAN.md §7, «Однократный допуск у
 * launcher»): the ONLY holder of the control-database credentials. The
 * launcher decides ONE child handshake from its own trusted expectations —
 * never from self-reported handshake facts: the expected binding (the exact
 * instance/nonce/consumer the launcher issued this proof for) is a launcher
 * INPUT, and every handshake field must match it before any witness check,
 * CAS, or approval. The sequence per decision:
 *
 *   1. match the handshake against the launcher's expected binding
 *      (instance, nonce, consumer kind, digest) — mismatches are rejected
 *      without touching the database;
 *   2. re-verify the live witness on the application database (per-instance
 *      key, exact holder pid);
 *   3. consume the one-time proof row: single-winner ISSUED→CONSUMED CAS
 *      bound to the verified token facts (digest/consumer/instance/channel,
 *      expiry from the row);
 *   4. AFTER the durable COMMIT: re-check the witness AND the DB clock
 *      (clock_timestamp() < the row's stored expiry — a proof that expired
 *      while the CAS waited never approves);
 *   5. send exactly ONE approve to that child's channel and await its
 *      activation acknowledgement (bounded): an approve that is never
 *      acknowledged is a failed launch, reported as a lost child.
 *
 * Losers and replays get no approval; a lost witness or expired row after
 * the CAS never approves. The module is the isolated/launcher contour — the
 * application never imports it and never sees the control credentials.
 */
import { createRequire } from 'node:module';
import { consumeProof, readRegistryState } from './registry.js';
import { witnessVisible } from './witness.js';
import type { WitnessKey } from './witness.js';
import type { ChildHandshake } from './process-admission.js';

const apiRequire = createRequire(new URL('../../../package.json', import.meta.url));
const { Client } = apiRequire('pg') as typeof import('pg');

/** The launcher's OWN trusted expectations for one launched child. */
export interface ExpectedChild {
  /** The instance this proof was issued for (launcher-side knowledge). */
  readonly instanceId: string;
  /** The launch nonce of the issued proof. */
  readonly launchNonce: string;
  /** The consumer kind the proof was issued for. */
  readonly consumerKind: 'API' | 'WORKER' | 'TEST';
  /** The digest of the signed token the launcher issued. */
  readonly proofDigest: string;
  /** The issuer generation the launcher issued this proof under (trusted,
   * launcher-side; never taken from the child's handshake). */
  readonly issuerGeneration: number;
  /** The exact backend pid holding the witness for this instance (the
   * launcher's own connection pid; never taken from the handshake). */
  readonly witnessHolderPid: number;
  /** The channel id the launcher issued this proof for. */
  readonly channelId: string;
}

export interface LauncherDeps {
  /** Application-database operator view (witness visibility + DB clock). */
  readonly app: { readonly host: string; readonly port: number; readonly database: string;
    readonly user: string; readonly password: string };
  /** Control-database operator credentials (launcher-only). */
  readonly control: { readonly host: string; readonly port: number; readonly database: string;
    readonly user: string; readonly password: string };
  /** The per-instance witness key derivation shared with the child binding. */
  readonly witnessKeyOf: (instanceId: string) => WitnessKey;
  /** Acknowledgement window after the approval (ms). */
  readonly ackTimeoutMs: number;
}

export type LaunchDecision =
  | { readonly approved: true; readonly instanceId: string; readonly launchNonce: string; readonly acked: boolean }
  | { readonly approved: false; readonly reason: 'BINDING' | 'WITNESS' | 'CAS' | 'EXPIRED' | 'NO_ACK' };

/** Shape check independent of the expected binding. */
function wellFormed(handshake: ChildHandshake): boolean {
  return Number.isInteger(handshake.pid) && handshake.pid > 0
    && Number.isInteger(handshake.databaseOid) && handshake.databaseOid > 0
    && Number.isInteger(handshake.witnessHolderPid) && handshake.witnessHolderPid > 0
    && Number.isInteger(handshake.issuerGeneration) && handshake.issuerGeneration >= 0
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(handshake.instanceId)
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(handshake.channelId)
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(handshake.launchNonce)
    && /^[0-9a-f]{64}$/.test(handshake.proofDigest)
    && (handshake.profile === 'S0' || handshake.profile === 'S1');
}

/**
 * Decides ONE child handshake against the launcher's expected binding.
 * `sendApprove`/`sendReject` write to that child's exclusive channel. The
 * activation acknowledgement is awaited with the launcher's OWN deadline
 * (ackTimeoutMs) — a silent child after approval is a failed launch, reported
 * as approved-but-unacked. Only the winner ever receives approve.
 */
export async function decideLaunch(deps: LauncherDeps, expected: ExpectedChild, handshake: ChildHandshake,
  sendApprove: (instanceId: string, launchNonce: string) => void,
  sendReject: (instanceId: string) => void,
  awaitAck: () => Promise<boolean>): Promise<LaunchDecision> {
  // 1. Trusted-binding match FIRST: self-reported facts are never trusted.
  //    Instance, nonce, consumer, digest, issuer generation, witness holder
  //    pid and channel all come from the launcher's own expectations.
  const bindingMatches = wellFormed(handshake)
    && handshake.instanceId === expected.instanceId
    && handshake.launchNonce === expected.launchNonce
    && handshake.consumerKind === expected.consumerKind
    && handshake.proofDigest === expected.proofDigest
    && handshake.issuerGeneration === expected.issuerGeneration
    && handshake.witnessHolderPid === expected.witnessHolderPid
    && handshake.channelId === expected.channelId;
  if (!bindingMatches) {
    sendReject(handshake.instanceId ?? '');
    return { approved: false, reason: 'BINDING' };
  }
  const reject = (reason: 'WITNESS' | 'CAS' | 'EXPIRED'): LaunchDecision => {
    sendReject(expected.instanceId);
    return { approved: false, reason };
  };
  // 2. Live witness on the application database: the launcher's OWN pinned
  //    holder pid and per-instance key.
  const app = new Client({ host: deps.app.host, port: deps.app.port, database: deps.app.database,
    user: deps.app.user, password: deps.app.password, connectionTimeoutMillis: 5000, statement_timeout: 5000, query_timeout: 5000 });
  try {
    await app.connect();
    const visibility = await witnessVisible(app, deps.witnessKeyOf(expected.instanceId), expected.witnessHolderPid);
    if (!visibility.visible) { return reject('WITNESS'); }
  } catch { return reject('WITNESS'); }
  finally { await app.end().catch(() => undefined); }
  // 3. One-time durable CAS bound to the verified token facts, under the
  //    launcher's trusted generation. The control connection ALSO reads the
  //    row's expiry for the post-COMMIT check.
  const control = new Client({ host: deps.control.host, port: deps.control.port, database: deps.control.database,
    user: deps.control.user, password: deps.control.password, connectionTimeoutMillis: 5000, statement_timeout: 5000, query_timeout: 5000 });
  let won = false;
  let rowExpiry: Date | undefined;
  try {
    await control.connect();
    won = await consumeProof(control, { issuerGeneration: expected.issuerGeneration,
      launchNonce: expected.launchNonce, expectedDigest: expected.proofDigest,
      binding: { consumerKind: expected.consumerKind, instanceId: expected.instanceId, channelId: expected.channelId } });
    if (won) { rowExpiry = (await readRegistryState(control, expected.issuerGeneration, expected.launchNonce))?.expires_at; }
  } catch { won = false; }
  finally { await control.end().catch(() => undefined); }
  if (!won) { return reject('CAS'); }
  // 4. Post-COMMIT: witness AND DB-clock expiry re-check. The DB clock is
  //    read on the application database; the deadline is the row's own
  //    expires_at (read above from the registry AFTER the durable COMMIT) —
  //    a proof that expired while the CAS waited never approves.
  const recheck = new Client({ host: deps.app.host, port: deps.app.port, database: deps.app.database,
    user: deps.app.user, password: deps.app.password, connectionTimeoutMillis: 5000, statement_timeout: 5000, query_timeout: 5000 });
  try {
    await recheck.connect();
    const visibility = await witnessVisible(recheck, deps.witnessKeyOf(expected.instanceId), expected.witnessHolderPid);
    if (!visibility.visible) { return reject('WITNESS'); }
    const clock = await recheck.query<{ db_now: Date }>('SELECT clock_timestamp() AS db_now');
    const now = clock.rows[0]?.db_now;
    if (!(now instanceof Date) || !(rowExpiry instanceof Date) || rowExpiry.getTime() - now.getTime() <= 0) {
      return reject('EXPIRED');
    }
  } catch { return reject('WITNESS'); }
  finally { await recheck.end().catch(() => undefined); }
  // 5. Exactly one approval, then the activation acknowledgement under the
  //    launcher's own deadline: a child that never acks is not a launch.
  sendApprove(expected.instanceId, expected.launchNonce);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const acked = await Promise.race([
    awaitAck().catch(() => false),
    new Promise<false>((resolve) => {
      timer = setTimeout(() => { resolve(false); }, deps.ackTimeoutMs);
      timer.unref?.();
    }),
  ]).finally(() => { if (timer) { clearTimeout(timer); } });
  return { approved: true, instanceId: expected.instanceId, launchNonce: expected.launchNonce, acked };
}
