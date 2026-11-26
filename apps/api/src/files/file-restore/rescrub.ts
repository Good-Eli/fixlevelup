import { randomBytes } from 'node:crypto';
import type { LedgerItem, LedgerScope } from '../file-ledger/contract.js';
import type { StorageTarget } from '../storage/attempt.js';
import type { RestoreContext, RestoreObject, RestoreReaderTarget, RestoreGateReceipt, SignedSnapshotManifest, FileRestoreFailure, SnapshotManifest } from './contract.js';
import { refuseRestore } from './contract.js';
import { readAuthorityInventory, readRestoreInventory, requireExactTombstones, requireMatchingInventory } from './inventory.js';
import { p05Tables, readP05RestoreDrainState, type CarriedRestorePolicy } from './p05-inventory.js';
import { S3_HEAD } from '../../infrastructure/database/p05-profile-catalog.js';
import { observeFencedSource } from './p05-source-fence.js';
import type { FencedSourceObservation } from './p05-source-fence.js';
import { verifyP05Attestation } from './p05-attestation.js';
import { objectId, readSnapshot, requireAuthorityV2, requireAuthorityV3, sameHead, sha256, targetId, validateLimits, verifyApproval } from './records.js';
import { issueReadyGetGrant, requireLifecycleGetGrant, type ReadyGetGrant } from '../storage/lifecycle-proof.js';
import type { ReadyReadStorage } from '../file-lifecycle/contract.js';
import { privateStorageError } from '../storage/errors.js';

/** §5.3 gate: file-only activation requires a proven P05-absent TARGET whose
 * fact matches the manifest's schema profile exactly — a clean pre-P05 target
 * (schema absent) for an S0 restore, a fully drained S1 target (all ten
 * 022 tables empty, no 023 objects) for an S1 restore, or a fully drained S2
 * target (all thirteen tables empty) for an S2 restore. Surviving rows, a
 * partial P05 schema, or a target/source profile mismatch refuse activation:
 * two individually KNOWN but DIFFERENT profiles (S1 target with an S2
 * manifest, S2 target with an S1 manifest) both report the same
 * P05_EMPTY_AFTER_DRAIN fact but never admit activation — the actual target
 * profile must equal the signed manifest profile exactly (plan §5.3: «два
 * известных, но разных профиля не дают допуск»). Exported for the isolated
 * profile-mismatch proof (tests/file-restore-p05.test.ts, round-4 audit
 * finding #9): the full rescrubFileRestore contour needs S3/Garage IO, while
 * this gate is provable against real disposable PostgreSQL targets alone. */
export async function requireP05AbsentForActivation(client: { readonly query: import('pg').PoolClient['query'] },
  manifest: Pick<SnapshotManifest, 'schemaVersion' | 'policySha256'>,
  carried?: CarriedRestorePolicy): Promise<'P05_EMPTY_AFTER_DRAIN' | 'P05_SCHEMA_ABSENT_AFTER_DRAIN'> {
  let expectedProfile: 'S0' | 'S1' | 'S2' | 'S3';
  try {
    expectedProfile = manifestSourceSchemaProfile(manifest);
  } catch {return refuseRestore('RESTORE_AUTHORITY');}
  const expectedFact = expectedProfile === 'S0' ? 'P05_SCHEMA_ABSENT_AFTER_DRAIN' : 'P05_EMPTY_AFTER_DRAIN';
  try {
    if (manifest.policySha256 !== carried?.sha256) {refuseRestore('RESTORE_AUTHORITY');}
    const target = await readP05RestoreDrainState(client, expectedProfile, carried);
    if (target.profile !== expectedProfile || target.fact !== expectedFact) {refuseRestore('RESTORE_AUTHORITY');}
    return target.fact;
  } catch { return refuseRestore('RESTORE_AUTHORITY'); }
}

/** Only REVIEWED heads resolve (docs/P05-01-CONTRACT.md): the exact reviewed
 * pre-P05 baseline 021 `20261122000700_catalog_management` (S0, docs/P05-PLAN.md
 * §1 base 7a60d4c = 021, the only pre-P05 profile the P05 plan accepts as a
 * restore source), the reviewed P05 act 022 = migration
 * `20261123000100_request_intake_foundation` (S1) and the reviewed P05-02
 * head 023 = migration `20261124000100_form_session_foundation` (S2) and the
 * reviewed S3 head 024. The
 * manifest schemaVersion is the exact reviewed migration directory name
 * (records.ts enforces `^\d{14}_[a-z_]+$`). Any other head — earlier unknown,
 * later unknown or malformed-but-syntax-valid — is never silently classified;
 * it refuses as an unreviewed profile. Callers that need the classification
 * must treat a thrown refusal as RESTORE_AUTHORITY. */
const REVIEWED_S0_HEAD = '20261122000700_catalog_management';
const REVIEWED_S1_HEAD = '20261123000100_request_intake_foundation';
const REVIEWED_S2_HEAD = '20261124000100_form_session_foundation';

export function manifestSourceSchemaProfile(manifest: Pick<SnapshotManifest, 'schemaVersion'>): 'S0' | 'S1' | 'S2' | 'S3' {
  const version = manifest.schemaVersion;
  if (version === REVIEWED_S0_HEAD) { return 'S0'; }
  if (version === REVIEWED_S1_HEAD) { return 'S1'; }
  if (version === REVIEWED_S2_HEAD) { return 'S2'; }
  if (version === S3_HEAD) { return 'S3'; }
  throw new Error(`Unreviewed schema profile: ${version}`);
}

function sameCluster(left: { readonly systemIdentifier: string; readonly serverVersionNum: string;
  readonly postmasterStart: string }, right: { readonly systemIdentifier: string; readonly serverVersionNum: string;
  readonly postmasterStart: string }): boolean {
  return left.systemIdentifier === right.systemIdentifier && left.serverVersionNum === right.serverVersionNum
    && left.postmasterStart === right.postmasterStart;
}

/**
 * §5.3: the signed v2 authority must name exactly the source this run fenced
 * (database, numeric OID, cluster identity, reviewed schema profile, old ledger
 * namespace/epoch) and exactly the destination the manifest names. The cluster
 * fact is compared against the SAME observation that produced the drain fact, so
 * a signature over another cluster's facts can never admit this target.
 */
export function requireBoundAuthority(record: {
  readonly sourceDatabase: string; readonly sourceDatabaseOid: number;
  readonly cluster: { readonly systemIdentifier: string; readonly serverVersionNum: string; readonly postmasterStart: string };
  readonly sourceProfile: 'S0' | 'S1' | 'S2' | 'S3'; readonly oldNamespace: string; readonly oldWriterEpoch: string;
  readonly destinationDatabase: string; readonly manifestSha256: string; readonly inventorySha256: string;
}, expected: {
  readonly manifestSha256: string; readonly sourceDatabase: string; readonly destinationDatabase: string;
  readonly sourceDatabaseOid: number; readonly sourceProfile: 'S0' | 'S1' | 'S2' | 'S3';
  readonly oldNamespace: string; readonly oldWriterEpoch: string;
  readonly observed: Pick<FencedSourceObservation, 'cluster' | 'inventorySha256'>;
}): void {
  if (record.manifestSha256 !== expected.manifestSha256
    || record.inventorySha256 !== expected.observed.inventorySha256
    || record.sourceDatabase !== expected.sourceDatabase || record.destinationDatabase !== expected.destinationDatabase
    || record.sourceDatabaseOid !== expected.sourceDatabaseOid
    || !sameCluster(record.cluster, expected.observed.cluster)
    || record.sourceProfile !== expected.sourceProfile
    || record.oldNamespace !== expected.oldNamespace || record.oldWriterEpoch !== expected.oldWriterEpoch) {
    refuseRestore('RESTORE_AUTHORITY');
  }
}

/** The bridge callback returns no clock reading: the drain fact is bound to the
 * observation instant of this handoff, and cross-handoff freshness is the nonce
 * inequality below. maxAgeMs therefore only covers verify-time parsing slack. */
const P05_SOURCE_FACT_MAX_AGE_MS = 60_000;

/** §5.3: the fact a drained source may return is bound to the manifest's exact
 * schema profile — schema absence only for the pre-P05 S0 source, emptiness
 * only for the S1/S2 source. `previousNonce` is undefined on the first handoff and
 * the recorded nonce of the first handoff on the second, so a replayed fact
 * across the two activation checks refuses. MUST 11 (Astra round 1): when
 * `expectedChallenge` is given, the attestation nonce MUST equal it — the
 * answer is cryptographically bound to THIS handoff's challenge, so an
 * arbitrary/self-minted nonce from an unbound (possibly replayed) response
 * refuses as RESTORE_AUTHORITY. */
export function requireP05ProfileFact(manifest: Pick<SnapshotManifest, 'schemaVersion' | 'sourceDatabase'>,
  attestation: { readonly fact: 'P05_EMPTY_AFTER_DRAIN' | 'P05_SCHEMA_ABSENT_AFTER_DRAIN'; readonly profile: 'S0' | 'S1' | 'S2' | 'S3'; readonly nonce: string },
  previousNonce: string | undefined, observedAt: Date, expectedChallenge?: string): void {
  const expected = manifestSourceSchemaProfile(manifest);
  if (attestation.profile !== expected || typeof attestation.nonce !== 'string' || attestation.nonce === ''
    || attestation.nonce === previousNonce
    || (expectedChallenge !== undefined && attestation.nonce !== expectedChallenge)
    || !verifyP05Attestation(
      { kind: attestation.fact, sourceDatabase: manifest.sourceDatabase, sourceSchemaProfile: attestation.profile,
        nonce: attestation.nonce, recordedAt: observedAt.toISOString() },
      { sourceDatabase: manifest.sourceDatabase, sourceSchemaProfile: expected,
        fact: expected === 'S0' ? 'P05_SCHEMA_ABSENT_AFTER_DRAIN' : 'P05_EMPTY_AFTER_DRAIN',
        maxAgeMs: P05_SOURCE_FACT_MAX_AGE_MS, now: observedAt },
    )) {refuseRestore('RESTORE_AUTHORITY');}
}

const IDLE = new WeakSet<object>();
const ACTIVATION_STARTED = new WeakSet<object>();
// Native getter enforces the brand and cannot be overridden by an own property.
// eslint-disable-next-line @typescript-eslint/unbound-method
const ABORTED = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;
const NONCE = (): string => randomBytes(32).toString('hex');

/** Test-only restore diagnostics are deliberately categorical: never print SQL,
 * database names, archive paths, row data, or raw driver/process messages. */
function restoreTestDiagnostic(event: string, error?: unknown): void {
  if (process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] !== '1'
    || process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1') { return; }
  const value = error !== null && typeof error === 'object'
    ? error as { readonly name?: unknown; readonly message?: unknown; readonly code?: unknown } : undefined;
  const name = typeof value?.name === 'string' && /^[A-Za-z][A-Za-z0-9]{0,39}$/.test(value.name) ? value.name : 'UnknownError';
  const pgCode = typeof value?.code === 'string' && /^[0-9A-Z]{5}$/.test(value.code) ? value.code : undefined;
  const labStage = typeof value?.message === 'string'
    ? /^Synthetic lab restore failed: ([a-z0-9:-]{1,48})$/.exec(value.message)?.[1] : undefined;
  const expressionStage = typeof value?.message === 'string'
    ? /^Unrecognised reviewed restore expression: ([a-z0-9-]{1,96})(?:\s|$)/.exec(value.message)?.[1] : undefined;
  process.stderr.write(`[p05-restore-diagnostic] ${JSON.stringify({ event, name,
    ...(pgCode === undefined ? {} : { pgCode }), ...(labStage === undefined ? {} : { labStage }),
    ...(expressionStage === undefined ? {} : { expressionStage }) })}\n`);
}
interface AliasFacts { readonly object: RestoreObject; readonly destination: StorageTarget }
const ALIASES = new WeakMap<RestoreGateReceipt, { readonly database: string; readonly entries: ReadonlyMap<string, AliasFacts>;
  readonly destinations: readonly StorageTarget[] }>();

/** Trusted post-restore wiring only. A copied/serialized receipt carries no authority. */
export function readRestoreDeleteScope(receipt: RestoreGateReceipt): { readonly epoch: RestoreGateReceipt['epoch']; readonly database: string;
  readonly destinations: readonly StorageTarget[]; readonly copies: readonly AliasFacts[] } {
  const proof = ALIASES.get(receipt);
  if (proof === undefined) {return refuseRestore('RESTORE_AUTHORITY');}
  return Object.freeze({ epoch: receipt.epoch, database: proof.database, destinations: proof.destinations,
    copies: Object.freeze([...proof.entries.values()]) });
}

/** Resolve only a copied, settled, exact registered tuple. No old bucket, tombstone, or unknown debt is a physical target. */
export function resolveRestoredDeleteTarget(receipt: RestoreGateReceipt, input: { readonly namespace: string;
  readonly runtimeEpoch: bigint; readonly item: LedgerItem; readonly intentId: string }): StorageTarget | undefined {
  const proof = ALIASES.get(receipt);
  if (proof === undefined || input.namespace !== receipt.epoch.namespace || input.runtimeEpoch !== receipt.epoch.epoch
    || input.item.writeProof !== 'VERIFIED_SETTLED') {return undefined;}
  const matched = proof.entries.get(objectId(input.item));
  if (matched === undefined || matched.object.intentId !== input.intentId || matched.object.key !== input.item.objectKey
    || targetId(matched.object.target) !== targetId(input.item.target)) {return undefined;}
  return matched.destination;
}

async function fetchCheckedObject(ctx: RestoreContext, item: RestoreObject, signal: AbortSignal): Promise<Uint8Array> {
  const bytes = await ctx.openBackupObject(item, signal);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== item.bytes || sha256(bytes) !== item.sha256) {return refuseRestore('RESTORE_OBJECT');}
  return bytes;
}

function abortCheck(signal: AbortSignal): void {
  if (ABORTED === undefined || !(signal instanceof AbortSignal)) {refuseRestore('RESTORE_INPUT');}
  if (Reflect.apply(ABORTED, signal, []) === true) {refuseRestore('RESTORE_ABORTED');}
}

/** Only the explicit synthetic controller calls this; any refusal leaves runtime CONNECT withheld.
 * A fresh target is single-use, including after ambiguous copy/COMMIT. All artifacts are retained. */
export async function rescrubFileRestore(ctx: RestoreContext, snapshot: SignedSnapshotManifest, signal: AbortSignal): Promise<RestoreGateReceipt> {
  let stage: FileRestoreFailure = 'RESTORE_INPUT';
  try {
    abortCheck(signal);
    if ((ctx.mode as unknown) !== 'local-synthetic' || IDLE.has(ctx)) {refuseRestore('RESTORE_INPUT');}
    const limits = validateLimits(ctx.limits);
    const { manifest, hash } = readSnapshot(snapshot, ctx.snapshotKey, limits);
    const old = Object.freeze({ ...ctx.oldScope });
    const nextScope: LedgerScope = Object.freeze({ namespace: old.namespace, incarnation: old.incarnation, writerEpoch: ctx.nextEpoch });
    if (manifest.sourceDatabase !== ctx.sourceDatabase || manifest.destinationDatabase !== ctx.destinationDatabase
      || manifest.schemaVersion !== ctx.schemaVersion || manifest.base.namespace !== old.namespace || manifest.base.incarnation !== old.incarnation
      || manifest.base.writerEpoch !== old.writerEpoch || nextScope.writerEpoch <= old.writerEpoch
      || nextScope.writerEpoch > 9_223_372_036_854_775_807n) {refuseRestore('RESTORE_INPUT');}
    IDLE.add(ctx);
    const conn = ctx.targetOperatorPool;
    stage = 'RESTORE_CLOSED';
    if (ACTIVATION_STARTED.has(conn)) { refuseRestore(stage); }
    stage = 'RESTORE_AUTHORITY';
    const challenge = NONCE();
    const observer = ctx.sourceObserver;
    const sourceProfile = manifestSourceSchemaProfile(manifest);
    let carried: CarriedRestorePolicy | undefined;
    if (manifest.policySha256 !== undefined) {
      if (sourceProfile !== 'S3' || ctx.policyPin === undefined) {refuseRestore('RESTORE_AUTHORITY');}
      carried = Object.freeze({ pin: Object.freeze({ ...ctx.policyPin }), sha256: manifest.policySha256 });
    }
    const source = Object.freeze({ database: manifest.sourceDatabase, databaseOid: ctx.sourceDatabaseOid,
      scope: old, profile: sourceProfile, manifestSha256: hash });
    const drained = await observeFencedSource(observer, { ...source, challenge }, limits, carried);
    requireP05ProfileFact(manifest, drained, undefined, new Date(), challenge);
    if (drained.manifestSha256 !== hash) { refuseRestore('RESTORE_AUTHORITY'); }
    abortCheck(signal);
    const readCurrentAuthority = async (nonce: string) => {
      const signed = await ctx.currentAuthority({ manifestSha256: hash, challenge: nonce }, signal);
      if (carried === undefined) { return requireAuthorityV2(signed, ctx.authorityKey); }
      const result = requireAuthorityV3(signed, ctx.authorityKey);
      if (result.record.policySha256 !== drained.policySha256 || result.record.drainFact !== drained.fact) {refuseRestore('RESTORE_AUTHORITY');}
      return result;
    };
    const auth = await readCurrentAuthority(challenge);
    if (auth.record.challenge !== challenge || auth.record.head.namespace !== nextScope.namespace
      || auth.record.head.incarnation !== nextScope.incarnation || auth.record.head.writerEpoch !== nextScope.writerEpoch) {
      refuseRestore('RESTORE_AUTHORITY');
    }
    requireBoundAuthority(auth.record, { manifestSha256: hash, sourceDatabase: manifest.sourceDatabase,
      destinationDatabase: manifest.destinationDatabase, sourceDatabaseOid: ctx.sourceDatabaseOid,
      sourceProfile, oldNamespace: old.namespace, oldWriterEpoch: old.writerEpoch.toString(), observed: drained });
    abortCheck(signal);
    stage = 'RESTORE_LEDGER';
    const lineage = await ctx.verifier.verifyLineage(nextScope, manifest.base);
    if (!sameHead(lineage.head, auth.record.head)) {refuseRestore('RESTORE_LEDGER');}
    stage = 'RESTORE_OBJECT';
    // Validate even the old artifacts destined to be skipped; they remain evidentiary backup bytes.
    // The second verification at actual copy is still necessary (artifact access is not an authenticity boundary).
    for (const item of manifest.inventory) {
      abortCheck(signal);
      if (item.disposition === 'COPY') {await fetchCheckedObject(ctx, item, signal);}
    }
    abortCheck(signal);
    stage = 'RESTORE_CLOSED';
    try {
      await ctx.restoreArchives(manifest, auth.record, signal);
    } catch (error) {
      restoreTestDiagnostic('archive-restore-failed', error);
      throw error;
    }
    let epoch: { db: string; namespace: string; epoch: string; mode: string; connect: boolean; primary: boolean; oid: string } | undefined;
    try {
      const result = await conn.query<{ db: string; namespace: string; epoch: string; mode: string; connect: boolean; primary: boolean; oid: string }>(`SELECT
      current_database() AS db,namespace_id::text AS namespace,epoch::text,mode,
      NOT pg_is_in_recovery() AS primary,
      (SELECT oid::text FROM pg_database WHERE datname=current_database()) AS oid,
      has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT') AS connect
      FROM foundation.file_runtime_epochs WHERE singleton`);
      epoch = result.rows[0];
    } catch (error) {
      restoreTestDiagnostic('target-epoch-query-failed', error);
      throw error;
    }
    const restoredEpoch = epoch;
    if (restoredEpoch === undefined) {
      restoreTestDiagnostic('target-epoch-invariant-missing');
      refuseRestore('RESTORE_CLOSED');
    }
    const epochFailure = !restoredEpoch.primary ? 'not-primary'
      : restoredEpoch.db !== manifest.destinationDatabase ? 'database-mismatch'
      : restoredEpoch.namespace !== old.namespace ? 'namespace-mismatch'
      : restoredEpoch.epoch !== old.writerEpoch.toString() ? 'epoch-mismatch'
      : restoredEpoch.mode !== 'RESTORE_CLOSED' ? 'mode-mismatch' : restoredEpoch.connect ? 'runtime-connect-enabled' : undefined;
    if (epochFailure !== undefined) {
      restoreTestDiagnostic(`target-epoch-invariant-${epochFailure}`);
      refuseRestore('RESTORE_CLOSED');
    }
    stage = 'RESTORE_AUTHORITY';
    await requireP05AbsentForActivation(conn, manifest, carried);
    if (await readAuthorityInventory(conn, limits) !== auth.record.inventorySha256) {refuseRestore('RESTORE_AUTHORITY');}
    const current = await readRestoreInventory(conn, limits);
    requireMatchingInventory(manifest.inventory, current);
    stage = 'RESTORE_LEDGER';
    await requireExactTombstones(conn, limits, ctx.verifier, old, manifest.base, lineage.head, lineage.events, current);

    const aliases = new Map(manifest.aliases.map(pair => [targetId(pair.source), pair.destination]));
    const resolved = new Map<string, AliasFacts>();
    let tombstoned = 0;
    let unresolved = 0;
    // Sequential caps; no unbounded parallel copy or preservation-by-overwrite.
    for (const item of current) {
      stage = 'RESTORE_OBJECT';
      abortCheck(signal);
      if (item.disposition === 'TOMBSTONED') { tombstoned += 1; continue; }
      if (item.disposition === 'UNRESOLVED') { unresolved += 1; continue; }
      if (item.disposition === 'NEVER_DISPATCHED') {continue;}
      const dest = aliases.get(targetId(item.target));
      if (dest === undefined) {refuseRestore('RESTORE_OBJECT');}
      const bytes = await fetchCheckedObject(ctx, item, signal);
      abortCheck(signal);
      await ctx.copyToFreshTarget(dest, item, bytes, signal);
      resolved.set(objectId(item), Object.freeze({ object: item, destination: dest }));
    }
    stage = 'RESTORE_AUTHORITY';
    const binding = { challenge: NONCE(), authoritySha256: auth.hash, destinationDatabase: manifest.destinationDatabase };
    verifyApproval(await ctx.approve(binding, signal), ctx.approvalKey, binding);
    // Re-read the source fence/authority and current floor-extended head after all IO. Same signed facts, new nonce.
    const last = NONCE();
    const fresh = (await readCurrentAuthority(last)).record;
    if (fresh.challenge !== last || fresh.overlaySha256 !== auth.record.overlaySha256
      || !sameHead(fresh.head, lineage.head)) {refuseRestore('RESTORE_AUTHORITY');}
    // The second signature must still name the same source/cluster/profile/epoch
    // AND the same drain inventory: only the challenge may differ. Binding the
    // fresh record to the ORIGINAL drain inventory (not to itself) is what makes
    // this a real check rather than a tautology.
    requireBoundAuthority(fresh, { manifestSha256: hash, sourceDatabase: manifest.sourceDatabase,
      destinationDatabase: manifest.destinationDatabase, sourceDatabaseOid: ctx.sourceDatabaseOid,
      sourceProfile, oldNamespace: old.namespace, oldWriterEpoch: old.writerEpoch.toString(),
      observed: { cluster: drained.cluster, inventorySha256: drained.inventorySha256 } });
    stage = 'RESTORE_LEDGER';
    if (!sameHead((await ctx.verifier.verifyLineage(nextScope, lineage.head)).head, lineage.head)) {refuseRestore('RESTORE_LEDGER');}
    stage = 'RESTORE_CLOSED';
    abortCheck(signal);
    // The migrator transaction can publish only this proven epoch, using an exact CAS;
    // the runtime role has no CONNECT before this same commit. DB identifier parser already allowlisted.
    if (ACTIVATION_STARTED.has(conn)) { refuseRestore('RESTORE_CLOSED'); }
    ACTIVATION_STARTED.add(conn);
    const client = await conn.connect();
    let commitStarted = false;
    let discard = false;
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      stage = 'RESTORE_AUTHORITY';
      // Prevent writes (including on empty inventory) until the activation commits.
      const tables = p05Tables(source.profile);
      if (tables.length > 0) {
        await client.query(`LOCK TABLE ${tables.map(table => `foundation.${table}`).join(', ')} IN SHARE MODE`);
      }
      await requireP05AbsentForActivation(client, manifest, carried);
      const terminal = await observeFencedSource(observer, { ...source, challenge: last, backendPid: drained.backendPid }, limits, carried);
      requireP05ProfileFact(manifest, terminal, drained.nonce, new Date(), last);
      if (terminal.fact !== drained.fact || terminal.policySha256 !== drained.policySha256
        || terminal.manifestSha256 !== hash || terminal.inventorySha256 !== fresh.inventorySha256
        || !sameCluster(terminal.cluster, fresh.cluster)) {
        refuseRestore('RESTORE_AUTHORITY');
      }
      abortCheck(signal);
      stage = 'RESTORE_CLOSED';
      const cas = await client.query(`UPDATE foundation.file_runtime_epochs SET mode='ACTIVE',epoch=$3
        WHERE singleton AND namespace_id=$1 AND epoch=$2 AND mode='RESTORE_CLOSED'
        AND current_database()=$4 AND NOT pg_is_in_recovery()
        AND (SELECT oid::text FROM pg_database WHERE datname=current_database())=$5
        AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT')`,
      [old.namespace, old.writerEpoch.toString(), nextScope.writerEpoch.toString(), manifest.destinationDatabase, restoredEpoch.oid]);
      if (cas.rowCount !== 1) { refuseRestore('RESTORE_CLOSED'); }
      commitStarted = true;
      const completion = await client.query('COMMIT');
      if (completion.command !== 'COMMIT') { refuseRestore('RESTORE_COMMIT_UNKNOWN'); }
    } catch (error) {
      if (commitStarted) {
        discard = true;
        stage = 'RESTORE_COMMIT_UNKNOWN';
      } else {
        try { await client.query('ROLLBACK'); } catch { discard = true; }
      }
      throw error;
    } finally { client.release(discard); }
    const receipt: RestoreGateReceipt = Object.freeze({ mode: 'ACTIVE', epoch: Object.freeze({ namespace: old.namespace,
      epoch: nextScope.writerEpoch }), copied: resolved.size, tombstoned, unresolved });
    ALIASES.set(receipt, { database: manifest.destinationDatabase, entries: resolved,
      destinations: Object.freeze(manifest.aliases.map(pair => pair.destination)) });
    return receipt;
  } catch {
    if (stage === 'RESTORE_COMMIT_UNKNOWN') { return refuseRestore(stage); }
    if (ABORTED !== undefined && signal instanceof AbortSignal && Reflect.apply(ABORTED, signal, []) === true) {refuseRestore('RESTORE_ABORTED');}
    return refuseRestore(stage);
  }
}

/** The only read remap: reauthorize via ordinary F access, consume its branded grant here, keep the key unchanged. */
export function createRestoredReadyStorage(receipt: RestoreGateReceipt, readerTargets: readonly RestoreReaderTarget[]): ReadyReadStorage {
  const aliases = ALIASES.get(receipt)?.entries;
  if (aliases === undefined) {return refuseRestore('RESTORE_AUTHORITY');}
  const readers = new Map(readerTargets.map(entry => [targetId(entry.target), { target: Object.freeze({ ...entry.target }), reader: entry.reader }]));
  const seen = new WeakSet<ReadyGetGrant>();
  return Object.freeze({ async fetchReadyBytes(grant: ReadyGetGrant, opts: Parameters<ReadyReadStorage['fetchReadyBytes']>[1]) {
    const facts = requireLifecycleGetGrant(grant, 'READY');
    if (facts.kind !== 'READY' || seen.has(grant) || facts.namespaceId !== receipt.epoch.namespace || facts.runtimeEpoch !== receipt.epoch.epoch) {
      throw privateStorageError('ATTEMPT_INVALID');
    }
    const alias = aliases.get(`SANITIZED/${facts.attemptId}`);
    const original = alias?.object;
    const physical = alias === undefined ? undefined : readers.get(targetId(alias.destination));
    if (original === undefined || physical === undefined || original.intentId !== facts.intentId || original.key !== facts.objectKey
      || original.bytes !== facts.expectedBytes || original.sha256 !== facts.expectedSha256 || targetId(original.target) !== targetId(facts.target)) {
      throw privateStorageError('ATTEMPT_INVALID');
    }
    seen.add(grant);
    const { intentId, quarantineId, attemptId, publicationId, objectKey, expectedBytes, expectedSha256, namespaceId,
      runtimeEpoch, accessEpoch, claimId, claimGeneration } = facts;
    return physical.reader.fetchReadyBytes(issueReadyGetGrant({ intentId, quarantineId, attemptId, publicationId, objectKey,
      expectedBytes, expectedSha256, namespaceId, runtimeEpoch, accessEpoch, claimId, claimGeneration, target: physical.target }), opts);
  } });
}