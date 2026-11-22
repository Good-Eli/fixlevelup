import { randomBytes } from 'node:crypto';
import type { LedgerItem, LedgerScope } from '../file-ledger/contract.js';
import type { StorageTarget } from '../storage/attempt.js';
import type { RestoreContext, RestoreObject, RestoreReaderTarget, RestoreGateReceipt, SignedSnapshotManifest, FileRestoreFailure } from './contract.js';
import { refuseRestore } from './contract.js';
import { readAuthorityInventory, readRestoreInventory, requireExactTombstones, requireMatchingInventory } from './inventory.js';
import { objectId, readAuthority, readSnapshot, sameHead, sha256, targetId, validateLimits, verifyApproval } from './records.js';
import { issueReadyGetGrant, requireLifecycleGetGrant, type ReadyGetGrant } from '../storage/lifecycle-proof.js';
import type { ReadyReadStorage } from '../file-lifecycle/contract.js';
import { privateStorageError } from '../storage/errors.js';

const IDLE = new WeakSet<object>();
// Native getter enforces the brand and cannot be overridden by an own property.
// eslint-disable-next-line @typescript-eslint/unbound-method
const ABORTED = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;
const NONCE = (): string => randomBytes(32).toString('hex');
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
    stage = 'RESTORE_AUTHORITY';
    const challenge = NONCE();
    const auth = readAuthority(await ctx.currentAuthority({ manifestSha256: hash, challenge }, signal), ctx.authorityKey);
    if (auth.record.challenge !== challenge || auth.record.manifestSha256 !== hash || auth.record.head.namespace !== nextScope.namespace
      || auth.record.head.incarnation !== nextScope.incarnation || auth.record.head.writerEpoch !== nextScope.writerEpoch) {refuseRestore('RESTORE_AUTHORITY');}
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
    await ctx.restoreArchives(manifest, auth.record, signal);
    const conn = ctx.targetOperatorPool;
    const { rows: [epoch] } = await conn.query<{ db: string; namespace: string; epoch: string; mode: string; connect: boolean }>(`SELECT
      current_database() AS db,namespace_id::text AS namespace,epoch::text,mode,
      has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT') AS connect
      FROM foundation.file_runtime_epochs WHERE singleton`);
    if (epoch === undefined || epoch.db !== manifest.destinationDatabase || epoch.namespace !== old.namespace
      || epoch.epoch !== old.writerEpoch.toString() || epoch.mode !== 'RESTORE_CLOSED' || epoch.connect) {refuseRestore('RESTORE_CLOSED');}
    stage = 'RESTORE_AUTHORITY';
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
    const fresh = readAuthority(await ctx.currentAuthority({ manifestSha256: hash, challenge: last }, signal), ctx.authorityKey).record;
    if (fresh.challenge !== last || fresh.manifestSha256 !== hash || fresh.overlaySha256 !== auth.record.overlaySha256
      || fresh.inventorySha256 !== auth.record.inventorySha256 || !sameHead(fresh.head, lineage.head)) {refuseRestore('RESTORE_AUTHORITY');}
    stage = 'RESTORE_LEDGER';
    if (!sameHead((await ctx.verifier.verifyLineage(nextScope, lineage.head)).head, lineage.head)) {refuseRestore('RESTORE_LEDGER');}
    stage = 'RESTORE_CLOSED';
    abortCheck(signal);
    // The migrator transaction can publish only this proven epoch, using an exact CAS;
    // the runtime role has no CONNECT before this same commit. DB identifier parser already allowlisted.
    const client = await conn.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      const cas = await client.query(`UPDATE foundation.file_runtime_epochs SET mode='ACTIVE',epoch=$3
        WHERE singleton AND namespace_id=$1 AND epoch=$2 AND mode='RESTORE_CLOSED'
        AND current_database()=$4 AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT')`,
      [old.namespace, old.writerEpoch.toString(), nextScope.writerEpoch.toString(), manifest.destinationDatabase]);
      if (cas.rowCount !== 1) {refuseRestore('RESTORE_CLOSED');}
      // No runtime role credentials are delivered by this function; the installer wires them only on confirmed acknowledgement.
      await client.query('COMMIT');
    } catch {
      await client.query('ROLLBACK').catch(() => undefined);
      refuseRestore('RESTORE_CLOSED');
    } finally { client.release(); }
    const receipt: RestoreGateReceipt = Object.freeze({ mode: 'ACTIVE', epoch: Object.freeze({ namespace: old.namespace,
      epoch: nextScope.writerEpoch }), copied: resolved.size, tombstoned, unresolved });
    ALIASES.set(receipt, { database: manifest.destinationDatabase, entries: resolved,
      destinations: Object.freeze(manifest.aliases.map(pair => pair.destination)) });
    return receipt;
  } catch {
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