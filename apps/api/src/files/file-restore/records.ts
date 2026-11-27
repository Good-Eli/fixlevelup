import { createHash, sign, verify, type KeyObject } from 'node:crypto';
import type { LedgerHead } from '../file-ledger/contract.js';
import type { StorageTarget } from '../storage/attempt.js';
import { canonicalRegistryTarget } from '../storage/config.js';
import type { AuthorityRecord, AuthorityRecordV2, AuthorityRecordV3, ClusterFact, RestoreAlias, RestoreApproval, RestoreLimits, RestoreObject, SignedRestoreRecord, SnapshotManifest } from './contract.js';
import { refuseRestore } from './contract.js';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const V4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SOURCE = /^fixlevelup_legal_test_[a-f0-9]{24}$/;
const DEST = /^fixlevelup_file_restore_[a-f0-9]{24}$/;
const BUCKET = /^fixlevelup-restore-[a-f0-9]{24}$/;
const MAX_BIGINT = 9_223_372_036_854_775_807n;
const deny = (): never => refuseRestore('RESTORE_INPUT');
export function sha256(value: string | Uint8Array): string { return createHash('sha256').update(value).digest('hex'); }
export function checkDatabaseNames(source: string, destination: string): void {
  if (!SOURCE.test(source) || !DEST.test(destination)) {deny();}
}
export function integer(v: unknown, max: number, min = 1): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < min || v > max) {return deny();}
  return v;
}
export function validateLimits(limits: RestoreLimits): RestoreLimits {
  return Object.freeze({ maxObjects: integer(limits.maxObjects, 4096), maxIntents: integer(limits.maxIntents, 4096),
    maxObjectBytes: integer(limits.maxObjectBytes, 16_777_216), maxTotalObjectBytes: integer(limits.maxTotalObjectBytes, 268_435_456),
    maxManifestBytes: integer(limits.maxManifestBytes, 4_194_304), maxDumpBytes: integer(limits.maxDumpBytes, 268_435_456) });
}
function uuid(v: unknown, format = UUID): string {
  return typeof v === 'string' && v.length === 36 && format.test(v) ? v : deny();
}
function digest(v: unknown): string { return typeof v === 'string' && v.length === 64 && /^[a-f0-9]{64}$/.test(v) ? v : deny(); }
function decimal(v: unknown, min: bigint): bigint {
  if (typeof v !== 'string' || v.length > 19 || !/^(0|[1-9][0-9]*)$/.test(v)) {return deny();}
  const n = BigInt(v);
  if (n < min || n > MAX_BIGINT) {return deny();}
  return n;
}
function tuple(value: unknown, length: number): readonly unknown[] {
  return Array.isArray(value) && value.length === length ? value : deny();
}
function list(value: unknown, max: number): readonly unknown[] {
  return Array.isArray(value) && value.length <= max ? value : deny();
}
function target(value: unknown): StorageTarget {
  const [endpoint, bucket, region] = tuple(value, 3);
  const result = canonicalRegistryTarget(endpoint, bucket, region);
  return result === undefined ? deny() : Object.freeze(result);
}
function head(value: unknown): LedgerHead {
  const [namespace, incarnation, epoch, seq, hash] = tuple(value, 5);
  return Object.freeze({ namespace: uuid(namespace, V4), incarnation: uuid(incarnation, V4), writerEpoch: decimal(epoch, 1n), seq: decimal(seq, 0n), hash: digest(hash) });
}
function readObject(value: unknown, limits: RestoreLimits): RestoreObject {
  const [kind, rawIntent, rawAttempt, key, store, disposition, rawBytes, hash] = tuple(value, 8);
  const intentId = uuid(rawIntent);
  const attemptId = uuid(rawAttempt, V4);
  if (kind !== 'RAW' && kind !== 'SANITIZED') {return deny();}
  const prefix = `${kind === 'RAW' ? 'quarantine' : 'sanitized'}/${attemptId}/`;
  if (typeof key !== 'string' || !key.startsWith(prefix)) {return deny();}
  uuid(key.slice(prefix.length), V4);
  if (disposition !== 'COPY' && disposition !== 'NEVER_DISPATCHED' && disposition !== 'UNRESOLVED' && disposition !== 'TOMBSTONED') {return deny();}
  if (disposition !== 'COPY' && (rawBytes !== null || hash !== null)) {return deny();}
  return Object.freeze({ kind, intentId, attemptId, key, target: target(store), disposition,
    bytes: disposition === 'COPY' ? integer(rawBytes, limits.maxObjectBytes) : null,
    sha256: disposition === 'COPY' ? digest(hash) : null });
}
const targetTuple = (t: StorageTarget): readonly string[] => [t.endpoint, t.bucket, t.region];
export const physicalBucket = (t: StorageTarget): string => JSON.stringify([t.endpoint, t.bucket]);
export const targetId = (t: StorageTarget): string => JSON.stringify(targetTuple(t));
export const objectId = (o: Pick<RestoreObject, 'kind' | 'attemptId'>): string => `${o.kind}/${o.attemptId}`;
export const headTuple = (h: LedgerHead): readonly string[] => [h.namespace, h.incarnation, h.writerEpoch.toString(), h.seq.toString(), h.hash];
const objectTuple = (o: RestoreObject): readonly unknown[] => [o.kind, o.intentId, o.attemptId, o.key, targetTuple(o.target), o.disposition, o.bytes, o.sha256];
export const inventoryJson = (objects: readonly RestoreObject[]): string => JSON.stringify(objects.map(objectTuple));
export const sameHead = (a: LedgerHead, b: LedgerHead): boolean => JSON.stringify(headTuple(a)) === JSON.stringify(headTuple(b));

function snapshotValue(s: SnapshotManifest): readonly unknown[] {
  const fields = [s.sourceDatabase, s.destinationDatabase, s.schemaVersion, s.dumpSha256, headTuple(s.base),
    s.aliases.map(a => [targetTuple(a.source), targetTuple(a.destination)]), s.inventory.map(objectTuple)];
  return s.policySha256 === undefined ? [1, ...fields] : [2, ...fields, s.policySha256];
}
function authorityValue(r: AuthorityRecord): readonly unknown[] {
  return [1, r.challenge, r.manifestSha256, r.overlaySha256, r.inventorySha256, headTuple(r.head)];
}
const DIGITS = /^(0|[1-9][0-9]{0,19})$/;
function clusterFact(value: unknown): ClusterFact {
  const [systemIdentifier, serverVersionNum, postmasterStart] = tuple(value, 3);
  // system_identifier is a uint64 decimal text; the version is a reviewed 6-digit
  // major; the start time is the exact database-rendered timestamptz text.
  if (typeof systemIdentifier !== 'string' || !DIGITS.test(systemIdentifier)
    || typeof serverVersionNum !== 'string' || !/^[1-9][0-9]{5}$/.test(serverVersionNum)
    || typeof postmasterStart !== 'string' || postmasterStart.length < 10 || postmasterStart.length > 64) {return deny();}
  return Object.freeze({ systemIdentifier, serverVersionNum, postmasterStart });
}
const PROFILE = /^S[0-3]$/;
function authorityV2Value(r: AuthorityRecordV2): readonly unknown[] {
  return [2, r.challenge, r.manifestSha256, r.overlaySha256, r.inventorySha256, headTuple(r.head),
    r.sourceDatabase, r.sourceDatabaseOid, [r.cluster.systemIdentifier, r.cluster.serverVersionNum, r.cluster.postmasterStart],
    r.sourceProfile, r.oldNamespace, r.oldWriterEpoch, r.destinationDatabase];
}
function authorityV3Value(r: AuthorityRecordV3): readonly unknown[] {
  return [3, ...authorityV2Value(r).slice(1), r.drainFact, r.policySha256];
}
function approvalValue(a: RestoreApproval): readonly unknown[] { return [1, a.challenge, a.authoritySha256, a.destinationDatabase]; }
function message(domain: string, payload: string): Buffer { return Buffer.from(`fixlevelup/file-restore/${domain}/v1\n${payload}`, 'utf8'); }
function signed(domain: string, value: readonly unknown[], key: KeyObject): SignedRestoreRecord {
  const payload = JSON.stringify(value);
  return Object.freeze({ payload, signature: sign(null, message(domain, payload), key).toString('base64url') });
}
/** These signers are for the trusted operator tools only; no feature barrel or HTTP. */
export const signSnapshot = (value: SnapshotManifest, key: KeyObject): SignedRestoreRecord => signed('snapshot', snapshotValue(value), key);
export const signAuthority = (value: AuthorityRecord, key: KeyObject): SignedRestoreRecord => signed('authority', authorityValue(value), key);
/** §5.3: the only admission-bearing authority. A v1 signature stays verifiable for
 * legacy artifacts but is refused as admission by `requireAuthorityV2`. */
export const signAuthorityV2 = (value: AuthorityRecordV2, key: KeyObject): SignedRestoreRecord => signed('authority-v2', authorityV2Value(value), key);
export const signAuthorityV3 = (value: AuthorityRecordV3, key: KeyObject): SignedRestoreRecord => signed('authority-v3', authorityV3Value(value), key);
export const signApproval = (value: RestoreApproval, key: KeyObject): SignedRestoreRecord => signed('approval', approvalValue(value), key);

function verified(domain: string, input: unknown, key: KeyObject, maxBytes: number): { payload: string; parsed: unknown } {
  try {
    if (input === null || typeof input !== 'object') {return deny();}
    const prototype: unknown = Reflect.getPrototypeOf(input);
    if ((prototype !== Object.prototype && prototype !== null) || Reflect.ownKeys(input).length !== 2) {return deny();}
    const payload: unknown = Reflect.getOwnPropertyDescriptor(input, 'payload')?.value;
    const signature: unknown = Reflect.getOwnPropertyDescriptor(input, 'signature')?.value;
    if (typeof payload !== 'string' || payload.length > maxBytes || Buffer.byteLength(payload) > maxBytes
      || typeof signature !== 'string' || !/^[a-zA-Z0-9_-]{86}$/.test(signature) || key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {return deny();}
    const sig = Buffer.from(signature, 'base64url');
    if (sig.toString('base64url') !== signature || !verify(null, message(domain, payload), key, sig)) {return deny();}
    const parsed: unknown = JSON.parse(payload);
    return { payload, parsed };
  } catch { return deny(); }
}
export function readSnapshot(input: SignedRestoreRecord, key: KeyObject, limits: RestoreLimits): { manifest: SnapshotManifest; hash: string } {
  const { payload, parsed } = verified('snapshot', input, key, limits.maxManifestBytes);
  const isCarried = Array.isArray(parsed) && parsed[0] === 2;
  const [version, sourceDatabase, destinationDatabase, schemaVersion, dumpSha, rawHead, pairs, contents, rawPolicy] = tuple(parsed, isCarried ? 9 : 8);
  if ((version !== 1 && version !== 2) || typeof sourceDatabase !== 'string' || typeof destinationDatabase !== 'string'
    || typeof schemaVersion !== 'string' || !/^\d{14}_[a-z_]+$/.test(schemaVersion)) {return deny();}
  checkDatabaseNames(sourceDatabase, destinationDatabase);
  const aliases: readonly RestoreAlias[] = Object.freeze(list(pairs, limits.maxObjects).map(raw => {
    const [from, to] = tuple(raw, 2);
    const source = target(from);
    const destination = target(to);
    if (!BUCKET.test(destination.bucket)) {return deny();}
    return Object.freeze({ source, destination });
  }));
  const inventory = Object.freeze(list(contents, limits.maxObjects).map(o => readObject(o, limits)));
  const sources = new Set(aliases.map(x => targetId(x.source)));
  const oldBuckets = new Set(aliases.map(x => physicalBucket(x.source)));
  const used = new Set(inventory.map(x => targetId(x.target)));
  if (sources.size !== aliases.length || oldBuckets.size !== aliases.length || sources.size !== used.size
    || used.size !== [...used].filter(t => sources.has(t)).length
    || new Set(aliases.map(x => physicalBucket(x.destination))).size !== aliases.length
    || aliases.some(x => oldBuckets.has(physicalBucket(x.destination)))
    || new Set(inventory.map(objectId)).size !== inventory.length
    || new Set(inventory.map(x => `${physicalBucket(x.target)}/${x.key}`)).size !== inventory.length
    || inventory.some((x, i) => i > 0 && objectId(inventory[i - 1] as RestoreObject) >= objectId(x))
    || inventory.reduce((n, o) => n + (o.bytes ?? 0), 0) > limits.maxTotalObjectBytes) {return deny();}
  const manifest = Object.freeze({ sourceDatabase, destinationDatabase, schemaVersion, dumpSha256: digest(dumpSha), base: head(rawHead), aliases, inventory,
    ...(isCarried ? { policySha256: digest(rawPolicy) } : {}) });
  if (JSON.stringify(snapshotValue(manifest)) !== payload) {return deny();}
  return { manifest, hash: sha256(payload) };
}
export function readAuthority(input: SignedRestoreRecord, key: KeyObject): { record: AuthorityRecord; hash: string } {
  const { payload, parsed } = verified('authority', input, key, 4096);
  const [v, challenge, manifest, overlay, inventory, ledgerHead] = tuple(parsed, 6);
  const record = Object.freeze({ challenge: digest(challenge), manifestSha256: digest(manifest), overlaySha256: digest(overlay),
    inventorySha256: digest(inventory), head: head(ledgerHead) });
  if (v !== 1 || JSON.stringify(authorityValue(record)) !== payload) {return deny();}
  return { record, hash: sha256(payload) };
}

/**
 * Reads the signed v2 authority (§5.3). Every bound field is re-serialized and
 * compared to the signed payload, so a partial or reordered record cannot pass.
 */
function parseBoundAuthority(fields: readonly unknown[]): AuthorityRecordV2 {
  const [, challenge, manifest, overlay, inventory, ledgerHead, sourceDatabase, rawOid, rawCluster, sourceProfile,
    oldNamespace, oldWriterEpoch, destinationDatabase] = fields;
  if (typeof sourceDatabase !== 'string' || typeof destinationDatabase !== 'string') {return deny();}
  checkDatabaseNames(sourceDatabase, destinationDatabase);
  if (typeof rawOid !== 'number' || !Number.isSafeInteger(rawOid) || rawOid < 1 || rawOid > 0xffff_ffff
    || typeof sourceProfile !== 'string' || !PROFILE.test(sourceProfile)
    || typeof oldNamespace !== 'string' || !UUID.test(oldNamespace)
    || typeof oldWriterEpoch !== 'string' || !DIGITS.test(oldWriterEpoch) || BigInt(oldWriterEpoch) < 1n) {return deny();}
  const record: AuthorityRecordV2 = Object.freeze({ challenge: digest(challenge), manifestSha256: digest(manifest),
    overlaySha256: digest(overlay), inventorySha256: digest(inventory), head: head(ledgerHead),
    sourceDatabase, sourceDatabaseOid: rawOid, cluster: clusterFact(rawCluster),
    sourceProfile: sourceProfile as AuthorityRecordV2['sourceProfile'], oldNamespace, oldWriterEpoch, destinationDatabase });
  return record;
}

export function readAuthorityV2(input: SignedRestoreRecord, key: KeyObject): { record: AuthorityRecordV2; hash: string } {
  const { payload, parsed } = verified('authority-v2', input, key, 8192);
  const record = parseBoundAuthority(tuple(parsed, 13));
  if (JSON.stringify(authorityV2Value(record)) !== payload) {return deny();}
  return { record, hash: sha256(payload) };
}

export function requireAuthorityV3(input: SignedRestoreRecord, key: KeyObject): { record: AuthorityRecordV3; hash: string } {
  try {
    const { payload, parsed } = verified('authority-v3', input, key, 8192);
    const fields = tuple(parsed, 15);
    const base = parseBoundAuthority(fields);
    if (base.sourceProfile !== 'S3' || fields[13] !== 'P05_EMPTY_AFTER_DRAIN') {return deny();}
    const record: AuthorityRecordV3 = Object.freeze({ ...base, sourceProfile: base.sourceProfile,
      drainFact: fields[13], policySha256: digest(fields[14]) });
    if (JSON.stringify(authorityV3Value(record)) !== payload) {return deny();}
    return { record, hash: sha256(payload) };
  } catch { return refuseRestore('RESTORE_AUTHORITY'); }
}

/**
 * §5.3 strict-empty admission: only a signed v2 authority may authorise opening the
 * target. A v1 record — even a valid, freshly signed one — names no source
 * database/OID/cluster/profile/epoch/destination, so it is refused rather than
 * silently upgraded; that is the "fail closed on the old record alone" rule.
 */
export function requireAuthorityV2(input: SignedRestoreRecord, key: KeyObject): { record: AuthorityRecordV2; hash: string } {
  try {
    return readAuthorityV2(input, key);
  } catch {
    // A legacy v1 record, a malformed one and a bad signature are one safe refusal:
    // the caller can never tell an old-but-valid record from an unverifiable one.
    return refuseRestore('RESTORE_AUTHORITY');
  }
}
export function verifyApproval(input: SignedRestoreRecord, key: KeyObject, expected: RestoreApproval): void {
  const { payload } = verified('approval', input, key, 4096);
  if (payload !== JSON.stringify(approvalValue(expected))) {deny();}
}