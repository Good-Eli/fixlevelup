import { createHash, createPublicKey, type KeyObject } from 'node:crypto';
import { canonicalRegistryTarget } from '../storage/config.js';
import { FileLedgerError, type LedgerFloor, type LedgerGraph, type LedgerHead, type LedgerItem, type LedgerLimits, type LedgerScope } from './contract.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BIGINT = 9_223_372_036_854_775_807n;
export const MAX_ITEMS = 2_048, MAX_EVENTS = 4_096, MAX_PAYLOAD_BYTES = 524_288, MAX_PROOF_BYTES = 16_777_216;
export const SCOPE_FIELDS = ['namespace', 'incarnation', 'writerEpoch'] as const;
export const HEAD_FIELDS = [...SCOPE_FIELDS, 'seq', 'hash'] as const;
export function invalid(): never { throw new FileLedgerError('INVALID_LEDGER_INPUT'); }
export function unavailable(): never { throw new FileLedgerError('LEDGER_UNAVAILABLE'); }
export function deny(): never { throw new FileLedgerError('LEDGER_DENIED'); }

export function plain<K extends string>(value: unknown, required: readonly K[], optional?: K): Record<K, unknown> {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) { invalid(); }
    const prototype = Reflect.getPrototypeOf(value);
    const keys = optional !== undefined && Object.hasOwn(value, optional) ? [...required, optional] : required;
    if ((prototype !== null && prototype !== Object.prototype) || Reflect.ownKeys(value).length !== keys.length) { invalid(); }
    const result = Object.create(null) as Record<K, unknown>;
    for (const key of keys) {
      const desc = Reflect.getOwnPropertyDescriptor(value, key);
      if (!desc || !('value' in desc)) {invalid();}
      result[key] = desc.value;
    }
    return result;
  } catch { invalid(); }
}
export function array(value: unknown, limit: number, exact?: number): unknown[] {
  try {
    if (!Array.isArray(value) || Reflect.getPrototypeOf(value) !== Array.prototype) {invalid();}
    const length: unknown = Reflect.getOwnPropertyDescriptor(value, 'length')?.value;
    if (typeof length !== 'number' || !Number.isInteger(length) || length < 0 || length > limit || (exact !== undefined && length !== exact)) {invalid();}
    if (Reflect.ownKeys(value).length !== length + 1) {invalid();}
    return Array.from({ length }, (_, i) => {
      const desc = Reflect.getOwnPropertyDescriptor(value, String(i));
      return desc && 'value' in desc ? desc.value as unknown : invalid();
    });
  } catch { invalid(); }
}
export function uuid(value: unknown, fresh = false): string {
  return typeof value === 'string' && value.length === 36 && (fresh ? UUID_V4 : UUID).test(value) ? value : invalid();
}
export function hash(value: unknown): string {
  return typeof value === 'string' && value.length === 64 && /^[0-9a-f]{64}$/.test(value) ? value : invalid();
}
export function counter(value: unknown, min = 1n): bigint {
  return typeof value === 'bigint' && value >= min && value <= MAX_BIGINT ? value : invalid();
}
export function decimal(value: unknown, min = 1n): bigint {
  return typeof value === 'string' && value.length <= 19 && /^(0|[1-9][0-9]*)$/.test(value) ? counter(BigInt(value), min) : invalid();
}
function intLimit(value: unknown, upper: number, min = 1): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= upper ? value : invalid();
}
export function ledgerLimits(input: LedgerLimits): LedgerLimits {
  const v = plain(input, ['maxItems', 'maxProofEvents']);
  return Object.freeze({ maxItems: intLimit(v.maxItems, MAX_ITEMS), maxProofEvents: intLimit(v.maxProofEvents, MAX_EVENTS) });
}
function scope(v: Record<(typeof SCOPE_FIELDS)[number], unknown>): LedgerScope {
  return { namespace: uuid(v.namespace, true), incarnation: uuid(v.incarnation, true), writerEpoch: counter(v.writerEpoch) };
}
export function ledgerScope(input: unknown): LedgerScope { return Object.freeze(scope(plain(input, SCOPE_FIELDS))); }
function head(v: Record<(typeof HEAD_FIELDS)[number], unknown>): LedgerHead {
  return { ...scope(v), seq: counter(v.seq, 0n), hash: hash(v.hash) };
}
export function ledgerHead(input: unknown): LedgerHead { return Object.freeze(head(plain(input, HEAD_FIELDS))); }
export function ledgerFloor(input: unknown): LedgerFloor {
  const v = plain(input, [...HEAD_FIELDS, 'keySha256']);
  return Object.freeze({ ...head(v), keySha256: hash(v.keySha256) });
}
export function sameNamespace(a: LedgerScope, b: LedgerScope): boolean {
  return a.namespace === b.namespace && a.incarnation === b.incarnation;
}
export function sameHead(a: LedgerHead, b: LedgerHead): boolean {
  return sameNamespace(a, b) && a.writerEpoch === b.writerEpoch && a.seq === b.seq && a.hash === b.hash;
}
export function scopeOf(value: LedgerScope): LedgerScope {
  return { namespace: value.namespace, incarnation: value.incarnation, writerEpoch: value.writerEpoch };
}
function item(input: unknown): LedgerItem {
  const v = plain(input, ['kind', 'attemptId', 'target', 'objectKey', 'writeProof']);
  const t = plain(v.target, ['endpoint', 'bucket', 'region']);
  const target = canonicalRegistryTarget(t.endpoint, t.bucket, t.region) ?? invalid();
  const attemptId = uuid(v.attemptId, true);
  if ((v.kind !== 'RAW' && v.kind !== 'SANITIZED') || (v.writeProof !== 'NEVER_DISPATCHED'
    && v.writeProof !== 'VERIFIED_SETTLED' && v.writeProof !== 'UNKNOWN')) {invalid();}
  const prefix = `${v.kind === 'RAW' ? 'quarantine' : 'sanitized'}/${attemptId}/`;
  if (typeof v.objectKey !== 'string' || v.objectKey.length !== prefix.length + 36 || !v.objectKey.startsWith(prefix)) {invalid();}
  uuid(v.objectKey.slice(prefix.length), true);
  return Object.freeze({ kind: v.kind, attemptId, target, objectKey: v.objectKey, writeProof: v.writeProof });
}
export function encodeGraph(input: LedgerGraph, maxItems: number): { graph: LedgerGraph; payload: Buffer } {
  const v = plain(input, [...SCOPE_FIELDS, 'eventId', 'intentId', 'accessEpoch', 'items']);
  const items = array(v.items, intLimit(maxItems, MAX_ITEMS)).map(item);
  const identity = (i: LedgerItem): string => `${i.kind}/${i.attemptId}`;
  items.sort((a, b) => identity(a) < identity(b) ? -1 : identity(a) === identity(b) ? 0 : 1);
  if (new Set(items.map(identity)).size !== items.length || new Set(items.map((i) =>
    `${i.target.endpoint}/${i.target.bucket}/${i.target.region}/${i.objectKey}`)).size !== items.length) {invalid();}
  const graph = Object.freeze({ ...scope(v), eventId: uuid(v.eventId), intentId: uuid(v.intentId), accessEpoch: counter(v.accessEpoch), items: Object.freeze(items) });
  const tuples = items.map((i) => [i.kind, i.attemptId, i.target.endpoint, i.target.bucket, i.target.region, i.objectKey, i.writeProof]);
  const payload = json([1, graph.namespace, graph.incarnation, graph.writerEpoch.toString(), graph.eventId, graph.intentId,
    graph.accessEpoch.toString(), tuples.length, tuples]);
  if (payload.length > MAX_PAYLOAD_BYTES) { invalid(); }
  return { graph, payload };
}
export function decodeGraph(payload: Buffer, maxItems: number): LedgerGraph {
  if (payload.length > MAX_PAYLOAD_BYTES) {invalid();}
  const [v, namespace, incarnation, writerEpoch, eventId, intentId, accessEpoch, count, tuples] = array(JSON.parse(payload.toString('utf8')), 9, 9);
  if (v !== 1) {invalid();}
  const items = array(tuples, maxItems, intLimit(count, maxItems, 0)).map((tuple) => {
    const [kind, attemptId, endpoint, bucket, region, objectKey, writeProof] = array(tuple, 7, 7);
    return { kind, attemptId, target: { endpoint, bucket, region }, objectKey, writeProof };
  });
  const canonical = encodeGraph({ namespace, incarnation, writerEpoch: decimal(writerEpoch), eventId, intentId, accessEpoch: decimal(accessEpoch), items } as LedgerGraph, maxItems);
  if (!canonical.payload.equals(payload)) {invalid();}
  return canonical.graph;
}
export function json(value: unknown): Buffer { return Buffer.from(JSON.stringify(value), 'utf8'); }
const sha = (value: Buffer): string => createHash('sha256').update(value).digest('hex');
export function ledgerGraphSha256(graph: LedgerGraph, maxItems: number): string { return sha(encodeGraph(graph, maxItems).payload); }
export function chainHash(previousHash: string, seq: bigint, payload: Buffer): string {
  return createHash('sha256').update('fixlevelup/file-ledger/chain/v1\n').update(previousHash).update('\n')
    .update(seq.toString()).update('\n').update(payload).digest('hex');
}
export function genesisHash(scope: LedgerScope, keySha256: string): string {
  return sha(json(['fixlevelup/file-ledger/genesis/v1', scope.namespace, scope.incarnation, scope.writerEpoch.toString(), keySha256]));
}
export function headMessage(head: LedgerHead, challenge: string): Buffer {
  return json(['fixlevelup/file-ledger/head', 1, head.namespace, head.incarnation, head.writerEpoch.toString(), head.seq.toString(), head.hash, challenge]);
}
export function keyPin(key: KeyObject): string {
  try {
    const publicKey = key.type === 'private' ? createPublicKey(key) : key;
    if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') {invalid();}
    return sha(publicKey.export({ type: 'spki', format: 'der' }));
  } catch { invalid(); }
}
