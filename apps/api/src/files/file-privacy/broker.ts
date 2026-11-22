import { Readable } from 'node:stream';
import { DeleteObjectCommand, GetObjectCommand, NoSuchKey } from '@aws-sdk/client-s3';
import type { S3Client } from '@aws-sdk/client-s3';
import type { LedgerItem } from '../file-ledger/contract.js';
import type { RestoreGateReceipt } from '../file-restore/contract.js';
import { readRestoreDeleteScope, resolveRestoredDeleteTarget } from '../file-restore/rescrub.js';
import { sameTarget } from '../storage/attempt.js';
import type { StorageTarget } from '../storage/attempt.js';
import { createS3Client, validateConfig } from '../storage/config.js';
import type { PrivateQuarantineStorageConfig, ValidatedStorageConfig } from '../storage/config.js';
import { bindProbeTransport, ProbeTransport } from '../storage/response-limiter.js';
import { consumeCommittedDeleteGrant } from './delete-claim.js';
import { refusePrivacy } from './contract.js';
import type { CommittedDeleteGrant, DeleteBroker } from './contract.js';
import { checkSignal, epochNumber, isAborted, nativeSignal, snapshotRecord, snapshotTargets, uuid } from './input.js';

interface ExactTarget {
  readonly client: S3Client;
  readonly config: ValidatedStorageConfig;
  active: number;
  uncertain: boolean;
}
interface BrokerState {
  readonly namespace: string;
  readonly epoch: bigint;
  readonly targets: readonly ExactTarget[];
  readonly restore?: RestoreGateReceipt;
  readonly database?: string;
  readonly work: Set<Promise<unknown>>;
  closed: boolean;
}
const brokers = new WeakMap<object, BrokerState>();

export function createSyntheticDeleteBroker(input: {
  readonly mode: 'local-synthetic'; readonly namespace: string; readonly epoch: bigint;
  readonly targets: readonly PrivateQuarantineStorageConfig[];
}): DeleteBroker {
  const cmd = snapshotRecord(input, ['mode','namespace','epoch','targets']);
  if (cmd['mode'] !== 'local-synthetic') { return refusePrivacy('NOT_CONFIGURED'); }
  const namespace = uuid(cmd['namespace']);
  const epoch = epochNumber(cmd['epoch']);
  if (epoch !== 1n) { return refusePrivacy('NOT_CONFIGURED'); }
  const bucketPrefix = `p0304-${namespace}`;
  return brokerFor(namespace, epoch, cmd['targets'], (config) => config.bucket === bucketPrefix ||
    (config.bucket.startsWith(`${bucketPrefix}-`) && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(config.bucket.slice(bucketPrefix.length + 1))));
}

/** The old physical coordinates cannot be configured on this broker, even with valid credentials. */
export function createRestoredDeleteBroker(receipt: RestoreGateReceipt, targets: readonly PrivateQuarantineStorageConfig[]): DeleteBroker {
  try {
    const scope = readRestoreDeleteScope(receipt);
    if (scope.epoch.epoch <= 1n) { return refusePrivacy('NOT_CONFIGURED'); }
    return brokerFor(scope.epoch.namespace, scope.epoch.epoch, targets,
      (target) => scope.destinations.some((destination) => sameTarget(target, destination)), { restore: receipt, database: scope.database });
  } catch {
    return refusePrivacy('NOT_CONFIGURED');
  }
}

function brokerFor(namespace: string, epoch: bigint, input: unknown, allowed: (target: StorageTarget) => boolean,
  authority?: { readonly restore: RestoreGateReceipt; readonly database: string },
): DeleteBroker {
  try {
    const configs = snapshotTargets(input).map(validateConfig);
    for (const [i, config] of configs.entries()) {
      if (!allowed(config) || configs.slice(0, i).some((other) => other.endpoint === config.endpoint && other.bucket === config.bucket)) {
        return refusePrivacy('NOT_CONFIGURED');
      }
    }
    const targets = configs.map((config): ExactTarget => ({ config, client: createS3Client(config), active: 0, uncertain: false }));
    const broker = Object.freeze({}) as DeleteBroker;
    brokers.set(broker, { namespace, epoch, targets, work: new Set(), closed: false, ...authority });
    return broker;
  } catch {
    return refusePrivacy('NOT_CONFIGURED');
  }
}

function stateOf(value: unknown): BrokerState {
  const state = typeof value === 'object' && value !== null ? brokers.get(value) : undefined;
  return state ?? refusePrivacy('NOT_CONFIGURED');
}
export function requireDeleteBroker(value: unknown, namespace: string, epoch: bigint): DeleteBroker {
  const state = stateOf(value);
  if (state.closed || state.namespace !== namespace || state.epoch !== epoch) { return refusePrivacy('NOT_CONFIGURED'); }
  return value as DeleteBroker;
}
export function brokerDatabase(broker: DeleteBroker): string | undefined { return stateOf(broker).database; }
function exactTarget(state: BrokerState, intentId: string, item: LedgerItem): ExactTarget | undefined {
  if (state.closed) { return undefined; }
  const tuple = state.restore === undefined ? item.target : resolveRestoredDeleteTarget(state.restore,
    { namespace: state.namespace, runtimeEpoch: state.epoch, intentId, item });
  if (tuple === undefined || (state.restore !== undefined && sameTarget(tuple, item.target))) { return undefined; }
  return state.targets.find((target) => sameTarget(target.config, tuple));
}
function targetAvailable(target: ExactTarget): boolean {
  return !target.uncertain && target.active < target.config.maxConcurrentOperations;
}
export function hasDeleteTarget(broker: DeleteBroker, intentId: string, item: LedgerItem): boolean {
  const target = exactTarget(stateOf(broker), intentId, item);
  return target !== undefined && targetAvailable(target);
}

/** Internal SQL scheduling filter only, never a claim or a substitute for the exact resolver.
 * At most MAX_TARGETS ordinary coordinates or the bounded verified restore copy inventory. */
export function brokerSchedule(broker: DeleteBroker): string {
  const state = stateOf(broker);
  const available = state.closed ? [] : state.targets.filter(targetAvailable);
  const tuple = ({ endpoint, bucket, region }: StorageTarget): StorageTarget => ({ endpoint, bucket, region });
  if (state.restore === undefined) {
    return JSON.stringify(available.map(({ config }) => tuple(config)));
  }
  return JSON.stringify(readRestoreDeleteScope(state.restore).copies.flatMap(({ object, destination }) =>
    object.disposition === 'COPY' && !sameTarget(object.target, destination) &&
      available.some(({ config }) => sameTarget(config, destination))
      ? [{ ...tuple(object.target), intent: object.intentId, kind: object.kind, attempt: object.attemptId, key: object.key }]
      : []));
}

/** Trusted runtime shutdown. No new admissions; socket-close uncertainty is not a remote write fence.
 * After closing this is an authoritative bar on new sends by this broker instance only. The restore
 * executor must separately attest that it controls every old instance/credential capable of sending. */
export async function revokeDeleteBroker(value: DeleteBroker): Promise<void> {
  const state = stateOf(value);
  state.closed = true;
  await Promise.allSettled(state.work);
  for (const target of state.targets) { target.client.destroy(); }
}

const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
type Result = 'AUTHENTICATED_404' | 'VERIFY_PENDING';
function isBrokerClosed(state: BrokerState): boolean { return state.closed; }
async function exactRequest(state: BrokerState, target: ExactTarget, key: string, signal: AbortSignal, deadline: number): Promise<Result> {
  const expiry = Math.floor(Math.min(deadline - performance.now(), target.config.operationTimeoutMs));
  if (expiry <= 0 || state.closed || isAborted(signal)) { return 'VERIFY_PENDING'; }
  const operation = AbortSignal.any([signal, AbortSignal.timeout(expiry)]);
  const input = { Bucket: target.config.bucket, Key: key };
  let transport = new ProbeTransport();
  bindProbeTransport(operation, transport);
  try {
    const deleted = await target.client.send(new DeleteObjectCommand(input), { abortSignal: operation });
    await transport.wait();
    if (deleted.$metadata.httpStatusCode !== 204 || !transport.settled || !transport.fullResponse ||
        isBrokerClosed(state) || isAborted(operation) || performance.now() >= deadline) { return 'VERIFY_PENDING'; }
    transport = new ProbeTransport();
    bindProbeTransport(operation, transport);
    try {
      const present = await target.client.send(new GetObjectCommand(input), { abortSignal: operation });
      // No object body is needed. Abort/dispose it without attempting to buffer a 200 or 206.
      if (present.Body instanceof Readable) { present.Body.destroy(); }
      return 'VERIFY_PENDING';
    } catch (error: unknown) {
      await transport.wait();
      if (!(error instanceof NoSuchKey) || error.$metadata.httpStatusCode !== 404 || !transport.settled ||
        !transport.fullResponse || isAborted(operation) || performance.now() >= deadline) { return 'VERIFY_PENDING'; }
      const response = error.$response;
      // A delete marker, version response, or partial response is not the pinned unversioned Garage semantics.
      return response?.statusCode === 404 && response.headers['content-range'] === undefined &&
        response.headers['x-amz-delete-marker'] === undefined && response.headers['x-amz-version-id'] === undefined
        ? 'AUTHENTICATED_404' : 'VERIFY_PENDING';
    }
  } catch {
    return 'VERIFY_PENDING';
  } finally {
    await transport.wait();
    // Handler rejection without an exposed response (e.g. timeout before headers): don't recycle this
    // local target's transport capacity based on a timer or promise rejection alone; restart/fence it.
    if (!transport.settled) { target.uncertain = true; }
  }
}

/** A one-shot exact grant; no arbitrary key, prefix, version, endpoint or LIST operation is accepted. */
export async function executeCommittedDelete(broker: DeleteBroker, token: CommittedDeleteGrant, abort: AbortSignal): Promise<Result> {
  const state = stateOf(broker);
  const signal = nativeSignal(abort);
  checkSignal(signal);
  const { namespace, runtimeEpoch, intentId, item, deadline } = consumeCommittedDeleteGrant(token, broker);
  const target = exactTarget(state, intentId, item);
  const prefix = `${item.kind === 'RAW' ? 'quarantine' : 'sanitized'}/${item.attemptId}/`;
  if (state.namespace !== namespace || state.epoch !== runtimeEpoch || state.closed ||
    target === undefined || !item.objectKey.startsWith(prefix) || !V4.test(item.objectKey.slice(prefix.length))) {
    return refusePrivacy('NOT_CONFIGURED');
  }
  if (target.uncertain || target.active >= target.config.maxConcurrentOperations || performance.now() >= deadline) { return 'VERIFY_PENDING'; }
  target.active++;
  const operation = exactRequest(state, target, item.objectKey, signal, deadline);
  state.work.add(operation);
  try { return await operation; } catch { return 'VERIFY_PENDING'; }
  finally { target.active--; state.work.delete(operation); }
}
