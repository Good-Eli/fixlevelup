import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { validateSanitizedImage } from '../file-processing/sanitized-image.js';
import type { RegisteredSanitizedAttempt, SanitizedAttempt, StorageTarget } from '../storage/index.js';
import { canonicalRegistryTarget } from '../storage/config.js';
import type { ContentDigest, FileProcessingPolicy, ImageMime, ProcessingContext, WorkerClean } from './contract.js';
import { refuseLifecycle } from './errors.js';
import { ownFields, positive } from './input.js';
import { SHA256 } from './publication.js';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;
const TA = Object.getPrototypeOf(Uint8Array.prototype) as object;
const SIGNATURES = { jpeg: Uint8Array.of(0xff, 0xd8, 0xff), png: Uint8Array.of(137, 80, 78, 71, 13, 10, 26, 10),
  riff: Uint8Array.of(82, 73, 70, 70), webp: Uint8Array.of(87, 69, 66, 80) };

export interface PreparedSanitized {
  readonly descriptor: SanitizedAttempt;
  readonly id: string;
  readonly key: string;
  readonly target: StorageTarget;
  readonly maxChunkBytes: number;
}
export interface Clean {
  readonly evidence: WorkerClean;
  readonly mime: ImageMime;
  readonly served: ContentDigest;
  readonly output: Uint8Array;
  readonly policySha256: string;
  readonly engineVersion: string;
  readonly engineImageSha256: string;
  readonly defsSha256: string;
  readonly defsBuiltAt: string;
}

function closeDigest(input: unknown, maximum: number): ContentDigest {
  const { bytes, sha256 } = ownFields(input, ['bytes', 'sha256']);
  if (typeof sha256 !== 'string' || !SHA256.test(sha256)) {
    refuseLifecycle('PROCESSING_DENIED');
  }
  return Object.freeze({ bytes: positive(bytes, maximum), sha256 });
}

function prefix(bytes: Uint8Array, marker: Uint8Array, offset = 0): boolean {
  return marker.every((value, i) => bytes[offset + i] === value);
}

function matchesMime(bytes: Uint8Array, mime: ImageMime): boolean {
  switch (mime) {
    case 'image/jpeg': return prefix(bytes, SIGNATURES.jpeg);
    case 'image/png': return prefix(bytes, SIGNATURES.png);
    case 'image/webp': return prefix(bytes, SIGNATURES.riff) && prefix(bytes, SIGNATURES.webp, 8);
  }
}

/** Copy exact bytes before handing them to another port. Never trust asserted length/hash. */
export function copyAndCheckBytes(input: unknown, expected: ContentDigest, mime: ImageMime): Uint8Array {
  try {
    if (!types.isUint8Array(input) || Reflect.get(TA, 'byteLength', input) !== expected.bytes
      || types.isSharedArrayBuffer(Reflect.get(TA, 'buffer', input))) {
      refuseLifecycle('PROCESSING_DENIED');
    }
    const copy = new Uint8Array(input);
    if (copy.byteLength !== expected.bytes || !matchesMime(copy, mime)
      || createHash('sha256').update(copy).digest('hex') !== expected.sha256) {
      refuseLifecycle('PROCESSING_DENIED');
    }
    return copy;
  } catch {
    refuseLifecycle('PROCESSING_DENIED');
  }
}

function policyDigest(policy: FileProcessingPolicy): string {
  // All values are closed, validated primitives. The allowlist was sorted in the private snapshot.
  return createHash('sha256').update(JSON.stringify(['file-processing-policy-v1', policy.mode, policy.versionId,
    policy.expiresAt.toISOString(), policy.allowedMimeTypes, policy.maxRawBytes, policy.maxOutputBytes,
    policy.maxWidth, policy.maxHeight, policy.maxPixels, policy.maxChannels, policy.leaseMs, policy.wallMs,
    policy.maxDefsAgeMs]), 'utf8').digest('hex');
}

export function snapshotClean(input: unknown, raw: ContentDigest, mime: ImageMime, policy: FileProcessingPolicy): Clean {
  let unsupported = false;
  try {
    if (typeof input !== 'object' || input === null) {
      refuseLifecycle('PROCESSING_DENIED');
    }
    if (Reflect.getOwnPropertyDescriptor(input, 'kind')?.value !== 'CLEAN') {
      const failed = ownFields(input, ['kind', 'reason']);
      unsupported = (failed.kind === 'BLOCKED' || failed.kind === 'INDETERMINATE') && failed.reason === 'UNSUPPORTED_FORMAT';
      refuseLifecycle('PROCESSING_DENIED');
    }
    const fields = ownFields(input, ['kind', 'raw', 'served', 'output', 'mime', 'engineVersion', 'engineImageSha256',
      'defsSha256', 'defsBuiltAt']);
    const workerRaw = closeDigest(fields.raw, policy.maxRawBytes);
    const served = closeDigest(fields.served, policy.maxOutputBytes);
    if (fields.kind !== 'CLEAN' || fields.mime !== mime || raw.bytes !== workerRaw.bytes || raw.sha256 !== workerRaw.sha256
      || typeof fields.engineVersion !== 'string' || fields.engineVersion.length > 32 || !/^\d+\.\d+\.\d+$/.test(fields.engineVersion)
      || typeof fields.engineImageSha256 !== 'string' || !SHA256.test(fields.engineImageSha256)
      || typeof fields.defsSha256 !== 'string' || !SHA256.test(fields.defsSha256)
      || typeof fields.defsBuiltAt !== 'string' || !ISO_UTC.test(fields.defsBuiltAt) || !Number.isFinite(Date.parse(fields.defsBuiltAt))) {
      refuseLifecycle('PROCESSING_DENIED');
    }
    const output = copyAndCheckBytes(fields.output, served, mime);
    if (!validateSanitizedImage(mime, output, policy)) {
      refuseLifecycle('PROCESSING_DENIED');
    }
    return Object.freeze({ evidence: input as WorkerClean, mime, served, output,
      policySha256: policyDigest(policy), engineVersion: fields.engineVersion, engineImageSha256: fields.engineImageSha256,
      defsSha256: fields.defsSha256, defsBuiltAt: fields.defsBuiltAt });
  } catch {
    refuseLifecycle(unsupported ? 'UNSUPPORTED_FORMAT' : 'PROCESSING_DENIED');
  }
}

export function prepareSanitized(ctx: ProcessingContext): PreparedSanitized {
  try {
    const prepared: RegisteredSanitizedAttempt = ctx.storage.prepareSanitizedAttempt();
    const id = prepared.attempt.attemptId;
    const key = prepared.attempt.objectKey;
    const target = canonicalRegistryTarget(prepared.target.endpoint, prepared.target.bucket, prepared.target.region);
    const maxChunkBytes = positive(prepared.maxChunkBytes, 67_108_864);
    const prefix = `sanitized/${id}/`;
    if (!UUID_V4.test(id) || !key.startsWith(prefix) || !UUID_V4.test(key.slice(prefix.length)) || target === undefined
      || maxChunkBytes < ctx.uploadPolicy.maxSourceChunkBytes) {
      refuseLifecycle('NOT_CONFIGURED');
    }
    return Object.freeze({ descriptor: prepared.attempt, id, key, target, maxChunkBytes: ctx.uploadPolicy.maxSourceChunkBytes });
  } catch {
    refuseLifecycle('NOT_CONFIGURED');
  }
}

function utcMicros(value: string): bigint {
  const ms = Date.parse(value);
  if (!ISO_UTC.test(value) || !Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== value.slice(0, 19)) {
    refuseLifecycle('PROCESSING_DENIED');
  }
  const tail = value.charAt(19) === '.' ? value.slice(20, -1).padEnd(6, '0').slice(3) : '000';
  return BigInt(ms) * 1_000n + BigInt(tail);
}

export function assertCurrentEvidence(ctx: ProcessingContext, clean: Clean, dbNow: string): void {
  try {
    const age = utcMicros(dbNow) - utcMicros(clean.defsBuiltAt);
    const current: unknown = ctx.processor.isEvidenceCurrent(clean.evidence, dbNow);
    if (age < 0n || age >= BigInt(ctx.policy.maxDefsAgeMs) * 1_000n || current !== true) {
      refuseLifecycle('PROCESSING_DENIED');
    }
  } catch {
    refuseLifecycle('PROCESSING_DENIED');
  }
}
