import { createHash } from 'node:crypto';
import { types } from 'node:util';

import type {
  ContentDigest, ImageMime, LocalFileProcessor, WorkerClean, WorkerReason, WorkerResult,
} from '../file-lifecycle/contract.js';
import { singleImageStructure } from './image-structure.js';
import {
  bytesLength, bytesProto, closed, decoderLimitKeys, decoderLimits, definitionEngineImage, definitionEngineVersion, imageMime,
  intrinsic, makeDecoderFrame, maxFrameBytes, positive,
} from './protocol.js';
import { validateSanitizedImage } from './sanitized-image.js';

export interface DefinitionEpoch {
  readonly engineVersion: typeof definitionEngineVersion;
  readonly engineImageSha256: string;
  readonly defsSha256: string;
  readonly defsBuiltAt: string;
}

export interface ChildResult {
  readonly reaped: true;
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly stdinComplete: boolean;
  readonly stdoutEof: boolean;
  readonly stderrEof: boolean;
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
}

/** Host-only port: a report attests confirmed sandbox reap and pipe closure, or no start.
 * A rejection lacks this proof. No DB, S3 or scanner capability is passed to the decoder. */
export interface FileProcessingLauncher {
  scan(input: Uint8Array, epoch: DefinitionEpoch, signal: AbortSignal): Promise<ChildResult>;
  decode(frame: readonly Uint8Array[], maxOutputBytes: number, signal: AbortSignal): Promise<ChildResult>;
}

const scannerResponseCap = 1024;
const shaPattern = /^[0-9a-f]{64}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const datePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;
const timerCap = 0x7fffffff;
const getAborted = intrinsic(AbortSignal.prototype, 'aborted', true);
const getBuffer = intrinsic(bytesProto, 'buffer', true);
const addAbortListener = intrinsic(EventTarget.prototype, 'addEventListener', false);
const removeAbortListener = intrinsic(EventTarget.prototype, 'removeEventListener', false);

function utcMicros(text: unknown): bigint | undefined {
  if (typeof text !== 'string' || !datePattern.test(text)) { return undefined; }
  const ms = Date.parse(text);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== text.slice(0, 19)) { return undefined; }
  const micros = text.charAt(19) === '.' ? text.slice(20, -1).padEnd(6, '0').slice(3) : '000';
  return BigInt(ms) * 1_000n + BigInt(micros);
}

function settings(input: unknown) {
  const p = closed(input, ['epoch', 'maxRawBytes', 'maxOutputBytes', 'maxWallMs', 'maxJobs']);
  const e = closed(p.epoch, ['engineVersion', 'engineImageSha256', 'defsSha256', 'defsBuiltAt']);
  const builtAtMicros = utcMicros(e.defsBuiltAt);
  if (e.engineVersion !== definitionEngineVersion || e.engineImageSha256 !== definitionEngineImage ||
      typeof e.defsSha256 !== 'string' || !shaPattern.test(e.defsSha256) || typeof e.defsBuiltAt !== 'string' ||
      builtAtMicros === undefined) { throw new TypeError(); }
  const epoch: DefinitionEpoch = Object.freeze({
    engineVersion: e.engineVersion, engineImageSha256: e.engineImageSha256,
    defsSha256: e.defsSha256, defsBuiltAt: e.defsBuiltAt,
  });
  return {
    epoch, builtAtMicros, maxRawBytes: positive(p.maxRawBytes, maxFrameBytes),
    maxOutputBytes: positive(p.maxOutputBytes, maxFrameBytes), maxWallMs: positive(p.maxWallMs, timerCap),
    maxJobs: positive(p.maxJobs, 0x7fffffff),
  };
}

function policySnapshot(value: unknown, mime: ImageMime, config: ReturnType<typeof settings>) {
  const p = closed(value, ['mode', 'versionId', 'expiresAt', 'allowedMimeTypes', 'maxRawBytes',
    ...decoderLimitKeys, 'leaseMs', 'wallMs', 'maxDefsAgeMs']);
  const allowed = p.allowedMimeTypes;
  if (p.mode !== 'local-synthetic' || typeof p.versionId !== 'string' || !uuidPattern.test(p.versionId) ||
      !types.isDate(p.expiresAt) || types.isProxy(allowed) || !Array.isArray(allowed) || allowed.length < 1 || allowed.length > 3) {
    throw new TypeError();
  }
  if (Object.getPrototypeOf(allowed) !== Array.prototype || Reflect.ownKeys(allowed).length !== allowed.length + 1)
    {throw new TypeError();}
  const formats = new Set<unknown>();
  for (let i = 0; i < allowed.length; i++) {
    const d = Object.getOwnPropertyDescriptor(allowed, String(i));
    if (!d?.enumerable || !('value' in d) || !imageMime(d.value) || formats.has(d.value)) {throw new TypeError();}
    formats.add(d.value);
  }
  const expiresAt = Date.prototype.getTime.call(p.expiresAt);
  const maxRawBytes = positive(p.maxRawBytes, config.maxRawBytes);
  const limits = decoderLimits(p);
  const wallMs = positive(p.wallMs, config.maxWallMs);
  if (limits.maxOutputBytes > config.maxOutputBytes || !Number.isFinite(expiresAt) ||
      wallMs >= positive(p.leaseMs, timerCap)) {throw new TypeError();}
  return { mimeAllowed: formats.has(mime), expiresAt, maxRawBytes, limits, wallMs,
    maxDefsAgeMs: positive(p.maxDefsAgeMs, Number.MAX_SAFE_INTEGER) };
}

const fail = (reason: WorkerReason): WorkerResult => ({ kind: 'INDETERMINATE', reason });
const block = (reason: WorkerReason): WorkerResult => ({ kind: 'BLOCKED', reason });
const digest = (bytes: Uint8Array): ContentDigest => Object.freeze({
  bytes: bytes.byteLength, sha256: createHash('sha256').update(bytes).digest('hex'),
});

function structure(mime: ImageMime, bytes: Uint8Array, output: boolean): boolean {
  return singleImageStructure(mime, Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength), output);
}

function fullySettled(report: ChildResult, stdoutCap: number): boolean {
  return report.signal === null && [report.stdinComplete, report.stdoutEof, report.stderrEof].every((value: unknown) => value === true) &&
    bytesLength(report.stdout) <= stdoutCap && bytesLength(report.stderr) === 0;
}

function scannerVerdict(report: ChildResult): 'CLEAN' | 'MALWARE' | 'LIMIT_EXCEEDED' | 'SCAN_FAILED' {
  if (!fullySettled(report, scannerResponseCap)) {return 'SCAN_FAILED';}
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(report.stdout);
  if (report.exitCode === 0 && text === 'stdin: OK\n') {return 'CLEAN';}
  if (report.exitCode === 1) {
    const match = /^stdin: ([A-Za-z0-9_.(){}+-]{1,200}) FOUND\n$/.exec(text);
    if (match?.[0].length === text.length) {return match[1]?.startsWith('Heuristics.Limits.Exceeded.')
      ? 'LIMIT_EXCEEDED' : 'MALWARE';}
  }
  return 'SCAN_FAILED';
}

/** Internal default-off wiring. Revocation is terminal for this instance; new epoch requires new trusted wiring. */
export function createLocalFileProcessor(launcher: FileProcessingLauncher, input: unknown):
LocalFileProcessor & { readonly revokeDefinitions: () => void } {
  let config: ReturnType<typeof settings>;
  try { config = settings(input); } catch { throw new TypeError('Invalid local file processor configuration'); }
  const { epoch } = config;
  let revoked = false;
  const active = new Set<AbortController>();
  const issued = new WeakMap<WorkerClean, { readonly maxDefsAgeMs: number; readonly expiresAt: number }>();
  return Object.freeze({
    revokeDefinitions(): void {
      revoked = true;
      for (const operation of active) { operation.abort(); }
    },
    isEvidenceCurrent(evidence: WorkerClean, dbNow: string): boolean {
      const policy = issued.get(evidence);
      if (revoked || policy === undefined) {return false;}
      const now = utcMicros(dbNow);
      if (now === undefined) { return false; }
      const age = now - config.builtAtMicros;
      return age >= 0n && age < BigInt(policy.maxDefsAgeMs) * 1_000n && now < BigInt(policy.expiresAt) * 1_000n;
    },
    async process(value: Parameters<LocalFileProcessor['process']>[0], signal: AbortSignal): Promise<WorkerResult> {
      let mime: ImageMime;
      let source: Uint8Array;
      let raw: ContentDigest;
      let policy: ReturnType<typeof policySnapshot>;
      try {
        if (getAborted.call(signal) === true) {return fail('ABORTED');}
        if (revoked) {return fail('STALE_ENGINE');}
        if (active.size >= config.maxJobs) {return fail('BUSY');}
        const p = closed(value, ['mime', 'bytes', 'raw', 'policy']);
        if (!imageMime(p.mime)) {return block('UNSUPPORTED_FORMAT');}
        mime = p.mime;
        policy = policySnapshot(p.policy, mime, config);
        if (!policy.mimeAllowed) {return block('UNSUPPORTED_FORMAT');}
        const length = bytesLength(p.bytes);
        if (length < 1 || length > policy.maxRawBytes || types.isSharedArrayBuffer(getBuffer.call(p.bytes)))
          {return fail('LIMIT_EXCEEDED');}
        const expected = closed(p.raw, ['bytes', 'sha256']);
        if (expected.bytes !== length || typeof expected.sha256 !== 'string' || !shaPattern.test(expected.sha256))
          {return fail('SCAN_FAILED');}
        source = new Uint8Array(p.bytes as Uint8Array);
        raw = digest(source);
        if (expected.sha256 !== raw.sha256) {return fail('SCAN_FAILED');}
      } catch { return fail('SCAN_FAILED'); }

      const controller = new AbortController();
      const abort = () => { controller.abort(); }; // never forward caller reasons or child diagnostics
      const deadline = performance.now() + policy.wallMs;
      const stopped = (): WorkerReason | null => revoked ? 'STALE_ENGINE' :
        controller.signal.aborted || performance.now() >= deadline ? 'ABORTED' : null;
      active.add(controller);
      const timer = setTimeout(abort, policy.wallMs);
      let stage: WorkerReason = 'SCAN_FAILED';
      const settlement: { reaped: boolean } = { reaped: true };
      const child = async (launch: () => Promise<ChildResult>): Promise<ChildResult> => {
        settlement.reaped = false;
        const report = await launch();
        const proof: unknown = report.reaped;
        if (proof !== true) { throw new Error(); }
        settlement.reaped = true;
        return report;
      };
      try {
        addAbortListener.call(signal, 'abort', abort, { once: true });
        if (getAborted.call(signal) === true) {abort();}
        const scan = async (bytes: Uint8Array): Promise<WorkerResult | null> => {
          const report = await child(() => launcher.scan(bytes, epoch, controller.signal));
          const reason = stopped();
          if (reason) {return fail(reason);}
          const verdict = scannerVerdict(report);
          return verdict === 'CLEAN' ? null : verdict === 'MALWARE' ? block(verdict) : fail(verdict);
        };
        const before = stopped();
        if (before) {return fail(before);}
        const rawScan = await scan(source);
        if (rawScan) {return rawScan;}
        if (!structure(mime, source, false)) {return block('UNSUPPORTED_FORMAT');}
        stage = 'DECODE_FAILED';
        const frame = makeDecoderFrame(mime, source, policy.limits);
        const decoded = await child(() => launcher.decode(frame, policy.limits.maxOutputBytes, controller.signal));
        const afterDecode = stopped();
        if (afterDecode) {return fail(afterDecode);}
        if (decoded.exitCode !== 0 || !fullySettled(decoded, policy.limits.maxOutputBytes) || bytesLength(decoded.stdout) === 0)
          {return fail('DECODE_FAILED');}
        const output = new Uint8Array(decoded.stdout);
        if (!validateSanitizedImage(mime, output, policy.limits)) {return fail('DECODE_FAILED');}
        const served = digest(output);
        stage = 'SCAN_FAILED';
        const finalScan = await scan(output);
        if (finalScan) {return finalScan;}
        const evidence: WorkerClean = Object.freeze({ kind: 'CLEAN', mime, raw, served, output, ...epoch });
        issued.set(evidence, { maxDefsAgeMs: policy.maxDefsAgeMs, expiresAt: policy.expiresAt });
        return evidence;
      } catch {
        if (!settlement.reaped) {
          abort();
          throw new Error('Local file processing did not settle');
        }
        return fail(stopped() ?? stage);
      } finally {
        clearTimeout(timer);
        removeAbortListener.call(signal, 'abort', abort);
        if (settlement.reaped) { active.delete(controller); }
      }
    },
  });
}
