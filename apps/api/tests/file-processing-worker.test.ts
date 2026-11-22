import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { crc32 } from 'node:zlib';

import sharp from 'sharp';
import { describe, expect, it, vi } from 'vitest';

import type { FileProcessingPolicy, ImageMime } from '../src/files/file-lifecycle/contract.js';
import {
  createLocalFileProcessor, type ChildResult, type DefinitionEpoch, type FileProcessingLauncher,
} from '../src/files/file-processing/processor.js';
import { definitionEngineImage, definitionEngineVersion, makeDecoderFrame } from '../src/files/file-processing/protocol.js';
import { validateSanitizedImage } from '../src/files/file-processing/sanitized-image.js';

const epoch: DefinitionEpoch = {
  engineVersion: definitionEngineVersion, engineImageSha256: definitionEngineImage,
  defsSha256: 'b'.repeat(64), defsBuiltAt: '2026-11-21T06:27:04Z',
};
const testPolicy: FileProcessingPolicy = {
  mode: 'local-synthetic', versionId: '4e0eb02c-f486-4181-a1ad-6dd5a7d5a58e',
  expiresAt: new Date('2026-11-24T00:00:00Z'), allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp'],
  maxRawBytes: 65_536, maxOutputBytes: 65_536, maxWidth: 128, maxHeight: 128, maxPixels: 16_384, maxChannels: 4,
  leaseMs: 180_000, wallMs: 120_000, maxDefsAgeMs: 172_800_000,
};
const config = { epoch, maxRawBytes: 65_536, maxOutputBytes: 65_536, maxJobs: 1, maxWallMs: 120_000 };
const hash = (bytes: Uint8Array) => ({ bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
const command = (bytes: Uint8Array, mime: ImageMime = 'image/png', policy = testPolicy) => ({ mime, bytes, raw: hash(bytes), policy });
const report = (data: Uint8Array | string = 'stdin: OK\n', opts: Partial<ChildResult> = {}): ChildResult => ({
  reaped: true, exitCode: 0, signal: null, stdinComplete: true, stdoutEof: true, stderrEof: true, stderr: Buffer.alloc(0),
  stdout: typeof data === 'string' ? Buffer.from(data) : data, ...opts,
});
const getImage = (format: 'jpeg' | 'png' | 'webp', orientation?: number, width = 7, height = 4, channels: 3 | 4 = 3) => {
  const image = sharp({ create: { width, height, channels, background: channels === 4 ? '#4b293b66' : '#4b293b' } });
  if (orientation !== undefined) {image.withMetadata({ orientation });}
  return image.toFormat(format).toBuffer();
};
const fakeLauncher = (output: Uint8Array) => ({
  scan: vi.fn<FileProcessingLauncher['scan']>().mockResolvedValue(report()),
  decode: vi.fn<FileProcessingLauncher['decode']>().mockResolvedValue(report(output)),
});

const asciiEicar = String.raw`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`;

describe('trusted file processor', () => {
  it('scans its own raw snapshot and actual bounded output in separate invocations, then issues pinned evidence', async () => {
    const raw = await getImage('png', 1);
    const output = await getImage('png');
    const launcher = fakeLauncher(output);
    const mutableEpoch = { ...epoch };
    const worker = createLocalFileProcessor(launcher, { ...config, epoch: mutableEpoch });
    const mutablePolicy = { ...testPolicy, expiresAt: new Date(testPolicy.expiresAt) };
    const original = Buffer.from(raw);
    const call = worker.process(command(raw, 'image/png', mutablePolicy), new AbortController().signal);
    raw.fill(0);
    mutableEpoch.defsSha256 = 'a'.repeat(64);
    mutablePolicy.expiresAt.setTime(0);
    const evidence = await call;
    expect(evidence.kind).toBe('CLEAN');
    if (evidence.kind !== 'CLEAN') {throw new Error('Expected CLEAN');}
    expect(evidence).toMatchObject({ raw: hash(original), served: hash(output), ...epoch });
    expect(evidence.output).toEqual(new Uint8Array(output));
    expect(launcher.scan.mock.calls.map(([b]) => Buffer.from(b))).toEqual([original, output]);
    expect(launcher.scan.mock.calls.map(([, e]) => e)).toEqual([epoch, epoch]);
    expect(launcher.scan.mock.invocationCallOrder[0]).toBeLessThan(launcher.decode.mock.invocationCallOrder[0] ?? -1);
    expect(launcher.decode.mock.invocationCallOrder[0]).toBeLessThan(launcher.scan.mock.invocationCallOrder[1] ?? -1);
    expect(worker.isEvidenceCurrent(evidence, '2026-11-22T12:00:00.123456Z')).toBe(true);
    expect(worker.isEvidenceCurrent(evidence, '2026-11-21T06:27:03.999999Z')).toBe(false);
    expect(worker.isEvidenceCurrent(evidence, '2026-11-23T06:27:04.000000Z')).toBe(false);
    expect(worker.isEvidenceCurrent({ ...evidence }, '2026-11-22T12:00:00.123456Z')).toBe(false);
    worker.revokeDefinitions();
    expect(worker.isEvidenceCurrent(evidence, '2026-11-22T12:00:00Z')).toBe(false);
    expect(await worker.process(command(original), new AbortController().signal)).toEqual({ kind: 'INDETERMINATE', reason: 'STALE_ENGINE' });
  });

  it.each([
    report('stdin: OK\nlate warning\n'), report('stdin: OK\nstdin: OK\n'), report('stdin: OK\r\n'),
    report('stdin: OK\n', { stderr: Buffer.from('late stderr') }), report('stdin: OK\n', { stderrEof: false }),
    report('stdin: OK\n', { stdoutEof: false }), report('stdin: OK\n', { stdinComplete: false }),
    report('stdin: OK\n', { exitCode: 1 }), report('stdin: OK\n', { exitCode: 2 }), report('stdin: OK\n', { exitCode: 137 }),
    report('stdin: OK\n', { signal: 'SIGKILL' }), report(Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from('stdin: OK\n')])),
    report('stdin: OK\n'.padEnd(5000, 'x')), report(Buffer.from([0xff])),
  ])('rejects a non-exact/non-settled scan report %# without exposing diagnostics', async (badReport) => {
    const raw = await getImage('png');
    const launcher = fakeLauncher(raw);
    launcher.scan.mockResolvedValueOnce(badReport);
    const worker = createLocalFileProcessor(launcher, config);
    expect(await worker.process(command(raw), new AbortController().signal)).toEqual({ kind: 'INDETERMINATE', reason: 'SCAN_FAILED' });
    expect(launcher.decode).not.toHaveBeenCalled();
  });

  it('blocks a hit but treats limit alerts and final-scan late output as non-clean', async () => {
    const raw = await getImage('png');
    const launcher = fakeLauncher(raw);
    launcher.scan.mockResolvedValueOnce(report('stdin: Eicar-Test-Signature FOUND\n', { exitCode: 1 }));
    launcher.scan.mockResolvedValueOnce(report('stdin: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n', { exitCode: 1 }));
    launcher.scan.mockResolvedValueOnce(report()).mockResolvedValueOnce(report('stdin: OK\nlate warning\n'));
    const worker = createLocalFileProcessor(launcher, config);
    expect(await worker.process(command(raw), new AbortController().signal)).toEqual({ kind: 'BLOCKED', reason: 'MALWARE' });
    expect(await worker.process(command(raw), new AbortController().signal)).toEqual({ kind: 'INDETERMINATE', reason: 'LIMIT_EXCEEDED' });
    expect(await worker.process(command(raw), new AbortController().signal)).toEqual({ kind: 'INDETERMINATE', reason: 'SCAN_FAILED' });
    expect(launcher.decode).toHaveBeenCalledTimes(1);
  });

  it('does not trust decoder assertions, metadata, uncapped output, or captured diagnostics', async () => {
    const raw = await getImage('jpeg');
    const metadata = await getImage('jpeg', 6);
    const launcher = fakeLauncher(raw);
    for (const output of [Buffer.from('{"kind":"CLEAN","bytes":1}'), Buffer.from('stdin: OK\n'), metadata,
      Buffer.alloc(testPolicy.maxOutputBytes + 1), Buffer.concat([raw, Buffer.from('trailer')])]) {
      launcher.decode.mockResolvedValueOnce(report(output));
    }
    const worker = createLocalFileProcessor(launcher, config);
    for (let i = 0; i < 5; i++) {
      expect(await worker.process(command(raw, 'image/jpeg'), new AbortController().signal))
        .toEqual({ kind: 'INDETERMINATE', reason: 'DECODE_FAILED' });
    }
    expect(launcher.scan).toHaveBeenCalledTimes(5);
  });

  it.each(['png', 'jpeg', 'webp'] as const)('enforces actual %s output dimensions, pixels and channels before the final scan', async (format) => {
    const mime = `image/${format}` as const;
    const raw = await getImage(format, undefined, 1, 1);
    const valid = await getImage(format, undefined, 8, 2);
    const overWidth = await getImage(format, undefined, 9, 1);
    const overHeight = await getImage(format, undefined, 1, 9);
    const overPixels = await getImage(format, undefined, 8, 3);
    const launcher = fakeLauncher(valid);
    const worker = createLocalFileProcessor(launcher, config);
    const policy = { ...testPolicy, maxWidth: 8, maxHeight: 8, maxPixels: 16, maxChannels: 3 };
    const signal = new AbortController().signal;
    const cases = [
      { bytes: overWidth, policy }, { bytes: overHeight, policy }, { bytes: overPixels, policy },
      format === 'jpeg' ? { bytes: valid, policy: { ...policy, maxChannels: 2 } }
        : { bytes: await getImage(format, undefined, 8, 2, 4), policy },
    ];
    for (const bad of cases) {
      launcher.scan.mockClear();
      launcher.decode.mockResolvedValueOnce(report(bad.bytes));
      expect(await worker.process(command(raw, mime, bad.policy), signal)).toEqual({ kind: 'INDETERMINATE', reason: 'DECODE_FAILED' });
      expect(launcher.scan).toHaveBeenCalledTimes(1);
    }
    launcher.scan.mockClear();
    expect(await worker.process(command(raw, mime, policy), signal)).toMatchObject({ kind: 'CLEAN', served: hash(valid) });
    expect(launcher.scan).toHaveBeenCalledTimes(2);
    if (format !== 'jpeg') {
      const rgba = await getImage(format, undefined, 8, 2, 4);
      expect(validateSanitizedImage(mime, rgba, { ...policy, maxChannels: 4 })).toBe(true);
    }
  });

  it.each(['png', 'jpeg', 'webp'] as const)('rejects incomplete or inconsistent %s output framing before the final scan', async (format) => {
    const mime = `image/${format}` as const;
    const raw = await getImage(format);
    const output = Buffer.from(raw);
    let malformed: Buffer[];
    if (format === 'png') {
      const idat = output.indexOf('IDAT');
      const iend = output.indexOf('IEND');
      const noPayload = Buffer.concat([output.subarray(0, idat - 4), output.subarray(iend - 4)]);
      const corruptCrc = Buffer.from(output);
      corruptCrc.writeUInt8(corruptCrc.readUInt8(idat + 5) ^ 255, idat + 5);
      const duplicateHeader = Buffer.concat([output.subarray(0, 33), output.subarray(8)]);
      const unsupportedColor = Buffer.from(output);
      unsupportedColor.writeUInt8(3, 25);
      unsupportedColor.writeUInt32BE(crc32(unsupportedColor.subarray(12, 29)), 29);
      malformed = [noPayload, corruptCrc, duplicateHeader, unsupportedColor];
    } else if (format === 'jpeg') {
      const sof = output.indexOf(Buffer.from([0xff, 0xc0]));
      const sos = output.indexOf(Buffer.from([0xff, 0xda]));
      const scansStart = sos + 2 + output.readUInt16BE(sos + 2);
      malformed = [Buffer.concat([output.subarray(0, sof), output.subarray(sof + 2 + output.readUInt16BE(sof + 2))]),
        Buffer.concat([output.subarray(0, scansStart), output.subarray(-2)])];
    } else {
      const chunkHeaderOnly = output.subarray(0, 20);
      chunkHeaderOnly.writeUInt32LE(12, 4);
      chunkHeaderOnly.writeUInt32LE(0, 16);
      const rgba = await getImage(format, undefined, 8, 2, 4);
      const inconsistentCanvas = Buffer.from(rgba);
      inconsistentCanvas.writeUInt8(6, 24); // VP8X says 7; VP8 still says 8.
      malformed = [chunkHeaderOnly, inconsistentCanvas];
    }
    const launcher = fakeLauncher(output);
    const worker = createLocalFileProcessor(launcher, config);
    for (const bad of malformed) {
      launcher.scan.mockClear();
      launcher.decode.mockResolvedValueOnce(report(bad));
      expect(await worker.process(command(raw, mime), new AbortController().signal))
        .toEqual({ kind: 'INDETERMINATE', reason: 'DECODE_FAILED' });
      expect(launcher.scan).toHaveBeenCalledTimes(1);
    }
  });

  it.each(['rejection', 'unattested'] as const)('retains its slot on unknown child settlement: %s', async (fault) => {
    const raw = await getImage('png');
    const launcher = fakeLauncher(raw);
    if (fault === 'rejection') {
      launcher.scan.mockRejectedValueOnce(new Error('private-launcher-diagnostic'));
    } else {
      launcher.scan.mockResolvedValueOnce({ ...report(), reaped: false } as unknown as ChildResult);
    }
    const worker = createLocalFileProcessor(launcher, config);
    const signal = new AbortController().signal;
    await expect(worker.process(command(raw), signal)).rejects.toEqual(new Error('Local file processing did not settle'));
    expect(await worker.process(command(raw), signal)).toEqual({ kind: 'INDETERMINATE', reason: 'BUSY' });
    expect(launcher.scan).toHaveBeenCalledTimes(1);
    expect(launcher.decode).not.toHaveBeenCalled();
  });

  it('refuses policy/digest/mime/size changes or incompatible input before unnecessary IO', async () => {
    const raw = await getImage('png');
    const launcher = fakeLauncher(raw);
    const worker = createLocalFileProcessor(launcher, config);
    const signal = new AbortController().signal;
    expect(await worker.process({ ...command(raw), raw: { ...hash(raw), sha256: epoch.defsSha256 } }, signal))
      .toEqual({ kind: 'INDETERMINATE', reason: 'SCAN_FAILED' });
    expect(await worker.process(command(raw, 'image/png', { ...testPolicy, allowedMimeTypes: ['image/webp'] }), signal))
      .toEqual({ kind: 'BLOCKED', reason: 'UNSUPPORTED_FORMAT' });
    expect(await worker.process(command(Buffer.alloc(config.maxRawBytes + 1)), signal))
      .toEqual({ kind: 'INDETERMINATE', reason: 'LIMIT_EXCEEDED' });
    expect(await worker.process(command(raw, 'image/png', { ...testPolicy, wallMs: 0 }), signal)).toMatchObject({ kind: 'INDETERMINATE' });
    expect(launcher.scan).not.toHaveBeenCalled();
    expect(await worker.process(command(raw, 'image/jpeg'), signal)).toEqual({ kind: 'BLOCKED', reason: 'UNSUPPORTED_FORMAT' });
    expect(launcher.scan).toHaveBeenCalledTimes(1);
    expect(launcher.decode).not.toHaveBeenCalled();
    expect(() => createLocalFileProcessor(launcher, { ...config, extra: 'secret field' })).toThrow('Invalid local file processor configuration');
  });

  it('retains its only slot past the deadline until the launcher actually settles', async () => {
    const raw = await getImage('png');
    const launcher = fakeLauncher(raw);
    let resolveChild: (result: ChildResult) => void = () => { throw new Error('No child'); };
    const child = new Promise<ChildResult>((resolve) => { resolveChild = resolve; });
    const observedAbort = new Promise<void>((resolve) => {
      launcher.scan.mockImplementationOnce((_bytes, _epoch, signal) => {
        signal.addEventListener('abort', () => { resolve(); }, { once: true });
        return child;
      });
    });
    const worker = createLocalFileProcessor(launcher, config);
    const signal = new AbortController().signal;
    let settled = false;
    const ongoing = worker.process(command(raw, 'image/png', { ...testPolicy, wallMs: 5 }), signal)
      .finally(() => { settled = true; });
    await observedAbort;
    expect(settled).toBe(false);
    expect(await worker.process(command(raw), signal)).toEqual({ kind: 'INDETERMINATE', reason: 'BUSY' });
    resolveChild(report());
    expect(await ongoing).toEqual({ kind: 'INDETERMINATE', reason: 'ABORTED' });
    expect(await worker.process(command(raw), signal)).toMatchObject({ kind: 'CLEAN' });
  });
});

async function realFixture(): Promise<{ launcher: FileProcessingLauncher; epoch: DefinitionEpoch }> {
  const fixturePath = process.env['FIXLEVELUP_FILE_PROCESSING_FIXTURE'];
  if (fixturePath === undefined) {throw new Error('Missing isolated file processing fixture');}
  const descriptor: unknown = JSON.parse(await readFile(fixturePath, 'utf8'));
  const modPath = new URL('../../../infra/file-processing/docker-test-launcher.mjs', import.meta.url).href;
  const module = await import(modPath) as {
    createFileProcessingTestLauncher(input: unknown): Promise<{ launcher: FileProcessingLauncher; epoch: DefinitionEpoch }>;
  };
  return module.createFileProcessingTestLauncher(descriptor);
}

describe.runIf(process.env['FIXLEVELUP_FILE_PROCESSING_TESTS'] === '1')('pinned isolated real processing', () => {
  it('re-encodes EXIF-oriented JPEG, rechecks exact output and blocks real EICAR before decoding', async () => {
    const fixture = await realFixture();
    const worker = createLocalFileProcessor(fixture.launcher, { ...config, epoch: fixture.epoch });
    const raw = await getImage('jpeg', 6);
    expect((await sharp(raw).metadata()).orientation).toBe(6);
    const signal = new AbortController().signal;
    const evidence = await worker.process(command(raw, 'image/jpeg'), signal);
    expect(evidence.kind).toBe('CLEAN');
    if (evidence.kind !== 'CLEAN') {throw new Error('Expected real CLEAN');}
    expect(evidence).toMatchObject({ raw: hash(raw), served: hash(evidence.output), ...fixture.epoch });
    const metadata = await sharp(evidence.output).metadata();
    expect(metadata).toMatchObject({ format: 'jpeg', width: 4, height: 7, hasProfile: false });
    for (const name of ['exif', 'icc', 'xmp', 'iptc', 'orientation']) {expect(metadata).not.toHaveProperty(name);}
    expect(await worker.process(command(Buffer.from(asciiEicar), 'image/jpeg'), signal)).toEqual({ kind: 'BLOCKED', reason: 'MALWARE' });
  }, 165_000);

  it('decodes PNG and WebP and denies oversized, corrupt and malformed frames inside the isolated decoder', async () => {
    const { launcher } = await realFixture();
    const limits = { maxOutputBytes: 65_536, maxWidth: 128, maxHeight: 128, maxPixels: 16_384, maxChannels: 4 };
    const signal = new AbortController().signal;
    const png = await getImage('png', 6);
    const webp = await getImage('webp', 6);
    for (const [mime, format, bytes] of [['image/png', 'png', png], ['image/webp', 'webp', webp]] as const) {
      const result = await launcher.decode(makeDecoderFrame(mime, bytes, limits), limits.maxOutputBytes, signal);
      expect(result).toMatchObject({ exitCode: 0, signal: null, stdinComplete: true, stdoutEof: true, stderrEof: true });
      expect(result.stderr.length).toBe(0);
      const metadata = await sharp(result.stdout).metadata();
      expect(metadata).toMatchObject({ format, width: 4, height: 7, hasProfile: false });
      expect(metadata).not.toHaveProperty('exif');
    }
    const corrupt = Buffer.from(png);
    const idat = corrupt.indexOf('IDAT');
    expect(idat).toBeGreaterThan(0);
    corrupt.writeUInt8(corrupt.readUInt8(idat + 5) ^ 0xff, idat + 5);
    const animation = Buffer.concat([png.subarray(0, 33), Buffer.from([0, 0, 0, 0, 97, 99, 84, 76, 0, 0, 0, 0]), png.subarray(33)]);
    const frames = [
      makeDecoderFrame('image/png', png, { ...limits, maxPixels: 2 }),
      makeDecoderFrame('image/png', png, { ...limits, maxWidth: 6 }),
      makeDecoderFrame('image/png', png, { ...limits, maxOutputBytes: 8 }),
      makeDecoderFrame('image/png', corrupt, limits), makeDecoderFrame('image/png', animation, limits),
      makeDecoderFrame('image/png', png.subarray(0, -1), limits),
    ];
    const extra = makeDecoderFrame('image/png', png, limits);
    const [prefix, header] = extra;
    if (prefix === undefined || header === undefined) { throw new Error('Missing decoder framing'); }
    frames.push([prefix, header, Buffer.concat([png, Buffer.from([0])])]);
    for (const frame of frames) {
      const result = await launcher.decode(frame, limits.maxOutputBytes, signal);
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout.length).toBe(0);
    }
  }, 90_000);
});
