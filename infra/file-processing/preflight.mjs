// Windows/Linux local synthetic proof against a caller-supplied fixture descriptor.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { performance } from 'node:perf_hooks';
import { createFileProcessingTestLauncher } from './docker-test-launcher.mjs';

const [descriptor] = process.argv.slice(2);
assert.ok(descriptor && process.argv.length === 3, 'Supply a synthetic fixture descriptor');
const config = JSON.parse(await readFile(descriptor, 'utf8'));
assert.ok(config.decoderImage, 'A built Linux decoder image ID is required');
const { launcher, epoch } = await createFileProcessingTestLauncher(config);
const requireApi = createRequire(new URL('../../apps/api/package.json', import.meta.url));
const sharp = requireApi('sharp');
assert.equal(sharp.versions.sharp, '0.35.5');
assert.equal(sharp.versions.vips, '8.18.7');
const eicar = Buffer.from('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=', 'base64');

function settled(result, code) {
  assert.equal(result.exitCode, code);
  assert.equal(result.signal, null);
  assert.equal(result.stdinComplete, true);
  assert.equal(result.stdoutEof, true);
  assert.equal(result.stderrEof, true);
  assert.equal(result.stderr.byteLength, 0);
}

async function scan(input, clean) {
  const start = performance.now();
  const result = await launcher.scan(input, epoch, AbortSignal.timeout(config.scanner.wallMs));
  settled(result, clean ? 0 : 1);
  const expected = clean ? 'stdin: OK\n' : 'stdin: Eicar-Test-Signature FOUND\n';
  assert.equal(Buffer.from(result.stdout).equals(Buffer.from(expected)), true, 'Unexpected scanner result');
  return Math.round(performance.now() - start);
}

await assert.rejects(launcher.scan(Buffer.alloc(0), epoch, AbortSignal.timeout(1000)));
await assert.rejects(launcher.scan(Buffer.from('synthetic'), { ...epoch, defsSha256: '0'.repeat(64) }, AbortSignal.timeout(1000)));
for (const format of ['jpeg', 'png', 'webp']) {
  const input = await sharp({ create: { width: 12, height: 8, channels: 3, background: '#234567' } })
    .withExif({ IFD0: { Software: 'Synthetic test fixture' } }).toFormat(format).toBuffer();
  assert.ok((await sharp(input).metadata()).exif);
  const rawScanMs = await scan(input, true);
  const header = Buffer.from(JSON.stringify({ v: 1, mime: `image/${format}`, inputBytes: input.length,
    maxOutputBytes: 16_384, maxWidth: 64, maxHeight: 64, maxPixels: 4096, maxChannels: 4 }));
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(header.length);
  const output = await launcher.decode([prefix, header, input], 16_384, AbortSignal.timeout(config.decoder.wallMs));
  settled(output, 0);
  const image = await sharp(output.stdout).metadata();
  assert.equal(image.format, format);
  assert.equal(image.width, 12);
  assert.equal(image.height, 8);
  assert.equal(image.exif, undefined);
  const servedScanMs = await scan(output.stdout, true);
  console.log(JSON.stringify({ format, rawScanMs, servedScanMs, metadataStripped: true }));
}
assert.equal(eicar.length, 68);
console.log(JSON.stringify({ eicarDetected: true, scanMs: await scan(eicar, false) }));
