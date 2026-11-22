import { stdin, stdout } from 'node:process';

import sharp from 'sharp';

import { singleImageStructure } from './image-structure.js';
import { maxHeaderBytes, parseDecoderHeader } from './protocol.js';

async function readFrame() {
  const chunks = stdin[Symbol.asyncIterator]();
  let chunk: Buffer = Buffer.alloc(0);
  let offset = 0;
  async function exact(length: number): Promise<Buffer> {
    const result = Buffer.alloc(length);
    for (let filled = 0; filled < length;) {
      if (offset === chunk.length) {
        const next = await chunks.next();
        if (next.done || !Buffer.isBuffer(next.value)) {throw new TypeError();}
        chunk = next.value;
        offset = 0;
      }
      const count = Math.min(length - filled, chunk.length - offset);
      chunk.copy(result, filled, offset, offset + count);
      offset += count;
      filled += count;
    }
    return result;
  }
  const size = (await exact(4)).readUInt32BE(0);
  if (size < 1 || size > maxHeaderBytes) {throw new TypeError();}
  const header = parseDecoderHeader(await exact(size));
  const bytes = await exact(header.inputBytes);
  if (offset !== chunk.length || !(await chunks.next()).done) {throw new TypeError();}
  return { header, bytes };
}

async function decode(): Promise<Buffer> {
  if (sharp.versions.sharp !== '0.35.5' || sharp.versions.vips !== '8.18.7') {throw new TypeError();}
  sharp.cache(false);
  sharp.block({ operation: ['VipsForeignLoad'] });
  sharp.unblock({ operation: ['VipsForeignLoadJpegBuffer', 'VipsForeignLoadPngBuffer', 'VipsForeignLoadWebpBuffer'] });
  const { header: h, bytes } = await readFrame();
  if (!singleImageStructure(h.mime, bytes, false)) {throw new TypeError();}
  const format = h.mime === 'image/jpeg' ? 'jpeg' : h.mime === 'image/png' ? 'png' : 'webp';
  // A native error/warning is fatal. The process also must exit with fully drained, empty stderr.
  const decoder = sharp(bytes, { failOn: 'warning', limitInputPixels: h.maxPixels, limitInputChannels: h.maxChannels,
    sequentialRead: true, pages: 1, unlimited: false });
  decoder.on('warning', () => { process.exitCode = 2; });
  const check = (width: number | undefined, height: number | undefined, channels: number | undefined): void => {
    if (width === undefined || height === undefined || channels === undefined || width < 1 || height < 1 ||
        channels < 1 || width > h.maxWidth || height > h.maxHeight || width > Math.floor(h.maxPixels / height) ||
        channels > h.maxChannels) {throw new TypeError();}
  };
  const metadata = await decoder.metadata();
  if (metadata.format !== format || (metadata.pages ?? 1) !== 1 ||
      (metadata.pageHeight !== undefined && metadata.pageHeight !== metadata.height)) {throw new TypeError();}
  check(metadata.width, metadata.height, metadata.channels);
  if (metadata.orientation !== undefined && metadata.orientation >= 5) {check(metadata.height, metadata.width, metadata.channels);}
  // Force a full, orientation-normalized decode before encoding. Only pixels reach the new encoder.
  const { data: pixels, info } = await decoder.autoOrient().raw().toBuffer({ resolveWithObject: true });
  check(info.width, info.height, info.channels);
  if (pixels.length !== info.width * info.height * info.channels) {throw new TypeError();}
  const raw = sharp(pixels, { raw: { width: info.width, height: info.height, channels: info.channels },
    limitInputPixels: h.maxPixels, limitInputChannels: h.maxChannels });
  raw.on('warning', () => { process.exitCode = 2; });
  const output = await raw.toFormat(format).toBuffer();
  if (output.length < 1 || output.length > h.maxOutputBytes || !singleImageStructure(h.mime, output, true)) {throw new TypeError();}
  return output;
}

try {
  const output = await decode();
  if (process.exitCode === undefined || process.exitCode === 0) {
    await new Promise<void>((resolve, reject) => {
      stdout.write(output, (error) => {
        if (error) { reject(error); } else { resolve(); }
      });
    });
  }
} catch {
  // No native diagnostic or exception message goes on stdout or across the trusted boundary.
  process.exitCode = 2;
  stdin.destroy();
}
