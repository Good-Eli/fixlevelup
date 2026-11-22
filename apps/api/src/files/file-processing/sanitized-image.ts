import { crc32 } from 'node:zlib';

import type { DecoderLimits, ImageMime } from './protocol.js';

function bounded(limits: DecoderLimits, width: number, height: number, channels: number): boolean {
  return width > 0 && height > 0 && channels > 0 && width <= limits.maxWidth && height <= limits.maxHeight &&
    width <= Math.floor(limits.maxPixels / height) && channels <= limits.maxChannels;
}

function png(b: Buffer, limits: DecoderLimits): boolean {
  if (b.length < 45 || b.readBigUInt64BE(0) !== 0x89504e470d0a1a0an || b.readUInt32BE(8) !== 13 ||
      b.toString('latin1', 12, 16) !== 'IHDR') { return false; }
  const color = b.readUInt8(25);
  // The default Sharp PNG encoder is non-interlaced, 8-bit, and does not emit palettes.
  const channels = color === 0 ? 1 : color === 2 ? 3 : color === 4 ? 2 : color === 6 ? 4 : 0;
  if (b.readUInt8(24) !== 8 || b.readUIntBE(26, 3) !== 0 ||
      !bounded(limits, b.readUInt32BE(16), b.readUInt32BE(20), channels)) { return false; }
  let pixels = 0;
  let density = false;
  let zlibHeader = 0;
  for (let i = 8; i <= b.length - 12;) {
    const n = b.readUInt32BE(i);
    if (n > b.length - i - 12) { return false; }
    const data = i + 8;
    const end = data + n;
    const tag = b.toString('latin1', i + 4, data);
    if (crc32(b.subarray(i + 4, end)) !== b.readUInt32BE(end)) { return false; }
    if (tag === 'IDAT' && n > 0) {
      for (let j = 0; pixels + j < 2 && j < n; j++) { zlibHeader = (zlibHeader << 8) | b.readUInt8(data + j); }
      pixels += n;
    } else if (tag === 'IEND') {
      return n === 0 && pixels >= 8 && end + 4 === b.length && (zlibHeader & 0x0f00) === 0x0800 &&
        (zlibHeader >>> 12) <= 7 && (zlibHeader & 32) === 0 && zlibHeader % 31 === 0;
    } else if (tag === 'pHYs' && !density && pixels === 0 && n === 9 && b.readUInt8(data + 8) <= 1) {
      density = true;
    } else if (tag !== 'IHDR' || i !== 8) { return false; }
    i = end + 4;
  }
  return false;
}

function webp(b: Buffer, limits: DecoderLimits): boolean {
  if (b.length < 21 || b.toString('latin1', 0, 4) !== 'RIFF' || b.readUInt32LE(4) !== b.length - 8 ||
      b.toString('latin1', 8, 12) !== 'WEBP') { return false; }
  let canvas: { width: number; height: number } | undefined;
  let alphaChunk = false;
  for (let i = 12; i <= b.length - 8;) {
    const tag = b.toString('latin1', i, i + 4);
    const n = b.readUInt32LE(i + 4);
    const p = i + 8;
    const end = p + n + (n % 2);
    if (end > b.length || (n % 2 !== 0 && b.readUInt8(end - 1) !== 0)) { return false; }
    if (tag === 'VP8X' && i === 12 && n === 10 && b.readUInt32LE(p) === 0x10) {
      // Only the extended alpha feature belongs to this metadata-free encoder profile.
      canvas = { width: b.readUIntLE(p + 4, 3) + 1, height: b.readUIntLE(p + 7, 3) + 1 };
      if (!bounded(limits, canvas.width, canvas.height, 4)) { return false; }
    } else if (tag === 'ALPH' && canvas && !alphaChunk && n > 1) {
      const header = b.readUInt8(p);
      if ((header & 0xc0) !== 0 || (header & 3) > 1 || ((header >>> 4) & 3) > 1 ||
          ((header & 3) === 0 && n - 1 !== canvas.width * canvas.height)) { return false; }
      alphaChunk = true;
    } else if (tag === 'VP8 ' && end === b.length && n > 10 && alphaChunk === (canvas !== undefined)) {
      const frame = b.readUIntLE(p, 3);
      const width = b.readUInt16LE(p + 6);
      const height = b.readUInt16LE(p + 8);
      return (frame & 0x11) === 0x10 && ((frame >>> 1) & 7) <= 3 && (frame >>> 5) > 0 &&
        (frame >>> 5) < n - 10 && b.readUIntBE(p + 3, 3) === 0x9d012a &&
        (!canvas || (canvas.width === width && canvas.height === height)) &&
        (width & 0xc000) === 0 && (height & 0xc000) === 0 && bounded(limits, width, height, alphaChunk ? 4 : 3);
    } else if (tag === 'VP8L' && end === b.length && !alphaChunk && n > 5 && b.readUInt8(p) === 0x2f) {
      const bits = b.readUInt32LE(p + 1);
      const width = (bits & 0x3fff) + 1;
      const height = ((bits >>> 14) & 0x3fff) + 1;
      const alpha = (bits & 0x10000000) !== 0;
      return (bits >>> 29) === 0 && (!canvas || (alpha && canvas.width === width && canvas.height === height)) &&
        // VP8L's alpha flag is a hint, not a proof of an opaque pixel plane.
        bounded(limits, width, height, 4);
    } else { return false; }
    i = end;
  }
  return false;
}

function jpeg(b: Buffer, limits: DecoderLimits): boolean {
  if (b.length < 4 || b.readUInt16BE(0) !== 0xffd8) { return false; }
  const quant = new Set<number>();
  const huffman = new Set<number>();
  const components = new Set<number>();
  let jfif = false;
  for (let i = 2; i <= b.length - 4;) {
    if (b.readUInt8(i) !== 0xff) { return false; }
    const marker = b.readUInt8(i + 1);
    const n = b.readUInt16BE(i + 2);
    const p = i + 4;
    const end = i + 2 + n;
    if (n < 2 || end > b.length) { return false; }
    if (marker === 0xe0 && i === 2 && !jfif && n === 16 && b.toString('latin1', p, p + 5) === 'JFIF\0' &&
        b.readUInt16BE(end - 2) === 0) {
      jfif = true;
    } else if (marker === 0xdb && n >= 67 && (n - 2) % 65 === 0) {
      for (let j = p; j < end; j += 65) {
        const id = b.readUInt8(j);
        if (id > 3 || quant.has(id) || b.subarray(j + 1, j + 65).includes(0)) { return false; }
        quant.add(id);
      }
    } else if (marker === 0xc0 && components.size === 0 && n >= 11) {
      // The Sharp JPEG encoder here uses one baseline, 8-bit frame and one scan.
      const count = b.readUInt8(p + 5);
      if (n !== 8 + count * 3 || (count !== 1 && count !== 3) || b.readUInt8(p) !== 8 ||
          !bounded(limits, b.readUInt16BE(p + 3), b.readUInt16BE(p + 1), count)) { return false; }
      for (let j = p + 6; j < end; j += 3) {
        const id = b.readUInt8(j);
        const sampling = b.readUInt8(j + 1);
        const h = sampling >>> 4;
        const v = sampling & 15;
        if (components.has(id) || h < 1 || h > 4 || v < 1 || v > 4 || !quant.has(b.readUInt8(j + 2))) { return false; }
        components.add(id);
      }
    } else if (marker === 0xc4 && n >= 20) {
      for (let j = p; j < end;) {
        if (end - j < 18) { return false; }
        const id = b.readUInt8(j++);
        if ((id >>> 4) > 1 || (id & 15) > 3 || huffman.has(id)) { return false; }
        let symbols = 0;
        let free = 1;
        for (let k = 0; k < 16; k++) {
          const codes = b.readUInt8(j++);
          free = free * 2 - codes;
          if (free <= 0) { return false; }
          symbols += codes;
        }
        if (symbols < 1 || symbols > 256 || symbols > end - j) { return false; }
        huffman.add(id);
        j += symbols;
      }
    } else if (marker === 0xda && components.size > 0 && n === 6 + components.size * 2) {
      if (b.readUInt8(p) !== components.size || b.readUIntBE(end - 3, 3) !== 0x003f00) { return false; }
      for (let j = p + 1; j < end - 3; j += 2) {
        const tables = b.readUInt8(j + 1);
        if (!components.delete(b.readUInt8(j)) || !huffman.has(tables >>> 4) || !huffman.has(0x10 | (tables & 15))) {
          return false;
        }
      }
      for (let j = end; j < b.length - 1;) {
        const markerAt = b.indexOf(0xff, j);
        if (markerAt < 0 || markerAt + 1 >= b.length) { return false; }
        const code = b.readUInt8(markerAt + 1);
        if (code === 0xd9) { return markerAt > end && markerAt + 2 === b.length; }
        if (code !== 0) { return false; }
        j = markerAt + 2;
      }
      return false;
    } else { return false; }
    i = end;
  }
  return false;
}

/** Trusted host check of actual bytes. Checks encoder framing and limits, not complete codec decodability. */
export function validateSanitizedImage(mime: ImageMime, bytes: Uint8Array, limits: DecoderLimits): boolean {
  if (bytes.byteLength < 1 || bytes.byteLength > limits.maxOutputBytes) { return false; }
  const b = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (mime === 'image/png') { return png(b, limits); }
  if (mime === 'image/webp') { return webp(b, limits); }
  return jpeg(b, limits);
}
