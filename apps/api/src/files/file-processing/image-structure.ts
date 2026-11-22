import type { ImageMime } from './protocol.js';

// Check framing and reject animation/trailers even when a native loader would read only page one.
function png(input: Buffer, output: boolean): boolean {
  if (input.length < 20 || input.readBigUInt64BE(0) !== 0x89504e470d0a1a0an) {return false;}
  for (let i = 8; i <= input.length - 12;) {
    const n = input.readUInt32BE(i);
    if (n > input.length - i - 12) {return false;}
    const tag = input.toString('latin1', i + 4, i + 8);
    if (i === 8 && (tag !== 'IHDR' || n !== 13)) {return false;}
    if (tag === 'acTL' || tag === 'fcTL' || tag === 'fdAT') {return false;}
    if (output && !['IHDR', 'PLTE', 'tRNS', 'IDAT', 'IEND', 'pHYs'].includes(tag)) {return false;}
    i += n + 12;
    if (tag === 'IEND') {return n === 0 && i === input.length;}
  }
  return false;
}

function webp(input: Buffer, output: boolean): boolean {
  if (input.length < 20 || input.toString('latin1', 0, 4) !== 'RIFF' ||
      input.readUInt32LE(4) !== input.length - 8 || input.toString('latin1', 8, 12) !== 'WEBP') {return false;}
  let i = 12;
  let imageCount = 0;
  for (; i <= input.length - 8;) {
    const tag = input.toString('latin1', i, i + 4);
    const n = input.readUInt32LE(i + 4);
    if (n + (n % 2) > input.length - i - 8 || tag === 'ANIM' || tag === 'ANMF') {return false;}
    if (tag === 'VP8 ' || tag === 'VP8L') {imageCount++;}
    if (tag === 'VP8X' && (n !== 10 || (input.readUInt8(i + 8) & (output ? 0x2e : 0x02)) !== 0)) {return false;}
    if (output && !['VP8X', 'VP8 ', 'VP8L', 'ALPH'].includes(tag)) {return false;}
    i += 8 + n + (n % 2);
  }
  return i === input.length && imageCount === 1;
}

function jpeg(input: Buffer, output: boolean): boolean {
  if (input.length < 4 || input.readUInt16BE(0) !== 0xffd8) {return false;}
  let i = 2;
  let entropy = false;
  let scan = false;
  while (i < input.length) {
    if (entropy) {
      i = input.indexOf(0xff, i);
      if (i < 0) {return false;}
    } else if (input[i] !== 0xff) {return false;}
    while (input[i] === 0xff) {i++;}
    if (i >= input.length) {return false;}
    const marker = input.readUInt8(i++);
    if (entropy && (marker === 0 || (marker >= 0xd0 && marker <= 0xd7))) {continue;}
    if (marker === 0xd9) {return scan && i === input.length;}
    entropy = false;
    if (marker === 0 || marker === 0xd8 || marker <= 0x01 || (marker >= 0xd0 && marker <= 0xd7) ||
        i + 2 > input.length) {return false;}
    const n = input.readUInt16BE(i);
    if (n < 2 || n > input.length - i) {return false;}
    if (marker === 0xe2 && n >= 6 && input.toString('latin1', i + 2, i + 6) === 'MPF\0') {return false;}
    if (output && (marker === 0xfe || (marker >= 0xe0 && marker <= 0xef &&
        !(marker === 0xe0 && n === 16 && input.toString('latin1', i + 2, i + 7) === 'JFIF\0')))) {return false;}
    if (marker === 0xda) {scan = entropy = true;}
    i += n;
  }
  return false;
}

export function singleImageStructure(mime: ImageMime, bytes: Buffer, output: boolean): boolean {
  if (mime === 'image/png') {return png(bytes, output);}
  if (mime === 'image/webp') {return webp(bytes, output);}
  return jpeg(bytes, output);
}
