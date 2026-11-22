import { types } from 'node:util';

// Wire counterpart of the shared lifecycle image MIME enum; no API imports in decoder image.
export type ImageMime = 'image/jpeg' | 'image/png' | 'image/webp';

export const definitionEngineVersion = '1.4.7';
export const definitionEngineImage = '7c58440c10859ec126d4bba5a5f260cc467395d640c193a5197b1da12073e9f8';
export const maxHeaderBytes = 1024;
// Representation ceilings, not tenant policy or launcher resource settings.
export const maxFrameBytes = 64 * 1024 * 1024;

export interface DecoderLimits {
  readonly maxOutputBytes: number;
  readonly maxWidth: number;
  readonly maxHeight: number;
  readonly maxPixels: number;
  readonly maxChannels: number;
}

type DecodeHeader = DecoderLimits & { readonly v: 1; readonly mime: ImageMime; readonly inputBytes: number };
export const decoderLimitKeys = ['maxOutputBytes', 'maxWidth', 'maxHeight', 'maxPixels', 'maxChannels'] as const;

export function closed<Key extends string>(value: unknown, keys: readonly Key[]): Record<Key, unknown> {
  if (typeof value !== 'object' || value === null || types.isProxy(value) ||
      Reflect.ownKeys(value).length !== keys.length) { throw new TypeError(); }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) { throw new TypeError(); }
  const snapshot = Object.create(null) as Record<Key, unknown>;
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d?.enumerable || !('value' in d)) { throw new TypeError(); }
    snapshot[key] = d.value as unknown;
  }
  return snapshot;
}

export function positive(value: unknown, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max) {throw new TypeError();}
  return value;
}

export function imageMime(value: unknown): value is ImageMime {
  return value === 'image/jpeg' || value === 'image/png' || value === 'image/webp';
}

export function intrinsic(object: object, key: string, accessor: boolean): (this: unknown, ...args: unknown[]) => unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  const method: unknown = accessor ? (descriptor as { readonly get?: unknown } | undefined)?.get : descriptor?.value;
  if (typeof method !== 'function') { throw new TypeError(); }
  return method as (this: unknown, ...args: unknown[]) => unknown;
}

export const bytesProto = Object.getPrototypeOf(Uint8Array.prototype) as object;
const lengthGetter = intrinsic(bytesProto, 'byteLength', true);
export function bytesLength(value: unknown): number {
  if (!types.isUint8Array(value)) { throw new TypeError(); }
  return lengthGetter.call(value) as number;
}

export function decoderLimits(value: Record<typeof decoderLimitKeys[number], unknown>): DecoderLimits {
  return {
    maxOutputBytes: positive(value.maxOutputBytes, maxFrameBytes),
    maxWidth: positive(value.maxWidth, 0x7fffffff),
    maxHeight: positive(value.maxHeight, 0x7fffffff),
    maxPixels: positive(value.maxPixels, Number.MAX_SAFE_INTEGER),
    maxChannels: positive(value.maxChannels, 4),
  };
}

export function makeDecoderFrame(mime: ImageMime, bytes: Uint8Array, limits: DecoderLimits): readonly Uint8Array[] {
  const header = Buffer.from(JSON.stringify({ v: 1, mime, inputBytes: bytesLength(bytes), ...limits }));
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(header.byteLength);
  return [prefix, header, bytes];
}

export function parseDecoderHeader(value: Uint8Array): DecodeHeader {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(value);
  const p = closed(JSON.parse(text) as unknown, ['v', 'mime', 'inputBytes', ...decoderLimitKeys]);
  if (p.v !== 1 || !imageMime(p.mime)) {throw new TypeError();}
  const result = { v: 1 as const, mime: p.mime, inputBytes: positive(p.inputBytes, maxFrameBytes), ...decoderLimits(p) };
  if (JSON.stringify(result) !== text) {throw new TypeError();}
  return result;
}
