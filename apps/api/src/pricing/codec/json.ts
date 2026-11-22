import { Buffer } from 'node:buffer';
import { TextDecoder, types } from 'node:util';

// Shared limits apply in both directions, including the root at depth one.
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_DEPTH = 64;
const MAX_NODES = 100_000;

export type PricingJson =
  | null
  | boolean
  | string
  | number
  | PricingJson[]
  | { [key: string]: PricingJson };

export function invalidPricingJson(): never {
  throw new TypeError('Invalid pricing JSON');
}

function requireScalarUnicode(text: string): void {
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      index += 1;
      const next = text.charCodeAt(index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) { invalidPricingJson(); }
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      invalidPricingJson();
    }
  }
}

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;

export function boundedPricingText(bytes: string | Uint8Array): string {
  if (typeof bytes === 'string') {
    if (bytes.length > MAX_BYTES || Buffer.byteLength(bytes) > MAX_BYTES) { invalidPricingJson(); }
    requireScalarUnicode(bytes);
    return bytes;
  }
  // Use the intrinsic accessor: an input view may have a shadowing getter.
  if (!types.isUint8Array(bytes)) { invalidPricingJson(); }
  const length: unknown = Reflect.get(typedArrayPrototype, 'byteLength', bytes);
  if (typeof length !== 'number' || length > MAX_BYTES) { invalidPricingJson(); }
  try {
    // Retain BOM so the JSON grammar rejects it instead of dropping bytes.
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return invalidPricingJson();
  }
}

export function parseStrictPricingJson(bytes: string | Uint8Array): PricingJson {
  const text = boundedPricingText(bytes);
  let offset = 0;
  let nodes = 0;
  const integer = /-?(?:0|[1-9][0-9]{0,15})/y;

  function space(): void {
    while (
      text[offset] === ' ' || text[offset] === '\t' ||
      text[offset] === '\r' || text[offset] === '\n'
    ) { offset += 1; }
  }

  function readString(): string {
    const start = offset++;
    while (offset < text.length) {
      const char = text[offset++];
      if (char === '\\') {
        offset += 1;
      } else if (char === '"') {
        let value: string;
        try {
          // Decode a single string token only. Objects are never sent to JSON.parse.
          value = JSON.parse(text.slice(start, offset)) as string;
        } catch {
          return invalidPricingJson();
        }
        requireScalarUnicode(value);
        return value;
      }
    }
    return invalidPricingJson();
  }

  function readObject(depth: number): { [key: string]: PricingJson } {
    const result = Object.create(null) as { [key: string]: PricingJson };
    offset += 1;
    space();
    if (text[offset] === '}') {
      offset += 1;
      return result;
    }
    while (text[offset] === '"') {
      const key = readString();
      if (Object.hasOwn(result, key)) { invalidPricingJson(); }
      space();
      if (text[offset++] !== ':') { invalidPricingJson(); }
      result[key] = readValue(depth + 1);
      space();
      const next = text[offset++];
      if (next === '}') { return result; }
      if (next !== ',') { invalidPricingJson(); }
      space();
    }
    return invalidPricingJson();
  }

  function readArray(depth: number): PricingJson[] {
    const result: PricingJson[] = [];
    offset += 1;
    space();
    if (text[offset] === ']') {
      offset += 1;
      return result;
    }
    while (offset < text.length) {
      result.push(readValue(depth + 1));
      space();
      const next = text[offset++];
      if (next === ']') { return result; }
      if (next !== ',') { invalidPricingJson(); }
    }
    return invalidPricingJson();
  }

  function readValue(depth: number): PricingJson {
    nodes += 1;
    if (depth > MAX_DEPTH || nodes > MAX_NODES) { invalidPricingJson(); }
    space();
    switch (text[offset]) {
      case '{': return readObject(depth);
      case '[': return readArray(depth);
      case '"': return readString();
      case 't':
        if (!text.startsWith('true', offset)) { invalidPricingJson(); }
        offset += 4;
        return true;
      case 'f':
        if (!text.startsWith('false', offset)) { invalidPricingJson(); }
        offset += 5;
        return false;
      case 'n':
        if (!text.startsWith('null', offset)) { invalidPricingJson(); }
        offset += 4;
        return null;
      default: {
        integer.lastIndex = offset;
        const token = integer.exec(text)?.[0];
        if (token === undefined || token === '-0') { invalidPricingJson(); }
        const value = Number(token);
        if (!Number.isSafeInteger(value)) { invalidPricingJson(); }
        offset = integer.lastIndex;
        return value;
      }
    }
  }

  const result = readValue(1);
  space();
  if (offset !== text.length) { invalidPricingJson(); }
  return result;
}

export function canonicalPricingJson(value: unknown): string {
  let nodes = 0;
  let size = 0;
  const chunks: string[] = [];

  function append(text: string): void {
    size += Buffer.byteLength(text);
    if (size > MAX_BYTES) { invalidPricingJson(); }
    chunks.push(text);
  }

  function string(text: string): void {
    if (text.length > MAX_BYTES - size) { invalidPricingJson(); }
    requireScalarUnicode(text);
    append(JSON.stringify(text));
  }

  function readData(target: object, key: string): unknown {
    const descriptor = Object.getOwnPropertyDescriptor(target, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) { invalidPricingJson(); }
    return descriptor.value as unknown;
  }

  function visit(current: unknown, depth: number): void {
    nodes += 1;
    if (depth > MAX_DEPTH || nodes > MAX_NODES) { invalidPricingJson(); }
    if (current === null || typeof current === 'boolean') {
      append(String(current));
    } else if (typeof current === 'number') {
      if (!Number.isSafeInteger(current) || Object.is(current, -0)) { invalidPricingJson(); }
      append(String(current));
    } else if (typeof current === 'string') {
      string(current);
    } else if (typeof current === 'object' && !types.isProxy(current)) {
      const proto: unknown = Object.getPrototypeOf(current);
      if (Array.isArray(current)) {
        // No holes, extra properties, symbols, subclasses or index accessors.
        if (proto !== Array.prototype || current.length > MAX_NODES - nodes ||
            Reflect.ownKeys(current).length !== current.length + 1) { invalidPricingJson(); }
        append('[');
        for (let index = 0; index < current.length; index += 1) {
          if (index > 0) { append(','); }
          visit(readData(current, String(index)), depth + 1);
        }
        append(']');
      } else {
        if (proto !== null && proto !== Object.prototype) { invalidPricingJson(); }
        const keys = Reflect.ownKeys(current);
        if (keys.length > MAX_NODES - nodes || !keys.every((key) => typeof key === 'string')) {
          invalidPricingJson();
        }
        append('{');
        keys.sort();
        let first = true;
        for (const key of keys) {
          if (!first) { append(','); }
          first = false;
          string(key);
          append(':');
          visit(readData(current, key), depth + 1);
        }
        append('}');
      }
    } else {
      invalidPricingJson();
    }
  }

  visit(value, 1);
  return chunks.join('');
}
