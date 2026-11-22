import { Buffer } from 'node:buffer';
import { TextDecoder, types } from 'node:util';
import { parseP04JsonText, requireP04JsonScalar, P04_JSON_MAX_BYTES as MAX_BYTES,
  P04_JSON_MAX_DEPTH as MAX_DEPTH, P04_JSON_MAX_NODES as MAX_NODES } from '@fixlevelup/p03-contracts/p04-json';
import type { P04Json } from '@fixlevelup/p03-contracts/p04-json';

export type PricingJson = P04Json;

function invalidPricingJson(): never {
  throw new TypeError('Invalid pricing JSON');
}

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;

export function boundedPricingText(bytes: string | Uint8Array): string {
  if (typeof bytes === 'string') {
    if (bytes.length > MAX_BYTES || Buffer.byteLength(bytes) > MAX_BYTES) { invalidPricingJson(); }
    requireP04JsonScalar(bytes);
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
  return parseP04JsonText(boundedPricingText(bytes));
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
    requireP04JsonScalar(text);
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
