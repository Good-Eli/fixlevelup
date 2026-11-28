import { parseP04JsonText } from '@fixlevelup/p03-contracts/p04-json';
import { deny } from '../intake/errors.js';

export const SEARCH_BODY_BYTES = 1400;
export const SEARCH_RESULT_LIMIT = 50;

export type SearchKind = 'number' | 'name' | 'phone';
export interface SearchQuery {
  readonly kind: SearchKind;
  readonly value: string;
}

export function normalizeSearchName(value: string): string {
  return value.normalize('NFC').replace(/\p{Zs}+/gu,' ').trim().toLowerCase().normalize('NFC');
}

export function parseSearch(bytes: Uint8Array): SearchQuery {
  if (!bytes.length || bytes.length > SEARCH_BODY_BYTES) { return deny('INVALID_REQUEST'); }
  let input: ReturnType<typeof parseP04JsonText>;
  try { input = parseP04JsonText(new TextDecoder('utf-8',{fatal:true}).decode(bytes)); }
  catch { return deny('INVALID_REQUEST'); }
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 2
    || !Object.hasOwn(input,'kind') || !Object.hasOwn(input,'query')) { return deny('INVALID_REQUEST'); }
  const { kind,query } = input;
  if (typeof query !== 'string' || !query.length || query.length > 256
    || Buffer.byteLength(query,'utf8') > 1024 || /[\p{Cc}\p{Cs}]/u.test(query)) { return deny('INVALID_REQUEST'); }
  if (kind === 'number') {
    const value = query.trim();
    if (!/^(?:0|[1-9][0-9]{0,18})$/u.test(value) || BigInt(value) > 9223372036854775807n) {
      return deny('INVALID_REQUEST');
    }
    return { kind,value };
  }
  if (kind === 'name') {
    const value = normalizeSearchName(query);
    if (!value.length) { return deny('INVALID_REQUEST'); }
    return { kind,value };
  }
  if (kind === 'phone') {
    if (!/^\+[\d\p{Zs}().-]+$/u.test(query.trim())) { return deny('INVALID_REQUEST'); }
    const value = query.replace(/[\p{Zs}().-]/gu,'');
    if (!/^\+[1-9][0-9]{9,14}$/u.test(value)) { return deny('INVALID_REQUEST'); }
    return { kind,value };
  }
  return deny('INVALID_REQUEST');
}
