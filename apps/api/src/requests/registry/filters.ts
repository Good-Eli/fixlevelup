import {
  P05_CHANNEL_PROVIDERS, P05_CONTACT_MODES, P05_STATUSES, P05_URGENCIES,
} from '@fixlevelup/p03-contracts/p05';
import { deny } from '../intake/errors.js';

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const ENUMS = {
  status: P05_STATUSES,
  urgency: P05_URGENCIES,
  contactMode: P05_CONTACT_MODES,
  provider: P05_CHANNEL_PROVIDERS,
};
const IDS = ['categoryId', 'districtId', 'sourceId'] as const;
const KEYS = new Set(['from', 'to', 'limit', 'cursor', ...IDS, ...Object.keys(ENUMS)]);

export function isRegistryInstant(value: string): boolean {
  if (!INSTANT.test(value) || value.startsWith('0000-')) { return false; }
  const milliseconds = value.slice(0, 23) + 'Z';
  const parsed = new Date(milliseconds);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === milliseconds;
}

export interface RegistryQuery {
  readonly from: string | null;
  readonly to: string | null;
  readonly status: string | null;
  readonly urgency: string | null;
  readonly categoryId: string | null;
  readonly districtId: string | null;
  readonly sourceId: string | null;
  readonly contactMode: string | null;
  readonly provider: string | null;
  readonly limit: number;
  readonly cursor: string | null;
}

function period(query: URLSearchParams, key: 'from' | 'to'): string | null {
  const value = query.get(key);
  if (value === null) { return null; }
  const normalized = value.replace(/\.(\d{3})Z$/, '.$1000Z');
  if (!isRegistryInstant(normalized)) { return deny('INVALID_REQUEST'); }
  return normalized;
}

export function parseRegistryQuery(query: URLSearchParams): RegistryQuery {
  const seen = new Set<string>();
  for (const [key] of query) {
    if (!KEYS.has(key) || seen.has(key)) { return deny('INVALID_REQUEST'); }
    seen.add(key);
  }
  for (const key of IDS) {
    const value = query.get(key);
    if (value !== null && !UUID.test(value)) { return deny('INVALID_REQUEST'); }
  }
  for (const [key, values] of Object.entries(ENUMS)) {
    const value = query.get(key);
    if (value !== null && !(values as readonly string[]).includes(value)) { return deny('INVALID_REQUEST'); }
  }
  const from = period(query, 'from');
  const to = period(query, 'to');
  const limit = query.get('limit') ?? '30';
  if ((from !== null && to !== null && from >= to) || !/^(?:[1-9][0-9]?|100)$/.test(limit)) {
    return deny('INVALID_REQUEST');
  }
  return {
    from, to, limit: Number(limit), cursor: query.get('cursor'),
    status: query.get('status'), urgency: query.get('urgency'),
    categoryId: query.get('categoryId'), districtId: query.get('districtId'), sourceId: query.get('sourceId'),
    contactMode: query.get('contactMode'), provider: query.get('provider'),
  };
}
