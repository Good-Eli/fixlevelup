import { createHash } from 'node:crypto';
import { P03_DEFAULT_LIMIT, P03_MAX_CURSOR_LENGTH, P03_MAX_LIMIT, isP03Uuid, isP03Version } from '@fixlevelup/p03-contracts';
import type { P03Page } from '@fixlevelup/p03-contracts';
import { invalid } from './input.js';
import type { Query } from './input.js';

type Key = string | number;
export interface Paging { readonly limit: number; readonly cursor: string | undefined }
export function paging(query: Query): Paging {
  const raw = query.take('limit');
  const limit = raw === undefined ? P03_DEFAULT_LIMIT : Number(raw);
  if (raw !== undefined && (!/^[1-9][0-9]{0,2}$/.test(raw) || limit > P03_MAX_LIMIT)) { invalid(); }
  const cursor = query.take('cursor');
  if (cursor !== undefined && (!cursor.length || cursor.length > P03_MAX_CURSOR_LENGTH || !/^[A-Za-z0-9_-]+$/.test(cursor))) { invalid(); }
  return { limit, cursor };
}

/** Cursors are opaque ordering positions, not authorization. Each query reapplies live scope before LIMIT. */
export class Keyset<T extends Key> {
  private readonly binding: string;
  readonly limit: number;
  readonly key: T | null;
  readonly id: string | null;
  constructor(page: Paging, binding: readonly unknown[], type: 'code' | 'version') {
    this.binding = createHash('sha256').update(JSON.stringify(binding)).digest('base64url');
    this.limit = page.limit;
    this.key = null;
    this.id = null;
    if (page.cursor === undefined) { return; }
    let row: unknown;
    try {
      const bytes = Buffer.from(page.cursor, 'base64url');
      if (bytes.toString('base64url') !== page.cursor) { invalid(); }
      row = JSON.parse(bytes.toString('utf8')) as unknown;
    } catch { invalid(); }
    if (!Array.isArray(row) || row.length !== 4 || row[0] !== 1 || row[1] !== this.binding) { invalid(); }
    const key: unknown = row[2];
    const id: unknown = row[3];
    if (!isP03Uuid(id) || id !== id.toLowerCase() ||
      (type === 'code' ? typeof key !== 'string' || !/^[A-Za-z0-9_.:-]{1,96}$/.test(key) : !isP03Version(key))) { invalid(); }
    this.key = key as T;
    this.id = id;
  }
  get count(): number { return this.limit + 1; }
  page<Row, Item>(rows: readonly Row[], project: (row: Row) => Item, position: (row: Row) => readonly [T, string]): P03Page<Item> {
    const hasMore = rows.length > this.limit;
    const selected = rows.slice(0, this.limit);
    const last = hasMore ? selected.at(-1) : undefined;
    const nextCursor = last === undefined ? null
      : Buffer.from(JSON.stringify([1, this.binding, ...position(last)]), 'utf8').toString('base64url');
    return { items: selected.map(project), pageInfo: { hasMore, nextCursor } };
  }
}
