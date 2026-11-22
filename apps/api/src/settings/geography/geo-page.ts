import { createHash } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { isP03Version } from '@fixlevelup/p03-contracts';
import type { P03Page } from '@fixlevelup/p03-contracts';
import { listQuery } from './catalog-input.js';
import type { ListQuery } from './catalog-input.js';
import type { GeoContext } from './geo-contract.js';

type BindingField = string | number | boolean | null;
type Position = readonly (string | number)[];
export interface GeoPage<K extends Position> extends ListQuery {
  readonly binding: string;
  readonly after: K | null;
  readonly take: number;
}

/** Cursor state is a position, not a credential. Scope is freshly authorized by GeoRunner and used
 * independently in the row predicates; the digest just binds the position to that exact traversal. */
export function readGeoPage<K extends Position>(ctx: GeoContext, body: unknown, operation: string,
  parents: readonly BindingField[], position: (value: unknown) => K, allowArchived = false): GeoPage<K> {
  const query = listQuery(body, allowArchived);
  const binding = createHash('sha256').update(JSON.stringify([
    operation, parents, ctx.staffId, ctx.cityIds === null ? null : [...ctx.cityIds].sort(), query.includeArchived,
  ])).digest('base64url');
  let after: K | null = null;
  if (query.cursor !== undefined) {
    try {
      const bytes = Buffer.from(query.cursor, 'base64url');
      if (bytes.toString('base64url') !== query.cursor) { throw new BadRequestException(); }
      const decoded: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (!Array.isArray(decoded) || decoded.length !== 3 || decoded[0] !== 1 || decoded[1] !== binding) {
        throw new BadRequestException();
      }
      after = position(decoded[2]);
    } catch {
      throw new BadRequestException();
    }
  }
  return { ...query, binding, after, take: query.limit + 1 };
}

export function finishGeoPage<Row, Item, K extends Position>(page: GeoPage<K>, rows: readonly Row[],
  item: (row: Row) => Item, position: (row: Row) => K): P03Page<Item> {
  const items = rows.slice(0, page.limit);
  const last = items.at(-1);
  const hasMore = rows.length > page.limit;
  return {
    items: items.map(item),
    pageInfo: { hasMore, nextCursor: hasMore && last !== undefined
      ? Buffer.from(JSON.stringify([1, page.binding, position(last)])).toString('base64url') : null },
  };
}

// UUIDs originate from PostgreSQL; unlike request identity validation this also accepts historical
// SQL UUIDs regardless of their RFC version/variant, without accepting any alternate textual form.
const CURSOR_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
function cursorId(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 36 || !CURSOR_ID.test(value)) { throw new BadRequestException(); }
  return value;
}

export function codePosition(value: unknown): readonly [string, string] {
  if (!Array.isArray(value) || value.length !== 2) { throw new BadRequestException(); }
  const code: unknown = value[0];
  if (typeof code !== 'string' || code.length < 2 || code.length > 32 || !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(code)
      || code.endsWith('\n')) { throw new BadRequestException(); }
  return [code, cursorId(value[1])];
}

export function versionPosition(value: unknown): readonly [number, string] {
  if (!Array.isArray(value) || value.length !== 2 || !isP03Version(value[0])) { throw new BadRequestException(); }
  return [value[0], cursorId(value[1])];
}

export function idPosition(value: unknown): readonly [string] {
  if (!Array.isArray(value) || value.length !== 1) { throw new BadRequestException(); }
  return [cursorId(value[0])];
}
