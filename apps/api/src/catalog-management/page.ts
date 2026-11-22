import { createHash } from 'node:crypto';
import { CatalogInternalError, isUuid, MAX_VERSION, refuse } from '../catalog/validation.js';

export type PageOrder = 'code' | 'id' | 'version';
type Position = readonly [string | number | null, string];

export interface PageQuery {
  readonly limit: number;
  readonly includeArchived: boolean;
  readonly kind: string | null;
  readonly position: Position | null;
  readonly binding: string;
}

interface PageOptions {
  readonly order?: PageOrder;
  readonly includeArchived?: boolean;
  readonly kinds?: readonly string[];
}

function encode(binding: string, position: Position): string {
  return Buffer.from(JSON.stringify([1, binding, position]), 'utf8').toString('base64url');
}

function invalidQuery(): never {
  return refuse('INVALID_INPUT', 'query');
}

function invalidCursor(): never {
  return refuse('INVALID_INPUT', 'cursor');
}

function cursor(token: string, binding: string, order: PageOrder): Position {
  if (!/^[A-Za-z0-9_-]{1,512}(?![\s\S])/u.test(token)) {
    return invalidCursor();
  }
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(token, 'base64url').toString('utf8')) as unknown;
  } catch {
    return invalidCursor();
  }
  if (!Array.isArray(value) || value.length !== 3 || value[0] !== 1 || value[1] !== binding) {
    return invalidCursor();
  }
  const key: unknown = value[2];
  if (!Array.isArray(key) || key.length !== 2) {
    return invalidCursor();
  }
  const primary: unknown = key[0];
  const id: unknown = key[1];
  if (!isUuid(id) || id !== id.toLowerCase()) {
    return invalidCursor();
  }
  let position: Position;
  if (order === 'code' && typeof primary === 'string' && /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?![\s\S])/u.test(primary)
      && primary.length <= 64) {
    position = [primary, id];
  } else if (order === 'version' && typeof primary === 'number' && Number.isInteger(primary)
      && primary >= 1 && primary <= MAX_VERSION) {
    position = [primary, id];
  } else if (order === 'id' && primary === null) {
    position = [null, id];
  } else {
    return invalidCursor();
  }
  return encode(binding, position) === token ? position : invalidCursor();
}

/** Parse the raw URL search string before a framework can collapse duplicate keys. */
export function managementPageQuery(raw: unknown, options: PageOptions, scope: readonly unknown[]): PageQuery {
  if (typeof raw !== 'string' || raw.length > 2048 || (raw !== '' && !raw.startsWith('?'))) {
    return invalidQuery();
  }
  const keys = new Map<string, string>();
  if (raw.length > 1) {
    for (const pair of raw.slice(1).split('&')) {
      const equals = pair.indexOf('=');
      if (equals <= 0) {
        return invalidQuery();
      }
      let key: string;
      let value: string;
      try {
        key = decodeURIComponent(pair.slice(0, equals));
        value = decodeURIComponent(pair.slice(equals + 1));
      } catch {
        return invalidQuery();
      }
      const allowed = (options.order !== undefined && (key === 'limit' || key === 'cursor'))
        || (options.includeArchived === true && key === 'includeArchived')
        || (options.kinds !== undefined && key === 'kind');
      if (!allowed || keys.has(key)) {
        return invalidQuery();
      }
      keys.set(key, value);
    }
  }
  const rawLimit = keys.get('limit');
  if (rawLimit !== undefined && !/^(?:[1-9]|[1-4][0-9]|50)(?![\s\S])/u.test(rawLimit)) {
    return invalidQuery();
  }
  const archived = keys.get('includeArchived');
  if (archived !== undefined && archived !== 'true' && archived !== 'false') {
    return invalidQuery();
  }
  const kind = keys.get('kind') ?? null;
  if (kind !== null && options.kinds?.includes(kind) !== true) {
    return invalidQuery();
  }
  const limit = rawLimit === undefined ? 20 : Number(rawLimit);
  const includeArchived = archived === 'true';
  const binding = createHash('sha256').update(JSON.stringify([scope, limit, includeArchived, kind])).digest('base64url');
  const token = keys.get('cursor');
  const position = token === undefined || options.order === undefined ? null : cursor(token, binding, options.order);
  return { limit, includeArchived, kind, position, binding };
}

/** Only typed values are parameterized. No caller data is an SQL fragment. */
export class SqlValues {
  readonly args: (string | number | boolean | readonly string[] | null)[] = [];

  add(value: (typeof this.args)[number]): string {
    this.args.push(value);
    return `$${String(this.args.length)}`;
  }
}

export interface PageRow {
  readonly sort_id: string;
  readonly sort_key: string | number | null;
  readonly dto: Readonly<Record<string, unknown>>;
}

/** SQL callers supply private, static aliases/column expressions only. */
export function pageSQL(values: SqlValues, page: PageQuery, order: PageOrder, id: string, key?: string) {
  const primary = order === 'id' ? null : order === 'code' ? `${key ?? 'e.code'} COLLATE "C"` : (key ?? 'v.version');
  const direction = order === 'version' ? 'DESC' : 'ASC';
  const op = order === 'version' ? '<' : '>';
  let where = 'true';
  if (page.position !== null) {
    const [sort, positionId] = page.position;
    if (primary === null) {
      where = `${id} ${op} ${values.add(positionId)}::uuid`;
    } else {
      const cast = order === 'version' ? 'integer' : 'text';
      where = `(${primary},${id}) ${op} (${values.add(sort)}::${cast},${values.add(positionId)}::uuid)`;
    }
  }
  return {
    select: `${id} AS sort_id, ${primary ?? 'NULL::text'} AS sort_key`,
    where,
    tail: `ORDER BY ${primary === null ? '' : `${primary} ${direction}, `}${id} ${direction} LIMIT ${values.add(page.limit + 1)}`,
  };
}

export function managementPage(rows: readonly PageRow[], page: PageQuery) {
  const last = rows[page.limit - 1];
  if (rows.length > page.limit && last === undefined) {
    throw new CatalogInternalError();
  }
  return {
    items: rows.slice(0, page.limit).map(({ dto }) => dto),
    pageInfo: { nextCursor: rows.length <= page.limit || last === undefined ? null : encode(page.binding, [last.sort_key, last.sort_id]) },
  };
}
