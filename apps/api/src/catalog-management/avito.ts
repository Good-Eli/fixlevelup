import { randomUUID } from 'node:crypto';
import type { CatalogCasInput, CatalogClient, CatalogReceipt, CatalogRevisionReceipt } from '../catalog/contracts.js';
import { checkCas, nextVersion, wrote } from '../catalog/records.js';
import { mutate } from '../catalog/transaction.js';
import { CatalogInternalError, choice, expectedVersion, integer, record, refuse, slug, text, uuid } from '../catalog/validation.js';

const KINDS = ['PROFILE', 'REVIEW'] as const;
type Kind = (typeof KINDS)[number];
type Action = 'create' | 'publish' | 'archive';

export type CreateAvitoInput = { readonly code: string } & (
  | { readonly kind: 'PROFILE'; readonly profileId?: never }
  | { readonly kind: 'REVIEW'; readonly profileId: string }
);

export interface PublishAvitoInput extends CatalogCasInput {
  readonly title: string;
  readonly sourceUrl: string;
  readonly permissionRef: string;
  readonly sourceDate?: string | null;
  readonly excerpt?: string | null;
  readonly rating?: number | null;
}

// This is a format check only. No URL parser normalization, fetch, or redirect.
const SOURCE_URL = /^https:\/\/(?:www\.)?avito\.ru\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*(?![\s\S])/u;

function sourceUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length > 2048 || !SOURCE_URL.test(value)) {
    return refuse('INVALID_INPUT', 'sourceUrl');
  }
  return value;
}

function sourceDate(value: unknown): string | null {
  if (value === undefined || value === null) { return null; }
  if (typeof value !== 'string' || value.length !== 10 || value.startsWith('0000')
      || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/u.test(value)) {
    return refuse('INVALID_INPUT', 'sourceDate');
  }
  const at = `${value}T00:00:00.000Z`;
  const parsed = new Date(at);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== at) {
    return refuse('INVALID_INPUT', 'sourceDate');
  }
  return value;
}

function plainText(value: unknown, max: number, field: string): string {
  if (typeof value !== 'string' || value.length > 12 * 1024 || /[<>]/u.test(value)) {
    return refuse('INVALID_INPUT', field);
  }
  return text(value, max, field);
}

const PUBLISH_FIELDS = ['title', 'sourceUrl', 'permissionRef', 'sourceDate', 'excerpt', 'rating'] as const;

export function normalizeAvitoPublish(input: unknown) {
  const dto = record(input, PUBLISH_FIELDS);
  const { excerpt, rating } = dto;
  return {
    title: plainText(dto['title'], 160, 'title'),
    sourceUrl: sourceUrl(dto['sourceUrl']),
    permissionRef: plainText(dto['permissionRef'], 200, 'permissionRef'),
    sourceDate: sourceDate(dto['sourceDate']),
    excerpt: excerpt === undefined || excerpt === null ? null : plainText(excerpt, 1500, 'excerpt'),
    rating: rating === undefined || rating === null ? null : integer(rating, 1, 5, 'rating'),
  } as const;
}

export type AvitoPublishForm = Pick<ReturnType<typeof normalizeAvitoPublish>, 'sourceDate' | 'excerpt' | 'rating'>;

/** Durable shape only; current publication eligibility belongs to a fresh write. */
export function assertAvitoPublishForm(kind: string, dto: AvitoPublishForm): void {
  if (kind === 'PROFILE') {
    if (dto.sourceDate !== null) { refuse('INVALID_INPUT', 'sourceDate'); }
    if (dto.excerpt !== null) { refuse('INVALID_INPUT', 'excerpt'); }
    if (dto.rating !== null) { refuse('INVALID_INPUT', 'rating'); }
  } else if (kind === 'REVIEW') {
    if (dto.sourceDate === null) { refuse('INVALID_INPUT', 'sourceDate'); }
    if (dto.excerpt === null) { refuse('INVALID_INPUT', 'excerpt'); }
  } else {
    throw new CatalogInternalError();
  }
}

interface Entry {
  kind: Kind;
  profile_id: string | null;
  current_version_id: string | null;
  row_version: number;
  revision_version: number | null;
  archived: boolean;
}

async function entry(client: CatalogClient, id: string, field = 'id'): Promise<Entry> {
  const { rows } = await client.query<Entry>(`SELECT e.kind, e.profile_id, e.current_version_id, e.row_version,
      e.archived_at IS NOT NULL AS archived, r.version AS revision_version
    FROM foundation.external_reviews e
    LEFT JOIN foundation.external_review_revisions r ON (r.entry_id, r.kind, r.id) = (e.id, e.kind, e.current_version_id)
    WHERE e.id = $1`, [id]);
  const row = rows[0] ?? refuse('NOT_FOUND', field);
  if (!KINDS.includes(row.kind) || (row.kind === 'PROFILE') !== (row.profile_id === null)
      || (row.current_version_id === null) !== (row.revision_version === null)) {
    throw new CatalogInternalError();
  }
  return row;
}

async function liveProfile(client: CatalogClient, id: string): Promise<Entry> {
  const row = await entry(client, id, 'profileId');
  if (row.kind !== 'PROFILE') { return refuse('CONFLICT', 'profileId'); }
  if (row.archived) { return refuse('ARCHIVED', 'profileId'); }
  return row;
}

async function audit(client: CatalogClient, action: Action, actorStaffId: string, kind: Kind,
  receipt: CatalogReceipt | CatalogRevisionReceipt): Promise<void> {
  const operation = `content.externalreviews.${action}`;
  const correlationId = randomUUID();
  const body = JSON.stringify({
    actorStaffId, kind, id: receipt.id, version: receipt.version,
    ...('revisionId' in receipt ? { revisionId: receipt.revisionId, revisionVersion: receipt.revisionVersion } : {}),
  });
  try {
    wrote((await client.query(`INSERT INTO foundation.audit_logs
      (id, operation, correlation_id, details) VALUES ($1, $2, $3, $4::jsonb)`,
    [randomUUID(), operation, correlationId, body])).rowCount);
    wrote((await client.query(`INSERT INTO foundation.outbox_events
      (id, event_id, event_type, payload) VALUES ($1, $2, $3, $4::jsonb)`,
    [randomUUID(), correlationId, operation, body])).rowCount);
  } catch {
    throw new CatalogInternalError();
  }
}

export async function createAvito(client: CatalogClient, actorId: string, input: CreateAvitoInput): Promise<CatalogReceipt> {
  const actor = uuid(actorId, 'reviewedBy');
  const dto = record(input, ['kind', 'code', 'profileId']);
  const kind = choice(dto['kind'], KINDS, 'kind');
  const code = slug(dto['code'], 2, 64, 'code');
  if (kind === 'PROFILE' && 'profileId' in dto) { return refuse('INVALID_INPUT', 'profileId'); }
  const profileId = kind === 'REVIEW' ? uuid(dto['profileId'], 'profileId') : null;
  return mutate(client, async () => {
    if (profileId !== null) { await liveProfile(client, profileId); }
    const id = randomUUID();
    const { rows } = await client.query<{ row_version: number }>(`INSERT INTO foundation.external_reviews
      (id, code, kind, profile_id) VALUES ($1, $2, $3, $4)
      ON CONFLICT (kind, code) DO NOTHING RETURNING row_version`, [id, code, kind, profileId]);
    const row = rows[0] ?? refuse('CONFLICT', 'code');
    if (row.row_version !== 1) { throw new CatalogInternalError(); }
    const receipt = { id, version: row.row_version };
    await audit(client, 'create', actor, kind, receipt);
    return receipt;
  });
}

export async function publishAvito(client: CatalogClient, actorId: string, input: PublishAvitoInput): Promise<CatalogRevisionReceipt> {
  const actor = uuid(actorId, 'reviewedBy');
  const raw = record(input, ['id', 'expectedVersion', ...PUBLISH_FIELDS]);
  const { id: rawId, expectedVersion: rawExpected, ...body } = raw;
  const id = uuid(rawId, 'id');
  const expected = expectedVersion(rawExpected);
  const dto = normalizeAvitoPublish(body);
  return mutate(client, async () => {
    const row = await entry(client, id);
    assertAvitoPublishForm(row.kind, dto);
    checkCas(row, expected);
    let profileRevisionId: string | null = null;
    if (row.profile_id !== null) {
      const profile = await liveProfile(client, row.profile_id);
      profileRevisionId = profile.current_version_id ?? refuse('CONFLICT', 'profileId');
    }
    const revisionId = randomUUID();
    const revisionVersion = nextVersion(row.revision_version ?? 0);
    wrote((await client.query(`INSERT INTO foundation.external_review_revisions
      (id, entry_id, kind, version, title, source_url, source_date, excerpt, rating, permission_ref,
       profile_id, profile_revision_id, reviewed_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
    [revisionId, id, row.kind, revisionVersion, dto.title, dto.sourceUrl, dto.sourceDate, dto.excerpt, dto.rating,
      dto.permissionRef, row.profile_id, profileRevisionId, actor])).rowCount);
    const { rows } = await client.query<{ row_version: number }>(`UPDATE foundation.external_reviews
      SET current_version_id = $3 WHERE id = $1 AND row_version = $2 RETURNING row_version`, [id, expected, revisionId]);
    const updated = rows[0] ?? refuse('STALE_VERSION', 'expectedVersion');
    if (updated.row_version !== expected + 1) { throw new CatalogInternalError(); }
    const receipt = { id, version: updated.row_version, revisionId, revisionVersion };
    await audit(client, 'publish', actor, row.kind, receipt);
    return receipt;
  });
}

export async function archiveAvito(client: CatalogClient, actorId: string, input: CatalogCasInput): Promise<CatalogReceipt> {
  const actor = uuid(actorId, 'reviewedBy');
  const dto = record(input, ['id', 'expectedVersion']);
  const id = uuid(dto['id'], 'id');
  const expected = expectedVersion(dto['expectedVersion']);
  return mutate(client, async () => {
    const row = await entry(client, id);
    checkCas(row, expected);
    const { rows } = await client.query<{ row_version: number }>(`UPDATE foundation.external_reviews
      SET archived_at = pg_catalog.clock_timestamp() WHERE id = $1 AND row_version = $2 RETURNING row_version`, [id, expected]);
    const updated = rows[0] ?? refuse('STALE_VERSION', 'expectedVersion');
    if (updated.row_version !== expected + 1) { throw new CatalogInternalError(); }
    const receipt = { id, version: updated.row_version };
    await audit(client, 'archive', actor, row.kind, receipt);
    return receipt;
  });
}
