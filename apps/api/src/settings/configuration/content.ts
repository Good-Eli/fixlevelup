/**
 * Internal content-block port (P03-03).
 *
 * Content is public-facing text (FAQ answers, factual statements, SEO copy) with a
 * stable block identity and immutable reviewed revisions. Two scopes exist:
 *
 * - `COMPANY` (`city_id` NULL) is the company-wide value;
 * - `CITY` names exactly one city.
 *
 * A city value wins when it exists. The company value is used only when the
 * company block explicitly allows it (`allow_company_fallback`), and the resolved
 * result always reports its provenance (scope, city, block, revision, source
 * reference, and whether the company fallback was used). There is no implicit
 * fallback: a company block with the flag off is never substituted.
 *
 * Content never carries contacts, office hours or a timezone (those live only in
 * `service_city_versions`), and never overrides legal, retention, security or
 * upload policy (those are company settings columns with their own reviewed
 * provenance). Reserved codes for both are refused before SQL.
 *
 * ## Caller transaction
 *
 * Writes run on the caller's `PoolClient` inside the caller's explicit
 * transaction and append safe audit + outbox rows in the same transaction.
 */
import { randomUUID } from 'node:crypto';
import { writeConfigurationAudit } from './configuration-audit.js';
import { assertCallerTransaction } from './configuration-tx.js';
import { ConfigurationError, conflict, notFound, staleVersion } from './configuration-errors.js';
import {
  contentArchiveInput, contentBlockCreateInput, contentListInput, contentResolutionInput,
  contentRevisionInput, contentSnapshotInput, requireUuid,
} from './configuration-input.js';
import type {
  ContentArchiveInput, ContentBlockCreateInput, ContentKind, ContentListInput, ContentResolutionInput,
  ContentRevisionInput, ContentScope, ContentSnapshotInput,
} from './configuration-input.js';
import type { ConfigurationClient } from './configuration-port.js';
import {
  CONTENT_BLOCK_COLUMNS, CONTENT_REVISION_COLUMNS, mapDatabaseError,
} from './configuration-rows.js';
import type { ContentBlockRow, ContentRevisionRow } from './configuration-rows.js';

export interface ContentBlockView {
  readonly id: string;
  readonly code: string;
  readonly kind: ContentKind;
  readonly scope: ContentScope;
  readonly cityId: string | null;
  readonly allowCompanyFallback: boolean;
  readonly version: number;
  readonly currentRevisionId: string | null;
  readonly archivedAt: string | null;
}

export interface ContentRevisionView {
  readonly id: string;
  readonly blockId: string;
  readonly version: number;
  readonly title: string;
  readonly body: string;
  readonly sourceRef: string;
  readonly publishedAt: string;
}

export interface ContentBlockReceipt {
  readonly id: string;
  readonly version: number;
}

export interface ContentRevisionReceipt {
  readonly id: string;
  readonly blockId: string;
  readonly version: number;
  readonly blockVersion: number;
}

export interface ContentList {
  readonly items: readonly ContentBlockView[];
}

export interface ContentSnapshot {
  readonly block: ContentBlockView;
  readonly revision: ContentRevisionView;
}

/**
 * Where an effective value came from. `fallback` is true only when the company
 * block was substituted for a missing city value with its explicit permission.
 */
export interface ContentProvenance {
  readonly scope: ContentScope;
  readonly cityId: string | null;
  readonly blockId: string;
  readonly revisionId: string;
  readonly version: number;
  readonly sourceRef: string;
  readonly fallback: boolean;
}

export interface EffectiveContent {
  readonly code: string;
  readonly kind: ContentKind;
  readonly title: string;
  readonly body: string;
  readonly provenance: ContentProvenance;
}

function blockView(row: ContentBlockRow): ContentBlockView {
  return {
    id: row.id,
    code: row.code,
    kind: row.kind as ContentKind,
    scope: row.scope as ContentScope,
    cityId: row.city_id,
    allowCompanyFallback: row.allow_company_fallback,
    version: row.row_version,
    currentRevisionId: row.current_revision_id,
    archivedAt: row.archived_at === null ? null : row.archived_at.toISOString(),
  };
}

function revisionView(row: ContentRevisionRow): ContentRevisionView {
  return {
    id: row.id,
    blockId: row.block_id,
    version: row.version,
    title: row.title,
    body: row.body,
    sourceRef: row.source_ref,
    publishedAt: row.published_at.toISOString(),
  };
}

/**
 * Creates one stable block identity. The partial unique index on
 * (scope, city_id, code) is the database rule that a city has at most one block
 * per code and the company at most one; a duplicate is refused as a conflict.
 */
export async function createContentBlock(
  client: ConfigurationClient,
  actorStaffId: unknown,
  raw: unknown,
): Promise<ContentBlockReceipt> {
  // Re-validated here so a caller that skipped the parser still cannot reach SQL.
  const actor = requireUuid(actorStaffId, 'actorStaffId');
  const input: ContentBlockCreateInput = contentBlockCreateInput(raw);
  // The caller's explicit transaction is mandatory: the block row, its audit row and
  // its outbox event must commit or roll back together.
  await assertCallerTransaction(client);
  if (input.cityId !== null) {
    const city = await client.query('SELECT 1 FROM foundation.service_cities WHERE id=$1', [input.cityId]);
    if (city.rows.length !== 1) {
      notFound('cityId');
    }
  }
  const insert = await client.query<{ id: string; row_version: number }>(
    `INSERT INTO foundation.content_blocks (id,code,kind,scope,city_id,allow_company_fallback)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,row_version`,
    [randomUUID(), input.code, input.kind, input.scope, input.cityId, input.allowCompanyFallback],
  ).catch(mapDatabaseError);
  const row = insert.rows[0];
  if (!row) {
    conflict('code');
  }
  await writeConfigurationAudit({
    client,
    operation: 'content.block.create',
    details: {
      actorStaffId: actor,
      entity: 'CONTENT_BLOCK',
      entityId: row.id,
      type: input.kind,
      scope: input.scope,
      cityId: input.cityId,
    },
  });
  return { id: row.id, version: row.row_version };
}

/**
 * Publishes one immutable reviewed revision and moves the current pointer.
 *
 * A publish is a CAS on the block token: `expectedVersion` must equal the block's
 * `row_version`, so two publishers cannot both append to one revision and a
 * caller that never saw the current state cannot publish over it. The block must
 * not be archived.
 */
export async function publishContentRevision(
  client: ConfigurationClient,
  actorStaffId: unknown,
  raw: unknown,
): Promise<ContentRevisionReceipt> {
  const actor = requireUuid(actorStaffId, 'actorStaffId');
  const input: ContentRevisionInput = contentRevisionInput(raw);
  // Guard before any row lock: an autocommit FOR UPDATE would release instantly.
  await assertCallerTransaction(client);
  const locked = await client.query<ContentBlockRow>(
    `SELECT ${CONTENT_BLOCK_COLUMNS} FROM foundation.content_blocks WHERE id=$1 FOR UPDATE`, [input.blockId]);
  const block = locked.rows[0];
  if (!block) {
    notFound('blockId');
  }
  if (block.archived_at !== null) {
    throw new ConfigurationError('ARCHIVED', 'blockId');
  }
  if (block.row_version !== input.expectedVersion) {
    staleVersion();
  }
  const next = await client.query<{ version: number }>(
    'SELECT (COALESCE(max(version),0)+1)::int AS version FROM foundation.content_block_revisions WHERE block_id=$1',
    [block.id]);
  const version = next.rows[0]?.version;
  if (version === undefined) {
    conflict('version');
  }
  const insert = await client.query<{ id: string; version: number }>(
    `INSERT INTO foundation.content_block_revisions (id,block_id,version,title,body,source_ref,reviewed_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,version`,
    [randomUUID(), block.id, version, input.title, input.body, input.sourceRef, actor],
  ).catch(mapDatabaseError);
  const revision = insert.rows[0];
  if (!revision) {
    conflict('version');
  }
  const moved = await client.query<{ row_version: number }>(
    'UPDATE foundation.content_blocks SET current_revision_id=$2 WHERE id=$1 AND row_version=$3 RETURNING row_version',
    [block.id, revision.id, input.expectedVersion]);
  const blockVersion = moved.rows[0]?.row_version;
  if (blockVersion === undefined) {
    staleVersion();
  }
  await writeConfigurationAudit({
    client,
    operation: 'content.revision.publish',
    details: {
      actorStaffId: actor,
      entity: 'CONTENT_REVISION',
      entityId: revision.id,
      blockId: block.id,
      type: block.kind,
      scope: block.scope,
      cityId: block.city_id,
      version: revision.version,
      previousVersion: input.expectedVersion,
    },
  });
  return { id: revision.id, blockId: block.id, version: revision.version, blockVersion };
}

/**
 * Archives a block. Existing revisions stay readable as the historical snapshot
 * they were reviewed as; the block is simply no longer selected for new use.
 */
export async function archiveContentBlock(
  client: ConfigurationClient,
  actorStaffId: unknown,
  raw: unknown,
): Promise<ContentBlockReceipt> {
  const actor = requireUuid(actorStaffId, 'actorStaffId');
  const input: ContentArchiveInput = contentArchiveInput(raw);
  await assertCallerTransaction(client);
  const locked = await client.query<ContentBlockRow>(
    `SELECT ${CONTENT_BLOCK_COLUMNS} FROM foundation.content_blocks WHERE id=$1 FOR UPDATE`, [input.blockId]);
  const block = locked.rows[0];
  if (!block) {
    notFound('blockId');
  }
  if (block.archived_at !== null) {
    // Archive is strictly one-way: an archived block is never re-archived or
    // un-archived, so the operation is refused instead of silently rewriting history.
    // Checked before the token so a write-only caller cannot learn the archive state
    // from an ETag comparison.
    throw new ConfigurationError('ARCHIVED', 'blockId');
  }
  if (block.row_version !== input.expectedVersion) {
    staleVersion();
  }
  const archived = await client.query<{ row_version: number }>(
    `UPDATE foundation.content_blocks SET archived_at=clock_timestamp()
     WHERE id=$1 AND row_version=$2 AND archived_at IS NULL RETURNING row_version`,
    [block.id, input.expectedVersion]).catch(mapDatabaseError);
  const row = archived.rows[0];
  if (!row) {
    staleVersion();
  }
  await writeConfigurationAudit({
    client,
    operation: 'content.block.archive',
    details: {
      actorStaffId: actor,
      entity: 'CONTENT_BLOCK',
      entityId: block.id,
      type: block.kind,
      scope: block.scope,
      cityId: block.city_id,
      version: row.row_version,
    },
  });
  return { id: block.id, version: row.row_version };
}

/** Bounded list; archived blocks are excluded unless explicitly requested. */
export async function listContentBlocks(
  client: ConfigurationClient,
  raw: unknown,
): Promise<ContentList> {
  const input: ContentListInput = contentListInput(raw);
  const filters: string[] = [];
  const parameters: unknown[] = [];
  if (input.scope !== null) {
    parameters.push(input.scope);
    filters.push(`scope=$${String(parameters.length)}`);
  }
  if (input.cityId !== null) {
    parameters.push(input.cityId);
    filters.push(`city_id=$${String(parameters.length)}`);
  }
  if (input.kind !== null) {
    parameters.push(input.kind);
    filters.push(`kind=$${String(parameters.length)}`);
  }
  if (!input.includeArchived) {
    filters.push('archived_at IS NULL');
  }
  parameters.push(input.limit);
  const where = filters.length === 0 ? '' : `WHERE ${filters.join(' AND ')}`;
  const result = await client.query<ContentBlockRow>(
    `SELECT ${CONTENT_BLOCK_COLUMNS} FROM foundation.content_blocks ${where} ORDER BY code LIMIT $${String(parameters.length)}`,
    parameters);
  return { items: result.rows.map(blockView) };
}

/**
 * Exact historical snapshot: stable block identity plus one exact revision. An
 * archived block and an old revision stay readable, because archiving and later
 * publishes never rewrite what was reviewed.
 */
export async function readContentSnapshot(
  client: ConfigurationClient,
  raw: unknown,
): Promise<ContentSnapshot> {
  const input: ContentSnapshotInput = contentSnapshotInput(raw);
  const blockResult = await client.query<ContentBlockRow>(
    `SELECT ${CONTENT_BLOCK_COLUMNS} FROM foundation.content_blocks WHERE id=$1`, [input.blockId]);
  const block = blockResult.rows[0];
  if (!block) {
    notFound('blockId');
  }
  const revisionResult = input.version === null
    ? await client.query<ContentRevisionRow>(
      `SELECT ${CONTENT_REVISION_COLUMNS} FROM foundation.content_block_revisions WHERE block_id=$1 AND id=$2`,
      [block.id, block.current_revision_id])
    : await client.query<ContentRevisionRow>(
      `SELECT ${CONTENT_REVISION_COLUMNS} FROM foundation.content_block_revisions WHERE block_id=$1 AND version=$2`,
      [block.id, input.version]);
  const revision = revisionResult.rows[0];
  if (!revision) {
    notFound('version');
  }
  return { block: blockView(block), revision: revisionView(revision) };
}

interface ResolvedRow {
  id: string; code: string; kind: string; scope: string; city_id: string | null;
  allow_company_fallback: boolean; row_version: number;
  revision_id: string; revision_version: number; title: string; body: string; source_ref: string;
}

/**
 * Effective content for one code and one city.
 *
 * Resolution order is explicit and total:
 *
 * 1. the city block for `(CITY, cityId, code)` when it exists, is not archived and
 *    has a current revision;
 * 2. otherwise the company block for `(COMPANY, NULL, code)` only when it exists,
 *    is not archived, has a current revision and `allow_company_fallback` is true.
 *
 * An archived city block is not used (archiving is a withdrawal), but it does not
 * block the company fallback either. A company block with the flag off yields
 * NOT_FOUND: content is never inherited implicitly. The result always names the
 * exact scope/block/revision/source it came from.
 */
export async function resolveEffectiveContent(
  client: ConfigurationClient,
  raw: unknown,
): Promise<EffectiveContent> {
  const input: ContentResolutionInput = contentResolutionInput(raw);
  const select = `SELECT b.id, b.code, b.kind, b.scope, b.city_id, b.allow_company_fallback, b.row_version,
      r.id AS revision_id, r.version AS revision_version, r.title, r.body, r.source_ref
    FROM foundation.content_blocks AS b
    JOIN foundation.content_block_revisions AS r ON r.block_id=b.id AND r.id=b.current_revision_id`;
  const city = await client.query<ResolvedRow>(
    `${select} WHERE b.scope='CITY' AND b.city_id=$1 AND b.code=$2 AND b.archived_at IS NULL`,
    [input.cityId, input.code]);
  const cityRow = city.rows[0];
  if (cityRow) {
    return effective(cityRow, false);
  }
  const company = await client.query<ResolvedRow>(
    `${select} WHERE b.scope='COMPANY' AND b.city_id IS NULL AND b.code=$1
       AND b.archived_at IS NULL AND b.allow_company_fallback`,
    [input.code]);
  const companyRow = company.rows[0];
  if (companyRow) {
    return effective(companyRow, true);
  }
  notFound('code');
}

function effective(row: ResolvedRow, fallback: boolean): EffectiveContent {
  return {
    code: row.code,
    kind: row.kind as ContentKind,
    title: row.title,
    body: row.body,
    provenance: {
      scope: row.scope as ContentScope,
      cityId: row.city_id,
      blockId: row.id,
      revisionId: row.revision_id,
      version: row.revision_version,
      sourceRef: row.source_ref,
      fallback,
    },
  };
}
