import { randomUUID } from 'node:crypto';
import { audit } from './audit.js';
import { DIRECTORY_KINDS } from './contracts.js';
import type {
  CatalogCasInput, CatalogClient, CatalogReceipt, CatalogRevisionReceipt, CreateDirectoryInput, PublishDirectoryInput,
} from './contracts.js';
import { categoryRef, checkCas, directory, directoryRef, revisionSequence, wrote } from './records.js';
import { mutate } from './transaction.js';
import { choice, expectedVersion, optionalText, optionalUuid, record, refuse, slug, text, uuid } from './validation.js';

export async function createDirectory(
  client: CatalogClient, reviewedBy: string, input: CreateDirectoryInput,
): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, ['kind', 'code', 'categoryId', 'brandId']);
  const kind = choice(dto['kind'], DIRECTORY_KINDS, 'kind');
  const code = slug(dto['code'], 2, 64, 'code');
  const categoryId = optionalUuid(dto['categoryId'], 'categoryId');
  const brandId = optionalUuid(dto['brandId'], 'brandId');
  if (kind === 'MODEL' || kind === 'FAULT') {
    if (categoryId === null) {
      refuse('INVALID_INPUT', 'categoryId');
    }
  } else if ('categoryId' in dto) {
    refuse('INVALID_INPUT', 'categoryId');
  }
  if (kind === 'MODEL') {
    if (brandId === null) {
      refuse('INVALID_INPUT', 'brandId');
    }
  } else if ('brandId' in dto) {
    refuse('INVALID_INPUT', 'brandId');
  }
  return mutate(client, async () => {
    await categoryRef(client, categoryId, false);
    if (brandId !== null) {
      await directoryRef(client, brandId, 'BRAND', 'brandId', false);
    }
    const id = randomUUID();
    const { rows } = await client.query<{ row_version: number }>(`INSERT INTO foundation.catalog_directory_entries
      (id, kind, code, category_id, brand_id) VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (kind, code) DO NOTHING RETURNING row_version`, [id, kind, code, categoryId, brandId]);
    const row = rows[0] ?? refuse('CONFLICT', 'code');
    const receipt = { id, version: row.row_version };
    await audit(client, 'catalog.directory.create', actor, kind, receipt);
    return receipt;
  });
}

export async function publishDirectory(
  client: CatalogClient, reviewedBy: string, input: PublishDirectoryInput,
): Promise<CatalogRevisionReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, ['id', 'expectedVersion', 'title', 'description']);
  const id = uuid(dto['id'], 'id');
  const expected = expectedVersion(dto['expectedVersion']);
  const title = text(dto['title'], 160, 'title');
  const description = optionalText(dto['description'], 1000, 'description', 0);
  return mutate(client, async () => {
    const row = await directory(client, id);
    checkCas(row, expected);
    await categoryRef(client, row.category_id, true);
    if (row.brand_id !== null) {
      await directoryRef(client, row.brand_id, 'BRAND', 'brandId', true);
    }
    const revisionId = randomUUID();
    const revisionVersion = revisionSequence(row);
    const inserted = await client.query(`INSERT INTO foundation.catalog_directory_versions
      (id, entry_id, version, title, description, reviewed_by) VALUES ($1, $2, $3, $4, $5, $6)`,
    [revisionId, id, revisionVersion, title, description, actor]);
    wrote(inserted.rowCount);
    const { rows } = await client.query<{ row_version: number }>(`UPDATE foundation.catalog_directory_entries
      SET current_version_id = $3 WHERE id = $1 AND row_version = $2 RETURNING row_version`,
    [id, expected, revisionId]);
    const updated = rows[0] ?? refuse('STALE_VERSION', 'expectedVersion');
    const receipt = { id, version: updated.row_version, revisionId, revisionVersion };
    await audit(client, 'catalog.directory.publish', actor, row.kind, receipt);
    return receipt;
  });
}

export async function archiveDirectory(
  client: CatalogClient, reviewedBy: string, input: CatalogCasInput,
): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, ['id', 'expectedVersion']);
  const id = uuid(dto['id'], 'id');
  const expected = expectedVersion(dto['expectedVersion']);
  return mutate(client, async () => {
    const row = await directory(client, id);
    checkCas(row, expected);
    const { rows } = await client.query<{ row_version: number }>(`UPDATE foundation.catalog_directory_entries
      SET archived_at = pg_catalog.clock_timestamp() WHERE id = $1 AND row_version = $2 RETURNING row_version`,
    [id, expected]);
    const updated = rows[0] ?? refuse('STALE_VERSION', 'expectedVersion');
    const receipt = { id, version: updated.row_version };
    await audit(client, 'catalog.directory.archive', actor, row.kind, receipt);
    return receipt;
  });
}
