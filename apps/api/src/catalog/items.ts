import { randomUUID } from 'node:crypto';
import { audit } from './audit.js';
import { ITEM_KINDS } from './contracts.js';
import type {
  CatalogCasInput, CatalogClient, CatalogReceipt, CatalogRevisionReceipt, CreateItemInput, PublishItemInput,
} from './contracts.js';
import { categoryRef, checkCas, item, revisionSequence, wrote } from './records.js';
import { mutate } from './transaction.js';
import { choice, expectedVersion, flag, integer, optionalText, optionalUuid, record, refuse, slug, text, uuid } from './validation.js';

export async function createItem(client: CatalogClient, reviewedBy: string, input: CreateItemInput): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, ['kind', 'code', 'unit', 'categoryId']);
  const kind = choice(dto['kind'], ITEM_KINDS, 'kind');
  const code = slug(dto['code'], 2, 64, 'code');
  const unit = slug(dto['unit'], 1, 24, 'unit');
  const categoryId = optionalUuid(dto['categoryId'], 'categoryId');
  if (kind === 'WORK' && categoryId === null) {
    refuse('INVALID_INPUT', 'categoryId');
  }
  return mutate(client, async () => {
    await categoryRef(client, categoryId, false);
    const id = randomUUID();
    const { rows } = await client.query<{ row_version: number }>(`INSERT INTO foundation.catalog_items
      (id, kind, code, category_id, unit) VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (code) DO NOTHING RETURNING row_version`, [id, kind, code, categoryId, unit]);
    const row = rows[0] ?? refuse('CONFLICT', 'code');
    const receipt = { id, version: row.row_version };
    await audit(client, 'catalog.item.create', actor, kind, receipt);
    return receipt;
  });
}

export async function publishItem(
  client: CatalogClient, reviewedBy: string, input: PublishItemInput,
): Promise<CatalogRevisionReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, [
    'id', 'kind', 'expectedVersion', 'title', 'description', 'durationMinutes', 'technicianVisible', 'publicVisible',
  ]);
  const id = uuid(dto['id'], 'id');
  const kind = choice(dto['kind'], ITEM_KINDS, 'kind');
  const expected = expectedVersion(dto['expectedVersion']);
  const title = text(dto['title'], 160, 'title');
  const description = optionalText(dto['description'], 1000, 'description', 0);
  const durationMinutes = kind === 'WORK' || kind === 'DIAGNOSTICS'
    ? integer(dto['durationMinutes'], 1, 1440, 'durationMinutes')
    : 'durationMinutes' in dto ? refuse('INVALID_INPUT', 'durationMinutes') : null;
  const technicianVisible = flag(dto['technicianVisible'], 'technicianVisible');
  const publicVisible = flag(dto['publicVisible'], 'publicVisible');
  return mutate(client, async () => {
    const row = await item(client, id);
    if (row.kind !== kind) {
      refuse('CONFLICT', 'kind');
    }
    checkCas(row, expected);
    await categoryRef(client, row.category_id, true);
    const revisionId = randomUUID();
    const revisionVersion = revisionSequence(row);
    const inserted = await client.query(`INSERT INTO foundation.catalog_item_versions
      (id, item_id, kind, version, title, description, duration_minutes, technician_visible, public_visible, reviewed_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [revisionId, id, row.kind, revisionVersion, title, description, durationMinutes, technicianVisible, publicVisible, actor]);
    wrote(inserted.rowCount);
    const { rows } = await client.query<{ row_version: number }>(`UPDATE foundation.catalog_items
      SET current_version_id = $3 WHERE id = $1 AND row_version = $2 RETURNING row_version`,
    [id, expected, revisionId]);
    const updated = rows[0] ?? refuse('STALE_VERSION', 'expectedVersion');
    const receipt = { id, version: updated.row_version, revisionId, revisionVersion };
    await audit(client, 'catalog.item.publish', actor, row.kind, receipt);
    return receipt;
  });
}

export async function archiveItem(client: CatalogClient, reviewedBy: string, input: CatalogCasInput): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, ['id', 'expectedVersion']);
  const id = uuid(dto['id'], 'id');
  const expected = expectedVersion(dto['expectedVersion']);
  return mutate(client, async () => {
    const row = await item(client, id);
    checkCas(row, expected);
    const { rows } = await client.query<{ row_version: number }>(`UPDATE foundation.catalog_items
      SET archived_at = pg_catalog.clock_timestamp() WHERE id = $1 AND row_version = $2 RETURNING row_version`,
    [id, expected]);
    const updated = rows[0] ?? refuse('STALE_VERSION', 'expectedVersion');
    const receipt = { id, version: updated.row_version };
    await audit(client, 'catalog.item.archive', actor, row.kind, receipt);
    return receipt;
  });
}
