import { randomUUID } from 'node:crypto';
import { audit } from './audit.js';
import type { CatalogCasInput, CatalogClient, CatalogReceipt, CreateMappingInput } from './contracts.js';
import { categoryRef, checkCas, checkedRevisionId, directoryRef, item } from './records.js';
import { mutate } from './transaction.js';
import { expectedVersion, record, refuse, uuid } from './validation.js';

interface MappingRefs {
  categoryId: string;
  faultId: string;
  itemId: string;
}

async function checkRefs(client: CatalogClient, refs: MappingRefs, published: boolean): Promise<void> {
  await categoryRef(client, refs.categoryId, published);
  const fault = await directoryRef(client, refs.faultId, 'FAULT', 'faultId', published);
  if (fault.category_id !== refs.categoryId) {
    refuse('CONFLICT', 'faultId');
  }
  const work = await item(client, refs.itemId, 'itemId');
  if (work.kind !== 'WORK' || work.category_id !== refs.categoryId) {
    refuse('CONFLICT', 'itemId');
  }
  if (work.archived) {
    refuse('ARCHIVED', 'itemId');
  }
  if (published) {checkedRevisionId(work, 'itemId');}
}

export async function createMapping(
  client: CatalogClient, reviewedBy: string, input: CreateMappingInput,
): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, ['categoryId', 'faultId', 'itemId']);
  const refs = { categoryId: uuid(dto['categoryId'], 'categoryId'), faultId: uuid(dto['faultId'], 'faultId'),
    itemId: uuid(dto['itemId'], 'itemId') };
  return mutate(client, async () => {
    await checkRefs(client, refs, false);
    const id = randomUUID();
    const { rows } = await client.query<{ row_version: number }>(`INSERT INTO foundation.catalog_fault_service_mappings
      (id, category_id, fault_id, item_id) VALUES ($1, $2, $3, $4)
      ON CONFLICT (fault_id, item_id) DO NOTHING RETURNING row_version`, [id, refs.categoryId, refs.faultId, refs.itemId]);
    const row = rows[0] ?? refuse('CONFLICT', 'mapping');
    const receipt = { id, version: row.row_version };
    await audit(client, 'catalog.mapping.create', actor, 'FAULT_SERVICE_MAPPING', receipt);
    return receipt;
  });
}

async function changeMapping(
  client: CatalogClient, reviewedBy: string, input: CatalogCasInput, action: 'publish' | 'archive',
): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, ['id', 'expectedVersion']);
  const id = uuid(dto['id'], 'id');
  const expected = expectedVersion(dto['expectedVersion']);
  return mutate(client, async () => {
    const { rows: current } = await client.query<MappingRefs & { row_version: number; published: boolean; archived: boolean }>(
      `SELECT category_id AS "categoryId", fault_id AS "faultId", item_id AS "itemId", row_version,
        published_at IS NOT NULL AS published, archived_at IS NOT NULL AS archived
      FROM foundation.catalog_fault_service_mappings WHERE id = $1`, [id]);
    const row = current[0] ?? refuse('NOT_FOUND', 'id');
    checkCas(row, expected);
    if (action === 'publish') {
      if (row.published) {
        refuse('CONFLICT', 'mapping');
      }
      await checkRefs(client, row, true);
    }
    const { rows } = action === 'publish'
      ? await client.query<{ row_version: number }>(`UPDATE foundation.catalog_fault_service_mappings
          SET published_at = pg_catalog.clock_timestamp(), published_by = $3
          WHERE id = $1 AND row_version = $2 RETURNING row_version`, [id, expected, actor])
      : await client.query<{ row_version: number }>(`UPDATE foundation.catalog_fault_service_mappings
          SET archived_at = pg_catalog.clock_timestamp()
          WHERE id = $1 AND row_version = $2 RETURNING row_version`, [id, expected]);
    const updated = rows[0] ?? refuse('STALE_VERSION', 'expectedVersion');
    const receipt = { id, version: updated.row_version };
    await audit(client, `catalog.mapping.${action}`, actor, 'FAULT_SERVICE_MAPPING', receipt);
    return receipt;
  });
}

export function publishMapping(client: CatalogClient, reviewedBy: string, input: CatalogCasInput): Promise<CatalogReceipt> {
  return changeMapping(client, reviewedBy, input, 'publish');
}

export function archiveMapping(client: CatalogClient, reviewedBy: string, input: CatalogCasInput): Promise<CatalogReceipt> {
  return changeMapping(client, reviewedBy, input, 'archive');
}
