import type { CatalogClient, DirectoryKind, ItemKind } from './contracts.js';
import { CatalogInternalError, MAX_VERSION, refuse } from './validation.js';

export interface AggregateRow {
  row_version: number;
  archived: boolean;
}

interface RevisionParent extends AggregateRow {
  current_version_id: string | null;
  revision_version: number | null;
  category_id: string | null;
}

export interface DirectoryRow extends RevisionParent {
  kind: DirectoryKind;
  brand_id: string | null;
}

export interface ItemRow extends RevisionParent {
  kind: ItemKind;
}

export async function directory(client: CatalogClient, id: string, field = 'id'): Promise<DirectoryRow> {
  const { rows } = await client.query<DirectoryRow>(`SELECT e.kind, e.category_id, e.brand_id, e.row_version,
      e.current_version_id, e.archived_at IS NOT NULL AS archived, v.version AS revision_version
    FROM foundation.catalog_directory_entries AS e
    LEFT JOIN foundation.catalog_directory_versions AS v ON (v.entry_id, v.id) = (e.id, e.current_version_id)
    WHERE e.id = $1`, [id]);
  return rows[0] ?? refuse('NOT_FOUND', field);
}

export async function item(client: CatalogClient, id: string, field = 'id'): Promise<ItemRow> {
  const { rows } = await client.query<ItemRow>(`SELECT i.kind, i.category_id, i.row_version,
      i.current_version_id, i.archived_at IS NOT NULL AS archived, v.version AS revision_version
    FROM foundation.catalog_items AS i
    LEFT JOIN foundation.catalog_item_versions AS v ON (v.item_id, v.id) = (i.id, i.current_version_id)
    WHERE i.id = $1`, [id]);
  return rows[0] ?? refuse('NOT_FOUND', field);
}

export function checkCas(row: AggregateRow, expected: number): void {
  if (row.row_version !== expected) {
    refuse('STALE_VERSION', 'expectedVersion');
  }
  if (row.archived) {
    refuse('ARCHIVED', 'id');
  }
  nextVersion(row.row_version);
}

export function nextVersion(version: number): number {
  if (!Number.isInteger(version) || version < 0) {
    throw new CatalogInternalError();
  }
  if (version >= MAX_VERSION) {
    refuse('CONFLICT', 'version');
  }
  return version + 1;
}

export async function directoryRef(
  client: CatalogClient, id: string, kind: DirectoryKind, field: string, published: boolean,
): Promise<DirectoryRow> {
  const row = await directory(client, id, field);
  if (row.kind !== kind) {
    refuse('CONFLICT', field);
  }
  if (row.archived) {
    refuse('ARCHIVED', field);
  }
  if (published && row.current_version_id === null) {
    refuse('CONFLICT', field);
  }
  return row;
}

export async function categoryRef(client: CatalogClient, id: string | null, published: boolean): Promise<void> {
  if (id !== null) {
    await directoryRef(client, id, 'CATEGORY', 'categoryId', published);
  }
}

export function checkedRevisionId(row: ItemRow, field: string): string {
  if (row.archived) {
    refuse('ARCHIVED', field);
  }
  return row.current_version_id ?? refuse('CONFLICT', field);
}

export function revisionSequence(row: RevisionParent): number {
  if ((row.current_version_id === null) !== (row.revision_version === null)) {
    throw new CatalogInternalError();
  }
  return nextVersion(row.revision_version ?? 0);
}

export function wrote(rowCount: number | null): void {
  if (rowCount !== 1) {
    throw new CatalogInternalError();
  }
}
