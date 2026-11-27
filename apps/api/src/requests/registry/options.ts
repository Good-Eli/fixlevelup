import type { PoolClient } from 'pg';

type Group = 'categories' | 'districts' | 'sources';
interface Option { readonly id: string; readonly name: string }

/** Directory values are independent of request visibility and include historical choices. */
export async function readRegistryOptions(client: PoolClient, cityId: string) {
  const { rows } = await client.query<Option & { group: Group }>(`
    SELECT 'categories' AS "group", entry.id, version.title AS name
    FROM foundation.catalog_directory_entries AS entry
    JOIN foundation.catalog_directory_versions AS version
      ON version.entry_id = entry.id AND version.id = entry.current_version_id
    WHERE entry.kind = 'CATEGORY'
    UNION ALL
    SELECT 'districts', district.id, district.name
    FROM foundation.administrative_districts AS district WHERE district.city_id = $1
    UNION ALL
    SELECT 'sources', entry.id, version.label
    FROM foundation.reference_entries AS entry
    JOIN foundation.reference_entry_versions AS version
      ON version.entry_id = entry.id AND version.id = entry.current_version_id
    WHERE entry.type = 'REQUEST_SOURCE' AND entry.scope = 'COMPANY'
    ORDER BY "group", name, id`, [cityId]);
  const options: Record<Group, Option[]> = { categories: [], districts: [], sources: [] };
  for (const { group, id, name } of rows) { options[group].push({ id, name }); }
  return { ...options, unavailable: { technician:'not_ready', payment:'not_ready', alert:'not_ready' } as const };
}
