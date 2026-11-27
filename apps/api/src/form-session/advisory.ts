import { FormSessionError } from './contract.js';

/** District-only hint before consent. Never an exact coverage verdict. */
export interface AdvisoryCoverage {
  readonly outcome: 'AREA_REVIEW_REQUIRED';
  readonly districtId: string;
  readonly hints: readonly { readonly areaId: string; readonly relation: 'FULL' | 'PARTIAL' }[];
}

/** Read-only query port: the advisory path never writes and never locks. */
export interface AdvisoryReader {
  query(
    sql: string, values: readonly unknown[],
  ): Promise<{ readonly rows: readonly Record<string, unknown>[] }>;
}

/**
 * Protocol cap of advisory hints per district (64). The cap is already enforced
 * in SQL (`LIMIT cap + 1`), so an unbounded district mapping can never be
 * collected only to be discarded after serialization; one over the cap is a
 * predictable refusal (§5.1: over the limit — refuse, never a truncated basis).
 */
export const F_MAX_ADVISORY_HINTS = 64;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** One frozen coverage hint: the exact closed vocabulary of `coverage.relation`. */
type AdvisoryHint = { readonly areaId: string; readonly relation: 'FULL' | 'PARTIAL' };

/** Narrows a stored `relation` to the closed coverage vocabulary, never trusting text. */
function relationOf(value: unknown): 'FULL' | 'PARTIAL' {
  if (value === 'FULL' || value === 'PARTIAL') {
    return value;
  }
  throw new FormSessionError('UNAVAILABLE');
}

/** Non-empty canonical UUID text from a result column, or `UNAVAILABLE`. */
function uuidOf(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) {
    throw new FormSessionError('UNAVAILABLE');
  }
  return value;
}

/**
 * Same-city active district only. A FULL mapping still returns AREA_REVIEW_REQUIRED:
 * district mapping is not address proof and must not set IN_ZONE.
 * An unknown or foreign district is NOT_FOUND, identical to a missing one.
 */
export async function adviseDistrict(
  reader: AdvisoryReader, cityId: string, districtId: string,
): Promise<AdvisoryCoverage> {
  if (!UUID.test(cityId) || !UUID.test(districtId)) {
    throw new FormSessionError('MALFORMED');
  }
  const district = await reader.query(
    `SELECT id FROM foundation.administrative_districts
     WHERE id=$1 AND city_id=$2 AND archived_at IS NULL`,
    [districtId, cityId],
  );
  if (district.rows.length !== 1) {
    throw new FormSessionError('NOT_FOUND');
  }
  const mapped = await reader.query(
    `SELECT area.id AS area_id, coverage.relation
     FROM foundation.service_area_district_coverage coverage
     JOIN foundation.service_area_versions version
       ON version.city_id = coverage.city_id AND version.id = coverage.area_version_id
     JOIN foundation.service_areas area
       ON area.city_id = version.city_id AND area.id = version.area_id
      AND area.current_version_id = version.id
     WHERE coverage.city_id=$1 AND coverage.district_id=$2
       AND version.published_at IS NOT NULL
       AND area.archived_at IS NULL
     ORDER BY area.id ASC
     LIMIT $3`,
    [cityId, districtId, F_MAX_ADVISORY_HINTS + 1],
  );
  if (mapped.rows.length > F_MAX_ADVISORY_HINTS) {
    // Over the protocol cap: a refusal, never a truncated hint basis (§5.1).
    throw new FormSessionError('UNAVAILABLE');
  }
  const hints: AdvisoryHint[] = [];
  for (const row of mapped.rows) {
    const relation: 'FULL' | 'PARTIAL' = relationOf(row['relation']);
    hints.push({ areaId: uuidOf(row['area_id']), relation });
  }
  const coverage: AdvisoryCoverage = {
    outcome: 'AREA_REVIEW_REQUIRED',
    districtId,
    hints: Object.freeze(hints),
  };
  return Object.freeze(coverage);
}
