/**
 * Server-trusted city identity for the v1 `SINGLE_CITY` launch mode.
 *
 * Read port only: it resolves which city the database says is configured. It does
 * not assert readiness of zones, prices, legal content or any other prerequisite,
 * and it never takes a city from caller input.
 */
export interface SingleCityContext {
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly timezone: string;
}

export type CityContextErrorCode = 'CONFIGURATION_INCOMPLETE';

/** Typed refusal: the database does not describe exactly one valid ACTIVE SINGLE_CITY. */
export class CityContextError extends Error {
  readonly code: CityContextErrorCode = 'CONFIGURATION_INCOMPLETE';

  constructor() {
    // Deliberately carries no database values, identifiers or driver text.
    super('City context is not configured');
    this.name = 'CityContextError';
  }
}

/** Minimal read-only pg surface: a `Pool` or a connected client satisfies it. */
export interface CityContextReader {
  query(sql: string): Promise<{ readonly rows: readonly Record<string, unknown>[] }>;
}

/**
 * One statement, no bind parameters: every value comes from the database, so a
 * caller cannot supply a city id, a timezone or a launch mode.
 *
 * - only the latest immutable published revision (`version DESC LIMIT 1`) counts;
 * - that revision must be `SINGLE_CITY` and its primary city must be the one and
 *   only `ACTIVE` city in the database (no "first city" pick);
 * - the primary's `current_version_id` must be a version of that same city;
 * - timezone validity is enforced when a version is inserted, and published
 *   revisions are immutable, so no timezone catalog scan is needed per read.
 *
 * Nothing falls back to an older revision, a global/browser timezone or a hidden
 * default. Any other state yields zero rows.
 */
export const SINGLE_CITY_CONTEXT_SQL = `WITH latest_settings_revision AS (
  SELECT launch_mode, primary_city_id
  FROM foundation.business_settings_versions
  ORDER BY version DESC
  LIMIT 1
), active_cities AS (
  SELECT id, current_version_id
  FROM foundation.service_cities
  WHERE lifecycle = 'ACTIVE'
), resolved AS (
  SELECT city.id AS "cityId", city_version.id AS "cityVersionId", city_version.timezone AS "timezone"
  FROM latest_settings_revision AS settings
  JOIN active_cities AS city ON city.id = settings.primary_city_id
  JOIN foundation.service_city_versions AS city_version
    ON city_version.id = city.current_version_id
   AND city_version.city_id = city.id
  WHERE settings.launch_mode = 'SINGLE_CITY'
    AND (SELECT count(*) FROM active_cities) = 1
)
SELECT "cityId", "cityVersionId", "timezone" FROM resolved`;

const isIdentity = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0;

/** Narrowed field by field: nothing unvalidated reaches the result. */
function toContext(row: Record<string, unknown>): SingleCityContext {
  const { cityId, cityVersionId, timezone } = row;
  if (!isIdentity(cityId) || !isIdentity(cityVersionId) || !isIdentity(timezone)) {
    throw new CityContextError();
  }
  return Object.freeze({ cityId, cityVersionId, timezone });
}

/**
 * Resolves the single configured city from PostgreSQL.
 *
 * Database failures propagate unchanged: an unreachable or broken database is an
 * operational failure, not an incomplete optional configuration.
 */
export async function readSingleCityContext(reader: CityContextReader): Promise<SingleCityContext> {
  const { rows } = await reader.query(SINGLE_CITY_CONTEXT_SQL);
  const [row] = rows;
  if (rows.length !== 1 || !row) {
    throw new CityContextError();
  }
  return toContext(row);
}
