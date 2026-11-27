/**
 * P05 §3 / §5.1 — purpose-bound address verification and the complete coverage basis.
 *
 * This module is the only early internal decrypt use case of P05 and the only
 * producer of the coverage basis an immutable assessment pins. It is a port, not a
 * route, not a controller and not a command: the caller (the `RecordCoverageAssessment`
 * command runner) owns the transaction, the request-row lock, the RBAC/scope
 * decision and the final commit. Everything here is deliberately narrow:
 *
 * ## Order that must not be reordered
 *
 * 1. pure input guards — nothing is read before they pass;
 * 2. GEO/CFG fence proof — the basis is only read while this backend already holds
 *    the shared `(734305,1)` advisory lock (the caller takes it as its first
 *    statement, exactly like every other GEO/CFG reader); this module never
 *    acquires the fence itself, so it can never invert the documented lock order;
 * 3. trusted, independent `COVERAGE_REVIEW` evidence for the exact
 *    actor/request/address revision — the address candidate comes from that port
 *    only, never from the caller or from the wire DTO;
 * 4. complete basis read (current ACTIVE city + version + timezone, every current
 *    published zone of that city, and, when the address names a district, the
 *    district's current `row_version` plus the mappings of the current zones for
 *    that district) — bounded but never truncated: over the cap refuses;
 * 5. one committed append-only audit attempt on a separate admitted S3 connection
 *    (`foundation.request_address_review_attempts`), with its own short
 *    transaction, before any ciphertext byte is read;
 * 6. the caller's own final actor/session/legal/clock recheck;
 * 7. only now the exact address payload cell is read by the IDs the basis
 *    returned, decrypted and compared; a second caller recheck follows the
 *    comparison, before the caller commits.
 *
 * The plaintext comparator is never reachable from outside: it is module-private
 * and the exported `verifyAssessmentAddress` additionally requires a branded
 * consumption token that only this module's command path can mint, so no route,
 * fixture or helper can use it as an authority-free plaintext oracle.
 *
 * ## What is never returned or logged
 *
 * The candidate, the decrypted address, the ciphertext, key material, filenames
 * and per-field comparison details never leave this module. A refused evidence or
 * a failed comparison produces the same single safe `FORBIDDEN`; the result carries
 * only IDs, the basis digest and the outcome.
 *
 * ## Reproof
 *
 * `reproofCoverageBasis` re-reads the WHOLE basis after the caller's waits and
 * refuses with `COVERAGE_ASSESSMENT_STALE` on any difference from the pinned
 * digest (address revision, city version, timezone, district `row_version`, zone
 * set or mappings). It is the live predicate `ReadyForDispatch` needs; a stored
 * readiness flag never replaces it.
 */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import type { PoolClient } from 'pg';
import { decodeP05Address } from '@fixlevelup/p03-contracts/p05';
import { canonicalJson } from '../../infrastructure/admission/proof.js';
import { requireRequestEffectsPool } from '../../infrastructure/admission/pool-guard.js';
import { openManagedPayload } from '../crypto/payload-cipher.js';
import type { PayloadCiphertext } from '../crypto/payload-cipher.js';
import type { PayloadKeySlotRef, PayloadKeySlots, PayloadKeyWrap } from '../crypto/payload-key-directory.js';
import type { KeyringConfig } from '../crypto/keyring.js';
import { deny } from './errors.js';

/* -------------------------------------------------------------------------- */
/* Closed vocabularies (mirror of the migration 024 CHECKs and the P05 wire)   */
/* -------------------------------------------------------------------------- */

export const COVERAGE_OUTCOMES = Object.freeze(['IN_ZONE', 'OUTSIDE', 'REVIEW', 'EXCEPTION'] as const);
export type CoverageOutcome = (typeof COVERAGE_OUTCOMES)[number];

export const COVERAGE_REASONS = Object.freeze(['OVERLAP_REVIEW', 'OUTSIDE_REVIEW', 'OPERATOR_REVIEW'] as const);
export type CoverageReason = (typeof COVERAGE_REASONS)[number];

/** The only evidence purpose this module consumes. */
export const COVERAGE_EVIDENCE_PURPOSE = 'COVERAGE_REVIEW' as const;
/** The only evidence issuer allowed to mint a coverage-review handle: the test contour. */
export const COVERAGE_EVIDENCE_ISSUER = 'T' as const;

/** Immutable basis format version; it is part of the pinned digest. */
export const COVERAGE_BASIS_VERSION = 'p05/coverage-basis/v1' as const;

const COVERAGE_PAYLOAD_KIND = 'ADDRESS' as const;

/** Technical ceiling of one basis. The caller passes its configured cap; a basis
 * larger than the cap is a refusal, never a truncated "complete" set. */
export const COVERAGE_BASIS_DEFAULT_CAP = 256;
export const COVERAGE_BASIS_MAX_CAP = 1024;

/** The one GEO/CFG advisory-lock key every basis read is fenced by (§5.1). */
export const COVERAGE_BASIS_FENCE_KEY = Object.freeze({ classId: 734305, objectId: 1 } as const);

/** First statement of a coverage reader: shared GEO/CFG fence. */
export const COVERAGE_BASIS_FENCE_SQL = 'SELECT pg_catalog.pg_advisory_xact_lock_shared(734305, 1)';

/** Proves that THIS backend already holds the fence in its current transaction.
 * `objsubid=2` is the two-int advisory form; `pid=pg_backend_pid()` keeps another
 * session's lock from satisfying the probe. */
export const COVERAGE_BASIS_FENCE_HELD_SQL = `SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_locks
  WHERE locktype='advisory' AND granted AND pid=pg_catalog.pg_backend_pid()
    AND classid=$1::int::oid AND objid=$2::int::oid AND objsubid=2
) AS held`;

const COVERAGE_CLOCK_SQL = 'SELECT clock_timestamp() AS now';

/* -------------------------------------------------------------------------- */
/* Basis shape                                                                */
/* -------------------------------------------------------------------------- */

export interface CoverageZone {
  readonly areaId: string;
  readonly areaVersionId: string;
}

export interface CoverageMapping {
  readonly areaId: string;
  readonly areaVersionId: string;
  readonly districtId: string;
  readonly relation: 'FULL' | 'PARTIAL';
}

/** The exact immutable address revision the assessment is about. */
export interface CoverageAddressFacts {
  readonly requestId: string;
  readonly addressRevisionId: string;
  readonly addressRevision: number;
  /** District provenance recorded with the address (immutable history). */
  readonly districtId: string | null;
  readonly districtRowVersion: number | null;
  /** The exact payload cell to open; it is never selected before the audit commit. */
  readonly payloadCellId: string;
  /** Whether this revision is still the request's current address. */
  readonly current: boolean;
}

/** The request aggregate facts the basis was read for (mutable columns excluded from the digest). */
export interface CoverageRequestFacts {
  readonly requestId: string;
  readonly cityId: string;
  readonly type: 'CALLBACK' | 'REPAIR';
  readonly status: string;
  readonly rowVersion: number;
  readonly currentAddressRevisionId: string | null;
}

/** Current administrative district of the address, when it names one. */
export interface CoverageDistrictFacts {
  readonly districtId: string;
  readonly rowVersion: number;
  readonly archived: boolean;
}

export interface CoverageBasis {
  readonly version: typeof COVERAGE_BASIS_VERSION;
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly timezone: string;
  readonly request: CoverageRequestFacts;
  readonly address: CoverageAddressFacts;
  readonly district: CoverageDistrictFacts | null;
  /** Every current published zone of this city, sorted by (areaId, areaVersionId). */
  readonly zones: readonly CoverageZone[];
  /** Mappings of those current zones for the address district (empty without a district). */
  readonly mappings: readonly CoverageMapping[];
  /** SHA-256 of `canonicalJson` over the immutable basis material. */
  readonly basisDigest: string;
}

/* -------------------------------------------------------------------------- */
/* Small pure guards                                                          */
/* -------------------------------------------------------------------------- */

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const MAX_CANDIDATE_BYTES = 4096;
const MAX_CANDIDATE_TEXT = 1000;

function uuidValue(value: unknown): string {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) { return deny('UNPROCESSABLE'); }
  return value;
}

function positiveInteger(value: unknown, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max) {
    return deny('UNPROCESSABLE');
  }
  return value;
}

function basisCap(value: unknown): number {
  return positiveInteger(value, COVERAGE_BASIS_MAX_CAP);
}

function closedOutcome(value: unknown): CoverageOutcome {
  const outcome: string = typeof value === 'string' ? value : '';
  if (!(COVERAGE_OUTCOMES as readonly string[]).includes(outcome)) { return deny('UNPROCESSABLE'); }
  return outcome as CoverageOutcome;
}

function closedReason(value: unknown): CoverageReason {
  const reason: string = typeof value === 'string' ? value : '';
  if (!(COVERAGE_REASONS as readonly string[]).includes(reason)) { return deny('UNPROCESSABLE'); }
  return reason as CoverageReason;
}

function rowValue(value: unknown): Record<string, unknown> {
  // A database row that does not have the exact reviewed shape is a dependency
  // failure, not a user error; it must never be coerced into a permissive default.
  if (typeof value !== 'object' || value === null || Array.isArray(value)) { return deny('DEPENDENCY_UNAVAILABLE'); }
  return value as Record<string, unknown>;
}

function textValue(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) { return deny('DEPENDENCY_UNAVAILABLE'); }
  return value;
}

function intValue(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    return deny('DEPENDENCY_UNAVAILABLE');
  }
  return value;
}

function nullableUuid(value: unknown): string | null {
  if (value === null) { return null; }
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) { return deny('DEPENDENCY_UNAVAILABLE'); }
  return value;
}

function nullableInt(value: unknown): number | null {
  if (value === null) { return null; }
  return intValue(value);
}

/* -------------------------------------------------------------------------- */
/* GEO/CFG fence                                                              */
/* -------------------------------------------------------------------------- */

/** Takes the shared GEO/CFG fence. The caller runs this as its first statement. */
export async function lockCoverageBasisFence(client: PoolClient): Promise<void> {
  await client.query(COVERAGE_BASIS_FENCE_SQL);
}

/**
 * Proves the caller already holds the GEO/CFG fence. This module never acquires it
 * after a domain read or row lock: a late shared→exclusive or shared-after-row-lock
 * acquisition could invert the documented order.
 */
export async function assertCoverageBasisFence(client: PoolClient): Promise<void> {
  const { rows } = await client.query<{ held: boolean }>(COVERAGE_BASIS_FENCE_HELD_SQL,
    [COVERAGE_BASIS_FENCE_KEY.classId, COVERAGE_BASIS_FENCE_KEY.objectId]);
  if (rows[0]?.held !== true) { return deny('NOT_READY'); }
}

/* -------------------------------------------------------------------------- */
/* Basis read                                                                 */
/* -------------------------------------------------------------------------- */

const CITY_SQL = `SELECT city.id AS city_id, city.lifecycle, city.current_version_id,
    version.timezone
  FROM foundation.service_cities AS city
  LEFT JOIN foundation.service_city_versions AS version
    ON version.id = city.current_version_id AND version.city_id = city.id
  WHERE city.id = $1`;

const ADDRESS_SQL = `SELECT address.id AS address_revision_id, address.revision AS address_revision,
    address.district_id, address.district_row_version, address.payload_cell_id,
    request.id AS request_id, request.type, request.status, request.row_version,
    request.city_id, request.current_address_revision_id
  FROM foundation.request_address_revisions AS address
  JOIN foundation.requests AS request ON request.id = address.request_id
  WHERE address.id = $1 AND request.city_id = $2`;

const ZONES_SQL = `SELECT area.id AS area_id, version.id AS area_version_id
  FROM foundation.service_areas AS area
  JOIN foundation.service_area_versions AS version
    ON version.id = area.current_version_id AND version.area_id = area.id AND version.city_id = area.city_id
  WHERE area.city_id = $1 AND area.archived_at IS NULL AND area.current_version_id IS NOT NULL
    AND version.published_at IS NOT NULL
  ORDER BY area.id, version.id
  LIMIT $2`;

const MAPPINGS_SQL = `SELECT version.area_id, mapping.area_version_id, mapping.district_id, mapping.relation
  FROM foundation.service_area_district_coverage AS mapping
  JOIN foundation.service_area_versions AS version
    ON version.id = mapping.area_version_id AND version.city_id = mapping.city_id
  JOIN foundation.service_areas AS area
    ON area.id = version.area_id AND area.city_id = version.city_id
   AND area.current_version_id = version.id AND area.archived_at IS NULL
  WHERE mapping.city_id = $1 AND mapping.district_id = $2
  ORDER BY version.area_id, version.id
  LIMIT $3`;

const DISTRICT_SQL = `SELECT district.id AS district_id, district.row_version, district.archived_at
  FROM foundation.administrative_districts AS district
  WHERE district.id = $1 AND district.city_id = $2`;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortedZones(rows: readonly Record<string, unknown>[]): CoverageZone[] {
  const zones = rows.map((row) => {
    const value = rowValue(row);
    return Object.freeze({ areaId: textValue(value['area_id']), areaVersionId: textValue(value['area_version_id']) });
  });
  zones.sort((left, right) => compareText(left.areaId, right.areaId)
    || compareText(left.areaVersionId, right.areaVersionId));
  for (let index = 1; index < zones.length; index += 1) {
    const prior = zones[index - 1];
    const current = zones[index];
    if (prior && current && prior.areaId === current.areaId && prior.areaVersionId === current.areaVersionId) {
      return deny('DEPENDENCY_UNAVAILABLE');
    }
  }
  return zones;
}

function sortedMappings(rows: readonly Record<string, unknown>[]): CoverageMapping[] {
  const mappings = rows.map((row) => {
    const value = rowValue(row);
    const relation: string = textValue(value['relation']);
    if (relation !== 'FULL' && relation !== 'PARTIAL') { return deny('DEPENDENCY_UNAVAILABLE'); }
    return Object.freeze({
      areaId: textValue(value['area_id']),
      areaVersionId: textValue(value['area_version_id']),
      districtId: textValue(value['district_id']),
      relation,
    });
  });
  mappings.sort((left, right) => compareText(left.areaId, right.areaId)
    || compareText(left.areaVersionId, right.areaVersionId)
    || compareText(left.districtId, right.districtId));
  for (let index = 1; index < mappings.length; index += 1) {
    const prior = mappings[index - 1];
    const current = mappings[index];
    if (prior && current && prior.areaVersionId === current.areaVersionId && prior.districtId === current.districtId) {
      return deny('DEPENDENCY_UNAVAILABLE');
    }
  }
  return mappings;
}

/** The immutable basis material the digest pins: no mutable request columns. */
function basisMaterial(input: {
  cityId: string; cityVersionId: string; timezone: string; requestId: string;
  addressRevisionId: string; addressRevision: number;
  addressDistrictId: string | null; addressDistrictRowVersion: number | null;
  district: CoverageDistrictFacts | null; zones: readonly CoverageZone[]; mappings: readonly CoverageMapping[];
}): string {
  return canonicalJson({
    version: COVERAGE_BASIS_VERSION,
    cityId: input.cityId,
    cityVersionId: input.cityVersionId,
    timezone: input.timezone,
    requestId: input.requestId,
    addressRevisionId: input.addressRevisionId,
    addressRevision: input.addressRevision,
    addressDistrictId: input.addressDistrictId,
    addressDistrictRowVersion: input.addressDistrictRowVersion,
    district: input.district === null ? null
      : [input.district.districtId, input.district.rowVersion, input.district.archived],
    zones: input.zones.map((zone) => [zone.areaId, zone.areaVersionId]),
    mappings: input.mappings.map((mapping) => [mapping.areaId, mapping.areaVersionId, mapping.districtId, mapping.relation]),
  });
}

function digestOf(material: string): string {
  return createHash('sha256').update(material, 'utf8').digest('hex');
}

/**
 * Reads the complete, sorted, bounded coverage basis for one exact address revision.
 *
 * The caller must already hold the GEO/CFG fence in its transaction (see
 * `lockCoverageBasisFence`) and the request-row lock; this function only proves the
 * fence and reads. Nothing is truncated: `zones + mappings` over `cap` refuses.
 */
export async function readCoverageBasis(client: PoolClient, cityId: string, addressRevisionId: string,
  cap: number): Promise<CoverageBasis> {
  const city = uuidValue(cityId);
  const addressRevision = uuidValue(addressRevisionId);
  const limit = basisCap(cap);

  await assertCoverageBasisFence(client);

  const cityRows = (await client.query<Record<string, unknown>>(CITY_SQL, [city])).rows;
  if (cityRows.length !== 1) { return deny('CITY_CONTEXT_STALE'); }
  const cityRow = rowValue(cityRows[0]);
  if (cityRow['lifecycle'] !== 'ACTIVE') { return deny('CITY_CONTEXT_STALE'); }
  const currentVersion = cityRow['current_version_id'];
  const timezoneValue = cityRow['timezone'];
  if (typeof currentVersion !== 'string' || !UUID_PATTERN.test(currentVersion)
    || typeof timezoneValue !== 'string' || timezoneValue.length === 0) {
    return deny('CITY_CONTEXT_STALE');
  }
  const cityVersionId = currentVersion;
  const timezone = timezoneValue;

  const addressRows = (await client.query<Record<string, unknown>>(ADDRESS_SQL, [addressRevision, city])).rows;
  if (addressRows.length !== 1) { return deny('NOT_FOUND'); }
  const addressRow = rowValue(addressRows[0]);
  const requestId = uuidValue(addressRow['request_id']);
  const requestCityId = uuidValue(addressRow['city_id']);
  if (requestCityId !== city) { return deny('NOT_FOUND'); }
  const requestType: string = textValue(addressRow['type']);
  if (requestType !== 'CALLBACK' && requestType !== 'REPAIR') { return deny('DEPENDENCY_UNAVAILABLE'); }
  const requestStatus = textValue(addressRow['status']);
  const requestVersion = intValue(addressRow['row_version']);
  const currentAddressRevisionId = nullableUuid(addressRow['current_address_revision_id']);
  const districtId = nullableUuid(addressRow['district_id']);
  const districtRowVersion = nullableInt(addressRow['district_row_version']);
  if ((districtId === null) !== (districtRowVersion === null)) { return deny('DEPENDENCY_UNAVAILABLE'); }
  const addressFacts: CoverageAddressFacts = Object.freeze({
    requestId,
    addressRevisionId: addressRevision,
    addressRevision: intValue(addressRow['address_revision']),
    districtId,
    districtRowVersion,
    payloadCellId: uuidValue(addressRow['payload_cell_id']),
    current: currentAddressRevisionId === addressRevision,
  });

  let district: CoverageDistrictFacts | null = null;
  if (districtId !== null) {
    const districtRows = (await client.query<Record<string, unknown>>(DISTRICT_SQL, [districtId, city])).rows;
    if (districtRows.length !== 1) { return deny('NOT_FOUND'); }
    const districtRow = rowValue(districtRows[0]);
    if (uuidValue(districtRow['district_id']) !== districtId) { return deny('DEPENDENCY_UNAVAILABLE'); }
    district = Object.freeze({
      districtId,
      rowVersion: intValue(districtRow['row_version']),
      archived: districtRow['archived_at'] !== null && districtRow['archived_at'] !== undefined,
    });
  }

  const zoneRows = (await client.query<Record<string, unknown>>(ZONES_SQL, [city, limit + 1])).rows;
  if (zoneRows.length > limit) { return deny('UNPROCESSABLE'); }
  const zones = sortedZones(zoneRows);

  let mappings: CoverageMapping[] = [];
  if (districtId !== null) {
    const mappingRows = (await client.query<Record<string, unknown>>(MAPPINGS_SQL, [city, districtId, limit + 1])).rows;
    if (mappingRows.length > limit) { return deny('UNPROCESSABLE'); }
    mappings = sortedMappings(mappingRows);
    if (mappings.some((mapping) => mapping.districtId !== districtId)) { return deny('DEPENDENCY_UNAVAILABLE'); }
  }
  if (zones.length + mappings.length > limit) { return deny('UNPROCESSABLE'); }

  const basisDigest = digestOf(basisMaterial({
    cityId: city, cityVersionId, timezone, requestId, addressRevisionId: addressRevision,
    addressRevision: addressFacts.addressRevision, addressDistrictId: districtId,
    addressDistrictRowVersion: districtRowVersion, district, zones, mappings,
  }));

  return Object.freeze({
    version: COVERAGE_BASIS_VERSION,
    cityId: city,
    cityVersionId,
    timezone,
    request: Object.freeze({
      requestId, cityId: requestCityId, type: requestType,
      status: requestStatus, rowVersion: requestVersion, currentAddressRevisionId,
    }),
    address: addressFacts,
    district,
    zones: Object.freeze(zones),
    mappings: Object.freeze(mappings),
    basisDigest,
  });
}

/**
 * Re-reads the whole basis after the caller's waits and refuses with
 * `COVERAGE_ASSESSMENT_STALE` on any difference from the pinned digest (or when the
 * assessed address is no longer current). This is the live `ReadyForDispatch`
 * predicate; no stored readiness flag replaces it.
 */
export async function reproofCoverageBasis(client: PoolClient, cityId: string, addressRevisionId: string,
  expectedDigest: string, cap: number): Promise<CoverageBasis> {
  if (typeof expectedDigest !== 'string' || !DIGEST_PATTERN.test(expectedDigest)) { return deny('UNPROCESSABLE'); }
  const basis = await readCoverageBasis(client, cityId, addressRevisionId, cap);
  if (!basis.address.current || basis.basisDigest !== expectedDigest) {
    return deny('COVERAGE_ASSESSMENT_STALE');
  }
  return basis;
}

/* -------------------------------------------------------------------------- */
/* Selection validation (pure)                                                */
/* -------------------------------------------------------------------------- */

export interface CoverageSelection {
  readonly outcome: CoverageOutcome;
  readonly areaId?: string;
  readonly reason?: CoverageReason;
}

export interface ResolvedCoverageSelection {
  readonly outcome: CoverageOutcome;
  readonly reason: CoverageReason | null;
  readonly areaId: string | null;
  readonly areaVersionId: string | null;
}

/**
 * Validates one operator selection against the complete basis.
 *
 * - `IN_ZONE`/`EXCEPTION` require exactly one currently published zone of this city
 *   (`IN_ZONE` takes no reason; `EXCEPTION` always requires one, migration 024);
 * - a positive outcome is refused on an empty basis (an empty zone set can never
 *   establish coverage);
 * - `IN_ZONE` is refused when more than one current zone maps the address district:
 *   an overlap must be recorded as `REVIEW`/`OVERLAP_REVIEW`, never silently
 *   collapsed into a positive assessment (without a district an overlap cannot be
 *   observed from mappings, so the operator's reviewed procedure decides);
 * - `OUTSIDE` takes no zone and requires `OUTSIDE_REVIEW`; `REVIEW` takes no zone
 *   and requires `OVERLAP_REVIEW` or `OPERATOR_REVIEW` (the P05 wire contract).
 */
export function validateCoverageSelection(basis: CoverageBasis, input: CoverageSelection): ResolvedCoverageSelection {
  const selection: unknown = input;
  if (typeof selection !== 'object' || selection === null || Array.isArray(selection)) { return deny('UNPROCESSABLE'); }
  const { outcome: rawOutcome, reason: rawReason, areaId: rawArea } = selection as Record<string, unknown>;
  const outcome = closedOutcome(rawOutcome);
  const reason = rawReason === undefined ? null : closedReason(rawReason);
  const areaId = rawArea === undefined ? null : uuidValue(rawArea);

  const zoneFor = (id: string): CoverageZone => {
    const zone = basis.zones.find((entry) => entry.areaId === id);
    return zone ?? deny('UNPROCESSABLE');
  };

  if (outcome === 'IN_ZONE' || outcome === 'EXCEPTION') {
    if (areaId === null) { return deny('UNPROCESSABLE'); }
    if (basis.zones.length === 0) { return deny('UNPROCESSABLE'); }
    const zone = zoneFor(areaId);
    if (outcome === 'IN_ZONE') {
      if (reason !== null && reason !== 'OVERLAP_REVIEW') { return deny('UNPROCESSABLE'); }
      if (basis.district?.archived) { return deny('COVERAGE_ASSESSMENT_STALE'); }
      const districtId = basis.address.districtId;
      if (districtId !== null) {
        const covering = new Set(basis.mappings
          .filter((mapping) => mapping.districtId === districtId)
          .map((mapping) => mapping.areaVersionId));
        if (covering.size > 1 && reason !== 'OVERLAP_REVIEW') { return deny('UNPROCESSABLE'); }
      }
    } else if (reason !== 'OUTSIDE_REVIEW' && reason !== 'OPERATOR_REVIEW') {
      return deny('UNPROCESSABLE');
    }
    return Object.freeze({ outcome, reason, areaId, areaVersionId: zone.areaVersionId });
  }

  if (areaId !== null) { return deny('UNPROCESSABLE'); }
  if (outcome === 'OUTSIDE') {
    if (reason !== 'OUTSIDE_REVIEW' && reason !== 'OPERATOR_REVIEW') { return deny('UNPROCESSABLE'); }
  } else if (reason !== 'OVERLAP_REVIEW' && reason !== 'OPERATOR_REVIEW') {
    return deny('UNPROCESSABLE');
  }
  return Object.freeze({ outcome, reason, areaId: null, areaVersionId: null });
}

/* -------------------------------------------------------------------------- */
/* Trusted evidence port and the one-time committed audit attempt              */
/* -------------------------------------------------------------------------- */

export interface CoverageReviewEvidenceRequest {
  readonly issuer: typeof COVERAGE_EVIDENCE_ISSUER;
  readonly purpose: typeof COVERAGE_EVIDENCE_PURPOSE;
  readonly evidenceId: string;
  readonly staffId: string;
  readonly requestId: string;
  readonly addressRevisionId: string;
  readonly now: Date;
}

/**
 * Evidence returned by the trusted, independent test-only issuer. It binds the
 * exact issuer/purpose/actor/request/address revision and the canonical address
 * candidate observed through the independent procedure. The caller cannot supply
 * or replace the candidate: only this handle is accepted from the wire.
 */
export interface CoverageReviewEvidence {
  readonly evidenceId: string;
  readonly issuer: typeof COVERAGE_EVIDENCE_ISSUER;
  readonly purpose: typeof COVERAGE_EVIDENCE_PURPOSE;
  readonly staffId: string;
  readonly requestId: string;
  readonly addressRevisionId: string;
  /** Normalized wire address object or its canonical UTF-8 bytes; guarded here. */
  readonly candidate: unknown;
  readonly expiresAt: Date;
}

/** Only the isolated test composition provides an implementation. */
export interface CoverageReviewEvidencePort {
  verify(request: CoverageReviewEvidenceRequest): Promise<CoverageReviewEvidence | null | undefined>;
}

export interface CoverageAuditAttempt {
  readonly evidenceId: string;
  readonly staffId: string;
  readonly requestId: string;
  readonly addressRevisionId: string;
  readonly purpose: typeof COVERAGE_EVIDENCE_PURPOSE;
  readonly correlationId: string;
}

export type CoverageAuditCommit = 'COMMITTED' | 'DUPLICATE' | 'UNCONFIRMED';

/**
 * Append-only, separate-connection audit port. `COMMITTED` means the minimal
 * attempt row is durably committed; `DUPLICATE` means the evidence was already
 * consumed (or this correlation exists) and no new attempt was created;
 * `UNCONFIRMED` covers a lost/unknown acknowledgement. There is no retry: an
 * unknown outcome must never be reused.
 */
export interface CoverageAuditAttemptStore {
  record(attempt: CoverageAuditAttempt): Promise<CoverageAuditCommit>;
}

const AUDIT_INSERT_SQL = `INSERT INTO foundation.request_address_review_attempts
  (evidence_id,staff_id,request_id,address_revision_id,purpose,correlation_id)
  VALUES ($1,$2,$3,$4,$5,$6)`;

/**
 * Builds the S3-only audit store over an admitted request-effects pool. The
 * factory refuses a pool that is not an admitted S3 request-effects pool, so no
 * ordinary or pre-S3 composition can reach the attempt table. Each attempt uses
 * its own short transaction on its own connection — never the caller's locked
 * transaction and never an FK to a held domain row.
 */
export function requestEffectsAuditStore(pool: object): CoverageAuditAttemptStore {
  requireRequestEffectsPool(pool);
  const connect = (pool as { connect(): Promise<PoolClient> }).connect.bind(pool);
  return Object.freeze({
    async record(attempt: CoverageAuditAttempt): Promise<CoverageAuditCommit> {
      let client: PoolClient | undefined;
      try {
        client = await connect();
      } catch {
        return 'UNCONFIRMED';
      }
      let committing = false;
      let discard = false;
      try {
        await client.query('BEGIN');
        await client.query('SET LOCAL synchronous_commit=on');
        await client.query(AUDIT_INSERT_SQL, [attempt.evidenceId, attempt.staffId, attempt.requestId,
          attempt.addressRevisionId, attempt.purpose, attempt.correlationId]);
        committing = true;
        if ((await client.query('COMMIT')).command === 'COMMIT') { return 'COMMITTED'; }
        discard = true;
        return 'UNCONFIRMED';
      } catch (error) {
        if (committing) { discard = true; return 'UNCONFIRMED'; }
        try { await client.query('ROLLBACK'); } catch { discard = true; }
        const code = (error as { code?: unknown } | null)?.code;
        return code === '23505' ? 'DUPLICATE' : 'UNCONFIRMED';
      } finally {
        client.release(discard);
      }
    },
  });
}

/* -------------------------------------------------------------------------- */
/* Address candidate guard and the attested plaintext comparator              */
/* -------------------------------------------------------------------------- */

/** Branded consumption token: only the command path below can mint one. */
export interface AssessmentAddressConsumption {
  readonly consumed: true;
}

const attestedConsumptions = new WeakSet<object>();

function attestConsumption(): AssessmentAddressConsumption {
  const token: AssessmentAddressConsumption = Object.freeze({ consumed: true as const });
  attestedConsumptions.add(token);
  return token;
}

function strictAddressRecord(value: unknown): unknown {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) { return deny('FORBIDDEN'); }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) { return deny('FORBIDDEN'); }
  if (Object.getOwnPropertySymbols(value).length !== 0) { return deny('FORBIDDEN'); }
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) {
      return deny('FORBIDDEN');
    }
  }
  return value;
}

/** Normalizes the candidate through the exact P05 wire address decoder and returns
 * its canonical bytes. Anything the wire would not accept is refused before any
 * ciphertext is opened. */
function canonicalCandidate(candidate: unknown): Buffer {
  let value: unknown = candidate;
  if (candidate instanceof Uint8Array) {
    if (candidate.byteLength === 0 || candidate.byteLength > MAX_CANDIDATE_BYTES) { return deny('FORBIDDEN'); }
    const bytes = Buffer.from(candidate);
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      return deny('FORBIDDEN');
    } finally {
      bytes.fill(0);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      return deny('FORBIDDEN');
    }
    if (canonicalJson(parsed) !== text) { return deny('FORBIDDEN'); }
    value = parsed;
  }
  let normalized: unknown;
  try {
    normalized = decodeP05Address(strictAddressRecord(value));
  } catch {
    return deny('FORBIDDEN');
  }
  const canonical = canonicalJson(normalized);
  if (Buffer.byteLength(canonical, 'utf8') > MAX_CANDIDATE_BYTES) { return deny('FORBIDDEN'); }
  return Buffer.from(canonical, 'utf8');
}

/** Canonical bytes of an opened address plaintext (the store may pad short cells
 * with trailing spaces up to the SQL minimum; anything else must be exact). */
function canonicalOpened(plaintext: Buffer): Buffer {
  let end = plaintext.length;
  while (end > 0 && plaintext[end - 1] === 0x20) { end -= 1; }
  const trimmed = plaintext.subarray(0, end);
  if (trimmed.length === 0 || trimmed.length > MAX_CANDIDATE_TEXT) { return deny('DEPENDENCY_UNAVAILABLE'); }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(trimmed);
  } catch {
    return deny('DEPENDENCY_UNAVAILABLE');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return deny('DEPENDENCY_UNAVAILABLE');
  }
  let normalized: unknown;
  try {
    normalized = decodeP05Address(parsed);
  } catch {
    return deny('DEPENDENCY_UNAVAILABLE');
  }
  return Buffer.from(canonicalJson(normalized), 'utf8');
}

function constantTimeEqual(left: Buffer, right: Buffer): boolean {
  const leftDigest = createHash('sha256').update(left).digest();
  const rightDigest = createHash('sha256').update(right).digest();
  const equal = timingSafeEqual(leftDigest, rightDigest) && left.length === right.length;
  leftDigest.fill(0);
  rightDigest.fill(0);
  return equal;
}

/**
 * The only decrypt use case of P05 (§3). Opens the exact address cell and compares
 * it with the candidate from the trusted evidence. Never returns plaintext.
 *
 * Reachable only through the branded `consumption` token this module mints inside
 * `recordCoverageAssessment`, so it can never be used as an authority-free
 * plaintext comparator by a route, a fixture or a helper.
 */
export function verifyAssessmentAddress(input: {
  readonly consumption: AssessmentAddressConsumption;
  readonly ring: KeyringConfig;
  readonly ref: PayloadKeySlotRef;
  readonly cell: PayloadCiphertext;
  readonly wrap: PayloadKeyWrap;
  readonly candidate: unknown;
}): boolean {
  if (!attestedConsumptions.delete(input.consumption)) { return deny('FORBIDDEN'); }
  const candidate = canonicalCandidate(input.candidate);
  let plaintext: Buffer | undefined;
  let opened: Buffer | undefined;
  try {
    try {
      plaintext = openManagedPayload(input.ref, input.ring, input.cell, input.wrap);
    } catch {
      // Tampering, a wrong environment/schema/kind/revision or a missing historical
      // key: one safe dependency refusal, never a per-field diagnostic.
      return deny('DEPENDENCY_UNAVAILABLE');
    }
    opened = canonicalOpened(plaintext);
    return constantTimeEqual(candidate, opened);
  } finally {
    candidate.fill(0);
    plaintext?.fill(0);
    opened?.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/* RecordCoverageAssessment basis step                                        */
/* -------------------------------------------------------------------------- */

const PAYLOAD_CELL_SQL = `SELECT kind, revision, nonce, ciphertext, auth_tag, aad_context
  FROM foundation.request_payload_cells
  WHERE request_id = $1 AND id = $2`;

export interface RecordCoverageAssessmentInput {
  readonly client: PoolClient;
  readonly ring: KeyringConfig;
  readonly environment: string;
  readonly keySlots: PayloadKeySlots;
  readonly actor: { readonly staffId: string };
  readonly request: {
    readonly requestId: string;
    readonly cityId: string;
    readonly addressRevisionId: string;
    readonly expectedVersion: number;
  };
  /** Optional caller-held snapshot facts; when supplied they must equal the basis. */
  readonly snapshot?: {
    readonly addressRevisionId?: string;
    readonly districtId?: string | null;
    readonly districtRowVersion?: number | null;
    readonly cityVersionId?: string;
  };
  readonly evidenceHandle: string;
  readonly selection: CoverageSelection;
  readonly cap: number;
  readonly evidence: CoverageReviewEvidencePort;
  readonly audit: CoverageAuditAttemptStore;
  /** Caller's final authority/session/legal/clock recheck; invoked after the audit
   * commit and again after the comparison, before the caller commits. */
  readonly recheck: () => Promise<Date>;
}

/** What the command runner needs to insert the immutable assessment row itself. */
export interface CoverageAssessmentResult {
  readonly assessmentId: string;
  readonly requestId: string;
  readonly addressRevisionId: string;
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly areaId: string | null;
  readonly areaVersionId: string | null;
  readonly basisDigest: string;
  readonly outcome: CoverageOutcome;
  readonly reason: CoverageReason | null;
  readonly staffId: string;
  readonly attemptCorrelationId: string;
  readonly evidenceId: string;
  /** Internal commit deadline, never returned by the HTTP surface. */
  readonly evidenceExpiresAt: Date;
}

function requireEvidence(evidence: CoverageReviewEvidence | null | undefined,
  request: CoverageReviewEvidenceRequest): CoverageReviewEvidence {
  if (!evidence) { return deny('FORBIDDEN'); }
  if (evidence.evidenceId !== request.evidenceId || !Object.is(evidence.issuer,request.issuer)
    || !Object.is(evidence.purpose,request.purpose) || evidence.staffId !== request.staffId
    || evidence.requestId !== request.requestId || evidence.addressRevisionId !== request.addressRevisionId) {
    return deny('FORBIDDEN');
  }
  if (!(evidence.expiresAt instanceof Date) || !Number.isFinite(evidence.expiresAt.getTime())
    || evidence.expiresAt.getTime() <= request.now.getTime()) {
    return deny('FORBIDDEN');
  }
  return evidence;
}

function requireSnapshotMatch(basis: CoverageBasis, snapshot: NonNullable<RecordCoverageAssessmentInput['snapshot']>): void {
  if (snapshot.addressRevisionId !== undefined && snapshot.addressRevisionId !== basis.address.addressRevisionId) {
    return deny('COVERAGE_ASSESSMENT_STALE');
  }
  if (snapshot.cityVersionId !== undefined && snapshot.cityVersionId !== basis.cityVersionId) {
    return deny('COVERAGE_ASSESSMENT_STALE');
  }
  if (snapshot.districtId !== undefined && snapshot.districtId !== basis.address.districtId) {
    return deny('COVERAGE_ASSESSMENT_STALE');
  }
  if (snapshot.districtRowVersion !== undefined && snapshot.districtRowVersion !== basis.address.districtRowVersion) {
    return deny('COVERAGE_ASSESSMENT_STALE');
  }
}

/**
 * Performs every check of `RecordCoverageAssessment` up to (and including) the
 * admitted address comparison, then returns the exact IDs the caller inserts.
 *
 * It never inserts the assessment row, the command event, the receipt or the
 * request pointer, and it never commits: those stay one atomic unit owned by the
 * caller. The audit attempt, by contrast, is deliberately committed on its own
 * connection and survives a later rollback (§3).
 */
export async function recordCoverageAssessment(input: RecordCoverageAssessmentInput): Promise<CoverageAssessmentResult> {
  /* 1. Pure input guards: nothing is read before these pass. */
  const client = input.client;
  const staffId = uuidValue(input.actor.staffId);
  const requestId = uuidValue(input.request.requestId);
  const cityId = uuidValue(input.request.cityId);
  const addressRevisionId = uuidValue(input.request.addressRevisionId);
  const expectedVersion = positiveInteger(input.request.expectedVersion, Number.MAX_SAFE_INTEGER);
  const evidenceId = uuidValue(input.evidenceHandle);
  const cap = basisCap(input.cap);
  if (typeof input.recheck !== 'function') { return deny('DEPENDENCY_UNAVAILABLE'); }

  /* 2. Fence proof and the database clock used for the evidence/expiry check. */
  await assertCoverageBasisFence(client);
  const clockRows = (await client.query<{ now: Date }>(COVERAGE_CLOCK_SQL)).rows;
  const now = clockRows[0]?.now;
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) { return deny('DEPENDENCY_UNAVAILABLE'); }

  /* 3. Trusted, independent, purpose-bound evidence for this exact actor/request/
   *    address revision. No SQL, no decrypt and no audit before it verifies. */
  const evidenceRequest: CoverageReviewEvidenceRequest = Object.freeze({
    issuer: COVERAGE_EVIDENCE_ISSUER,
    purpose: COVERAGE_EVIDENCE_PURPOSE,
    evidenceId,
    staffId,
    requestId,
    addressRevisionId,
    now,
  });
  let evidence: CoverageReviewEvidence;
  try {
    evidence = requireEvidence(await input.evidence.verify(evidenceRequest), evidenceRequest);
  } catch {
    return deny('FORBIDDEN');
  }

  /* 3b. Guard and canonicalize the candidate before any basis read, any audit
   *     attempt and any ciphertext byte. A malformed candidate therefore refuses
   *     without touching the domain at all. */
  const candidate = canonicalCandidate(evidence.candidate);
  const expiresAt = evidence.expiresAt.getTime();
  const requireEvidenceLive = (clock: Date | undefined): void => {
    if (!(clock instanceof Date) || !Number.isFinite(clock.getTime()) || expiresAt <= clock.getTime()) {
      deny('FORBIDDEN');
    }
  };
  try {
    /* 4. Complete basis after the fence, then the caller's own facts against it. */
    const basis = await readCoverageBasis(client, cityId, addressRevisionId, cap);
    if (basis.request.requestId !== requestId) { return deny('NOT_FOUND'); }
    if (basis.request.rowVersion !== expectedVersion) { return deny('PRECONDITION_FAILED'); }
    if (!basis.address.current || basis.request.currentAddressRevisionId !== addressRevisionId) {
      return deny('COVERAGE_ASSESSMENT_STALE');
    }
    if (basis.request.type !== 'REPAIR' || basis.request.status !== 'MANAGER_REVIEW') { return deny('NOT_READY'); }
    if (input.snapshot !== undefined) { requireSnapshotMatch(basis, input.snapshot); }

    /* 5. The operator selection must be resolvable inside this exact basis. */
    const selection = validateCoverageSelection(basis, input.selection);
    requireEvidenceLive((await client.query<{ now: Date }>(COVERAGE_CLOCK_SQL)).rows[0]?.now);

    /* 6. One committed minimal audit attempt on the separate admitted S3 pool,
     *    before any ciphertext byte is read. A duplicate or an unconfirmed commit
     *    refuses; there is no retry and no decrypt. */
    const attemptCorrelationId = randomUUID();
    let commit: CoverageAuditCommit;
    try {
      commit = await input.audit.record(Object.freeze({
        evidenceId,
        staffId,
        requestId,
        addressRevisionId,
        purpose: COVERAGE_EVIDENCE_PURPOSE,
        correlationId: attemptCorrelationId,
      }));
    } catch {
      return deny('DEPENDENCY_UNAVAILABLE');
    }
    if (commit === 'DUPLICATE') { return deny('CONFLICT'); }
    if (commit !== 'COMMITTED') { return deny('DEPENDENCY_UNAVAILABLE'); }

    /* 7. The caller's final authority/session/legal/clock recheck, after the audit
     *    wait and before the decrypt. A refusal propagates unchanged. */
    requireEvidenceLive(await input.recheck());

    /* 8. Only now the exact cell named by the basis is read and opened. */
    const cellRows = (await client.query<Record<string, unknown>>(PAYLOAD_CELL_SQL,
      [basis.address.requestId, basis.address.payloadCellId])).rows;
    if (cellRows.length !== 1) { return deny('DEPENDENCY_UNAVAILABLE'); }
    const cell = rowValue(cellRows[0]);
    if (cell['kind'] !== COVERAGE_PAYLOAD_KIND || intValue(cell['revision']) !== basis.address.addressRevision) {
      return deny('DEPENDENCY_UNAVAILABLE');
    }
    if (!Buffer.isBuffer(cell['nonce']) || !Buffer.isBuffer(cell['ciphertext'])
      || !Buffer.isBuffer(cell['auth_tag']) || typeof cell['aad_context'] !== 'string') {
      return deny('DEPENDENCY_UNAVAILABLE');
    }
    const payload = { nonce: cell['nonce'], ciphertext: cell['ciphertext'], authTag: cell['auth_tag'], aadContext: cell['aad_context'] };
    const ref: PayloadKeySlotRef = Object.freeze({ environment: input.environment, cellId: basis.address.payloadCellId,
      requestId: basis.address.requestId, kind: COVERAGE_PAYLOAD_KIND, revision: basis.address.addressRevision });
    requireEvidenceLive(await input.recheck());
    let wrap: PayloadKeyWrap;
    try {
      if (input.keySlots.environment !== ref.environment) { return deny('DEPENDENCY_UNAVAILABLE'); }
      // Never select an inline wrap. Historical ciphertext must be enrolled by
      // a separate offline ceremony before this reader is switched to its slots.
      wrap = await input.keySlots.read(ref);
    } catch { return deny('DEPENDENCY_UNAVAILABLE'); }
    requireEvidenceLive(await input.recheck());
    const matched = verifyAssessmentAddress({ consumption: attestConsumption(), ring: input.ring, ref, cell: payload, wrap, candidate });
    if (!matched) { return deny('FORBIDDEN'); }

    /* 9. Final caller recheck after the comparison, before returning an effect. */
    requireEvidenceLive(await input.recheck());

    return Object.freeze({
      assessmentId: randomUUID(),
      requestId: basis.request.requestId,
      addressRevisionId: basis.address.addressRevisionId,
      cityId: basis.cityId,
      cityVersionId: basis.cityVersionId,
      areaId: selection.areaId,
      areaVersionId: selection.areaVersionId,
      basisDigest: basis.basisDigest,
      outcome: selection.outcome,
      reason: selection.reason,
      staffId,
      attemptCorrelationId,
      evidenceId,
      evidenceExpiresAt: new Date(expiresAt),
    });
  } finally {
    candidate.fill(0);
  }
}
