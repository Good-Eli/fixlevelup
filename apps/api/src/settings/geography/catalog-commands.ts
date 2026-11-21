/**
 * P03-02 geography catalog commands: cities, their immutable reviewed versions,
 * the current-version pointer, districts, service areas and draft area versions
 * with FULL/PARTIAL district coverage.
 *
 * This module is a typed registry only. It contains no HTTP controller, no
 * transaction boundary, no global lock, no idempotency store and no audit write:
 * the shared runner supplies all of that and calls `check` before replay and
 * `run` afterwards on the same `ctx.client` transaction. Every statement here is
 * bound-parameter SQL on that one client; nothing opens a second connection and
 * nothing uses a migration/owner role.
 *
 * ## Revision domains and receipts
 *
 * Mutable aggregates own an optimistic token (`row_version`, maintained by the
 * database triggers in migrations 010/011, never by the caller):
 *
 * | aggregate            | token         | If-Match for                     |
 * |----------------------|---------------|----------------------------------|
 * | service city         | row_version   | publish pointer, activate, ...   |
 * | administrative district | row_version | update, archive                  |
 * | service area         | row_version   | archive, add version             |
 * | service area version | row_version   | edit draft, publish, coverage    |
 *
 * `expected` is always the token of the aggregate the operation modifies, and a
 * mismatch is 412. A mutation whose aggregate row is not itself UPDATEd still
 * advances that token with an explicit no-op UPDATE on a column the runtime role
 * is actually granted (`SET lifecycle = lifecycle` on a city, `SET
 * current_version_id = current_version_id` on an area); the database trigger turns
 * that into `row_version = OLD.row_version + 1`, so a stale client cannot chain
 * two nested creates on one revision. `row_version` itself is never written by
 * this module where the reviewed grant does not include it. Those parent advances
 * are noted per command.
 *
 * A write receipt is exactly `{id, version}` and never a projection of the
 * written row: `version` is the token of the object named by `id`. The single
 * documented exception is `cityAddVersion`: an immutable city version has no
 * mutable state of its own, so the receipt carries the city aggregate token that
 * the following publish/activate needs, and the city-version GET envelope exposes
 * the same number.
 *
 * ## Same-city and least-privilege rules
 *
 * Every subresource query filters by `city_id` as well as by the child id, so a
 * foreign id is a 404 and never a 403 that confirms existence. Responses carry no
 * staff ids, audit rows, request bodies or customer data: only the reviewed
 * public city settings and the administrative geography itself. Reads are limited
 * to an explicit row cap supplied by the caller (see `catalog-input.ts`).
 *
 * ## Role matrix (P03-02, approved 21.11.2026)
 *
 * `withGeography` already proves the capability grant and the trusted city scope
 * for `action`; `check` adds the matrix constraints that a capability alone does
 * not express, and it runs before an idempotent replay so a revoked grant cannot
 * be replayed:
 *
 * - SYSTEM ADMIN only: create a city, append a reviewed city version, publish a
 *   city version or area version, activate/deactivate a city, change the primary.
 * - Administrative read: a verified web ADMIN/MANAGER principal whose effective
 *   role is a SYSTEM ADMIN/MANAGER or an explicitly authorized CUSTOM role, in the
 *   trusted city scope.
 * - Administrative write below a city: the same principals, limited to districts,
 *   areas, draft area versions and their coverage, and only inside the assigned
 *   city. Archiving a zone that still serves a published revision withdraws
 *   published coverage: it needs an effective `geography.publish` grant as well as
 *   the SYSTEM ADMIN role, and is refused while a live technician admission still
 *   names the zone. Archiving a district that the currently served coverage maps is
 *   refused until a new published area revision stops mapping it. Old published
 *   history alone never blocks archive, so neither operation is a permanent freeze.
 * - TECHNICIAN and every Telegram principal: no administrative catalog command.
 *
 * A custom role is accepted only on a verified web MANAGER principal, so a custom
 * role can never promote a technician channel identity or a Telegram session into
 * geography administration.
 *
 * No command derives authority from a request-supplied `cityId`: the target id is
 * only accepted when `ctx.cityIds` (server-trusted membership) contains it, and a
 * null list is accepted only for a verified SYSTEM ADMIN.
 */
import { randomUUID } from 'node:crypto';
import { acquireCompanySettingsLock } from '../configuration/company-lock.js';
import { ConfigurationError } from '../configuration/configuration-errors.js';
import {
  BadRequestException, ConflictException, ForbiddenException, HttpException, InternalServerErrorException, NotFoundException,
} from '@nestjs/common';
import { isSystemAdmin } from '../../authz/authorization.service.js';
import {
  areaCreateInput, areaVersionInput, areaVersionPatchInput, cityActivateInput, cityCreateInput, cityDeactivateInput,
  cityVersionInput, coverageInput, districtCreateInput, districtUpdateInput, emptyBody, expectedVersion, listQuery,
  noExpected, publicationAreaVersion, routeId,
} from './catalog-input.js';
import type {
  AreaVersionInput, AreaVersionPatch, CityVersionInput, CoverageEntryInput, ListQuery,
} from './catalog-input.js';
import type { GeoAction, GeoCommand, GeoContext, GeoReceipt, GeoTarget } from './geo-contract.js';

type CityLifecycle = 'DRAFT' | 'ACTIVE' | 'INACTIVE';
type CoverageRelation = 'FULL' | 'PARTIAL';

interface CityRow {
  id: string; code: string; lifecycle: CityLifecycle; current_version_id: string | null; row_version: number;
}
interface CityVersionRow {
  id: string; version: number; display_name: string; address_display: string | null;
  timezone: string; public_contact: string; office_hours: unknown; published_at: Date;
}
interface DistrictRow {
  id: string; city_id: string; code: string; name: string; archived_at: Date | null; row_version: number;
}
interface AreaRow {
  id: string; city_id: string; code: string; current_version_id: string | null; archived_at: Date | null; row_version: number;
}
interface AreaVersionRow {
  id: string; city_id: string; area_id: string; version: number; name: string;
  coverage_description: string | null; address_criteria: string | null;
  published_at: Date | null; row_version: number;
}
interface CoverageRow { district_id: string; relation: CoverageRelation; description: string | null }
interface SettingsRow { version: number; launch_mode: string; primary_city_id: string }

export interface CityView {
  id: string; code: string; lifecycle: CityLifecycle; version: number; currentVersionId: string | null;
}
export interface CityVersionView {
  id: string; sequence: number; displayName: string; addressDisplay: string | null;
  timezone: string; publicContact: string; officeHours: unknown; publishedAt: string;
}
export interface CityDetailView extends CityView { currentVersion: CityVersionView | null }
export interface DistrictView {
  id: string; cityId: string; code: string; name: string; archivedAt: string | null; version: number;
}
export interface AreaView {
  id: string; cityId: string; code: string; currentVersionId: string | null; archivedAt: string | null; version: number;
}
export interface AreaVersionView {
  id: string; cityId: string; areaId: string; sequence: number; version: number; name: string;
  coverageDescription: string | null; addressCriteria: string | null; publishedAt: string | null;
}
export interface CoverageEntryView { districtId: string; relation: CoverageRelation; description: string | null }
/**
 * A nested collection carries its parent aggregate token: it is the value the next
 * nested write needs as `If-Match`, and it is the token the matching create returned,
 * so a list ETag and a write receipt never disagree. `cityList` spans aggregates and
 * therefore has no single token; it returns `items` only.
 */
export interface CollectionView<T> { version: number; items: readonly T[] }
export interface CoverageView extends CollectionView<CoverageEntryView> { areaVersionId: string }

const CITY_COLUMNS = 'id,code,lifecycle,current_version_id,row_version';
const CITY_VERSION_COLUMNS = 'id,version,display_name,address_display,timezone,public_contact,office_hours,published_at';
const DISTRICT_COLUMNS = 'id,city_id,code,name,archived_at,row_version';
const AREA_COLUMNS = 'id,city_id,code,current_version_id,archived_at,row_version';
const AREA_VERSION_COLUMNS = 'id,city_id,area_id,version,name,coverage_description,address_criteria,published_at,row_version';

/* ------------------------------------------------------------------ *
 * Role and scope checks (matrix constraints on top of withGeography).  *
 * ------------------------------------------------------------------ */

/**
 * Administrative role gate on top of `withGeography`.
 *
 * `withGeography` has already proved the capability grant and the trusted city
 * scope for `action`; this gate adds the P03-02 matrix constraints that a
 * capability alone does not express:
 *
 * - a verified staff-web principal with an ADMIN or MANAGER channel marker;
 * - the live effective role is either a SYSTEM ADMIN/MANAGER or an explicitly
 *   authorized CUSTOM role. A custom role is only accepted for a web MANAGER
 *   (P02 keeps a custom role on a web manager), so a custom role can never turn a
 *   TECHNICIAN or a Telegram-only principal into an administrator;
 * - every Telegram principal is refused: the staff bot is the technician surface,
 *   not an administrative geography surface.
 */
function requireCatalogRole(ctx: GeoContext): void {
  const { principal } = ctx;
  // The principal type already restricts a web session to the ADMIN/MANAGER markers;
  // a Telegram principal is the technician surface and never an administrative one.
  if (principal.kind !== 'staff-web') {
    throw new ForbiddenException();
  }
  const { role } = ctx;
  if (role.type === 'SYSTEM') {
    if (role.code !== 'ADMIN' && role.code !== 'MANAGER') {
      throw new ForbiddenException();
    }
    return;
  }
  // A CUSTOM role is accepted only on a web MANAGER marker: P02 never leaves a custom
  // role on an ADMIN marker, so this closes the one combination that would otherwise
  // read as administrative without being a SYSTEM role.
  if (principal.role === 'ADMIN') {
    throw new ForbiddenException();
  }
}

function requireSystemAdmin(ctx: GeoContext): void {
  if (!isSystemAdmin(ctx.role)) {
    throw new ForbiddenException();
  }
}

/**
 * Withdrawing something that is already published is a publish-level decision.
 *
 * The role alone is not enough: the caller must also hold an *effective*
 * `geography.publish` grant (GLOBAL, or CITY which `withGeography` already bounded
 * to the trusted assignment). Without this a manager with only `geography.manage`
 * could hide a served zone or district by archiving it and bypass the separate
 * publish step that the approved matrix reserves for publication.
 */
async function requireEffectivePublish(ctx: GeoContext, cityId: string): Promise<void> {
  requireSystemAdmin(ctx);
  const grant = ctx.geoPermissions?.find(g => g.code === 'geography.publish');
  if (!grant) { throw new ForbiddenException(); }
  if (grant.scope === 'GLOBAL' || ctx.cityIds?.includes(cityId)) { return; }
  // The primary action is manage. GLOBAL manage must not accidentally widen a CITY-only publish grant.
  const assigned = await ctx.client.query(`SELECT 1 FROM foundation.staff_admin_city_assignments
    WHERE staff_id=$1 AND city_id=$2 AND revoked_at IS NULL`, [ctx.staffId,cityId]);
  if (assigned.rowCount !== 1) { throw new NotFoundException(); }
}

/** GLOBAL-scope operations: verified SYSTEM ADMIN and no narrower city membership. */
function requireAdminGlobal(ctx: GeoContext): void {
  requireSystemAdmin(ctx);
  if (ctx.cityIds !== null) {
    throw new ForbiddenException();
  }
}

/**
 * City scope is decided by the server-trusted membership list only. A null list
 * is accepted for a verified SYSTEM ADMIN and is never trusted for anyone else,
 * so a missing membership can never widen access to every city.
 */
function requireCityScope(ctx: GeoContext, cityId: string): void {
  if (ctx.cityIds === null) {
    requireSystemAdmin(ctx);
    return;
  }
  if (!ctx.cityIds.includes(cityId)) {
    throw new NotFoundException();
  }
}

function targetIdentity(value: string | undefined, required: boolean): string | null {
  if (value === undefined) {
    if (required) {
      throw new BadRequestException();
    }
    return null;
  }
  if (value.length === 0) {
    throw new BadRequestException();
  }
  return value;
}

function targetCity(target: GeoTarget): string {
  const cityId = targetIdentity(target.cityId, true);
  if (cityId === null) {
    throw new BadRequestException();
  }
  return cityId;
}

function requiredTarget(value: string | undefined): string {
  const id = targetIdentity(value, true);
  if (id === null) {
    throw new BadRequestException();
  }
  return id;
}

/* ----------------------- *
 * Row loading and locking *
 * ----------------------- */

async function cityRow(ctx: GeoContext, cityId: string): Promise<CityRow | null> {
  const result = await ctx.client.query<CityRow>(
    `SELECT ${CITY_COLUMNS} FROM foundation.service_cities WHERE id=$1`, [cityId]);
  return result.rows[0] ?? null;
}

/** Existence/readability probe used by `check`; never reveals a foreign city. */
async function assertCityVisible(ctx: GeoContext, cityId: string): Promise<void> {
  if ((await cityRow(ctx, cityId)) === null) {
    throw new NotFoundException();
  }
}

/** Locks the city aggregate and verifies the client token: 404 absent, 412 stale. */
async function lockCity(ctx: GeoContext, cityId: string, expected: number | null): Promise<CityRow> {
  const version = expectedVersion(expected);
  const result = await ctx.client.query<CityRow>(
    `SELECT ${CITY_COLUMNS} FROM foundation.service_cities WHERE id=$1 FOR UPDATE`, [cityId]);
  const row = result.rows[0];
  if (!row) {
    throw new NotFoundException();
  }
  if (row.row_version !== version) {
    throw new HttpException('Precondition Failed', 412);
  }
  return row;
}

/**
 * Advances the city token without changing any value. The no-op writes a column
 * the runtime role is actually granted (`lifecycle`); the 010 trigger still turns
 * the update into `row_version = OLD.row_version + 1`. Writing `row_version`
 * directly is avoided on purpose: the reviewed grant does not include it, and the
 * database owns the increment.
 */
async function advanceCity(ctx: GeoContext, cityId: string): Promise<number> {
  const result = await ctx.client.query<{ row_version: number }>(
    'UPDATE foundation.service_cities SET lifecycle=lifecycle WHERE id=$1 RETURNING row_version', [cityId]);
  const row = result.rows[0];
  if (!row) {
    throw new NotFoundException();
  }
  return row.row_version;
}

async function setCityLifecycle(ctx: GeoContext, cityId: string, lifecycle: CityLifecycle): Promise<number> {
  const result = await ctx.client.query<{ row_version: number }>(
    'UPDATE foundation.service_cities SET lifecycle=$2 WHERE id=$1 RETURNING row_version', [cityId, lifecycle]);
  const row = result.rows[0];
  if (!row) {
    throw new NotFoundException();
  }
  return row.row_version;
}

async function setCityPointer(ctx: GeoContext, cityId: string, versionId: string): Promise<number> {
  const result = await ctx.client.query<{ row_version: number }>(
    'UPDATE foundation.service_cities SET current_version_id=$2 WHERE id=$1 RETURNING row_version', [cityId, versionId]);
  const row = result.rows[0];
  if (!row) {
    throw new NotFoundException();
  }
  return row.row_version;
}

async function activeCities(ctx: GeoContext): Promise<readonly CityRow[]> {
  const result = await ctx.client.query<CityRow>(
    `SELECT ${CITY_COLUMNS} FROM foundation.service_cities WHERE lifecycle='ACTIVE' ORDER BY id`);
  return result.rows;
}

/** Keep the existing geography transport contract when the internal lock port refuses. */
async function lockCompanySettings(ctx: GeoContext): Promise<void> {
  try {
    await acquireCompanySettingsLock(ctx.client);
  } catch (error) {
    if (error instanceof ConfigurationError) {
      if (error.code === 'CONFLICT') { throw new ConflictException(); }
      throw new InternalServerErrorException();
    }
    throw error;
  }
}

async function latestSettings(ctx: GeoContext): Promise<SettingsRow | null> {
  const result = await ctx.client.query<SettingsRow>(
    'SELECT version,launch_mode,primary_city_id FROM foundation.business_settings_versions ORDER BY version DESC LIMIT 1');
  return result.rows[0] ?? null;
}

/**
 * Geography changes only the primary pointer; company policy provenance must
 * survive in the new immutable revision. The company-settings lock is shared
 * with P03-03's internal publisher (which has no HTTP authority of its own).
 * Read the latest row after waiting, so a concurrent publish is carried forward.
 */
async function appendPrimaryRevision(ctx: GeoContext, primaryCityId: string): Promise<void> {
  const result = await ctx.client.query(
    `INSERT INTO foundation.business_settings_versions
       (id,version,launch_mode,primary_city_id,reviewed_by,operator_name,operator_registration_id,
        operator_address,legal_review_ref,security_policy_ref,retention_policy_ref,upload_policy_ref)
     SELECT $1, COALESCE(latest.version,0)+1, 'SINGLE_CITY', $2, $3,
       latest.operator_name,latest.operator_registration_id,latest.operator_address,latest.legal_review_ref,
       latest.security_policy_ref,latest.retention_policy_ref,latest.upload_policy_ref
     FROM (SELECT 1) AS singleton LEFT JOIN LATERAL
       (SELECT version,operator_name,operator_registration_id,operator_address,legal_review_ref,
         security_policy_ref,retention_policy_ref,upload_policy_ref
        FROM foundation.business_settings_versions ORDER BY version DESC LIMIT 1) AS latest ON true`,
    [randomUUID(), primaryCityId, ctx.staffId]);
  if (result.rowCount !== 1) {
    throw new ConflictException();
  }
}

/** The resolver needs the latest revision to be SINGLE_CITY with this primary. */
async function ensurePrimary(ctx: GeoContext, cityId: string): Promise<void> {
  const latest = await latestSettings(ctx);
  // MULTI_CITY remains reserved vocabulary, never an implicit mode conversion.
  if (latest !== null && latest.launch_mode !== 'SINGLE_CITY') {
    throw new ConflictException();
  }
  if (latest !== null && latest.primary_city_id === cityId) {
    return;
  }
  await appendPrimaryRevision(ctx, cityId);
}

async function districtRow(ctx: GeoContext, cityId: string, districtId: string): Promise<DistrictRow | null> {
  const result = await ctx.client.query<DistrictRow>(
    `SELECT ${DISTRICT_COLUMNS} FROM foundation.administrative_districts WHERE id=$1 AND city_id=$2`,
    [districtId, cityId]);
  return result.rows[0] ?? null;
}

async function lockDistrict(ctx: GeoContext, cityId: string, districtId: string, expected: number | null): Promise<DistrictRow> {
  const version = expectedVersion(expected);
  const result = await ctx.client.query<DistrictRow>(
    `SELECT ${DISTRICT_COLUMNS} FROM foundation.administrative_districts WHERE id=$1 AND city_id=$2 FOR UPDATE`,
    [districtId, cityId]);
  const row = result.rows[0];
  if (!row) {
    throw new NotFoundException();
  }
  if (row.row_version !== version) {
    throw new HttpException('Precondition Failed', 412);
  }
  return row;
}

async function areaRow(ctx: GeoContext, cityId: string, areaId: string): Promise<AreaRow | null> {
  const result = await ctx.client.query<AreaRow>(
    `SELECT ${AREA_COLUMNS} FROM foundation.service_areas WHERE id=$1 AND city_id=$2`, [areaId, cityId]);
  return result.rows[0] ?? null;
}

async function lockArea(ctx: GeoContext, cityId: string, areaId: string, expected: number | null): Promise<AreaRow> {
  const version = expectedVersion(expected);
  const result = await ctx.client.query<AreaRow>(
    `SELECT ${AREA_COLUMNS} FROM foundation.service_areas WHERE id=$1 AND city_id=$2 FOR UPDATE`, [areaId, cityId]);
  const row = result.rows[0];
  if (!row) {
    throw new NotFoundException();
  }
  if (row.row_version !== version) {
    throw new HttpException('Precondition Failed', 412);
  }
  return row;
}

/** No-op advance of the area token on an ACL-granted column; the 011 guard bumps row_version. */
async function advanceArea(ctx: GeoContext, cityId: string, areaId: string): Promise<number> {
  const result = await ctx.client.query<{ row_version: number }>(
    'UPDATE foundation.service_areas SET current_version_id=current_version_id WHERE id=$1 AND city_id=$2 RETURNING row_version',
    [areaId, cityId]);
  const row = result.rows[0];
  if (!row) {
    throw new NotFoundException();
  }
  return row.row_version;
}

async function areaVersionRow(
  ctx: GeoContext, cityId: string, areaId: string, versionId: string,
): Promise<AreaVersionRow | null> {
  const result = await ctx.client.query<AreaVersionRow>(
    `SELECT ${AREA_VERSION_COLUMNS} FROM foundation.service_area_versions
     WHERE id=$1 AND city_id=$2 AND area_id=$3`, [versionId, cityId, areaId]);
  return result.rows[0] ?? null;
}

/**
 * Locks one area revision and verifies the client token. The composite
 * (city, area, id) predicate is the same-city guard: a foreign or mismatched
 * revision is a 404 before any state is inspected.
 */
async function lockAreaVersion(
  ctx: GeoContext, cityId: string, areaId: string, versionId: string, expected: number | null,
): Promise<AreaVersionRow> {
  const version = expectedVersion(expected);
  const result = await ctx.client.query<AreaVersionRow>(
    `SELECT ${AREA_VERSION_COLUMNS} FROM foundation.service_area_versions
     WHERE id=$1 AND city_id=$2 AND area_id=$3 FOR UPDATE`, [versionId, cityId, areaId]);
  const row = result.rows[0];
  if (!row) {
    throw new NotFoundException();
  }
  if (row.row_version !== version) {
    throw new HttpException('Precondition Failed', 412);
  }
  return row;
}

/** A published revision and its mapping are frozen by 011; the app refuses before the trigger does. */
function requireDraft(row: AreaVersionRow): void {
  if (row.published_at !== null) {
    throw new ConflictException();
  }
}



/* ---------------------- *
 * Projections (no PII).  *
 * ---------------------- */

const iso = (value: Date): string => value.toISOString();
const isoOrNull = (value: Date | null): string | null => value === null ? null : iso(value);

function cityView(row: CityRow): CityView {
  return {
    id: row.id, code: row.code, lifecycle: row.lifecycle, version: row.row_version, currentVersionId: row.current_version_id,
  };
}

function cityVersionView(row: CityVersionRow): CityVersionView {
  return {
    id: row.id,
    sequence: row.version,
    displayName: row.display_name,
    addressDisplay: row.address_display,
    timezone: row.timezone,
    publicContact: row.public_contact,
    officeHours: row.office_hours,
    publishedAt: iso(row.published_at),
  };
}

function districtView(row: DistrictRow): DistrictView {
  return {
    id: row.id, cityId: row.city_id, code: row.code, name: row.name,
    archivedAt: isoOrNull(row.archived_at), version: row.row_version,
  };
}

function areaView(row: AreaRow): AreaView {
  return {
    id: row.id, cityId: row.city_id, code: row.code, currentVersionId: row.current_version_id,
    archivedAt: isoOrNull(row.archived_at), version: row.row_version,
  };
}

function areaVersionView(row: AreaVersionRow): AreaVersionView {
  return {
    id: row.id,
    cityId: row.city_id,
    areaId: row.area_id,
    sequence: row.version,
    version: row.row_version,
    name: row.name,
    coverageDescription: row.coverage_description,
    addressCriteria: row.address_criteria,
    publishedAt: isoOrNull(row.published_at),
  };
}

/* ------------------------- *
 * Error and receipt mapping *
 * ------------------------- */

/**
 * Database constraint/guard failures are translated in exactly one place: the
 * shared runner's `mapConstraint`. This module only raises the specific, safe
 * HttpExceptions it can prove from a re-read (404 for a foreign id, 409 for a
 * non-draft revision, 412 for a stale token) and lets anything else surface.
 */
function isReceipt(value: unknown): value is GeoReceipt {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return typeof record['id'] === 'string' && record['id'].length > 0
    && typeof record['version'] === 'number' && Number.isSafeInteger(record['version']);
}

interface CommandSpec {
  readonly action: GeoAction;
  readonly write: boolean;
  readonly scoped: GeoCommand['scoped'];
  readonly check: (ctx: GeoContext, target: GeoTarget) => Promise<void>;
  readonly run: (ctx: GeoContext, target: GeoTarget, body: unknown, expected: number | null) => Promise<unknown>;
}

/**
 * Builds one registry entry. The wrapper guarantees the invariant every caller may
 * rely on: a write returns a minimal `{id, version}` receipt and never a
 * projection of the written row, so a receipt cannot leak fields the caller is
 * not entitled to read.
 */
function command(spec: CommandSpec): GeoCommand {
  return {
    action: spec.action,
    write: spec.write,
    scoped: spec.scoped,
    check: spec.check,
    run: async (ctx, target, body, expected) => {
      const result = await spec.run(ctx, target, body, expected);
      if (spec.write && !isReceipt(result)) {
        // A programming error, not a client error: never leak a partial projection.
        throw new InternalServerErrorException();
      }
      return result;
    },
  };
}

/* ---------------------------- *
 * Shared command preconditions *
 * ---------------------------- */

/** Reads of one city: admin or manager, and the city must be inside the trusted scope. */
async function cityReadCheck(ctx: GeoContext, target: GeoTarget): Promise<void> {
  requireCatalogRole(ctx);
  const cityId = targetCity(target);
  requireCityScope(ctx, cityId);
  await assertCityVisible(ctx, cityId);
}

/** Writes below one city: the manager matrix applies and the city must be in scope. */
async function cityWriteCheck(ctx: GeoContext, target: GeoTarget): Promise<void> {
  requireCatalogRole(ctx);
  const cityId = targetCity(target);
  requireCityScope(ctx, cityId);
  await assertCityVisible(ctx, cityId);
}

/** Admin-only city operations that still target one city (prepare/publish a city version). */
async function cityPublishCheck(ctx: GeoContext, target: GeoTarget): Promise<void> {
  requireSystemAdmin(ctx);
  const cityId = targetCity(target);
  requireCityScope(ctx, cityId);
  await assertCityVisible(ctx, cityId);
}

async function districtCheck(ctx: GeoContext, target: GeoTarget, requireDistrict: boolean): Promise<void> {
  await cityWriteCheck(ctx, target);
  if (!requireDistrict) {
    return;
  }
  const cityId = targetCity(target);
  const districtId = requiredTarget(target.districtId);
  if ((await districtRow(ctx, cityId, districtId)) === null) {
    throw new NotFoundException();
  }
}

async function areaCheck(ctx: GeoContext, target: GeoTarget, requireArea: boolean): Promise<void> {
  await cityWriteCheck(ctx, target);
  if (!requireArea) {
    return;
  }
  const cityId = targetCity(target);
  const areaId = requiredTarget(target.areaId);
  if ((await areaRow(ctx, cityId, areaId)) === null) {
    throw new NotFoundException();
  }
}

async function areaVersionCheck(ctx: GeoContext, target: GeoTarget): Promise<void> {
  await cityWriteCheck(ctx, target);
  const cityId = targetCity(target);
  const areaId = requiredTarget(target.areaId);
  const versionId = requiredTarget(target.versionId);
  if ((await areaVersionRow(ctx, cityId, areaId, versionId)) === null) {
    throw new NotFoundException();
  }
}

/* ------------------- *
 * City version values *
 * ------------------- */

/**
 * Reuses migration 010's own validators instead of duplicating the IANA catalog
 * rule or the office-hours format in TypeScript. The reviewed timezone is stored
 * verbatim (never normalised), and 010's immutability triggers keep the snapshot
 * exactly as reviewed after a later tzdata update.
 */
async function assertCityVersionContent(ctx: GeoContext, input: CityVersionInput): Promise<void> {
  const result = await ctx.client.query<{ timezone_valid: boolean; office_hours_valid: boolean }>(
    `SELECT foundation.city_timezone_is_valid($1) AS timezone_valid,
            foundation.city_office_hours_is_valid($2::jsonb) AS office_hours_valid`,
    [input.timezone, JSON.stringify(input.officeHours)]);
  const row = result.rows[0];
  if (!row || !row.timezone_valid || !row.office_hours_valid) {
    throw new BadRequestException();
  }
}

async function nextCityVersion(ctx: GeoContext, cityId: string): Promise<number> {
  const result = await ctx.client.query<{ sequence: number }>(
    'SELECT (COALESCE(max(version),0)+1)::int AS sequence FROM foundation.service_city_versions WHERE city_id=$1',
    [cityId]);
  const row = result.rows[0];
  if (!row) {
    throw new ConflictException();
  }
  return row.sequence;
}

async function nextAreaVersion(ctx: GeoContext, cityId: string, areaId: string): Promise<number> {
  const result = await ctx.client.query<{ sequence: number }>(
    `SELECT (COALESCE(max(version),0)+1)::int AS sequence FROM foundation.service_area_versions
     WHERE city_id=$1 AND area_id=$2`, [cityId, areaId]);
  const row = result.rows[0];
  if (!row) {
    throw new ConflictException();
  }
  return row.sequence;
}

/* ------------------- *
 * The command registry *
 * ------------------- */

export const catalogCommands = {
  /* ----------------------------- cities ----------------------------- */
  cityList: command({
    action: 'geography.read',
    write: false,
    scoped: 'list',
    // The list has no target city: the runner authorizes a GLOBAL read and the
    // SQL below restricts rows to the trusted membership list.
    check: (ctx) => { requireCatalogRole(ctx); return Promise.resolve(); },
    run: async (ctx, _target, body) => {
      const query = listQuery(body);
      const result = ctx.cityIds === null
        ? await ctx.client.query<CityRow>(
          `SELECT ${CITY_COLUMNS} FROM foundation.service_cities ORDER BY code LIMIT $1`, [query.limit])
        : await ctx.client.query<CityRow>(
          `SELECT ${CITY_COLUMNS} FROM foundation.service_cities WHERE id=ANY($2::uuid[]) ORDER BY code LIMIT $1`,
          [query.limit, ctx.cityIds]);
      // Every list is an envelope; a bare array would make a future page/total
      // addition a breaking change for the CRM client. A city list spans several
      // aggregates, so it carries no single parent revision token.
      return { items: result.rows.map(cityView) } satisfies Pick<CollectionView<CityView>, 'items'>;
    },
  }),

  cityGet: command({
    action: 'geography.read',
    write: false,
    scoped: 'city',
    check: cityReadCheck,
    run: async (ctx, target) => {
      const cityId = targetCity(target);
      const row = await cityRow(ctx, cityId);
      if (!row) {
        throw new NotFoundException();
      }
      let currentVersion: CityVersionView | null = null;
      if (row.current_version_id !== null) {
        const version = await ctx.client.query<CityVersionRow>(
          `SELECT ${CITY_VERSION_COLUMNS} FROM foundation.service_city_versions WHERE id=$1 AND city_id=$2`,
          [row.current_version_id, cityId]);
        const current = version.rows[0];
        currentVersion = current ? cityVersionView(current) : null;
      }
      return { ...cityView(row), currentVersion } satisfies CityDetailView;
    },
  }),

  cityCreate: command({
    action: 'geography.manage',
    write: true,
    scoped: 'global',
    check: (ctx) => { requireAdminGlobal(ctx); return Promise.resolve(); },
    run: async (ctx, _target, body, expected) => {
      // A brand new aggregate has no prior revision: an If-Match here is refused.
      noExpected(expected);
      const input = cityCreateInput(body);
      const id = randomUUID();
      const result = await ctx.client.query<CityRow>(
        `INSERT INTO foundation.service_cities (id,code) VALUES ($1,$2) RETURNING ${CITY_COLUMNS}`, [id, input.code]);
      const row = result.rows[0];
      if (!row) {
        throw new ConflictException();
      }
      // DRAFT only: creating a city never activates a second city or touches primary.
      return { id: row.id, version: row.row_version } satisfies GeoReceipt;
    },
  }),

  cityVersions: command({
    action: 'geography.read',
    write: false,
    scoped: 'city',
    check: cityReadCheck,
    run: async (ctx, target, body) => {
      const cityId = targetCity(target);
      const query = listQuery(body);
      const city = await cityRow(ctx, cityId);
      if (!city) {
        throw new NotFoundException();
      }
      const result = await ctx.client.query<CityVersionRow>(
        `SELECT ${CITY_VERSION_COLUMNS} FROM foundation.service_city_versions
         WHERE city_id=$1 ORDER BY version DESC LIMIT $2`, [cityId, query.limit]);
      return { version: city.row_version, items: result.rows.map(cityVersionView) } satisfies CollectionView<CityVersionView>;
    },
  }),

  cityAddVersion: command({
    action: 'geography.manage',
    write: true,
    scoped: 'city',
    check: cityPublishCheck,
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const input = cityVersionInput(body);
      // Parent aggregate revision: appending history is serialized on the city row.
      await lockCity(ctx, cityId, expected);
      await assertCityVersionContent(ctx, input);
      const sequence = await nextCityVersion(ctx, cityId);
      const id = randomUUID();
      const result = await ctx.client.query<{ id: string }>(
        `INSERT INTO foundation.service_city_versions
           (id,city_id,version,display_name,address_display,timezone,public_contact,office_hours,reviewed_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9) RETURNING id`,
        [id, cityId, sequence, input.displayName, input.addressDisplay, input.timezone,
          input.publicContact, JSON.stringify(input.officeHours), ctx.staffId]);
      if (result.rowCount !== 1) {
        throw new ConflictException();
      }
      // The row is immutable, so the receipt carries the city aggregate token the
      // following publish/activate needs; the versions envelope exposes it too.
      const cityVersion = await advanceCity(ctx, cityId);
      return { id, version: cityVersion } satisfies GeoReceipt;
    },
  }),

  cityPublish: command({
    action: 'geography.publish',
    write: true,
    scoped: 'city',
    check: cityPublishCheck,
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const versionId = routeId(requiredTarget(target.versionId));
      emptyBody(body);
      await lockCity(ctx, cityId, expected);
      // The composite FK already forbids a foreign city's history; the probe turns
      // that into an indistinguishable 404 instead of a constraint conflict.
      const version = await ctx.client.query(
        'SELECT 1 FROM foundation.service_city_versions WHERE id=$1 AND city_id=$2', [versionId, cityId]);
      if (version.rowCount !== 1) {
        throw new NotFoundException();
      }
      // Published revisions are immutable, so this pointer move is the only
      // "publish": the reviewed snapshot already exists and is not edited here.
      const cityVersion = await setCityPointer(ctx, cityId, versionId);
      return { id: cityId, version: cityVersion } satisfies GeoReceipt;
    },
  }),

  cityActivate: command({
    action: 'geography.publish',
    write: true,
    scoped: 'global',
    check: async (ctx, target) => { requireAdminGlobal(ctx); await assertCityVisible(ctx, targetCity(target)); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const input = cityActivateInput(body);
      await lockCompanySettings(ctx);
      const city = await lockCity(ctx, cityId, expected);
      // An ACTIVE city must point at the reviewed snapshot it serves (010 CHECK).
      if (city.current_version_id === null) {
        throw new ConflictException();
      }
      const others = (await activeCities(ctx)).filter((candidate) => candidate.id !== cityId);
      if (others.length > 1) {
        // Two active configurations already exist: refuse instead of guessing which
        // one the caller means to replace. Deactivate the extra one explicitly first.
        throw new ConflictException();
      }
      const replacement = others[0];
      if (replacement) {
        // No silent deactivation of another city: the caller must name it and its
        // expected revision. Moving to a second city is deliberately not enabled.
        if (input.replaceActiveCityId !== replacement.id || input.replaceActiveCityVersion === null) {
          throw new ConflictException();
        }
        const locked = await ctx.client.query<CityRow>(
          `SELECT ${CITY_COLUMNS} FROM foundation.service_cities WHERE id=$1 FOR UPDATE`, [replacement.id]);
        const previous = locked.rows[0];
        if (!previous || previous.lifecycle !== 'ACTIVE') {
          throw new ConflictException();
        }
        if (previous.row_version !== input.replaceActiveCityVersion) {
          throw new HttpException('Precondition Failed', 412);
        }
        await setCityLifecycle(ctx, previous.id, 'INACTIVE');
      } else if (input.replaceActiveCityId !== null) {
        // The caller asked to replace a city that is not currently active.
        throw new ConflictException();
      }
      const cityVersion = city.lifecycle === 'ACTIVE' ? await advanceCity(ctx, cityId) : await setCityLifecycle(ctx, cityId, 'ACTIVE');
      // Single primary, chosen atomically with activation, so the resolver sees one
      // consistent ACTIVE + primary configuration and never a "first city" guess.
      await ensurePrimary(ctx, cityId);
      return { id: cityId, version: cityVersion } satisfies GeoReceipt;
    },
  }),

  cityDeactivate: command({
    action: 'geography.publish',
    write: true,
    scoped: 'global',
    check: async (ctx, target) => { requireAdminGlobal(ctx); await assertCityVisible(ctx, targetCity(target)); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const input = cityDeactivateInput(body);
      await lockCompanySettings(ctx);
      const city = await lockCity(ctx, cityId, expected);
      const latest = await latestSettings(ctx);
      const isPrimary = latest !== null && latest.launch_mode === 'SINGLE_CITY' && latest.primary_city_id === cityId;
      // Deactivating the primary city suspends intake. That is only allowed when the
      // caller states it explicitly; otherwise a typo would silently take v1 offline.
      if (city.lifecycle === 'ACTIVE' && isPrimary && !input.suspendIntake) {
        throw new ConflictException();
      }
      // No settings revision is appended: an explicit suspension leaves zero ACTIVE
      // cities, so the resolver reports CONFIGURATION_INCOMPLETE instead of silently
      // promoting another city. Reactivation goes through cityActivate.
      const cityVersion = await setCityLifecycle(ctx, cityId, 'INACTIVE');
      return { id: cityId, version: cityVersion } satisfies GeoReceipt;
    },
  }),

  citySetPrimary: command({
    action: 'geography.publish',
    write: true,
    scoped: 'global',
    check: async (ctx, target) => { requireAdminGlobal(ctx); await assertCityVisible(ctx, targetCity(target)); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      emptyBody(body);
      await lockCompanySettings(ctx);
      const city = await lockCity(ctx, cityId, expected);
      // The primary must be the ACTIVE city the resolver serves; promoting a DRAFT
      // or INACTIVE city would produce a configuration the resolver refuses.
      if (city.lifecycle !== 'ACTIVE') {
        throw new ConflictException();
      }
      await ensurePrimary(ctx, cityId);
      const cityVersion = await advanceCity(ctx, cityId);
      return { id: cityId, version: cityVersion } satisfies GeoReceipt;
    },
  }),

  /* ---------------------------- districts ---------------------------- */
  districtList: command({
    action: 'geography.read',
    write: false,
    scoped: 'city',
    check: async (ctx, target) => { await cityReadCheck(ctx, target); },
    run: async (ctx, target, body) => {
      const cityId = targetCity(target);
      const query: ListQuery = listQuery(body);
      const city = await cityRow(ctx, cityId);
      if (!city) {
        throw new NotFoundException();
      }
      const result = query.includeArchived
        ? await ctx.client.query<DistrictRow>(
          `SELECT ${DISTRICT_COLUMNS} FROM foundation.administrative_districts
           WHERE city_id=$1 ORDER BY code LIMIT $2`, [cityId, query.limit])
        : await ctx.client.query<DistrictRow>(
          `SELECT ${DISTRICT_COLUMNS} FROM foundation.administrative_districts
           WHERE city_id=$1 AND archived_at IS NULL ORDER BY code LIMIT $2`, [cityId, query.limit]);
      return { version: city.row_version, items: result.rows.map(districtView) } satisfies CollectionView<DistrictView>;
    },
  }),

  districtGet: command({
    action: 'geography.read',
    write: false,
    scoped: 'city',
    check: async (ctx, target) => { await districtCheck(ctx, target, true); },
    run: async (ctx, target) => {
      const row = await districtRow(ctx, targetCity(target), requiredTarget(target.districtId));
      if (!row) {
        throw new NotFoundException();
      }
      return districtView(row);
    },
  }),

  districtCreate: command({
    action: 'geography.manage',
    write: true,
    scoped: 'city',
    check: async (ctx, target) => { await districtCheck(ctx, target, false); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const input = districtCreateInput(body);
      // Nested create: the parent city revision serializes it and is advanced below.
      await lockCity(ctx, cityId, expected);
      const result = await ctx.client.query<DistrictRow>(
        `INSERT INTO foundation.administrative_districts (id,city_id,code,name) VALUES ($1,$2,$3,$4)
         RETURNING ${DISTRICT_COLUMNS}`, [randomUUID(), cityId, input.code, input.name]);
      const row = result.rows[0];
      if (!row) {
        throw new ConflictException();
      }
      // Documented parent advance: a second nested create must re-read the city token.
      await advanceCity(ctx, cityId);
      return { id: row.id, version: row.row_version } satisfies GeoReceipt;
    },
  }),

  districtUpdate: command({
    action: 'geography.manage',
    write: true,
    scoped: 'city',
    check: async (ctx, target) => { await districtCheck(ctx, target, true); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const districtId = requiredTarget(target.districtId);
      const input = districtUpdateInput(body);
      const row = await lockDistrict(ctx, cityId, districtId, expected);
      // An archived district is read-only reference data: its label stays as reviewed.
      if (row.archived_at !== null) {
        throw new ConflictException();
      }
      const updated = await ctx.client.query<{ row_version: number }>(
        'UPDATE foundation.administrative_districts SET name=$2 WHERE id=$1 AND city_id=$3 RETURNING row_version',
        [districtId, input.name, cityId]);
      const next = updated.rows[0];
      if (!next) {
        throw new NotFoundException();
      }
      return { id: districtId, version: next.row_version } satisfies GeoReceipt;
    },
  }),

  districtArchive: command({
    action: 'geography.manage',
    write: true,
    scoped: 'city',
    check: async (ctx, target) => { await districtCheck(ctx, target, true); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const districtId = requiredTarget(target.districtId);
      emptyBody(body);
      const row = await lockDistrict(ctx, cityId, districtId, expected);
      if (row.archived_at === null) {
        // Old published history never blocks archive: a historical revision keeps the
        // district label it was reviewed with and stays readable. Only an EFFECTIVE
        // mapping counts, i.e. a coverage row of the revision an area currently serves.
        // Withdrawing that is a coverage decision: publish a new area revision first,
        // so a manager cannot bypass the publish step by archiving the reference row.
        const used = await ctx.client.query(
          `SELECT 1 FROM foundation.service_area_district_coverage AS coverage
           JOIN foundation.service_areas AS area
             ON area.city_id=coverage.city_id AND area.current_version_id=coverage.area_version_id
           WHERE coverage.city_id=$1 AND coverage.district_id=$2 AND area.archived_at IS NULL LIMIT 1`,
          [cityId, districtId]);
        if (used.rowCount !== 0) {
          // Reject while actively serving instead of granting a manage-level withdrawal:
          // the district is referenced by the coverage of a revision an area currently
          // serves, so the correct operation is a new published area revision without it.
          throw new ConflictException();
        }
      }
      // Idempotent archive: matching input still advances the token so a write-only
      // caller cannot learn whether the district was already archived from the ETag.
      const updated = await ctx.client.query<{ row_version: number }>(
        `UPDATE foundation.administrative_districts SET archived_at=COALESCE(archived_at,clock_timestamp())
         WHERE id=$1 AND city_id=$2 RETURNING row_version`, [districtId, cityId]);
      const next = updated.rows[0];
      if (!next) {
        throw new NotFoundException();
      }
      return { id: districtId, version: next.row_version } satisfies GeoReceipt;
    },
  }),

  /* --------------------------- service areas ------------------------- */
  areaList: command({
    action: 'geography.read',
    write: false,
    scoped: 'city',
    check: async (ctx, target) => { await cityReadCheck(ctx, target); },
    run: async (ctx, target, body) => {
      const cityId = targetCity(target);
      const query = listQuery(body);
      const city = await cityRow(ctx, cityId);
      if (!city) {
        throw new NotFoundException();
      }
      const result = query.includeArchived
        ? await ctx.client.query<AreaRow>(
          `SELECT ${AREA_COLUMNS} FROM foundation.service_areas WHERE city_id=$1 ORDER BY code LIMIT $2`,
          [cityId, query.limit])
        : await ctx.client.query<AreaRow>(
          `SELECT ${AREA_COLUMNS} FROM foundation.service_areas
           WHERE city_id=$1 AND archived_at IS NULL ORDER BY code LIMIT $2`, [cityId, query.limit]);
      return { version: city.row_version, items: result.rows.map(areaView) } satisfies CollectionView<AreaView>;
    },
  }),

  areaGet: command({
    action: 'geography.read',
    write: false,
    scoped: 'city',
    check: async (ctx, target) => { await areaCheck(ctx, target, true); },
    run: async (ctx, target) => {
      const row = await areaRow(ctx, targetCity(target), requiredTarget(target.areaId));
      if (!row) {
        throw new NotFoundException();
      }
      return areaView(row);
    },
  }),

  areaCreate: command({
    action: 'geography.manage',
    write: true,
    scoped: 'city',
    check: async (ctx, target) => { await areaCheck(ctx, target, false); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const input = areaCreateInput(body);
      // Nested create: serialized on the parent city revision, which is advanced below.
      await lockCity(ctx, cityId, expected);
      const result = await ctx.client.query<AreaRow>(
        `INSERT INTO foundation.service_areas (id,city_id,code) VALUES ($1,$2,$3) RETURNING ${AREA_COLUMNS}`,
        [randomUUID(), cityId, input.code]);
      const row = result.rows[0];
      if (!row) {
        throw new ConflictException();
      }
      await advanceCity(ctx, cityId);
      return { id: row.id, version: row.row_version } satisfies GeoReceipt;
    },
  }),

  areaArchive: command({
    action: 'geography.manage',
    write: true,
    scoped: 'city',
    check: async (ctx, target) => {
      await cityWriteCheck(ctx, target);
      const cityId = targetCity(target);
      const area = await areaRow(ctx, cityId, requiredTarget(target.areaId));
      if (!area) { throw new NotFoundException(); }
      // Re-evaluate the independent publication authority before a receipt is replayed.
      if (area.current_version_id !== null) { await requireEffectivePublish(ctx, cityId); }
    },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const areaId = requiredTarget(target.areaId);
      emptyBody(body);
      const row = await lockArea(ctx, cityId, areaId, expected);
      // Archiving a zone that still serves a published revision withdraws published
      // coverage, so it is a publish-level decision: the role alone is not enough, the
      // caller must hold an effective `geography.publish` grant. Old published history
      // alone never blocks archive, so this is not a permanent freeze.
      if (row.current_version_id !== null) {
        await requireEffectivePublish(ctx, cityId);
        // A live technician admission in this zone means the withdrawal affects actual
        // work eligibility: refuse until the admission is explicitly revoked, instead
        // of silently leaving a grant pointing at an archived zone.
        const admitted = await ctx.client.query(
          `SELECT 1 FROM foundation.technician_service_areas
           WHERE city_id=$1 AND service_area_id=$2 AND revoked_at IS NULL LIMIT 1`, [cityId, areaId]);
        if (admitted.rowCount !== 0) {
          throw new ConflictException();
        }
      }
      // Published history stays readable; a leftover draft can no longer be edited or
      // published because both commands refuse an archived area.
      const updated = await ctx.client.query<{ row_version: number }>(
        `UPDATE foundation.service_areas SET archived_at=COALESCE(archived_at,clock_timestamp())
         WHERE id=$1 AND city_id=$2 RETURNING row_version`, [areaId, cityId]);
      const next = updated.rows[0];
      if (!next) {
        throw new NotFoundException();
      }
      return { id: areaId, version: next.row_version } satisfies GeoReceipt;
    },
  }),

  areaVersions: command({
    action: 'geography.read',
    write: false,
    scoped: 'city',
    check: async (ctx, target) => { await areaCheck(ctx, target, true); },
    run: async (ctx, target, body) => {
      const cityId = targetCity(target);
      const areaId = requiredTarget(target.areaId);
      const query = listQuery(body);
      const area = await areaRow(ctx, cityId, areaId);
      if (!area) {
        throw new NotFoundException();
      }
      const result = await ctx.client.query<AreaVersionRow>(
        `SELECT ${AREA_VERSION_COLUMNS} FROM foundation.service_area_versions
         WHERE city_id=$1 AND area_id=$2 ORDER BY version DESC LIMIT $3`, [cityId, areaId, query.limit]);
      return { version: area.row_version, items: result.rows.map(areaVersionView) } satisfies CollectionView<AreaVersionView>;
    },
  }),

  areaVersionGet: command({
    action: 'geography.read',
    write: false,
    scoped: 'city',
    check: async (ctx, target) => { await areaVersionCheck(ctx, target); },
    run: async (ctx, target) => {
      const row = await areaVersionRow(ctx, targetCity(target), requiredTarget(target.areaId), requiredTarget(target.versionId));
      if (!row) {
        throw new NotFoundException();
      }
      return areaVersionView(row);
    },
  }),

  areaAddVersion: command({
    action: 'geography.manage',
    write: true,
    scoped: 'city',
    check: async (ctx, target) => { await areaCheck(ctx, target, true); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const areaId = requiredTarget(target.areaId);
      const input: AreaVersionInput = areaVersionInput(body);
      // Nested create: lock the area BEFORE computing max(version)+1, otherwise two
      // concurrent drafts would collide on unique(city,area,version).
      const area = await lockArea(ctx, cityId, areaId, expected);
      if (area.archived_at !== null) {
        throw new ConflictException();
      }
      const sequence = await nextAreaVersion(ctx, cityId, areaId);
      const id = randomUUID();
      // A revision is always born as a draft: publication is a separate command.
      const result = await ctx.client.query<{ row_version: number }>(
        `INSERT INTO foundation.service_area_versions
           (id,city_id,area_id,version,name,coverage_description,address_criteria,created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING row_version`,
        [id, cityId, areaId, sequence, input.name, input.coverageDescription, input.addressCriteria, ctx.staffId]);
      const row = result.rows[0];
      if (!row) {
        throw new ConflictException();
      }
      // Documented parent advance so the next nested create needs a fresh area token.
      await advanceArea(ctx, cityId, areaId);
      return { id, version: row.row_version } satisfies GeoReceipt;
    },
  }),

  areaEditDraft: command({
    action: 'geography.manage',
    write: true,
    scoped: 'city',
    check: async (ctx, target) => { await areaVersionCheck(ctx, target); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const areaId = requiredTarget(target.areaId);
      const versionId = requiredTarget(target.versionId);
      const patch: AreaVersionPatch = areaVersionPatchInput(body);
      const version = await lockAreaVersion(ctx, cityId, areaId, versionId, expected);
      requireDraft(version);
      const area = await ctx.client.query<AreaRow>(
        `SELECT ${AREA_COLUMNS} FROM foundation.service_areas WHERE id=$1 AND city_id=$2 FOR UPDATE`, [areaId, cityId]);
      const currentArea = area.rows[0];
      if (!currentArea) {
        throw new NotFoundException();
      }
      if (currentArea.archived_at !== null) {
        throw new ConflictException();
      }
      // Absent field keeps the stored value; an explicit null clears a nullable field.
      const updated = await ctx.client.query<{ row_version: number }>(
        `UPDATE foundation.service_area_versions SET
           name=COALESCE($4,name),
           coverage_description=CASE WHEN $5::boolean THEN $6 ELSE coverage_description END,
           address_criteria=CASE WHEN $7::boolean THEN $8 ELSE address_criteria END
         WHERE id=$1 AND city_id=$2 AND area_id=$3 RETURNING row_version`,
        [versionId, cityId, areaId, patch.name ?? null,
          Object.hasOwn(patch, 'coverageDescription'), patch.coverageDescription ?? null,
          Object.hasOwn(patch, 'addressCriteria'), patch.addressCriteria ?? null]);
      const next = updated.rows[0];
      if (!next) {
        throw new NotFoundException();
      }
      return { id: versionId, version: next.row_version } satisfies GeoReceipt;
    },
  }),

  areaPublish: command({
    action: 'geography.publish',
    write: true,
    scoped: 'city',
    check: async (ctx, target) => { requireSystemAdmin(ctx); await areaVersionCheck(ctx, target); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const areaId = requiredTarget(target.areaId);
      const versionId = requiredTarget(target.versionId);
      const expectedArea = publicationAreaVersion(body);
      const version = await lockAreaVersion(ctx, cityId, areaId, versionId, expected);
      requireDraft(version);
      // Another draft may have been published without changing this draft's token.
      const currentArea = await lockArea(ctx, cityId, areaId, expectedArea);
      if (currentArea.archived_at !== null) {
        throw new ConflictException();
      }
      // A district may have been archived after this draft was mapped. Publishing the
      // mapping would freeze a reference to withdrawn reference data, so the draft must
      // be corrected first (re-map through the coverage command, then publish).
      const stale = await ctx.client.query(
        `SELECT 1 FROM foundation.service_area_district_coverage AS coverage
         JOIN foundation.administrative_districts AS district
           ON district.city_id=coverage.city_id AND district.id=coverage.district_id
         WHERE coverage.city_id=$1 AND coverage.area_version_id=$2
           AND district.archived_at IS NOT NULL LIMIT 1`, [cityId, versionId]);
      if (stale.rowCount !== 0) {
        throw new ConflictException();
      }
      // Publish the revision first: the pointer guard requires published_at already set.
      const published = await ctx.client.query<{ row_version: number }>(
        `UPDATE foundation.service_area_versions
         SET published_at=clock_timestamp(), published_by=$2
         WHERE id=$1 AND city_id=$3 AND area_id=$4 AND published_at IS NULL RETURNING row_version`,
        [versionId, ctx.staffId, cityId, areaId]);
      const next = published.rows[0];
      if (!next) {
        throw new ConflictException();
      }
      // The pointer is a same-city, same-area, published-only reference (011 guard).
      const pointer = await ctx.client.query(
        'UPDATE foundation.service_areas SET current_version_id=$2 WHERE id=$1 AND city_id=$3',
        [areaId, versionId, cityId]);
      if (pointer.rowCount !== 1) {
        throw new NotFoundException();
      }
      return { id: versionId, version: next.row_version } satisfies GeoReceipt;
    },
  }),

  areaCoverageGet: command({
    action: 'geography.read',
    write: false,
    scoped: 'city',
    check: async (ctx, target) => { await areaVersionCheck(ctx, target); },
    run: async (ctx, target) => {
      const cityId = targetCity(target);
      const areaId = requiredTarget(target.areaId);
      const versionId = requiredTarget(target.versionId);
      const version = await areaVersionRow(ctx, cityId, areaId, versionId);
      if (!version) {
        throw new NotFoundException();
      }
      const result = await ctx.client.query<CoverageRow>(
        `SELECT district_id,relation,description FROM foundation.service_area_district_coverage
         WHERE city_id=$1 AND area_version_id=$2 ORDER BY district_id`, [cityId, versionId]);
      const items: CoverageEntryView[] = result.rows.map((row) => ({
        districtId: row.district_id, relation: row.relation, description: row.description,
      }));
      return { areaVersionId: versionId, version: version.row_version, items } satisfies CoverageView;
    },
  }),

  areaCoverage: command({
    action: 'geography.manage',
    write: true,
    scoped: 'city',
    check: async (ctx, target) => { await areaVersionCheck(ctx, target); },
    run: async (ctx, target, body, expected) => {
      const cityId = targetCity(target);
      const areaId = requiredTarget(target.areaId);
      const versionId = requiredTarget(target.versionId);
      const entries: readonly CoverageEntryInput[] = coverageInput(body);
      const version = await lockAreaVersion(ctx, cityId, areaId, versionId, expected);
      requireDraft(version);
      const area = await ctx.client.query<AreaRow>(
        `SELECT ${AREA_COLUMNS} FROM foundation.service_areas WHERE id=$1 AND city_id=$2 FOR UPDATE`, [areaId, cityId]);
      const currentArea = area.rows[0];
      if (!currentArea) {
        throw new NotFoundException();
      }
      if (currentArea.archived_at !== null) {
        throw new ConflictException();
      }
      // Same-city district validation before any child change: missing is 404, an
      // archived district is a conflict, and the city is always server-derived.
      if (entries.length !== 0) {
        const found = await ctx.client.query<{ id: string; archived_at: Date | null }>(
          `SELECT id,archived_at FROM foundation.administrative_districts
           WHERE city_id=$1 AND id=ANY($2::uuid[])`, [cityId, entries.map((entry) => entry.districtId)]);
        const byId = new Map(found.rows.map((row) => [row.id, row]));
        for (const entry of entries) {
          const district = byId.get(entry.districtId);
          if (!district) {
            throw new NotFoundException();
          }
          if (district.archived_at !== null) {
            throw new ConflictException();
          }
        }
      }
      // The mapping of a DRAFT revision is editable (011 explicitly permits DELETE
      // here); every child change bumps the draft row_version through the guard.
      await ctx.client.query(
        'DELETE FROM foundation.service_area_district_coverage WHERE city_id=$1 AND area_version_id=$2',
        [cityId, versionId]);
      if (entries.length !== 0) {
        await ctx.client.query(
          `INSERT INTO foundation.service_area_district_coverage (city_id,area_version_id,district_id,relation,description)
           SELECT $1,$2,entry.district_id,entry.relation,entry.description
           FROM unnest($3::uuid[],$4::text[],$5::text[]) AS entry(district_id,relation,description)`,
          [cityId, versionId, entries.map((entry) => entry.districtId),
            entries.map((entry) => entry.relation), entries.map((entry) => entry.description)]);
      }
      // Re-read the token: the coverage guard already advanced it once per child row,
      // so the pre-replace If-Match is stale for a following publish in the same tx.
      const after = await ctx.client.query<{ row_version: number }>(
        'SELECT row_version FROM foundation.service_area_versions WHERE id=$1 AND city_id=$2 AND area_id=$3',
        [versionId, cityId, areaId]);
      const next = after.rows[0];
      if (!next) {
        throw new NotFoundException();
      }
      return { id: versionId, version: next.row_version } satisfies GeoReceipt;
    },
  }),
} satisfies Record<string, GeoCommand>;

export type CatalogCommandKey = keyof typeof catalogCommands;
