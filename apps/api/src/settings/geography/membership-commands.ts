import { randomUUID } from 'node:crypto';
import {
  BadRequestException, ConflictException, ForbiddenException, HttpException, InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import type { PoolClient } from 'pg';
import type { P03Page, P03TechnicianPickerItem } from '@fixlevelup/p03-contracts';
import { isSystemAdmin } from '../../authz/authorization.service.js';
import { requireDomainCityExpansion } from '../../authz/p03-grants.js';
import { requireNoP05CityExpansion } from '../../authz/p05-grants.js';
import { uuid } from '../../authz/rbac-http.js';
import type { GeoCapability, GeoGrant } from '../../authz/capability.js';
import type { GeoCommand, GeoContext, GeoReceipt, GeoTarget } from './geo-contract.js';
import { finishGeoPage, idPosition, readGeoPage } from './geo-page.js';

const idKey = (row: { id: string }): readonly [string] => [row.id];

/**
 * P03-02 administrative city assignments and technician territory commands.
 *
 * This module is the command layer only. `GeoRunner` owns the HTTP boundary, the
 * preauthorization (`withGeography`), `Idempotency-Key` receipts, `If-Match` parsing
 * and the audit/outbox row written after `run` in the same transaction. Nothing here
 * writes `audit_logs`, deletes history, invents a city id from caller input or trusts
 * a client-supplied staff/city/area id without re-resolving it in this transaction.
 *
 * Two independent things are modelled, and they never substitute for each other:
 *
 * - `staff_admin_city_assignments` is administrative territory: it limits *where* a
 *   manager may act. It is granted only by a SYSTEM ADMIN through
 *   `geography.admin.assign`, never to a technician, never for the actor's own staff
 *   id and never as a side effect of a role change. It carries no technician
 *   eligibility and no role grant.
 * - `technician_city_memberships` / `technician_service_areas` are work eligibility:
 *   a dated city admission and a dated zone admission inside it. They are managed
 *   through `staff.geography.read`/`staff.geography.manage`, scoped to the assigned
 *   cities, and they are never administrative authority.
 *
 * Authority is always the *trusted* value produced by `withGeography` on this same
 * transaction: `ctx.geoPermissions` (the enabled geography grants with their scope)
 * and `ctx.cityIds` (`null` = GLOBAL, otherwise the actor's assigned cities; the SELF
 * summary gets `[]`). A request body, path id or channel never widens that scope.
 *
 * Lock order, after the common authorization/policy lock the runner already holds:
 * per-technician advisory lock -> staff row -> membership/grant rows. The per
 * technician key is shared with the dispatch/schedule writers (P09) so a membership
 * or zone change and a visit assignment serialize on the same key; keep
 * `TECHNICIAN_LOCK_NAMESPACE` byte-identical to migration 012.
 *
 * Time: every timestamp is a strict ISO-8601 instant with an explicit zone (`Z` or
 * `+HH:MM`) and is validated field by field, so `2026-02-30` or `24:00:00` is a 400
 * instead of a silently rolled-over calendar value. Intervals are half-open
 * `[valid_from, valid_to)`: a `valid_to` equal to the start is empty and rejected.
 */

/** Namespace of the global per-technician advisory lock; migration 012 must use the same text. */
export const TECHNICIAN_LOCK_NAMESPACE = 'fixlevelup:technician';

const INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/;
const MONTH_DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as const;

function digits(text: string | undefined): number {
  if (text === undefined) { throw new BadRequestException(); }
  return Number(text);
}

function daysInMonth(year: number, month: number): number {
  if (month === 2 && year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)) { return 29; }
  return MONTH_DAYS[month - 1] ?? 0;
}

/**
 * Parses one explicit-zone ISO-8601 instant into a `Date` (UTC). Rejects a bare
 * local time, a date without a zone, an impossible calendar date/time and an offset
 * outside `-14:00..+14:00`, so a server/browser default timezone can never be used.
 * Fractional seconds are millisecond-precise: a fourth or later digit is accepted
 * only when it is zero, so a sub-millisecond value is never silently rounded.
 */
export function parseGeoInstant(value: unknown): Date {
  if (typeof value !== 'string') { throw new BadRequestException(); }
  const match = INSTANT.exec(value);
  if (!match) { throw new BadRequestException(); }
  const year = digits(match[1]); const month = digits(match[2]); const day = digits(match[3]);
  const hour = digits(match[4]); const minute = digits(match[5]); const second = digits(match[6]);
  const offset = match[8];
  if (offset === undefined || year < 1000) { throw new BadRequestException(); }
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)
    || hour > 23 || minute > 59 || second > 59) { throw new BadRequestException(); }
  let offsetMinutes = 0;
  if (offset !== 'Z') {
    const offsetHours = digits(offset.slice(1, 3)); const offsetMins = digits(offset.slice(4, 6));
    if (offsetHours > 14 || offsetMins > 59 || (offsetHours === 14 && offsetMins !== 0)) { throw new BadRequestException(); }
    offsetMinutes = (offset.startsWith('-') ? -1 : 1) * (offsetHours * 60 + offsetMins);
  }
  const fraction = match[7];
  if (fraction !== undefined && fraction.length > 3 && /[1-9]/.test(fraction.slice(3))) {
    // Sub-millisecond input would be truncated; refuse it instead of storing a
    // different instant than the caller asked for.
    throw new BadRequestException();
  }
  const millis = fraction === undefined ? 0 : Number(fraction.padEnd(3, '0').slice(0, 3));
  const instant = Date.UTC(year, month - 1, day, hour, minute, second, millis) - offsetMinutes * 60_000;
  if (!Number.isFinite(instant)) { throw new BadRequestException(); }
  return new Date(instant);
}

export interface GrantInterval { readonly validFrom: Date; readonly validTo: Date | null }

/** `[validFrom, validTo)`; an open end means "until revoked". */
export function parseGrantInterval(body: Record<string, unknown>): GrantInterval {
  const validFrom = parseGeoInstant(body['validFrom']);
  const rawValidTo = body['validTo'];
  const validTo = rawValidTo === undefined || rawValidTo === null ? null : parseGeoInstant(rawValidTo);
  if (validTo !== null && validTo.getTime() <= validFrom.getTime()) { throw new BadRequestException(); }
  return { validFrom, validTo };
}

const GRANT_KEYS = ['validFrom', 'validTo'] as const;

function grantBody(body: unknown, extraKeys: readonly string[] = []): Record<string, unknown> {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) { throw new BadRequestException(); }
  const record = body as Record<string, unknown>;
  const allowed = new Set<string>([...GRANT_KEYS, ...extraKeys]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) { throw new BadRequestException(); }
  }
  return record;
}

function emptyBody(body: unknown): void {
  if (body === undefined) { return; }
  if (body === null || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== 0) {
    throw new BadRequestException();
  }
}

/** Staff capability from the role dictionary (`ctx.permissions`). */
function hasStaffPermission(ctx: GeoContext, code: 'staff.read' | 'staff.self.read' | 'staff.role.assign'): boolean {
  return (ctx.permissions as readonly string[]).includes(code);
}

/** Geography authority from the trusted grant list, never from the staff dictionary. */
function geoGrant(ctx: GeoContext, code: GeoCapability): GeoGrant | null {
  const grants: readonly GeoGrant[] = ctx.geoPermissions ?? [];
  return grants.find((grant) => grant.code === code) ?? null;
}

function requireGeoGrant(ctx: GeoContext, code: GeoCapability): void {
  if (!geoGrant(ctx, code)) { throw new ForbiddenException(); }
}

/** Administrative territory is GLOBAL and SYSTEM ADMIN-only: the role alone is not
 * enough, the actor must also hold `geography.manage` GLOBALLY (the same condition the
 * central `withGeography` enforces) and `staff.role.assign`. A city-scoped manager can
 * never reach it, and a geographic read/manage grant is not administrative authority. */
function requireAdministrativeActor(ctx: GeoContext): void {
  const manage = geoGrant(ctx, 'geography.manage');
  if (!isSystemAdmin(ctx.role) || ctx.cityIds !== null || manage?.scope !== 'GLOBAL'
    || !hasStaffPermission(ctx, 'staff.role.assign')) {
    throw new ForbiddenException();
  }
}

function requireCityInScope(ctx: GeoContext, cityId: string): void {
  if (ctx.cityIds !== null && !ctx.cityIds.includes(cityId)) { throw new NotFoundException(); }
}

function targetId(target: GeoTarget, key: 'cityId' | 'staffId' | 'grantId' | 'areaId'): string {
  const value = target[key];
  if (value === undefined) { throw new BadRequestException(); }
  return uuid(value);
}

function optionalTargetId(target: GeoTarget, key: 'cityId' | 'staffId' | 'grantId' | 'areaId'): string | undefined {
  const value = target[key];
  return value === undefined ? undefined : uuid(value);
}

function isoInstant(value: Date | string | null): string | null {
  if (value === null) { return null; }
  return isoDate(value);
}

function isoDate(value: Date | string): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) { throw new InternalServerErrorException(); }
  return date.toISOString();
}

interface StaffRow {
  readonly id: string;
  readonly channel_role: string;
  readonly employment_state: string;
  readonly auth_version: number;
  readonly profile_version: number;
  readonly role_code: string | null;
  readonly role_type: string | null;
  readonly has_web: boolean;
}

const STAFF_SQL = `SELECT s.id, s.role AS channel_role, s.employment_state, s.auth_version, s.profile_version,
  r.code AS role_code, r.role_type, EXISTS (SELECT FROM foundation.staff_web_credentials c WHERE c.staff_id=s.id) AS has_web
  FROM foundation.staff s
  LEFT JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
  LEFT JOIN foundation.roles r ON r.id=a.role_id`;

async function loadStaff(client: PoolClient, staffId: string): Promise<StaffRow | null> {
  const result = await client.query<StaffRow>(`${STAFF_SQL} WHERE s.id=$1`, [staffId]);
  return result.rows[0] ?? null;
}

function aggregateVersion(row: Pick<StaffRow, 'auth_version' | 'profile_version'>): number {
  return row.auth_version + row.profile_version;
}

/** Serializes every technician-scoped write and every dispatch/schedule decision for
 * one technician. Must be taken after the common policy lock and before row locks. */
async function lockTechnician(client: PoolClient, technicianId: string): Promise<void> {
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
    [`${TECHNICIAN_LOCK_NAMESPACE}:${technicianId}`]);
}

/** Row lock plus the aggregate `If-Match` check (`auth_version+profile_version`). */
async function lockStaff(client: PoolClient, staffId: string, expected: number): Promise<StaffRow> {
  const result = await client.query<StaffRow>(
    `SELECT s.id, s.role AS channel_role, s.employment_state, s.auth_version, s.profile_version,
       r.code AS role_code, r.role_type, EXISTS (SELECT FROM foundation.staff_web_credentials c WHERE c.staff_id=s.id) AS has_web
     FROM foundation.staff s
     LEFT JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
     LEFT JOIN foundation.roles r ON r.id=a.role_id
     WHERE s.id=$1 FOR UPDATE OF s`, [staffId]);
  const row = result.rows[0];
  if (!row) { throw new NotFoundException(); }
  if (aggregateVersion(row) !== expected) { throw new HttpException('Precondition Failed', 412); }
  return row;
}

/** One accepted membership/assignment mutation advances the staff aggregate exactly
 * once, so a stale ETag fails and a write-only grantee cannot compare no-ops. */
async function bumpProfileVersion(client: PoolClient, staffId: string): Promise<number> {
  const result = await client.query<{ auth_version: number; profile_version: number }>(
    'UPDATE foundation.staff SET profile_version=profile_version+1 WHERE id=$1 RETURNING auth_version, profile_version',
    [staffId]);
  const row = result.rows[0];
  if (!row) { throw new NotFoundException(); }
  return row.auth_version + row.profile_version;
}

async function staffAggregate(client: PoolClient, staffId: string): Promise<number> {
  const result = await client.query<{ auth_version: number; profile_version: number }>(
    'SELECT auth_version, profile_version FROM foundation.staff WHERE id=$1', [staffId]);
  const row = result.rows[0];
  if (!row) { throw new NotFoundException(); }
  return row.auth_version + row.profile_version;
}

function requireExpected(expected: number | null): number {
  if (expected === null) { throw new HttpException('Precondition Required', 428); }
  return expected;
}

async function cityLifecycle(client: PoolClient, cityId: string): Promise<string | null> {
  const result = await client.query<{ lifecycle: string }>(
    'SELECT lifecycle FROM foundation.service_cities WHERE id=$1', [cityId]);
  return result.rows[0]?.lifecycle ?? null;
}

interface AreaRow {
  readonly id: string;
  readonly city_id: string;
  readonly archived_at: Date | null;
  readonly current_version_id: string | null;
}

async function loadArea(client: PoolClient, areaId: string): Promise<AreaRow | null> {
  const result = await client.query<AreaRow>(
    'SELECT id, city_id, archived_at, current_version_id FROM foundation.service_areas WHERE id=$1', [areaId]);
  return result.rows[0] ?? null;
}

/** Zone admission always names a real, same-city, non-archived area that has at least
 * one published revision: a draft-only zone is not an effective territory yet. */
async function requireGrantableArea(client: PoolClient, cityId: string, areaId: string): Promise<AreaRow> {
  const area = await loadArea(client, areaId);
  if (!area || area.city_id !== cityId) { throw new NotFoundException(); }
  if (area.archived_at !== null || area.current_version_id === null) { throw new ConflictException(); }
  return area;
}

/**
 * Non-administrative actors may read a technician only through one of two narrow
 * doors: the normal staff roster (`staff.read`, which already projects the employee)
 * or an existing territory relation to the path city. A manager can therefore admit
 * a technician who has no membership yet, but cannot enumerate unrelated employees by
 * guessing their id.
 */
function technicianAccessSql(city: `$${number}`, global: `$${number}`, roster: `$${number}`): string {
  // P02 staff.read by a manager exposes only an actual SYSTEM TECHNICIAN. The
  // territory door is independent and deliberately includes historical relations.
  return `s.role='TECHNICIAN' AND (${global}::boolean
    OR (${roster}::boolean AND r.role_type='SYSTEM' AND r.code='TECHNICIAN')
    OR EXISTS (SELECT 1 FROM foundation.technician_city_memberships relation
      WHERE relation.technician_id=s.id AND relation.city_id=${city}))`;
}

async function requireTechnicianAccess(ctx: GeoContext, technicianId: string, cityId: string): Promise<StaffRow> {
  const result = await ctx.client.query<StaffRow>(`${STAFF_SQL} WHERE s.id=$1 AND ${technicianAccessSql('$2', '$3', '$4')}`,
    [technicianId, cityId, ctx.cityIds === null, hasStaffPermission(ctx, 'staff.read')]);
  const subject = result.rows[0];
  if (!subject) { throw new NotFoundException(); }
  return subject;
}

async function requireActiveTechnicianTarget(ctx: GeoContext, technicianId: string, cityId: string): Promise<StaffRow> {
  if (technicianId === ctx.staffId) { throw new ForbiddenException(); }
  const subject = await requireTechnicianAccess(ctx, technicianId, cityId);
  if (subject.employment_state !== 'ACTIVE') { throw new NotFoundException(); }
  return subject;
}

interface AdminAssignmentRow {
  readonly id: string; readonly staff_id: string; readonly city_id: string; readonly revoked_at: Date | null;
}

async function loadAdminAssignment(client: PoolClient, grantId: string, lock: boolean): Promise<AdminAssignmentRow | null> {
  const result = await client.query<AdminAssignmentRow>(
    `SELECT id, staff_id, city_id, revoked_at FROM foundation.staff_admin_city_assignments WHERE id=$1${lock ? ' FOR UPDATE' : ''}`,
    [grantId]);
  return result.rows[0] ?? null;
}

interface MembershipRow {
  readonly id: string; readonly technician_id: string; readonly city_id: string; readonly revoked_at: Date | null;
}

async function loadMembership(client: PoolClient, grantId: string, lock: boolean): Promise<MembershipRow | null> {
  const result = await client.query<MembershipRow>(
    `SELECT id, technician_id, city_id, revoked_at FROM foundation.technician_city_memberships WHERE id=$1${lock ? ' FOR UPDATE' : ''}`,
    [grantId]);
  return result.rows[0] ?? null;
}

interface ZoneGrantRow {
  readonly id: string; readonly technician_id: string; readonly city_id: string;
  readonly service_area_id: string; readonly revoked_at: Date | null;
}

async function loadZoneGrant(client: PoolClient, grantId: string, lock: boolean): Promise<ZoneGrantRow | null> {
  const result = await client.query<ZoneGrantRow>(
    `SELECT id, technician_id, city_id, service_area_id, revoked_at FROM foundation.technician_service_areas WHERE id=$1${lock ? ' FOR UPDATE' : ''}`,
    [grantId]);
  return result.rows[0] ?? null;
}

/** Disjoint dated periods are legitimate: an expired-but-not-revoked admission does not
 * block a new period. Only an overlap with a live row of the same key is refused, and
 * the database enforces the same rule (`23P01`) even if this check is bypassed. */
async function requireNoOverlap(client: PoolClient, table: 'technician_city_memberships' | 'technician_service_areas',
  technicianId: string, scopeColumn: 'city_id' | 'service_area_id', scopeId: string, interval: GrantInterval): Promise<void> {
  const overlapping = await client.query(
    `SELECT 1 FROM foundation.${table}
     WHERE technician_id=$1 AND ${scopeColumn}=$2 AND revoked_at IS NULL
       AND tstzrange(valid_from, valid_to, '[)') && tstzrange($3::timestamptz, $4::timestamptz, '[)')
     FOR UPDATE`, [technicianId, scopeId, interval.validFrom, interval.validTo]);
  if (overlapping.rowCount !== 0) { throw new ConflictException(); }
}

const adminList: GeoCommand = {
  action: 'geography.admin.assign',
  write: false,
  scoped: 'list',
  async check(ctx, target) {
    requireAdministrativeActor(ctx);
    const staffId = targetId(target, 'staffId');
    const cityId = optionalTargetId(target, 'cityId');
    const subject = await loadStaff(ctx.client, staffId);
    if (!subject) { throw new NotFoundException(); }
    if (cityId !== undefined && (await cityLifecycle(ctx.client, cityId)) === null) { throw new NotFoundException(); }
  },
  async run(ctx, target, body) {
    const staffId = targetId(target, 'staffId');
    const cityId = optionalTargetId(target, 'cityId') ?? null;
    // The returned aggregate belongs to the *subject* whose territory is listed, so a
    // client can chain If-Match on the next assignment change of that employee.
    const version = await staffAggregate(ctx.client, staffId);
    const page = readGeoPage(ctx, body, 'adminList', [cityId, staffId], idPosition);
    const result = await ctx.client.query<{
      id: string; staff_id: string; city_id: string; granted_at: Date; revoked_at: Date | null; active: boolean;
    }>(`SELECT a.id,a.staff_id,a.city_id,a.granted_at,a.revoked_at,(a.revoked_at IS NULL) AS active
      FROM foundation.staff_admin_city_assignments a
      WHERE a.staff_id=$1 AND ($2::uuid IS NULL OR a.city_id=$2)
        AND ($3::uuid IS NULL OR (a.city_id,a.granted_at,a.id)>(
          SELECT anchor.city_id,anchor.granted_at,anchor.id FROM foundation.staff_admin_city_assignments anchor
          WHERE anchor.id=$3 AND anchor.staff_id=$1 AND ($2::uuid IS NULL OR anchor.city_id=$2)))
      ORDER BY a.city_id,a.granted_at,a.id LIMIT $4`, [staffId, cityId, page.after?.[0] ?? null, page.take]);
    return { version, ...finishGeoPage(page, result.rows, row => ({
      id: row.id, staffId: row.staff_id, cityId: row.city_id,
      grantedAt: isoInstant(row.granted_at), revokedAt: isoInstant(row.revoked_at), active: row.active,
    }), idKey) };
  },
};

const adminAssign: GeoCommand = {
  action: 'geography.admin.assign',
  write: true,
  scoped: 'city',
  async check(ctx, target) {
    requireAdministrativeActor(ctx);
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    if (staffId === ctx.staffId) { throw new ForbiddenException(); }
    requireCityInScope(ctx, cityId);
    const subject = await loadStaff(ctx.client, staffId);
    // Administrative territory belongs to an active, credentialled web staff member with
    // a current role; a technician is never an administrative delegate and a role change
    // never grants it. A CRM-less employee cannot exercise territory, so the database
    // guard refuses it as well - the command reports it as not found, not as an error.
    if (!subject || subject.employment_state !== 'ACTIVE' || subject.channel_role === 'TECHNICIAN'
      || subject.role_code === null || !subject.has_web) { throw new NotFoundException(); }
    if ((await cityLifecycle(ctx.client, cityId)) === null) { throw new NotFoundException(); }
  },
  async run(ctx, target, body, expected) {
    emptyBody(body);
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const version = requireExpected(expected);
    const locked = await lockStaff(ctx.client, staffId, version);
    if (locked.employment_state !== 'ACTIVE') { throw new ConflictException(); }
    const lifecycle = await cityLifecycle(ctx.client, cityId);
    if (lifecycle === null) { throw new NotFoundException(); }
    if (lifecycle !== 'ACTIVE') { throw new ConflictException(); }
    const active = await ctx.client.query(
      'SELECT id FROM foundation.staff_admin_city_assignments WHERE staff_id=$1 AND city_id=$2 AND revoked_at IS NULL FOR UPDATE',
      [staffId, cityId]);
    if (active.rowCount !== 0) { throw new ConflictException(); }
    // A new city widens every effective CITY P03/P04 grant of the target. This runs
    // under the RBAC write and target staff locks, only on the actual INSERT path.
    await requireDomainCityExpansion(ctx, staffId);
    // The same assignment would widen a live CITY-scoped P05 request grant, which the
    // ordinary composition must never do implicitly: P05 provisioning is operator-owned.
    await requireNoP05CityExpansion(ctx, staffId);
    const id = randomUUID();
    // `granted_at` is database-stamped and deliberately not insertable by the runtime:
    // the caller cannot backdate a grant.
    await ctx.client.query(`INSERT INTO foundation.staff_admin_city_assignments
      (id, staff_id, city_id, granted_by) VALUES ($1,$2,$3,$4)`,
    [id, staffId, cityId, ctx.staffId]);
    return { id, version: await bumpProfileVersion(ctx.client, staffId) };
  },
};

const adminRevoke: GeoCommand = {
  action: 'geography.admin.assign',
  write: true,
  scoped: 'city',
  async check(ctx, target) {
    requireAdministrativeActor(ctx);
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const grantId = targetId(target, 'grantId');
    if (staffId === ctx.staffId) { throw new ForbiddenException(); }
    requireCityInScope(ctx, cityId);
    const assignment = await loadAdminAssignment(ctx.client, grantId, false);
    if (!assignment || assignment.staff_id !== staffId || assignment.city_id !== cityId) { throw new NotFoundException(); }
  },
  async run(ctx, target, body, expected) {
    emptyBody(body);
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const grantId = targetId(target, 'grantId');
    const version = requireExpected(expected);
    // Revocation must stay possible after the city was suspended or the employee was
    // deactivated, so this row lock deliberately does not require ACTIVE.
    await lockStaff(ctx.client, staffId, version);
    const assignment = await loadAdminAssignment(ctx.client, grantId, true);
    if (!assignment || assignment.staff_id !== staffId || assignment.city_id !== cityId) { throw new NotFoundException(); }
    if (assignment.revoked_at !== null) { throw new ConflictException(); }
    await ctx.client.query(
      'UPDATE foundation.staff_admin_city_assignments SET revoked_at=statement_timestamp(), revoked_by=$2 WHERE id=$1',
      [grantId, ctx.staffId]);
    return { id: grantId, version: await bumpProfileVersion(ctx.client, staffId) };
  },
};

const techPicker: GeoCommand = {
  action: 'staff.geography.read',
  write: false,
  scoped: 'city',
  async check(ctx, target) {
    requireGeoGrant(ctx, 'staff.geography.read');
    const cityId = targetId(target, 'cityId');
    requireCityInScope(ctx, cityId);
    if ((await cityLifecycle(ctx.client, cityId)) === null) { throw new NotFoundException(); }
  },
  async run(ctx, target, body): Promise<P03Page<P03TechnicianPickerItem>> {
    const cityId = targetId(target, 'cityId');
    const roster = hasStaffPermission(ctx, 'staff.read');
    const page = readGeoPage(ctx, body, 'techPicker', [cityId, roster], idPosition);
    const result = await ctx.client.query<Pick<StaffRow, 'id' | 'auth_version' | 'profile_version'> & { display_name: string | null }>(
      `SELECT s.id,s.display_name,s.auth_version,s.profile_version
       FROM foundation.staff s
       JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
       JOIN foundation.roles r ON r.id=a.role_id AND r.status='ACTIVE'
       WHERE ${technicianAccessSql('$1', '$2', '$3')} AND s.employment_state='ACTIVE'
         AND (r.role_type='CUSTOM' OR (r.role_type='SYSTEM' AND r.code='TECHNICIAN'))
         AND ($4::uuid IS NULL OR s.id>$4)
       ORDER BY s.id LIMIT $5`, [cityId, ctx.cityIds === null, roster, page.after?.[0] ?? null, page.take]);
    return finishGeoPage(page, result.rows, row => ({
      id: row.id, displayName: row.display_name, version: aggregateVersion(row),
    }), idKey);
  },
};

const techCities: GeoCommand = {
  action: 'staff.geography.read',
  write: false,
  scoped: 'city',
  async check(ctx, target) {
    requireGeoGrant(ctx, 'staff.geography.read');
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    requireCityInScope(ctx, cityId);
    await requireTechnicianAccess(ctx, staffId, cityId);
  },
  async run(ctx, target, body) {
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const version = await staffAggregate(ctx.client, staffId);
    const page = readGeoPage(ctx, body, 'techCities', [cityId, staffId], idPosition);
    const result = await ctx.client.query<{
      id: string; city_id: string; valid_from: Date; valid_to: Date | null; revoked_at: Date | null; active: boolean;
    }>(`SELECT m.id,m.city_id,m.valid_from,m.valid_to,m.revoked_at,
        (m.revoked_at IS NULL AND m.valid_from <= statement_timestamp()
          AND (m.valid_to IS NULL OR m.valid_to > statement_timestamp())) AS active
      FROM foundation.technician_city_memberships m
      WHERE m.technician_id=$1 AND m.city_id=$2
        AND ($3::uuid IS NULL OR (m.valid_from,m.id)>(
          SELECT anchor.valid_from,anchor.id FROM foundation.technician_city_memberships anchor
          WHERE anchor.id=$3 AND anchor.technician_id=$1 AND anchor.city_id=$2))
      ORDER BY m.valid_from,m.id LIMIT $4`, [staffId, cityId, page.after?.[0] ?? null, page.take]);
    return { version, ...finishGeoPage(page, result.rows, row => ({
      id: row.id, cityId: row.city_id,
      validFrom: isoInstant(row.valid_from), validTo: isoInstant(row.valid_to),
      revokedAt: isoInstant(row.revoked_at), active: row.active,
    }), idKey) };
  },
};

const techGrantCity: GeoCommand = {
  action: 'staff.geography.manage',
  write: true,
  scoped: 'city',
  async check(ctx, target) {
    requireGeoGrant(ctx, 'staff.geography.manage');
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    requireCityInScope(ctx, cityId);
    // A first city admission is legitimate while the technician has no eligibility
    // yet: the explicit city + a real technician identity is enough, and the roster
    // check keeps unrelated ids unreadable.
    await requireActiveTechnicianTarget(ctx, staffId, cityId);
    if ((await cityLifecycle(ctx.client, cityId)) === null) { throw new NotFoundException(); }
  },
  async run(ctx, target, body, expected) {
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const interval = parseGrantInterval(grantBody(body));
    const version = requireExpected(expected);
    await lockTechnician(ctx.client, staffId);
    const locked = await lockStaff(ctx.client, staffId, version);
    if (locked.employment_state !== 'ACTIVE') { throw new ConflictException(); }
    const lifecycle = await cityLifecycle(ctx.client, cityId);
    if (lifecycle === null) { throw new NotFoundException(); }
    if (lifecycle !== 'ACTIVE') { throw new ConflictException(); }
    await requireNoOverlap(ctx.client, 'technician_city_memberships', staffId, 'city_id', cityId, interval);
    const id = randomUUID();
    await ctx.client.query(`INSERT INTO foundation.technician_city_memberships
      (id, technician_id, city_id, valid_from, valid_to, approved_by)
      VALUES ($1,$2,$3,$4,$5,$6)`, [id, staffId, cityId, interval.validFrom, interval.validTo, ctx.staffId]);
    return { id, version: await bumpProfileVersion(ctx.client, staffId) };
  },
};

const techRevokeCity: GeoCommand = {
  action: 'staff.geography.manage',
  write: true,
  scoped: 'city',
  async check(ctx, target) {
    requireGeoGrant(ctx, 'staff.geography.manage');
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const grantId = targetId(target, 'grantId');
    if (staffId === ctx.staffId) { throw new ForbiddenException(); }
    requireCityInScope(ctx, cityId);
    const membership = await loadMembership(ctx.client, grantId, false);
    if (!membership || membership.technician_id !== staffId || membership.city_id !== cityId) { throw new NotFoundException(); }
  },
  async run(ctx, target, body, expected) {
    emptyBody(body);
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const grantId = targetId(target, 'grantId');
    const version = requireExpected(expected);
    await lockTechnician(ctx.client, staffId);
    await lockStaff(ctx.client, staffId, version);
    const membership = await loadMembership(ctx.client, grantId, true);
    if (!membership || membership.technician_id !== staffId || membership.city_id !== cityId) { throw new NotFoundException(); }
    if (membership.revoked_at !== null) { throw new ConflictException(); }
    await ctx.client.query(
      'UPDATE foundation.technician_city_memberships SET revoked_at=statement_timestamp(), revoked_by=$2 WHERE id=$1',
      [grantId, ctx.staffId]);
    // Zone admissions are contained in the city admission, so they cannot outlive it.
    // History is kept as revoked rows; nothing is deleted.
    await ctx.client.query(`UPDATE foundation.technician_service_areas
      SET revoked_at=statement_timestamp(), revoked_by=$2
      WHERE membership_id=$1 AND revoked_at IS NULL`, [grantId, ctx.staffId]);
    return { id: grantId, version: await bumpProfileVersion(ctx.client, staffId) };
  },
};

const techZones: GeoCommand = {
  action: 'staff.geography.read',
  write: false,
  scoped: 'city',
  async check(ctx, target) {
    requireGeoGrant(ctx, 'staff.geography.read');
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    requireCityInScope(ctx, cityId);
    await requireTechnicianAccess(ctx, staffId, cityId);
  },
  async run(ctx, target, body) {
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const version = await staffAggregate(ctx.client, staffId);
    const page = readGeoPage(ctx, body, 'techZones', [cityId, staffId], idPosition);
    const result = await ctx.client.query<{
      id: string; city_id: string; service_area_id: string; membership_id: string;
      valid_from: Date; valid_to: Date | null; revoked_at: Date | null; active: boolean;
    }>(`SELECT g.id,g.city_id,g.service_area_id,g.membership_id,g.valid_from,g.valid_to,g.revoked_at,
        (g.revoked_at IS NULL AND g.valid_from <= statement_timestamp()
          AND (g.valid_to IS NULL OR g.valid_to > statement_timestamp())) AS active
      FROM foundation.technician_service_areas g
      JOIN foundation.service_areas a ON a.id=g.service_area_id AND a.city_id=g.city_id
      WHERE g.technician_id=$1 AND g.city_id=$2 AND a.current_version_id IS NOT NULL
        AND ($3::uuid IS NULL OR (g.service_area_id,g.valid_from,g.id)>(
          SELECT anchor.service_area_id,anchor.valid_from,anchor.id FROM foundation.technician_service_areas anchor
          JOIN foundation.service_areas aa ON aa.id=anchor.service_area_id AND aa.city_id=anchor.city_id
          WHERE anchor.id=$3 AND anchor.technician_id=$1 AND anchor.city_id=$2 AND aa.current_version_id IS NOT NULL))
      ORDER BY g.service_area_id,g.valid_from,g.id LIMIT $4`, [staffId, cityId, page.after?.[0] ?? null, page.take]);
    return { version, ...finishGeoPage(page, result.rows, row => ({
      id: row.id, cityId: row.city_id, areaId: row.service_area_id, membershipId: row.membership_id,
      validFrom: isoInstant(row.valid_from), validTo: isoInstant(row.valid_to),
      revokedAt: isoInstant(row.revoked_at), active: row.active,
    }), idKey) };
  },
};

const techGrantZone: GeoCommand = {
  action: 'staff.geography.manage',
  write: true,
  scoped: 'city',
  async check(ctx, target) {
    requireGeoGrant(ctx, 'staff.geography.manage');
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const areaId = targetId(target, 'areaId');
    requireCityInScope(ctx, cityId);
    await requireActiveTechnicianTarget(ctx, staffId, cityId);
    if ((await cityLifecycle(ctx.client, cityId)) === null) { throw new NotFoundException(); }
    const area = await loadArea(ctx.client, areaId);
    if (!area || area.city_id !== cityId) { throw new NotFoundException(); }
  },
  async run(ctx, target, body, expected) {
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const record = grantBody(body, ['areaId']);
    const bodyAreaId = record['areaId'];
    const areaId = bodyAreaId === undefined ? targetId(target, 'areaId') : uuid(bodyAreaId);
    const pathAreaId = optionalTargetId(target, 'areaId');
    if (pathAreaId !== undefined && pathAreaId !== areaId) { throw new BadRequestException(); }
    const interval = parseGrantInterval(record);
    const version = requireExpected(expected);
    await lockTechnician(ctx.client, staffId);
    const locked = await lockStaff(ctx.client, staffId, version);
    if (locked.employment_state !== 'ACTIVE') { throw new ConflictException(); }
    const lifecycle = await cityLifecycle(ctx.client, cityId);
    if (lifecycle === null) { throw new NotFoundException(); }
    if (lifecycle !== 'ACTIVE') { throw new ConflictException(); }
    await requireGrantableArea(ctx.client, cityId, areaId);
    // The zone admission must sit entirely inside one active city admission of the
    // same technician and city; a partially covered or future-only interval is not a
    // qualification.
    const covering = await ctx.client.query<{ id: string }>(
      `SELECT id FROM foundation.technician_city_memberships
       WHERE technician_id=$1 AND city_id=$2 AND revoked_at IS NULL
         AND valid_from <= $3::timestamptz
         AND (($4::timestamptz IS NULL AND valid_to IS NULL)
           OR ($4::timestamptz IS NOT NULL AND (valid_to IS NULL OR valid_to >= $4::timestamptz)))
       FOR UPDATE`, [staffId, cityId, interval.validFrom, interval.validTo]);
    const membership = covering.rows[0];
    if (!membership) { throw new ConflictException(); }
    await requireNoOverlap(ctx.client, 'technician_service_areas', staffId, 'service_area_id', areaId, interval);
    const id = randomUUID();
    await ctx.client.query(`INSERT INTO foundation.technician_service_areas
      (id, technician_id, city_id, service_area_id, membership_id, valid_from, valid_to, approved_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [id, staffId, cityId, areaId, membership.id, interval.validFrom, interval.validTo, ctx.staffId]);
    return { id, version: await bumpProfileVersion(ctx.client, staffId) };
  },
};

const techRevokeZone: GeoCommand = {
  action: 'staff.geography.manage',
  write: true,
  scoped: 'city',
  async check(ctx, target) {
    requireGeoGrant(ctx, 'staff.geography.manage');
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const grantId = targetId(target, 'grantId');
    if (staffId === ctx.staffId) { throw new ForbiddenException(); }
    requireCityInScope(ctx, cityId);
    const grant = await loadZoneGrant(ctx.client, grantId, false);
    if (!grant || grant.technician_id !== staffId || grant.city_id !== cityId) { throw new NotFoundException(); }
  },
  async run(ctx, target, body, expected) {
    emptyBody(body);
    const cityId = targetId(target, 'cityId');
    const staffId = targetId(target, 'staffId');
    const grantId = targetId(target, 'grantId');
    const version = requireExpected(expected);
    await lockTechnician(ctx.client, staffId);
    await lockStaff(ctx.client, staffId, version);
    const grant = await loadZoneGrant(ctx.client, grantId, true);
    if (!grant || grant.technician_id !== staffId || grant.city_id !== cityId) { throw new NotFoundException(); }
    if (grant.revoked_at !== null) { throw new ConflictException(); }
    await ctx.client.query(
      'UPDATE foundation.technician_service_areas SET revoked_at=statement_timestamp(), revoked_by=$2 WHERE id=$1',
      [grantId, ctx.staffId]);
    return { id: grantId, version: await bumpProfileVersion(ctx.client, staffId) };
  },
};

interface SelfZone { readonly areaId: string; readonly validFrom: string; readonly validTo: string | null }
interface SelfCity {
  readonly cityId: string; readonly validFrom: string; readonly validTo: string | null;
  readonly zones: readonly SelfZone[];
}

const techSelf: GeoCommand = {
  action: 'geography.self.read',
  write: false,
  scoped: 'self',
  async check(ctx, target) {
    // `withGeography` already proves a verified Telegram master session (the only
    // principal kind whose channel role is TECHNICIAN) and the `staff.self.read`
    // grant; the subject is always that session's own staff id.
    if (ctx.principal.kind !== 'staff-telegram') { throw new ForbiddenException(); }
    if (Object.keys(target).length !== 0) { throw new BadRequestException(); }
    if (!hasStaffPermission(ctx, 'staff.self.read')) { throw new ForbiddenException(); }
    const subject = await loadStaff(ctx.client, ctx.staffId);
    if (!subject || subject.channel_role !== 'TECHNICIAN' || subject.employment_state !== 'ACTIVE') {
      throw new ForbiddenException();
    }
  },
  async run(ctx) {
    const memberships = await ctx.client.query<{
      id: string; city_id: string; valid_from: Date; valid_to: Date | null;
    }>(`SELECT m.id, m.city_id, m.valid_from, m.valid_to FROM foundation.technician_city_memberships m
      JOIN foundation.service_cities c ON c.id=m.city_id AND c.lifecycle='ACTIVE'
      WHERE m.technician_id=$1 AND m.revoked_at IS NULL
        AND m.valid_from <= CURRENT_TIMESTAMP AND (m.valid_to IS NULL OR m.valid_to > CURRENT_TIMESTAMP)
      ORDER BY m.city_id, m.valid_from, m.id`, [ctx.staffId]);
    const grants = await ctx.client.query<{
      service_area_id: string; membership_id: string; valid_from: Date; valid_to: Date | null;
    }>(`SELECT g.service_area_id, g.membership_id, g.valid_from, g.valid_to
      FROM foundation.technician_service_areas g
      JOIN foundation.service_areas a ON a.id=g.service_area_id AND a.city_id=g.city_id
      WHERE g.technician_id=$1 AND g.revoked_at IS NULL AND a.current_version_id IS NOT NULL AND a.archived_at IS NULL
        AND g.valid_from <= CURRENT_TIMESTAMP AND (g.valid_to IS NULL OR g.valid_to > CURRENT_TIMESTAMP)
      ORDER BY g.service_area_id, g.valid_from, g.id`, [ctx.staffId]);
    const items: SelfCity[] = memberships.rows.map((row) => ({
      cityId: row.city_id, validFrom: isoDate(row.valid_from), validTo: isoInstant(row.valid_to),
      zones: grants.rows.filter((grant) => grant.membership_id === row.id).map((grant) => ({
        areaId: grant.service_area_id, validFrom: isoDate(grant.valid_from), validTo: isoInstant(grant.valid_to),
      })),
    }));
    // Active rows only: no past or future history and no other employee's records.
    return { items, version: await staffAggregate(ctx.client, ctx.staffId) };
  },
};

export const membershipCommands = {
  adminList, adminAssign, adminRevoke,
  techCities, techGrantCity, techRevokeCity,
  techZones, techGrantZone, techRevokeZone,
  techPicker, techSelf,
} as const satisfies Record<string, GeoCommand>;

export type MembershipOperation = keyof typeof membershipCommands;
export type MembershipReceipt = GeoReceipt;
