import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { expect } from 'vitest';
import type { RbacFixture, Web } from './rbac-fixture.js';

/** Independent HTTP adapter for the P03-02 geography routes. It deliberately does not
 * reuse the private RbacFixture call helper: geography writes need extra security
 * headers (Idempotency-Key, aggregate If-Match) and the test must be able to prove the
 * exact status, envelope and ETag of every response. Every response is still checked
 * for the no-store directive and for leaked credentials, as the P02 fixture does. */
export type GeoMethod = 'get' | 'post' | 'patch' | 'put';

export interface GeoResult {
  readonly status: number;
  /** `data` of the {data, meta} envelope when it is an object; empty for an error. */
  readonly data: Record<string, unknown>;
  /** Raw `data` value, including the array form of GET /settings/service-cities. */
  readonly payload: unknown;
  readonly body: unknown;
  readonly etag: string;
}

export interface GeoWriteOptions {
  /** Strong aggregate validator exactly as the server expects it, e.g. geoTag(3). */
  readonly etag?: string;
  /** Idempotency-Key; a fresh UUID is generated for every write by default. */
  readonly key?: string;
  /** Browser Origin override for negative Origin/CSRF cases. */
  readonly origin?: string;
  /** Send a write without an Idempotency-Key (negative case). */
  readonly noKey?: boolean;
  /** Send a write without If-Match (negative case). */
  readonly noEtag?: boolean;
  /** Send a write with a wrong CSRF token (negative case). */
  readonly csrf?: string;
}

/** Strong aggregate validator for every geography write except the city creation. */
export function geoTag(version: number): string {
  if (!Number.isSafeInteger(version) || version < 0) { throw new Error('Invalid geo version'); }
  return `"geo-v${String(version)}"`;
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) { throw new Error('Expected object response'); }
  return value as Record<string, unknown>;
}
export function text(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== 'string') { throw new Error(`Expected string field: ${key}`); }
  return value;
}
export function num(obj: Record<string, unknown>, key: string): number {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) { throw new Error(`Expected integer field: ${key}`); }
  return value;
}
/** Asserts the exact status and returns the same value, so both geography results and
 * the shared P02 fixture results can be checked without re-wrapping them. */
export function check<T extends { readonly status: number }>(result: T, status: number): T {
  expect(result.status).toBe(status);
  return result;
}
/** Strict array projection of a response field; a missing/non-array field is a failure. */
export function records(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) { throw new Error('Expected an array'); }
  return value.map(record);
}
export function idOf(result: GeoResult): string { return text(result.data, 'id'); }
export function versionOf(result: GeoResult): number { return num(result.data, 'version'); }
export function itemsOf(result: GeoResult): Record<string, unknown>[] {
  const raw = result.payload;
  const list = Array.isArray(raw) ? raw : record(raw)['items'];
  if (!Array.isArray(list)) { throw new Error('Expected an items array'); }
  return list.map(record);
}

/** The five geography grants the approved bootstrap exception assigns to the first
 * registered administrator, bound to that administrator's original SYSTEM ADMIN
 * assignment. Sorted for a stable assertion. */
export const BOOTSTRAP_GEO_PERMISSIONS = Object.freeze([
  'geography.manage', 'geography.publish', 'geography.read', 'staff.geography.manage', 'staff.geography.read',
]);

const ORIGIN = 'https://crm.example.test';
const TG_ORIGIN = 'https://mini.example.test';

/** Seven open weekdays, 09:00-18:00 local time: a valid 010 office-hours schedule. */
const OFFICE_HOURS = Object.freeze(Array.from({ length: 7 }, () => [[540, 1080] as const]));

export interface City { readonly id: string; readonly version: number; readonly versionId: string }

export class GeographyFixture {
  private readonly secrets: string[] = [];
  constructor(readonly base: RbacFixture) {}

  /** Register a logged-in identity so every geography response is scanned for its
   * credentials. Returns the same value for convenient chaining. */
  remember<T extends Web>(web: T): T {
    this.secrets.push(web.token, web.csrf, web.password);
    return web;
  }
  private safe(value: unknown): void {
    const json = JSON.stringify(value);
    expect(this.secrets.some((secret) => json.includes(secret))).toBe(false);
  }
  private async submit(web: Web | { readonly token: string }, method: GeoMethod, path: string,
    body: unknown, options: GeoWriteOptions = {}): Promise<GeoResult> {
    // A loopback URL (not the in-process server handle) is required to send arbitrary
    // security headers through supertest while still exercising a real TCP request.
    const req = request(`http://127.0.0.1:${String(this.base.httpPort)}`)[method](`/api/v1${path}`);
    const telegram = !('cookie' in web);
    req.set('Origin', options.origin ?? (telegram ? TG_ORIGIN : ORIGIN));
    if (telegram) { req.set('Authorization', `Bearer ${web.token}`); }
    else {
      req.set('Cookie', web.cookie);
      if (method !== 'get') { req.set('X-CSRF-Token', options.csrf ?? web.csrf); }
    }
    if (method !== 'get') {
      if (!options.noEtag && options.etag !== undefined) { req.set('If-Match', options.etag); }
      if (!options.noKey) { req.set('Idempotency-Key', options.key ?? randomUUID()); }
    }
    if (body !== undefined) { req.set('Content-Type', 'application/json').send(JSON.stringify(body)); }
    const response = await req;
    expect(response.headers['cache-control']).toBe('no-store');
    this.safe(response.body);
    const envelope = response.body && typeof response.body === 'object' ? record(response.body) : {};
    const payload: unknown = response.status < 300 ? envelope['data'] : undefined;
    const data = payload && typeof payload === 'object' && !Array.isArray(payload) ? record(payload) : {};
    const etag: unknown = response.headers['etag'];
    return { status: response.status, data, payload, body: response.body, etag: typeof etag === 'string' ? etag : '' };
  }

  /** CRM session read (exact Origin only; no CSRF on reads). */
  read(web: Web, path: string, options: GeoWriteOptions = {}): Promise<GeoResult> {
    return this.submit(web, 'get', path, undefined, options);
  }
  /** CRM session write: Origin + CSRF + fresh Idempotency-Key unless a negative case
   * explicitly overrides them. */
  write(web: Web, method: Exclude<GeoMethod, 'get'>, path: string, body: unknown = {},
    options: GeoWriteOptions = {}): Promise<GeoResult> {
    return this.submit(web, method, path, body, options);
  }
  /** Telegram master read: bearer token only, never a CRM cookie. */
  tgRead(token: string, path: string): Promise<GeoResult> {
    return this.submit({ token }, 'get', path, undefined);
  }
  /** Telegram master write attempt: same route, but the TG channel must be refused. */
  tgWrite(token: string, method: Exclude<GeoMethod, 'get'>, path: string, body: unknown = {}): Promise<GeoResult> {
    return this.submit({ token }, method, path, body);
  }

  /* --------------------------- catalog helpers --------------------------- */

  createCity(web: Web, code: string): Promise<GeoResult> {
    return this.write(web, 'post', '/settings/service-cities', { code });
  }
  addCityVersion(web: Web, cityId: string, expected: number): Promise<GeoResult> {
    return this.write(web, 'post', `/settings/service-cities/${cityId}/versions`, {
      displayName: `City ${cityId.slice(0, 8)}`, addressDisplay: 'Synthetic street 1',
      timezone: 'Europe/Moscow', publicContact: '+70000000000', officeHours: OFFICE_HOURS,
    }, { etag: geoTag(expected) });
  }
  publishCityVersion(web: Web, cityId: string, versionId: string, expected: number): Promise<GeoResult> {
    return this.write(web, 'post', `/settings/service-cities/${cityId}/versions/${versionId}/publish`, {}, { etag: geoTag(expected) });
  }
  activateCity(web: Web, cityId: string, expected: number): Promise<GeoResult> {
    return this.write(web, 'post', `/settings/service-cities/${cityId}/activate`, {}, { etag: geoTag(expected) });
  }
  cityDetail(web: Web, cityId: string): Promise<GeoResult> {
    return this.read(web, `/settings/service-cities/${cityId}`);
  }

  /** Create a draft city and publish its first immutable local revision, leaving the
   * city lifecycle DRAFT (no second ACTIVE city is possible in SINGLE_CITY v1). */
  async publishedDraftCity(web: Web, code: string): Promise<City> {
    const created = check(await this.createCity(web, code), 201);
    const id = idOf(created); const version = versionOf(created);
    const added = check(await this.addCityVersion(web, id, version), 201);
    const versionId = idOf(added);
    const published = check(await this.publishCityVersion(web, id, versionId, versionOf(added)), 200);
    expect(published.data).toMatchObject({ id });
    return { id, version: versionOf(published), versionId };
  }

  /** Create, publish and activate the single ACTIVE/primary city of the fixture. */
  async activeCity(web: Web, code: string): Promise<City> {
    const draft = await this.publishedDraftCity(web, code);
    const activated = check(await this.activateCity(web, draft.id, draft.version), 200);
    expect(activated.data).toMatchObject({ id: draft.id });
    const detail = check(await this.cityDetail(web, draft.id), 200);
    expect(detail.data).toMatchObject({ id: draft.id, lifecycle: 'ACTIVE' });
    return { id: draft.id, version: versionOf(detail), versionId: draft.versionId };
  }

  createDistrict(web: Web, cityId: string, cityVersion: number, code: string, name = 'Synthetic district'): Promise<GeoResult> {
    return this.write(web, 'post', `/settings/service-cities/${cityId}/administrative-districts`,
      { code, name }, { etag: geoTag(cityVersion) });
  }
  createArea(web: Web, cityId: string, cityVersion: number, code: string): Promise<GeoResult> {
    return this.write(web, 'post', `/settings/service-cities/${cityId}/service-areas`, { code }, { etag: geoTag(cityVersion) });
  }
  addAreaVersion(web: Web, cityId: string, areaId: string, areaVersion: number, name: string): Promise<GeoResult> {
    return this.write(web, 'post', `/settings/service-cities/${cityId}/service-areas/${areaId}/versions`,
      { name }, { etag: geoTag(areaVersion) });
  }
  async publishAreaVersion(web: Web, cityId: string, areaId: string, versionId: string, versionRow: number): Promise<GeoResult> {
    const area = `/settings/service-cities/${cityId}/service-areas/${areaId}`;
    const expectedAreaVersion = versionOf(check(await this.read(web, area), 200));
    return this.write(web, 'post', `${area}/versions/${versionId}/publish`, { expectedAreaVersion }, { etag: geoTag(versionRow) });
  }

  /** Replace a role's whole permission set through the accepted P02 role editor. */
  replaceRolePermissions(web: Web, roleId: string, permissions: readonly { readonly code: string; readonly scope: string }[]): Promise<GeoResult> {
    return this.read(web, `/roles/${roleId}`).then((detail) =>
      this.write(web, 'put', `/roles/${roleId}/permissions`, { permissions }, { etag: detail.etag }));
  }

  /* --------------------------- database evidence -------------------------- */

  /** `auth_version + profile_version`: the aggregate every membership write checks. */
  async staffVersion(staffId: string): Promise<number> {
    const result = await this.base.db.query<{ version: number }>(
      'SELECT auth_version + profile_version AS version FROM foundation.staff WHERE id=$1', [staffId]);
    const row = result.rows[0];
    if (!row) { throw new Error('Missing staff row'); }
    return row.version;
  }
  /** The one live role assignment of a staff member (the bootstrap binding target). */
  async currentAssignment(staffId: string): Promise<string> {
    const result = await this.base.db.query<{ id: string }>(
      'SELECT id FROM foundation.staff_role_assignments WHERE staff_id=$1 AND revoked_at IS NULL', [staffId]);
    const row = result.rows[0];
    if (!row) { throw new Error('Missing live role assignment'); }
    return row.id;
  }
  /** Bootstrap exception rows as (permission_code, revoked) pairs, sorted. */
  async bootstrapRows(): Promise<{ assignmentId: string; code: string; revoked: boolean }[]> {
    const result = await this.base.db.query<{ assignment_id: string; permission_code: string; revoked_at: Date | null }>(
      'SELECT assignment_id, permission_code, revoked_at FROM foundation.geography_bootstrap_permissions ORDER BY permission_code');
    return result.rows.map((row) => ({ assignmentId: row.assignment_id, code: row.permission_code, revoked: row.revoked_at !== null }));
  }
  count(sql: string, params: readonly unknown[] = []): Promise<number> {
    return this.base.count(sql, [...params]);
  }
}
