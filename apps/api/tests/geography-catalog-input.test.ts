/**
 * Source-only contract tests for the P03-02 geography catalog inputs and the
 * typed command registry. No database is opened, no migration is applied and no
 * network call is made: the validators are pure functions and the registry is
 * asserted by shape only.
 *
 * The PostgreSQL guards (same-city FKs, draft/publish triggers, immutability) are
 * proven separately against an isolated database by the migration test suites;
 * duplicating them here with a fake driver would prove nothing about the real
 * constraint set.
 */
import { HttpException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_LIST_ROWS, MAX_COVERAGE_ENTRIES, MAX_LIST_ROWS,
  areaCreateInput, areaVersionInput, areaVersionPatchInput, cityActivateInput, cityCreateInput, cityDeactivateInput,
  cityVersionInput, coverageInput, districtCreateInput, districtUpdateInput, emptyBody, expectedVersion, listQuery,
  noExpected, routeId,
} from '../src/settings/geography/catalog-input.js';
import { catalogCommands } from '../src/settings/geography/catalog-commands.js';

const uuid = (suffix: number): string => `00000000-0000-4000-8000-${String(suffix).padStart(12, '0')}`;

/** A seven-day schedule with a single Monday morning interval and closed weekends. */
const officeHours = (): unknown => [
  [[540, 1080]],
  [],
  [],
  [],
  [],
  [],
  [],
];

function statusOf(run: () => unknown): number {
  try {
    run();
  } catch (error) {
    if (error instanceof HttpException) {
      return error.getStatus();
    }
    throw error;
  }
  return 0;
}

describe('geography catalog input validation', () => {
  it('accepts a stable city code and refuses anything the schema would refuse', () => {
    expect(cityCreateInput({ code: 'synthetic-city' })).toEqual({ code: 'synthetic-city' });
    for (const code of ['Synthetic', 'UPPER', 'a', 'a'.repeat(33), 'ab_', 'ab--cd', '-ab', '']) {
      expect(statusOf(() => cityCreateInput({ code }))).toBe(400);
    }
    // Unknown fields are refused instead of silently ignored.
    expect(statusOf(() => cityCreateInput({ code: 'ab', lifecycle: 'ACTIVE' }))).toBe(400);
    expect(statusOf(() => cityCreateInput(null))).toBe(400);
    expect(statusOf(() => cityCreateInput([]))).toBe(400);
  });

  it('narrows a reviewed city version and keeps nullable fields nullable', () => {
    expect(cityVersionInput({
      displayName: 'Synthetic city', timezone: 'Etc/UTC', publicContact: 'office@example.test', officeHours: officeHours(),
    })).toEqual({
      displayName: 'Synthetic city', addressDisplay: null, timezone: 'Etc/UTC',
      publicContact: 'office@example.test', officeHours: [[[540, 1080]], [], [], [], [], [], []],
    });
    expect(cityVersionInput({ displayName: 'X', timezone: 'UTC', publicContact: 'Y', officeHours: officeHours(),
      addressDisplay: '  1 Test street  ' }).addressDisplay).toBe('1 Test street');
  });

  it('rejects raw offsets, abbreviations, padding and reserved timezone trees', () => {
    for (const timezone of ['+03:00', 'UTC+3', 'MSK', 'EST5EDT', ' posix/UTC', 'posix/UTC', 'right/UTC',
      'SystemV/EST5', 'Europe/', '/Berlin', 'UTC\n', '']) {
      expect(statusOf(() => cityVersionInput({
        displayName: 'X', timezone, publicContact: 'Y', officeHours: officeHours(),
      }))).toBe(400);
    }
    // Shape only: catalog membership is migration 010's rule, checked in the DB.
    expect(cityVersionInput({ displayName: 'X', timezone: 'Etc/GMT-3', publicContact: 'Y',
      officeHours: officeHours() }).timezone).toBe('Etc/GMT-3');
  });

  it('enforces the seven-day office-hours format, ordering and bounds', () => {
    const build = (days: unknown): unknown => cityVersionInput({
      displayName: 'X', timezone: 'UTC', publicContact: 'Y', officeHours: days,
    });
    expect(statusOf(() => build([[], [], [], [], [], [], []]))).toBe(0);
    expect(statusOf(() => build([[[0, 1440]], [], [], [], [], [], []]))).toBe(0);
    // Touching intervals are allowed, overlaps and unsorted input are not.
    expect(statusOf(() => build([[[0, 60], [60, 120]], [], [], [], [], [], []]))).toBe(0);
    expect(statusOf(() => build([[[0, 120], [60, 180]], [], [], [], [], [], []]))).toBe(400);
    expect(statusOf(() => build([[[120, 180], [0, 60]], [], [], [], [], [], []]))).toBe(400);
    expect(statusOf(() => build([[[60, 60]], [], [], [], [], [], []]))).toBe(400);
    expect(statusOf(() => build([[[0, 1441]], [], [], [], [], [], []]))).toBe(400);
    expect(statusOf(() => build([[[-1, 60]], [], [], [], [], [], []]))).toBe(400);
    expect(statusOf(() => build([[[0.5, 60]], [], [], [], [], [], []]))).toBe(400);
    expect(statusOf(() => build([[[0, 60]]]))).toBe(400);
    expect(statusOf(() => build(Array.from({ length: 8 }, () => [])))).toBe(400);
    expect(statusOf(() => build(Array.from({ length: 7 }, () => [[0, 60], [120, 180], [240, 300],
      [360, 420], [480, 540], [600, 660], [720, 780], [840, 900], [960, 1020], [1080, 1140],
      [1200, 1260], [1320, 1380], [1400, 1440]])))).toBe(400);
    expect(statusOf(() => build('closed'))).toBe(400);
  });

  it('requires an explicit replacement pair for activation and a boolean for suspension', () => {
    expect(cityActivateInput(undefined)).toEqual({ replaceActiveCityId: null, replaceActiveCityVersion: null });
    expect(cityActivateInput({})).toEqual({ replaceActiveCityId: null, replaceActiveCityVersion: null });
    expect(cityActivateInput({ replaceActiveCityId: uuid(1), replaceActiveCityVersion: 3 }))
      .toEqual({ replaceActiveCityId: uuid(1), replaceActiveCityVersion: 3 });
    // Half a replacement is ambiguous: no silent deactivation of the other city.
    expect(statusOf(() => cityActivateInput({ replaceActiveCityId: uuid(1) }))).toBe(400);
    expect(statusOf(() => cityActivateInput({ replaceActiveCityVersion: 3 }))).toBe(400);
    expect(statusOf(() => cityActivateInput({ replaceActiveCityId: 'city', replaceActiveCityVersion: 3 }))).toBe(400);
    expect(statusOf(() => cityActivateInput({ replaceActiveCityId: uuid(1), replaceActiveCityVersion: 0 }))).toBe(400);
    expect(statusOf(() => cityActivateInput({ replaceActiveCityId: uuid(1), replaceActiveCityVersion: 3, extra: 1 }))).toBe(400);

    expect(cityDeactivateInput(undefined)).toEqual({ suspendIntake: false });
    expect(cityDeactivateInput({ suspendIntake: true })).toEqual({ suspendIntake: true });
    expect(statusOf(() => cityDeactivateInput({ suspendIntake: 'yes' }))).toBe(400);
    expect(statusOf(() => cityDeactivateInput({ active: false }))).toBe(400);
  });

  it('validates district and area bodies and trims reviewed text', () => {
    expect(districtCreateInput({ code: 'north', name: ' North district ' })).toEqual({ code: 'north', name: 'North district' });
    expect(statusOf(() => districtCreateInput({ code: 'north' }))).toBe(400);
    expect(statusOf(() => districtCreateInput({ code: 'north', name: '   ' }))).toBe(400);
    expect(statusOf(() => districtCreateInput({ code: 'north', name: 'X', cityId: uuid(1) }))).toBe(400);
    expect(districtUpdateInput({ name: 'Renamed' })).toEqual({ name: 'Renamed' });

    expect(areaCreateInput({ code: 'north-zone' })).toEqual({ code: 'north-zone' });
    expect(areaVersionInput({ name: 'North zone' }))
      .toEqual({ name: 'North zone', coverageDescription: null, addressCriteria: null });
    expect(statusOf(() => areaVersionInput({ name: '' }))).toBe(400);

    expect(areaVersionPatchInput({ name: 'Renamed' })).toEqual({ name: 'Renamed' });
    expect(areaVersionPatchInput({ coverageDescription: null })).toEqual({ coverageDescription: null });
    // An empty patch is not a write and must not advance a revision token.
    expect(statusOf(() => areaVersionPatchInput({}))).toBe(400);
    expect(statusOf(() => areaVersionPatchInput({ unknown: 1 }))).toBe(400);
  });

  it('replaces coverage as a full typed set and refuses duplicates and unknown relations', () => {
    expect(coverageInput({ districts: [] })).toEqual([]);
    expect(coverageInput({ districts: [
      { districtId: uuid(1), relation: 'FULL' },
      { districtId: uuid(2), relation: 'PARTIAL', description: 'Advisory only' },
    ] })).toEqual([
      { districtId: uuid(1), relation: 'FULL', description: null },
      { districtId: uuid(2), relation: 'PARTIAL', description: 'Advisory only' },
    ]);
    expect(statusOf(() => coverageInput({}))).toBe(400);
    expect(statusOf(() => coverageInput({ districts: [{ districtId: uuid(1), relation: 'FULL' },
      { districtId: uuid(1), relation: 'PARTIAL' }] }))).toBe(400);
    expect(statusOf(() => coverageInput({ districts: [{ districtId: uuid(1), relation: 'FULL', relation2: 'x' }] }))).toBe(400);
    expect(statusOf(() => coverageInput({ districts: [{ districtId: 'district', relation: 'FULL' }] }))).toBe(400);
    expect(statusOf(() => coverageInput({ districts: [{ districtId: uuid(1), relation: 'PART' }] }))).toBe(400);
    expect(statusOf(() => coverageInput({ districts: [{ districtId: uuid(1), relation: 'FULL' }],
      cityId: uuid(9) }))).toBe(400);
    expect(statusOf(() => coverageInput({ districts: Array.from({ length: MAX_COVERAGE_ENTRIES + 1 },
      (_unused, index) => ({ districtId: uuid(index + 1), relation: 'FULL' })) }))).toBe(400);
  });

  it('bounds list reads instead of returning unbounded tables', () => {
    expect(listQuery(undefined)).toEqual({ limit: DEFAULT_LIST_ROWS, includeArchived: true });
    expect(listQuery({})).toEqual({ limit: DEFAULT_LIST_ROWS, includeArchived: true });
    expect(listQuery({ limit: 1, includeArchived: false })).toEqual({ limit: 1, includeArchived: false });
    expect(listQuery({ limit: MAX_LIST_ROWS })).toEqual({ limit: MAX_LIST_ROWS, includeArchived: true });
    for (const limit of [0, -1, 1.5, MAX_LIST_ROWS + 1, '10', null]) {
      expect(statusOf(() => listQuery({ limit }))).toBe(400);
    }
    expect(statusOf(() => listQuery({ includeArchived: 'no' }))).toBe(400);
    expect(statusOf(() => listQuery({ offset: 10 }))).toBe(400);
  });

  it('requires If-Match for mutations and refuses one on creation', () => {
    expect(expectedVersion(1)).toBe(1);
    expect(expectedVersion(7)).toBe(7);
    // 428, not 400: the runner turns a missing precondition into Precondition Required.
    expect(statusOf(() => expectedVersion(null))).toBe(428);
    for (const value of [0, -1, 1.5, Number.NaN]) {
      expect(statusOf(() => expectedVersion(value))).toBe(400);
    }
    expect(statusOf(() => { noExpected(null); })).toBe(0);
    expect(statusOf(() => { noExpected(1); })).toBe(400);
    expect(statusOf(() => { emptyBody(undefined); })).toBe(0);
    expect(statusOf(() => { emptyBody({}); })).toBe(0);
    expect(statusOf(() => { emptyBody({ version: 2 }); })).toBe(400);
  });

  it('canonicalises path identifiers and refuses anything else', () => {
    expect(routeId('00000000-0000-4000-8000-00000000000A')).toBe('00000000-0000-4000-8000-00000000000a');
    for (const value of ['', 'city', `${uuid(1)}x`, 42, null, undefined]) {
      expect(statusOf(() => routeId(value))).toBe(400);
    }
  });
});

describe('geography catalog command registry', () => {
  const required = [
    'cityList', 'cityGet', 'cityCreate', 'cityVersions', 'cityAddVersion', 'cityPublish',
    'cityActivate', 'cityDeactivate', 'citySetPrimary',
    'districtList', 'districtGet', 'districtCreate', 'districtUpdate', 'districtArchive',
    'areaList', 'areaGet', 'areaCreate', 'areaArchive', 'areaVersions', 'areaVersionGet',
    'areaAddVersion', 'areaEditDraft', 'areaPublish', 'areaCoverageGet', 'areaCoverage',
  ] as const;
  const entries = Object.entries(catalogCommands);
  const actions = ['geography.read', 'geography.manage', 'geography.publish',
    'staff.geography.read', 'staff.geography.manage', 'geography.admin.assign', 'geography.self.read'];
  const scopes = ['global', 'city', 'list', 'self'];

  it('exposes every nested route of the approved geography contract', () => {
    for (const key of required) {
      expect(Object.hasOwn(catalogCommands, key), key).toBe(true);
    }
    expect(entries.length).toBe(required.length);
  });

  it('declares a capability, a write flag, a scope and both hooks for every command', () => {
    for (const [key, spec] of entries) {
      expect(actions, key).toContain(spec.action);
      expect(typeof spec.write, key).toBe('boolean');
      expect(scopes, key).toContain(spec.scoped);
      expect(typeof spec.check, key).toBe('function');
      expect(typeof spec.run, key).toBe('function');
    }
  });

  it('maps reads, manager writes and admin-only operations to distinct capabilities', () => {
    const write = (key: keyof typeof catalogCommands): boolean => catalogCommands[key].write;
    for (const key of ['cityList', 'cityGet', 'cityVersions', 'districtList', 'districtGet', 'areaList', 'areaGet',
      'areaVersions', 'areaVersionGet', 'areaCoverageGet'] as const) {
      expect(catalogCommands[key].action, key).toBe('geography.read');
      expect(write(key), key).toBe(false);
    }
    for (const key of ['districtCreate', 'districtUpdate', 'districtArchive', 'areaCreate', 'areaArchive',
      'areaAddVersion', 'areaEditDraft', 'areaCoverage'] as const) {
      expect(catalogCommands[key].action, key).toBe('geography.manage');
      expect(write(key), key).toBe(true);
    }
    for (const key of ['cityCreate', 'cityAddVersion'] as const) {
      expect(catalogCommands[key].action, key).toBe('geography.manage');
      expect(write(key), key).toBe(true);
    }
    for (const key of ['cityPublish', 'cityActivate', 'cityDeactivate', 'citySetPrimary', 'areaPublish'] as const) {
      expect(catalogCommands[key].action, key).toBe('geography.publish');
      expect(write(key), key).toBe(true);
    }
    // City creation, activation, deactivation and primary changes are GLOBAL;
    // every nested city resource is CITY scoped.
    for (const key of ['cityCreate', 'cityActivate', 'cityDeactivate', 'citySetPrimary'] as const) {
      expect(catalogCommands[key].scoped, key).toBe('global');
    }
    expect(catalogCommands.cityList.scoped).toBe('list');
    for (const key of ['cityGet', 'cityVersions', 'cityAddVersion', 'cityPublish', 'districtList', 'districtCreate',
      'areaList', 'areaCreate', 'areaVersions', 'areaAddVersion', 'areaEditDraft', 'areaPublish', 'areaCoverage',
      'areaCoverageGet'] as const) {
      expect(catalogCommands[key].scoped, key).toBe('city');
    }
  });

  it('validates the body before touching the transaction on every write', async () => {
    // A write with a malformed body must fail as a client error without a query:
    // the fake client records every statement so an accidental DB touch is visible.
    const statements: string[] = [];
    const client = { query: (sql: string) => { statements.push(sql); return Promise.reject(new Error('unexpected query')); } };
    const ctx = {
      staffId: uuid(99),
      role: { id: uuid(98), code: 'ADMIN', type: 'SYSTEM' },
      permissions: [],
      cityIds: null,
      principal: { kind: 'staff-web', staffId: uuid(99), role: 'ADMIN', authVersion: 0 },
      client,
    } as unknown as Parameters<typeof catalogCommands.cityCreate.run>[0];
    const failure = await catalogCommands.cityCreate.run(ctx, {}, { code: 'UPPER' }, null)
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(HttpException);
    expect((failure as HttpException).getStatus()).toBe(400);
    expect(statements).toEqual([]);
  });
});

/**
 * Scripted transaction double for the withdrawal guards. It answers only the exact
 * statements those commands issue and records them, so the test proves the decision
 * logic (which authority is demanded, which conflict is raised) without a database.
 * The real constraint/trigger behaviour is proven by the PostgreSQL suites.
 */
type Reply = { rows: readonly Record<string, unknown>[]; rowCount: number };
function scripted(responses: readonly (readonly [RegExp, Reply])[]) {
  const statements: string[] = [];
  const query = (sql: string): Promise<Reply> => {
    statements.push(sql);
    for (const [pattern, reply] of responses) {
      if (pattern.test(sql)) {
        return Promise.resolve(reply);
      }
    }
    return Promise.reject(new Error(`unexpected statement: ${sql}`));
  };
  return { query, statements };
}

const areaTarget = { cityId: uuid(1), areaId: uuid(2) };
const versionTarget = { cityId: uuid(1), areaId: uuid(2), versionId: uuid(3) };

function geoContext(
  client: { query: (sql: string) => Promise<Reply> },
  role: { code: string; type: 'SYSTEM' | 'CUSTOM' },
  geoPermissions: readonly { code: string; scope: 'GLOBAL' | 'CITY' }[],
  marker: 'ADMIN' | 'MANAGER' = 'ADMIN',
): Parameters<typeof catalogCommands.areaArchive.run>[0] {
  return {
    staffId: uuid(99),
    role: { id: uuid(98), ...role },
    permissions: [],
    geoPermissions,
    cityIds: [uuid(1)],
    principal: { kind: 'staff-web', staffId: uuid(99), role: marker, authVersion: 0 },
    client,
  } as unknown as Parameters<typeof catalogCommands.areaArchive.run>[0];
}

describe('geography catalog withdrawal guards', () => {
  const servedArea = {
    rows: [{ id: uuid(2), city_id: uuid(1), code: 'north-zone', current_version_id: uuid(3), archived_at: null, row_version: 4 }],
    rowCount: 1,
  };

  it('refuses a manager archiving a zone that still serves a published revision', async () => {
    const client = scripted([[/FROM foundation\.service_areas WHERE id=\$1 AND city_id=\$2 FOR UPDATE/, servedArea]]);
    const ctx = geoContext(client, { code: 'MANAGER', type: 'SYSTEM' }, [{ code: 'geography.manage', scope: 'CITY' }], 'MANAGER');
    const failure = await catalogCommands.areaArchive.run(ctx, areaTarget, undefined, 4).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(HttpException);
    expect((failure as HttpException).getStatus()).toBe(403);
    // No write was attempted: the withdrawal was refused before touching the row.
    expect(client.statements.every((sql) => !sql.startsWith('UPDATE'))).toBe(true);
  });

  it('refuses the withdrawal even for an administrator without an effective publish grant', async () => {
    const client = scripted([[/FROM foundation\.service_areas WHERE id=\$1 AND city_id=\$2 FOR UPDATE/, servedArea]]);
    const ctx = geoContext(client, { code: 'ADMIN', type: 'SYSTEM' }, [{ code: 'geography.manage', scope: 'GLOBAL' }]);
    const failure = await catalogCommands.areaArchive.run(ctx, areaTarget, undefined, 4).catch((error: unknown) => error);
    expect((failure as HttpException).getStatus()).toBe(403);
  });

  it('checks the city of the secondary publish grant even when manage is GLOBAL', async () => {
    const client = scripted([
      [/FROM foundation\.service_areas WHERE id=\$1 AND city_id=\$2 FOR UPDATE/, servedArea],
      [/FROM foundation\.staff_admin_city_assignments/, { rows: [], rowCount: 0 }],
    ]);
    const ctx = { ...geoContext(client, {code:'ADMIN',type:'SYSTEM'}, [
      {code:'geography.manage',scope:'GLOBAL'}, {code:'geography.publish',scope:'CITY'},
    ]), cityIds:null };
    await expect(catalogCommands.areaArchive.run(ctx,areaTarget,{},4)).rejects.toMatchObject({status:404});
    expect(client.statements.some(sql => sql.startsWith('UPDATE'))).toBe(false);
  });

  it('refuses the withdrawal while a live technician admission names the zone', async () => {
    const client = scripted([
      [/FROM foundation\.service_areas WHERE id=\$1 AND city_id=\$2 FOR UPDATE/, servedArea],
      [/FROM foundation\.technician_service_areas/, { rows: [{ '?column?': 1 }], rowCount: 1 }],
    ]);
    const ctx = geoContext(client, { code: 'ADMIN', type: 'SYSTEM' }, [{ code: 'geography.publish', scope: 'GLOBAL' }]);
    const failure = await catalogCommands.areaArchive.run(ctx, areaTarget, undefined, 4).catch((error: unknown) => error);
    expect((failure as HttpException).getStatus()).toBe(409);
  });

  it('archives a served zone only for an administrator with publish authority and no live admission', async () => {
    const client = scripted([
      [/FROM foundation\.service_areas WHERE id=\$1 AND city_id=\$2 FOR UPDATE/, servedArea],
      [/FROM foundation\.technician_service_areas/, { rows: [], rowCount: 0 }],
      [/UPDATE foundation\.service_areas SET archived_at/, { rows: [{ row_version: 5 }], rowCount: 1 }],
    ]);
    const ctx = geoContext(client, { code: 'ADMIN', type: 'SYSTEM' }, [{ code: 'geography.publish', scope: 'CITY' }]);
    await expect(catalogCommands.areaArchive.run(ctx, areaTarget, undefined, 4))
      .resolves.toEqual({ id: uuid(2), version: 5 });
  });

  it('refuses a district archive while the served coverage still maps it', async () => {
    const client = scripted([
      [/FROM foundation\.administrative_districts WHERE id=\$1 AND city_id=\$2 FOR UPDATE/,
        { rows: [{ id: uuid(4), city_id: uuid(1), code: 'north', name: 'North', archived_at: null, row_version: 2 }], rowCount: 1 }],
      [/FROM foundation\.service_area_district_coverage AS coverage/, { rows: [{ '?column?': 1 }], rowCount: 1 }],
    ]);
    const ctx = geoContext(client, { code: 'ADMIN', type: 'SYSTEM' }, [{ code: 'geography.manage', scope: 'GLOBAL' }]);
    const failure = await catalogCommands.districtArchive.run(ctx, { cityId: uuid(1), districtId: uuid(4) }, undefined, 2)
      .catch((error: unknown) => error);
    expect((failure as HttpException).getStatus()).toBe(409);
  });

  it('refuses publishing a draft whose mapping now names an archived district', async () => {
    const client = scripted([
      [/FROM foundation\.service_area_versions\s+WHERE id=\$1 AND city_id=\$2 AND area_id=\$3 FOR UPDATE/,
        { rows: [{ id: uuid(3), city_id: uuid(1), area_id: uuid(2), version: 1, name: 'Draft', coverage_description: null,
          address_criteria: null, published_at: null, row_version: 2 }], rowCount: 1 }],
      [/FROM foundation\.service_areas WHERE id=\$1 AND city_id=\$2 FOR UPDATE/,
        { rows: [{ id: uuid(2), city_id: uuid(1), code: 'north-zone', current_version_id: null, archived_at: null, row_version: 3 }], rowCount: 1 }],
      [/JOIN foundation\.administrative_districts AS district/, { rows: [{ '?column?': 1 }], rowCount: 1 }],
    ]);
    const ctx = geoContext(client, { code: 'ADMIN', type: 'SYSTEM' }, [{ code: 'geography.publish', scope: 'GLOBAL' }]);
    const failure = await catalogCommands.areaPublish.run(ctx, versionTarget, { expectedAreaVersion: 3 }, 2).catch((error: unknown) => error);
    expect((failure as HttpException).getStatus()).toBe(409);
    expect(client.statements.some((sql) => sql.includes('SET published_at'))).toBe(false);
  });
});
