import 'reflect-metadata';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { BadRequestException, ForbiddenException, HttpException, NotFoundException } from '@nestjs/common';
import { Client, Pool } from 'pg';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GEO_CAPABILITIES } from '../src/authz/capability.js';
import type { GeoGrant } from '../src/authz/capability.js';
import { AuthorizationError, AuthorizationService } from '../src/authz/authorization.service.js';
import type { EffectiveRole, SessionProof } from '../src/authz/authorization.service.js';
import type { GeoAction, GeoContext, GeoReceipt, GeoTarget } from '../src/settings/geography/geo-contract.js';
import {
  TECHNICIAN_LOCK_NAMESPACE, membershipCommands, parseGeoInstant, parseGrantInterval,
} from '../src/settings/geography/membership-commands.js';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { DUMMY_PASSWORD_HASH } from '../src/staff/password.js';
import { migrateAuthFixture } from './auth-db-fixture.js';

const CITY = '11111111-1111-4111-8111-111111111111';
const OTHER_CITY = '22222222-2222-4222-8222-222222222222';
const STAFF = '33333333-3333-4333-8333-333333333333';
const TARGET = '44444444-4444-4444-8444-444444444444';
const AREA = '55555555-5555-4555-8555-555555555555';
const GRANT = '66666666-6666-4666-8666-666666666666';

const role = (type: EffectiveRole['type'], code: string): EffectiveRole => ({ type, code, id: '77777777-7777-4777-8777-777777777777' });

/** A context whose client fails on any query: authority denials must be decided from
 * the trusted session values before the command touches the database. */
function context(overrides: Partial<Omit<GeoContext, 'geoPermissions'>> & { geoPermissions?: readonly GeoGrant[] } = {}): GeoContext {
  const client = {
    query: () => Promise.reject(new Error('The command must not read the database on this path')),
  } as unknown as PoolClient;
  const staffId = overrides.staffId ?? STAFF;
  const base: GeoContext = {
    staffId,
    role: role('SYSTEM', 'MANAGER'),
    permissions: [],
    geoPermissions: [],
    client,
    principal: { kind: 'staff-web', staffId, role: 'MANAGER', authVersion: 0 },
    cityIds: [CITY],
  };
  const { geoPermissions, ...rest } = overrides;
  return { ...base, ...rest, ...(geoPermissions === undefined ? {} : { geoPermissions }) };
}

const adminContext = (geoPermissions: readonly GeoGrant[] = [{ code: 'geography.manage', scope: 'GLOBAL' }]): GeoContext =>
  context({
    role: role('SYSTEM', 'ADMIN'),
    permissions: ['staff.role.assign'],
    geoPermissions,
    principal: { kind: 'staff-web', staffId: STAFF, role: 'ADMIN', authVersion: 0 },
    cityIds: null,
  });

const telegramContext = (permissions: GeoContext['permissions'] = ['staff.self.read']): GeoContext =>
  context({
    role: role('SYSTEM', 'TECHNICIAN'),
    permissions,
    principal: { kind: 'staff-telegram', staffId: STAFF, role: 'TECHNICIAN', authVersion: 0, telegramUserId: '1' },
    cityIds: [],
  });

describe('geography membership command registry', () => {
  it('exposes exactly the eleven named operations the transport routes use', () => {
    expect(Object.keys(membershipCommands).sort()).toEqual([
      'adminAssign', 'adminList', 'adminRevoke',
      'techCities', 'techGrantCity', 'techGrantZone', 'techPicker', 'techRevokeCity', 'techRevokeZone', 'techSelf', 'techZones',
    ]);
  });

  it('declares a trusted action, a write flag and a scope for every command', () => {
    const expected: Record<keyof typeof membershipCommands, { action: GeoAction; write: boolean; scoped: string }> = {
      adminList: { action: 'geography.admin.assign', write: false, scoped: 'list' },
      adminAssign: { action: 'geography.admin.assign', write: true, scoped: 'city' },
      adminRevoke: { action: 'geography.admin.assign', write: true, scoped: 'city' },
      techCities: { action: 'staff.geography.read', write: false, scoped: 'city' },
      techGrantCity: { action: 'staff.geography.manage', write: true, scoped: 'city' },
      techRevokeCity: { action: 'staff.geography.manage', write: true, scoped: 'city' },
      techZones: { action: 'staff.geography.read', write: false, scoped: 'city' },
      techPicker: { action: 'staff.geography.read', write: false, scoped: 'city' },
      techGrantZone: { action: 'staff.geography.manage', write: true, scoped: 'city' },
      techRevokeZone: { action: 'staff.geography.manage', write: true, scoped: 'city' },
      techSelf: { action: 'geography.self.read', write: false, scoped: 'self' },
    };
    for (const [name, command] of Object.entries(membershipCommands)) {
      expect(command.action).toBe(expected[name as keyof typeof membershipCommands].action);
      expect(command.write).toBe(expected[name as keyof typeof membershipCommands].write);
      expect(command.scoped).toBe(expected[name as keyof typeof membershipCommands].scoped);
    }
    // Every action is part of the shared contract; a typo cannot become a new authority.
    for (const command of Object.values(membershipCommands)) {
      expect(['geography.admin.assign', 'staff.geography.read', 'staff.geography.manage', 'geography.self.read'])
        .toContain(command.action);
    }
    expect(GEO_CAPABILITIES).toEqual(expect.arrayContaining(['staff.geography.read', 'staff.geography.manage']));
  });

  it('keeps the per-technician lock namespace identical to the database writer contract', () => {
    // Migration 012 and P09 dispatch take the same key: changing this text silently
    // splits the serialization between membership changes and visit assignment.
    expect(TECHNICIAN_LOCK_NAMESPACE).toBe('fixlevelup:technician');
  });
});

describe('administrative territory authority', () => {
  it('refuses a manager even with a city-scoped geography.manage grant', async () => {
    const manager = context({ geoPermissions: [{ code: 'geography.manage', scope: 'CITY' }], permissions: ['staff.role.assign'] });
    for (const command of [membershipCommands.adminList, membershipCommands.adminAssign, membershipCommands.adminRevoke]) {
      await expect(command.check(manager, { cityId: CITY, staffId: TARGET })).rejects.toBeInstanceOf(ForbiddenException);
    }
  });

  it('refuses an administrator without the GLOBAL geography.manage grant or staff.role.assign', async () => {
    const noManage = adminContext([]);
    await expect(membershipCommands.adminAssign.check(noManage, { cityId: CITY, staffId: TARGET }))
      .rejects.toBeInstanceOf(ForbiddenException);
    const cityManage = adminContext([{ code: 'geography.manage', scope: 'CITY' }]);
    await expect(membershipCommands.adminList.check(cityManage, { staffId: TARGET }))
      .rejects.toBeInstanceOf(ForbiddenException);
    const noRoleAssign = context({
      role: role('SYSTEM', 'ADMIN'), permissions: [], geoPermissions: [{ code: 'geography.manage', scope: 'GLOBAL' }], cityIds: null,
    });
    await expect(membershipCommands.adminList.check(noRoleAssign, { staffId: TARGET }))
      .rejects.toBeInstanceOf(ForbiddenException);
  });

  it('forbids changing the actor’s own administrative territory before any database read', async () => {
    for (const command of [membershipCommands.adminAssign, membershipCommands.adminRevoke]) {
      await expect(command.check(adminContext(), { cityId: CITY, staffId: STAFF, grantId: GRANT }))
        .rejects.toBeInstanceOf(ForbiddenException);
    }
  });
});

describe('technician territory authority', () => {
  it('requires the explicit geography grant, not the staff dictionary entry', async () => {
    const manager = context({ permissions: ['staff.read'] });
    await expect(membershipCommands.techCities.check(manager, { cityId: CITY, staffId: TARGET }))
      .rejects.toBeInstanceOf(ForbiddenException);
    await expect(membershipCommands.techGrantCity.check(manager, { cityId: CITY, staffId: TARGET }))
      .rejects.toBeInstanceOf(ForbiddenException);
  });

  it('never lets a city outside the trusted assignment resolve, whatever the request says', async () => {
    const manager = context({ geoPermissions: [{ code: 'staff.geography.read', scope: 'CITY' }], permissions: ['staff.read'] });
    await expect(membershipCommands.techCities.check(manager, { cityId: OTHER_CITY, staffId: TARGET }))
      .rejects.toBeInstanceOf(NotFoundException);
    await expect(membershipCommands.techZones.check(manager, { cityId: OTHER_CITY, staffId: TARGET }))
      .rejects.toBeInstanceOf(NotFoundException);
  });

  it('requires a path city and a staff id before any database read', async () => {
    const manager = context({ geoPermissions: [{ code: 'staff.geography.manage', scope: 'CITY' }], permissions: ['staff.read'] });
    await expect(membershipCommands.techGrantCity.check(manager, { staffId: TARGET }))
      .rejects.toBeInstanceOf(BadRequestException);
    await expect(membershipCommands.techGrantCity.check(manager, { cityId: CITY }))
      .rejects.toBeInstanceOf(BadRequestException);
  });

  it('never lets a technician write, and never lets a CRM session read the SELF summary', async () => {
    const technician = telegramContext();
    for (const command of [membershipCommands.techGrantCity, membershipCommands.techGrantZone,
      membershipCommands.techRevokeCity, membershipCommands.techRevokeZone, membershipCommands.adminAssign]) {
      await expect(command.check(technician, { cityId: CITY, staffId: TARGET, areaId: AREA, grantId: GRANT }))
        .rejects.toBeInstanceOf(ForbiddenException);
    }
    await expect(membershipCommands.techSelf.check(context(), {})).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('binds the SELF summary to the verified Telegram subject and the staff-self grant', async () => {
    await expect(membershipCommands.techSelf.check(telegramContext([]), {}))
      .rejects.toBeInstanceOf(ForbiddenException);
    // A staff id in the target is not accepted: the subject always comes from the session.
    await expect(membershipCommands.techSelf.check(telegramContext(), { staffId: TARGET }))
      .rejects.toBeInstanceOf(BadRequestException);
  });
});

describe('explicit-zone UTC instant parsing', () => {
  it('accepts Z and numeric offsets and converts them to the same instant', () => {
    const utc = parseGeoInstant('2026-11-21T06:00:00Z');
    expect(utc.toISOString()).toBe('2026-11-21T06:00:00.000Z');
    expect(parseGeoInstant('2026-11-21T09:00:00+03:00').toISOString()).toBe(utc.toISOString());
    expect(parseGeoInstant('2026-11-21T01:00:00-05:00').toISOString()).toBe(utc.toISOString());
    expect(parseGeoInstant('2026-11-21T20:30:00+14:00').toISOString()).toBe('2026-11-21T06:30:00.000Z');
    expect(parseGeoInstant('2026-11-20T20:00:00-10:00').toISOString()).toBe('2026-11-21T06:00:00.000Z');
  });

  it('keeps millisecond precision and refuses silently truncated sub-millisecond input', () => {
    expect(parseGeoInstant('2026-11-21T06:00:00.123Z').toISOString()).toBe('2026-11-21T06:00:00.123Z');
    expect(parseGeoInstant('2026-11-21T06:00:00.1Z').toISOString()).toBe('2026-11-21T06:00:00.100Z');
    expect(parseGeoInstant('2026-11-21T06:00:00.123000Z').toISOString()).toBe('2026-11-21T06:00:00.123Z');
    expect(() => parseGeoInstant('2026-11-21T06:00:00.123456Z')).toThrow(BadRequestException);
  });

  it('refuses a zone-less local time and any impossible calendar value', () => {
    for (const value of [
      '2026-11-21T06:00:00',            // no zone: a server/browser default would be used
      '2026-11-21',                     // date only
      '2026-11-21T06:00Z',              // missing seconds
      '2026-02-30T00:00:00Z',           // February 30
      '2026-02-29T00:00:00Z',           // 2026 is not a leap year
      '2026-04-31T00:00:00Z',           // April 31
      '2026-13-01T00:00:00Z',           // month 13
      '2026-00-10T00:00:00Z',           // month 0
      '2026-01-00T00:00:00Z',           // day 0
      '2026-01-01T24:00:00Z',           // 24:00 rollover
      '2026-01-01T00:60:00Z',           // minute 60
      '2026-01-01T00:00:60Z',           // second 60 (leap second not modelled)
      '2026-01-01T00:00:00+14:01',      // offset beyond the real range
      '2026-01-01T00:00:00+15:00',
      ' 2026-01-01T00:00:00Z',          // padding
      '2026-01-01T00:00:00Z ',
      '2026-1-1T00:00:00Z',             // not zero padded
      '0000-01-01T00:00:00Z',           // out of the supported range
      '', null, 42, {},
    ] as readonly unknown[]) {
      expect(() => parseGeoInstant(value)).toThrow(BadRequestException);
    }
    // A real leap day is accepted.
    expect(parseGeoInstant('2024-02-29T00:00:00Z').toISOString()).toBe('2024-02-29T00:00:00.000Z');
  });

  it('interprets the explicit offset, not the process timezone', () => {
    // The same wall-clock text in two real zones denotes two different instants; only
    // the explicit offset decides, so a Moscow/UTC host cannot change the stored value.
    expect(parseGeoInstant('2026-11-21T09:00:00+03:00').getTime())
      .toBe(parseGeoInstant('2026-11-21T09:00:00Z').getTime() - 3 * 60 * 60 * 1000);
    expect(parseGeoInstant('2026-11-21T09:00:00+03:00').getTime())
      .toBe(Date.UTC(2026, 10, 21, 6, 0, 0));
  });
});

describe('grant interval parsing', () => {
  it('accepts a closed and an open interval, both half-open', () => {
    expect(parseGrantInterval({ validFrom: '2026-11-21T09:00:00+03:00', validTo: '2026-12-31T23:59:59+03:00' }))
      .toEqual({ validFrom: new Date('2026-11-21T06:00:00Z'), validTo: new Date('2026-12-31T20:59:59Z') });
    expect(parseGrantInterval({ validFrom: '2026-11-21T09:00:00Z' }).validTo).toBeNull();
    expect(parseGrantInterval({ validFrom: '2026-11-21T09:00:00Z', validTo: null }).validTo).toBeNull();
  });

  it('rejects an empty or inverted interval and a missing start', () => {
    expect(() => parseGrantInterval({ validFrom: '2026-11-21T09:00:00Z', validTo: '2026-11-21T09:00:00Z' }))
      .toThrow(BadRequestException);
    expect(() => parseGrantInterval({ validFrom: '2026-11-21T09:00:00Z', validTo: '2026-11-20T09:00:00Z' }))
      .toThrow(BadRequestException);
    expect(() => parseGrantInterval({})).toThrow(BadRequestException);
    expect(() => parseGrantInterval({ validFrom: 'not-a-date' })).toThrow(BadRequestException);
    // An offset makes two different wall-clock times comparable.
    expect(() => parseGrantInterval({ validFrom: '2026-11-21T12:00:00+03:00', validTo: '2026-11-21T08:59:59Z' }))
      .toThrow(BadRequestException);
  });
});

// Explicit opt-in only: creates a random isolated database and never touches the dev database.
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');
const connection = { host: '127.0.0.1' as const, port: 55432 };

/**
 * End-to-end command test through the real `withGeography` authorization and the real
 * PostgreSQL guards of migration 012, in an isolated database. Every write goes through
 * `fixlevelup_runtime`; fixtures are created by the migration owner, exactly as the
 * application would run. This proves the parts the unit tests cannot: the trusted city
 * scope, the staff aggregate ETag, the membership/zone containment, revocation history
 * and the per-technician lock/guard interaction.
 */
integration('membership commands against isolated PostgreSQL', () => {
  const pools: Pool[] = [];
  let migrator: Pool;
  let runtime: Pool;
  let auth: AuthorizationService;
  let adminId: string;
  let managerId: string;
  let technicianId: string;
  let adminProof: SessionProof;
  let managerProof: SessionProof;
  let techProof: SessionProof;
  let cityA: string;
  let cityB: string;
  let areaA: string;
  let areaDraftOnly: string;
  let areaArchived: string;
  let areaB: string;
  let managerAssignmentId = '';
  let cityMembershipId = '';
  let zoneGrantId = '';
  // This fixture is compared with PostgreSQL's *current* time, not with a fixed release date.
  const anchor = Date.now();
  const day = (offset: number) => new Date(anchor + offset * 86_400_000).toISOString();
  const liveCity = { validFrom: day(-30), validTo: day(30) };
  const liveZone = { validFrom: day(-10), validTo: day(10) };

  const TOKEN = () => randomBytes(32).toString('base64url');
  /** Wraps guarded GEO/CFG basis DML (migration 022) in one transaction that takes
   * the unified writer fence before its first statement, on one pinned client. */
  const fencedDml = async <T,>(run: (client: PoolClient) => Promise<T>): Promise<T> => {
    const client = await migrator.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(734305,1)');
      const result = await run(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  };
  const createCity = async (code: string, lifecycle: string, timezone = 'Europe/Moscow') => {
    const id = randomUUID();
    const versionId = randomUUID();
    await fencedDml(async (client) => {
      await client.query('INSERT INTO foundation.service_cities (id, code) VALUES ($1,$2)', [id, code]);
      await client.query(`INSERT INTO foundation.service_city_versions
        (id, city_id, version, display_name, timezone, public_contact, office_hours, reviewed_by)
        VALUES ($1,$2,1,'Synthetic city',$3,'office@example.test',$4::jsonb,$5)`,
      [versionId, id, timezone, JSON.stringify(Array.from({ length: 7 }, () => [])), adminId]);
      await client.query('UPDATE foundation.service_cities SET current_version_id=$2, lifecycle=$3 WHERE id=$1',
        [id, versionId, lifecycle]);
    });
    return id;
  };
  const createArea = async (cityId: string, code: string) => {
    const id = randomUUID();
    await fencedDml((client) => client.query('INSERT INTO foundation.service_areas (id, city_id, code) VALUES ($1,$2,$3)',
      [id, cityId, code]));
    return id;
  };
  const publishArea = async (cityId: string, areaId: string, name: string) => {
    const versionId = randomUUID();
    await fencedDml(async (client) => {
      await client.query(`INSERT INTO foundation.service_area_versions
        (id, city_id, area_id, version, name, created_by) VALUES ($1,$2,$3,1,$4,$5)`,
      [versionId, cityId, areaId, name, adminId]);
      await client.query('UPDATE foundation.service_area_versions SET published_at=statement_timestamp(), published_by=$2 WHERE id=$1',
        [versionId, adminId]);
      await client.query('UPDATE foundation.service_areas SET current_version_id=$2 WHERE id=$1', [areaId, versionId]);
    });
    return versionId;
  };
  /** The 009 deferred constraint requires a live role and a matching channel by commit,
   * so an employee is always created in one transaction with its assignment. */
  const createStaff = async (roleCode: 'MANAGER' | 'TECHNICIAN') => {
    const id = randomUUID();
    await migrator.query('BEGIN');
    try {
      await migrator.query("INSERT INTO foundation.staff (id, role, employment_state) VALUES ($1,$2,'ACTIVE')", [id, roleCode]);
      await migrator.query(`INSERT INTO foundation.staff_role_assignments (id, staff_id, role_id, assigned_by)
        SELECT $1,$2,r.id,$3 FROM foundation.roles r WHERE r.role_type='SYSTEM' AND r.code=$4 AND r.status='ACTIVE'`,
      [randomUUID(), id, adminId, roleCode]);
      await migrator.query(
        'INSERT INTO foundation.staff_web_credentials (staff_id, login, password_hash) VALUES ($1,$2,$3)',
        [id, `geo-${randomBytes(8).toString('hex')}`, DUMMY_PASSWORD_HASH]);
      await migrator.query('COMMIT');
    } catch (error) { await migrator.query('ROLLBACK'); throw error; }
    return id;
  };
  const session = async (staffId: string, kind: 'staff-web' | 'staff-telegram', telegramLinkId: string | null = null) => {
    const token = TOKEN();
    const channel = kind === 'staff-web' ? 'CRM' : 'STAFF_TELEGRAM';
    const authVersion = (await migrator.query<{ auth_version: number }>(
      'SELECT auth_version FROM foundation.staff WHERE id=$1', [staffId])).rows[0]?.auth_version;
    if (authVersion === undefined) { throw new Error('Missing staff'); }
    // The 007 channel-pair CHECK requires the Telegram digest/exchange pair to be
    // present exactly for the STAFF_TELEGRAM channel, so a synthetic row states both.
    await migrator.query(`INSERT INTO foundation.web_sessions
      (id, staff_id, token_hash, auth_version, channel, telegram_link_id, initdata_digest, initdata_exchanged_at,
       created_at, idle_expires_at, absolute_expires_at)
      VALUES ($1,$2,$3,$4,$5::varchar,$6,$7,
        CASE WHEN $5::varchar='STAFF_TELEGRAM' THEN statement_timestamp() END,
        statement_timestamp(), statement_timestamp()+interval '1 hour', statement_timestamp()+interval '2 hours')`,
    [randomUUID(), staffId, createHash('sha256').update(token).digest('hex'), authVersion, channel, telegramLinkId,
      kind === 'staff-web' ? null : createHash('sha256').update(randomBytes(16)).digest('hex')]);
    return { token, kind } as SessionProof;
  };
  const aggregate = async (staffId: string) => {
    const row = (await migrator.query<{ v: number }>(
      'SELECT auth_version+profile_version AS v FROM foundation.staff WHERE id=$1', [staffId])).rows[0];
    if (!row) { throw new Error('Missing staff'); }
    return row.v;
  };

  /** Mirrors the runner: authorize on one transaction, then `check` and `run`. */
  const exec = (proof: SessionProof, name: keyof typeof membershipCommands, target: GeoTarget,
    body?: unknown, expected?: number) => {
    const command = membershipCommands[name];
    return auth.withGeography(proof, command.write ? 'write' : 'read', command.action, target.cityId ?? null,
      async (ctx) => {
        await command.check(ctx, target);
        return command.run(ctx, target, body, command.write ? (expected ?? null) : null);
      });
  };

  const status = async (promise: Promise<unknown>): Promise<number | string> => {
    try { await promise; } catch (error) {
      if (error instanceof HttpException) { return error.getStatus(); }
      if (error instanceof AuthorizationError) { return error.code; }
      throw error;
    }
    throw new Error('Expected the command to be refused');
  };

  beforeAll(async () => {
    const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
    const toolingEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(toolingEnv)?.[1];
    const runtimePassword = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(toolingEnv)?.[1];
    if (!adminPassword || !migratorPassword || !runtimePassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const database = `fixlevelup_auth_e2e_test_${randomBytes(12).toString('hex')}`;
    const admin = new Client({ ...connection, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
    await admin.connect();
    try {
      await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
      await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
    } finally { await admin.end(); }
    const fixture = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
    await fixture.connect();
    try {
      await fixture.query('CREATE SCHEMA IF NOT EXISTS foundation AUTHORIZATION fixlevelup_migrator');
      await migrateAuthFixture(fixture, database);
    } finally { await fixture.end(); }
    migrator = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword, max: 2 });
    pools.push(migrator);
    runtime = new Pool({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword, max: 2 });
    pools.push(runtime);
    auth = new AuthorizationService(runtime);

    adminId = (await bootstrapFirstAdmin(migrator, { login: `geo-${randomBytes(12).toString('hex')}`,
      password: `Synthetic-Geo-${randomBytes(12).toString('hex')}!` })).staffId;
    managerId = await createStaff('MANAGER');
    // Delegated geography in assigned cities only: the manager needs both the read and
    // the manage code, and a manager can never hold GLOBAL geography.
    await migrator.query(`INSERT INTO foundation.role_permissions (role_id, permission_code, scope_type)
      SELECT r.id, g.code, 'CITY' FROM foundation.roles r
      CROSS JOIN unnest(ARRAY['staff.geography.read','staff.geography.manage']) AS g(code)
      WHERE r.role_type='SYSTEM' AND r.code='MANAGER'`);
    technicianId = await createStaff('TECHNICIAN');
    const linkId = randomUUID();
    await migrator.query('INSERT INTO foundation.staff_telegram_links (id, staff_id, telegram_user_id) VALUES ($1,$2,$3)',
      [linkId, technicianId, BigInt(`0x${randomBytes(5).toString('hex')}`) + 1n]);

    adminProof = await session(adminId, 'staff-web');
    managerProof = await session(managerId, 'staff-web');
    techProof = await session(technicianId, 'staff-telegram', linkId);

    cityA = await createCity('city-a', 'ACTIVE');
    cityB = await createCity('city-b', 'ACTIVE', 'Asia/Tokyo');
    areaA = await createArea(cityA, 'zone-a');
    await publishArea(cityA, areaA, 'Zone A');
    areaDraftOnly = await createArea(cityA, 'zone-draft');
    areaArchived = await createArea(cityA, 'zone-archived');
    await publishArea(cityA, areaArchived, 'Archived zone');
    await fencedDml((client) => client.query(
      'UPDATE foundation.service_areas SET archived_at=statement_timestamp() WHERE id=$1', [areaArchived]));
    areaB = await createArea(cityB, 'zone-b');
    await publishArea(cityB, areaB, 'Zone B');
  }, 60000);

  afterAll(async () => { await Promise.all(pools.map(pool => pool.end())); });

  it('administrator assigns a city and the receipt carries the subject aggregate version', async () => {
    const before = await exec(adminProof, 'adminList', { staffId: managerId });
    expect(before).toMatchObject({ items: [], version: 0 });
    expect(await aggregate(managerId)).toBe(0);

    const created = await exec(adminProof, 'adminAssign', { cityId: cityA, staffId: managerId }, {}, 0) as GeoReceipt;
    expect(created.version).toBe(1);
    managerAssignmentId = created.id;
    expect(await aggregate(managerId)).toBe(1);
    const row = (await migrator.query<{ city_id: string; granted_by: string; revoked_at: Date | null }>(
      'SELECT city_id, granted_by, revoked_at FROM foundation.staff_admin_city_assignments WHERE id=$1', [created.id])).rows[0];
    expect(row).toMatchObject({ city_id: cityA, granted_by: adminId, revoked_at: null });

    const after = await exec(adminProof, 'adminList', { staffId: managerId }) as { items: Record<string, unknown>[]; version: number };
    expect(after.version).toBe(1);
    expect(after.items).toHaveLength(1);
    const [listedAssignment] = after.items;
    expect(listedAssignment).toMatchObject({ id: created.id, staffId: managerId, cityId: cityA, revokedAt: null, active: true });
    expect(typeof listedAssignment?.['grantedAt']).toBe('string');

    // A second active assignment for the same staff+city is a conflict, not a duplicate.
    expect(await status(exec(adminProof, 'adminAssign', { cityId: cityA, staffId: managerId }, {}, 1))).toBe(409);
    // A stale aggregate is a precondition failure.
    expect(await status(exec(adminProof, 'adminAssign', { cityId: cityB, staffId: managerId }, {}, 0))).toBe(412);
  });

  it('administrative territory is not a manager operation and never targets the actor', async () => {
    expect(await status(exec(managerProof, 'adminAssign', { cityId: cityA, staffId: technicianId }, {}, 0))).toBe('FORBIDDEN');
    expect(await status(exec(managerProof, 'adminList', { staffId: technicianId }))).toBe('FORBIDDEN');
    expect(await status(exec(adminProof, 'adminAssign', { cityId: cityA, staffId: adminId }, {}, 0))).toBe(403);
    // A technician is never an administrative delegate.
    expect(await status(exec(adminProof, 'adminAssign', { cityId: cityA, staffId: technicianId }, {}, 0))).toBe(404);
  });

  it('a manager can only act in a city from its trusted assignment', async () => {
    expect(await status(exec(managerProof, 'techGrantCity', { cityId: cityB, staffId: technicianId },
      { validFrom: liveCity.validFrom }, 0))).toBe(404);
    expect(await status(exec(managerProof, 'techCities', { cityId: cityB, staffId: technicianId }))).toBe(404);
  });

  it('admits a technician to the assigned city and refuses a stale aggregate', async () => {
    const receipt = await exec(managerProof, 'techGrantCity', { cityId: cityA, staffId: technicianId },
      liveCity, 0) as GeoReceipt;
    expect(receipt.version).toBe(1);
    cityMembershipId = receipt.id;
    expect(await aggregate(technicianId)).toBe(1);
    const row = (await migrator.query<{ valid_from: Date; valid_to: Date; approved_by: string }>(
      'SELECT valid_from, valid_to, approved_by FROM foundation.technician_city_memberships WHERE id=$1', [receipt.id])).rows[0];
    expect(row?.valid_from.toISOString()).toBe(liveCity.validFrom);
    expect(row?.valid_to.toISOString()).toBe(liveCity.validTo);
    expect(row?.approved_by).toBe(managerId);
    // The command itself refuses a repeated admission, and a stale ETag is a 412.
    expect(await status(exec(managerProof, 'techGrantCity', { cityId: cityA, staffId: technicianId },
      { validFrom: day(-15) }, 1))).toBe(409);
    expect(await status(exec(managerProof, 'techGrantCity', { cityId: cityA, staffId: technicianId },
      { validFrom: day(-15) }, 0))).toBe(412);
  });

  it('a zone admission must sit entirely inside the city admission', async () => {
    const outsideStart = { validFrom: day(-31), validTo: day(10) };
    const outsideEnd = { validFrom: day(-15), validTo: day(31) };
    const openEnded = { validFrom: day(-15) };
    expect(await status(exec(managerProof, 'techGrantZone', { cityId: cityA, staffId: technicianId, areaId: areaA }, outsideStart, 1))).toBe(409);
    expect(await status(exec(managerProof, 'techGrantZone', { cityId: cityA, staffId: technicianId, areaId: areaA }, outsideEnd, 1))).toBe(409);
    expect(await status(exec(managerProof, 'techGrantZone', { cityId: cityA, staffId: technicianId, areaId: areaA }, openEnded, 1))).toBe(409);
    const receipt = await exec(managerProof, 'techGrantZone', { cityId: cityA, staffId: technicianId, areaId: areaA },
      liveZone, 1) as GeoReceipt;
    expect(receipt.version).toBe(2);
    zoneGrantId = receipt.id;
    const row = (await migrator.query<{ membership_id: string; city_id: string; service_area_id: string }>(
      'SELECT membership_id, city_id, service_area_id FROM foundation.technician_service_areas WHERE id=$1', [receipt.id])).rows[0];
    expect(row).toMatchObject({ membership_id: cityMembershipId, city_id: cityA, service_area_id: areaA });
  });

  it('refuses an archived zone, a zone with no published revision and a foreign city zone', async () => {
    const interval = { validFrom: day(-2), validTo: day(2) };
    expect(await status(exec(managerProof, 'techGrantZone', { cityId: cityA, staffId: technicianId, areaId: areaArchived }, interval, 2))).toBe(409);
    expect(await status(exec(managerProof, 'techGrantZone', { cityId: cityA, staffId: technicianId, areaId: areaDraftOnly }, interval, 2))).toBe(409);
    // An area of another city cannot be smuggled through the path city.
    expect(await status(exec(managerProof, 'techGrantZone', { cityId: cityA, staffId: technicianId, areaId: areaB }, interval, 2))).toBe(404);
    // An area id that does not exist is indistinguishable from a foreign one.
    expect(await status(exec(managerProof, 'techGrantZone', { cityId: cityA, staffId: technicianId, areaId: randomUUID() }, interval, 2))).toBe(404);
  });

  it('the technician sees only its own currently active territory', async () => {
    const summary = await exec(techProof, 'techSelf', {}) as { items: Record<string, unknown>[]; version: number };
    expect(summary.version).toBe(2);
    expect(summary.items).toHaveLength(1);
    const [entry] = summary.items;
    expect(entry).toMatchObject({ cityId: cityA, validFrom: liveCity.validFrom, validTo: liveCity.validTo });
    const zones = entry?.['zones'];
    expect(zones).toEqual([{ areaId: areaA, validFrom: liveZone.validFrom, validTo: liveZone.validTo }]);
    // No actor, staff or history identifiers leak into the self projection.
    const serialized = JSON.stringify(summary);
    expect(serialized).not.toContain(managerId);
    expect(serialized).not.toContain(technicianId);
    expect(serialized).not.toContain('approvedBy');
    expect(serialized).not.toContain('membershipId');
  });

  it('revoking the city admission also revokes its zone admissions and keeps history', async () => {
    const receipt = await exec(managerProof, 'techRevokeCity', { cityId: cityA, staffId: technicianId, grantId: cityMembershipId }, {}, 2) as GeoReceipt;
    expect(receipt).toMatchObject({ id: cityMembershipId, version: 3 });
    const membership = (await migrator.query<{ revoked_at: Date | null; revoked_by: string | null }>(
      'SELECT revoked_at, revoked_by FROM foundation.technician_city_memberships WHERE id=$1', [cityMembershipId])).rows[0];
    expect(membership?.revoked_at).not.toBeNull();
    expect(membership?.revoked_by).toBe(managerId);
    const zone = (await migrator.query<{ revoked_at: Date | null }>(
      'SELECT revoked_at FROM foundation.technician_service_areas WHERE id=$1', [zoneGrantId])).rows[0];
    expect(zone?.revoked_at).not.toBeNull();
    // History is preserved as rows: nothing was deleted.
    expect((await migrator.query('SELECT 1 FROM foundation.technician_city_memberships WHERE id=$1', [cityMembershipId])).rowCount).toBe(1);
    expect((await migrator.query('SELECT 1 FROM foundation.technician_service_areas WHERE id=$1', [zoneGrantId])).rowCount).toBe(1);
    // The effective self summary is empty, while the manager still sees the revoked row.
    const summary = await exec(techProof, 'techSelf', {}) as { items: unknown[]; version: number };
    expect(summary).toMatchObject({ items: [], version: 3 });
    const listed = await exec(managerProof, 'techCities', { cityId: cityA, staffId: technicianId }) as { items: Record<string, unknown>[]; version: number };
    expect(listed.version).toBe(3);
    expect(listed.items).toHaveLength(1);
    const [revokedRow] = listed.items;
    expect(revokedRow).toMatchObject({ id: cityMembershipId, cityId: cityA,
      validFrom: liveCity.validFrom, validTo: liveCity.validTo, active: false });
    expect(typeof revokedRow?.['revokedAt']).toBe('string');
    // A second revocation is a conflict, not a silent success.
    expect(await status(exec(managerProof, 'techRevokeCity', { cityId: cityA, staffId: technicianId, grantId: cityMembershipId }, {}, 3))).toBe(409);
  });

  it('a technician cannot write territory and a mismatched subject id is not found', async () => {
    expect(await status(exec(techProof, 'techGrantCity', { cityId: cityA, staffId: technicianId },
      { validFrom: day(-10) }, 3))).toBe('FORBIDDEN');
    expect(await status(exec(techProof, 'techZones', { cityId: cityA, staffId: technicianId }))).toBe('FORBIDDEN');
    // A grant id of another subject cannot be used as an alias.
    expect(await status(exec(adminProof, 'adminRevoke', { cityId: cityA, staffId: technicianId, grantId: managerAssignmentId }, {}, 3))).toBe(404);
    // Revoking a membership through a mismatched staff id is not found either.
    expect(await status(exec(managerProof, 'techRevokeCity', { cityId: cityA, staffId: adminId, grantId: cityMembershipId }, {}, 3))).toBe(404);
  });

  it('revocation still works after the city is suspended, but new admission does not', async () => {
    await fencedDml((client) => client.query(
      "UPDATE foundation.service_cities SET lifecycle='INACTIVE' WHERE id=$1", [cityA]));
    expect(await status(exec(managerProof, 'techGrantCity', { cityId: cityA, staffId: technicianId },
      { validFrom: day(0) }, 3))).toBe(409);
    const receipt = await exec(adminProof, 'adminRevoke',
      { cityId: cityA, staffId: managerId, grantId: managerAssignmentId }, {}, 1) as GeoReceipt;
    expect(receipt).toMatchObject({ id: managerAssignmentId, version: 2 });
    const row = (await migrator.query<{ revoked_at: Date | null }>(
      'SELECT revoked_at FROM foundation.staff_admin_city_assignments WHERE id=$1', [managerAssignmentId])).rows[0];
    expect(row?.revoked_at).not.toBeNull();
    // The revoked assignment no longer grants the city scope.
    expect(await status(exec(managerProof, 'techCities', { cityId: cityA, staffId: technicianId }))).toBe(404);
  }, 30000);

  it('allows disjoint dated periods and refuses an overlap or a second open period', async () => {
    // A separate city keeps this evidence independent from the revoked city A rows.
    let version = await aggregate(technicianId);
    const grant = async (body: Record<string, unknown>) => {
      const receipt = await exec(adminProof, 'techGrantCity', { cityId: cityB, staffId: technicianId }, body, version) as GeoReceipt;
      version = receipt.version;
      return receipt;
    };
    // An expired-but-not-revoked admission does not block a later period: only an
    // actual interval overlap is a conflict.
    await grant({ validFrom: '2025-01-01T00:00:00Z', validTo: '2025-12-01T00:00:00Z' });
    await grant({ validFrom: '2027-01-01T00:00:00Z', validTo: '2028-01-01T00:00:00Z' });
    expect(await status(exec(adminProof, 'techGrantCity', { cityId: cityB, staffId: technicianId },
      { validFrom: '2027-06-01T00:00:00Z', validTo: '2027-07-01T00:00:00Z' }, version))).toBe(409);
    await grant({ validFrom: '2029-01-01T00:00:00Z' });
    // At most one open-ended admission per technician and city.
    expect(await status(exec(adminProof, 'techGrantCity', { cityId: cityB, staffId: technicianId },
      { validFrom: '2030-01-01T00:00:00Z' }, version))).toBe(409);
    expect(await aggregate(technicianId)).toBe(version);
    const rows = (await migrator.query<{ valid_from: Date; valid_to: Date | null; revoked_at: Date | null }>(
      `SELECT valid_from, valid_to, revoked_at FROM foundation.technician_city_memberships
       WHERE technician_id=$1 AND city_id=$2 ORDER BY valid_from`, [technicianId, cityB])).rows;
    expect(rows.map((row) => [row.valid_from.toISOString(), row.valid_to?.toISOString() ?? null])).toEqual([
      ['2025-01-01T00:00:00.000Z', '2025-12-01T00:00:00.000Z'],
      ['2027-01-01T00:00:00.000Z', '2028-01-01T00:00:00.000Z'],
      ['2029-01-01T00:00:00.000Z', null],
    ]);
    expect(rows.every((row) => row.revoked_at === null)).toBe(true);
  }, 30000);
});
