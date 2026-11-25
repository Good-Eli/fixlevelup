import 'reflect-metadata';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  P05_CAPABILITIES, P05_MODULE, P05_SCOPE_CONTRACT, PROTECTED_CAPABILITIES, STAFF_CAPABILITIES, isP05Capability,
  isPermissionCode,
} from '../src/authz/capability.js';
import type { Capability, GeoGrant, P05Grant } from '../src/authz/capability.js';
import {
  AuthorizationService, P05CommitUnknown,
} from '../src/authz/authorization.service.js';
import type { AccessView, AuthorizationServiceApi, EffectiveRole, SessionProof, StaffWriteContext } from '../src/authz/authorization.service.js';
import { effectiveP05Grants, p05GrantableScopes, requireNoP05CityExpansion } from '../src/authz/p05-grants.js';
import {
  catalogEntry, checkReplacement, grantableScopes, permissionReplacement, replacement,
} from '../src/roles/role-policy.js';
import type { PermissionDto } from '../src/roles/role-policy.js';
import { RolesService } from '../src/roles/index.js';
import { StaffService } from '../src/staff/staff.service.js';
import { membershipCommands } from '../src/settings/geography/membership-commands.js';
import type { GeoContext } from '../src/settings/geography/geo-contract.js';
import { hashPassword } from '../src/staff/password.js';
import { configurationIntegration, createConfigurationFixture, createSyntheticCity } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';

const staffId = '00000000-0000-4000-8000-000000000005';
const cityA = '00000000-0000-4000-8000-0000000000a1';
const cityB = '00000000-0000-4000-8000-0000000000b1';
const roleId = '00000000-0000-4000-8000-000000000007';
const crm: SessionProof = { kind: 'staff-web', token: 'a'.repeat(43) };
const telegram: SessionProof = { kind: 'staff-telegram', token: 'b'.repeat(43) };
const admin = { id: roleId, type: 'SYSTEM', code: 'ADMIN' } as const;
const manager = { id: roleId, type: 'SYSTEM', code: 'MANAGER' } as const;
const custom = { id: roleId, type: 'CUSTOM', code: 'CUSTOM_A' } as const;
const p05 = (code: P05Grant['code'], scope: P05Grant['scope'] = 'CITY'): P05Grant => ({ code, scope });

describe('P05 capability contract', () => {
  it('is exactly the seven closed ordinary codes in the fixed requests module', () => {
    expect([...P05_CAPABILITIES]).toEqual([
      'requests.read', 'requests.create', 'requests.review', 'requests.coverage.assess',
      'requests.contact.manage', 'requests.ready', 'requests.cancel',
    ]);
    expect(P05_MODULE).toBe('requests');
    for (const code of P05_CAPABILITIES) {
      expect(isP05Capability(code)).toBe(true);
      expect(isPermissionCode(code)).toBe(true);
      expect(P05_SCOPE_CONTRACT[code]).toEqual(['CITY', 'GLOBAL']);
    }
    // A near miss, a nested variant and a foreign module string are not contract codes.
    for (const value of ['requests', 'requests.manage', 'requests.read.all', 'request.read', 'requests.publish', '']) {
      expect(isP05Capability(value)).toBe(false);
    }
  });

  it('never marks a P05 code protected, so it can never be mandatory on ADMIN', () => {
    for (const code of P05_CAPABILITIES) { expect(PROTECTED_CAPABILITIES).not.toContain(code); }
    // Staff dictionary and P05 stay disjoint: P05 is not a staff capability.
    for (const code of P05_CAPABILITIES) { expect(STAFF_CAPABILITIES).not.toContain(code); }
  });

  it('stores GLOBAL only on the exact SYSTEM ADMIN role and CITY on manager/custom web roles', () => {
    for (const code of P05_CAPABILITIES) {
      expect(p05GrantableScopes(code, admin)).toEqual(['CITY', 'GLOBAL']);
      expect(p05GrantableScopes(code, manager)).toEqual(['CITY']);
      expect(p05GrantableScopes(code, custom)).toEqual(['CITY']);
      expect(p05GrantableScopes(code, { type: 'SYSTEM', code: 'TECHNICIAN' })).toEqual([]);
      expect(grantableScopes(code, admin)).toEqual(['CITY', 'GLOBAL']);
      expect(grantableScopes(code, manager)).toEqual(['CITY']);
      expect(grantableScopes(code, { type: 'SYSTEM', code: 'TECHNICIAN' })).toEqual([]);
    }
  });

  it('accepts only the exact ordinary requests catalog row for display and editing', () => {
    const base = { description: 'test', module: P05_MODULE, protected: false };
    expect(catalogEntry({ ...base, code: 'requests.review' }))
      .toMatchObject({ code: 'requests.review', scope: 'CITY', scopes: ['CITY', 'GLOBAL'], protected: false });
    // A protected, foreign-module or renamed row is not the reviewed contract.
    expect(catalogEntry({ ...base, code: 'requests.review', protected: true })).toBeNull();
    expect(catalogEntry({ ...base, code: 'requests.review', module: 'catalog' })).toBeNull();
    expect(catalogEntry({ ...base, code: 'requests.unknown' })).toBeNull();
  });
});

interface GrantOptions {
  role?: EffectiveRole;
  telegram?: boolean;
  grants?: readonly { code: string; scope: string }[];
  expiresAfterCallback?: boolean;
  cityExists?: boolean;
  commitError?: Error;
}
/** Mock only the transaction/driver boundary of the real service. Every expected
 * statement is matched by a marker, so an unexpected read or write fails the test. */
function authorizationFixture(options: GrantOptions = {}) {
  const statements: { sql: string; params?: unknown[] }[] = [];
  const role = options.role ?? admin;
  const marker = options.telegram ? 'TECHNICIAN' : role.type === 'CUSTOM' ? 'MANAGER' : role.code;
  const query = (sql: string, params?: unknown[]) => {
    statements.push(params ? { sql, params } : { sql });
    if (sql === 'COMMIT' && options.commitError) { return Promise.reject(options.commitError); }
    let rows: readonly unknown[] = [];
    if (sql.startsWith('BEGIN') || sql.includes('pg_advisory_xact_lock') || sql === 'COMMIT' || sql === 'ROLLBACK'
      || sql === 'SET LOCAL synchronous_commit=on') {
      // plumbing only
    } else if (sql.startsWith('SELECT staff_id, telegram_link_id')) {
      rows = [{ staff_id: staffId, telegram_link_id: options.telegram ? 'link' : null }];
    } else if (sql.startsWith('SELECT id, role, auth_version')) {
      rows = [{ id: staffId, role: marker, auth_version: 8 }];
    } else if (sql.startsWith('SELECT id FROM foundation.web_sessions')) {
      rows = [{ id: 'session' }];
    } else if (sql.startsWith('SELECT telegram_user_id')) {
      rows = [{ telegram_user_id: '12345' }];
    } else if (sql.includes('FROM foundation.web_sessions ws')) {
      rows = options.expiresAfterCallback ? [] : [{ id: staffId, db_now: new Date('2026-11-25T07:00:00Z') }];
    } else if (sql.includes('p.module=$4')) {
      rows = options.grants ?? [];
    } else if (sql.includes('geography_bootstrap_permissions')) {
      rows = [];
    } else if (sql.startsWith('SELECT r.id, r.code, r.role_type')) {
      rows = [{ ...role, role_type: role.type, permission_code: 'roles.permissions.manage',
        scope_type: 'GLOBAL', protected: true }];
    } else if (sql.includes('staff_admin_city_assignments')) {
      rows = [{ city_id: cityA }];
    } else if (sql.includes('FROM foundation.service_cities')) {
      rows = options.cityExists === false ? [] : [{ id: cityA }];
    } else { throw new Error(`Unexpected query: ${sql}`); }
    return Promise.resolve({ rows, rowCount: rows.length, command: sql });
  };
  const release = vi.fn();
  const client = { query, release } as unknown as PoolClient;
  return { auth: new AuthorizationService({ connect: async () => Promise.resolve(client) }), statements, release };
}

describe('P05 staff authorization port', () => {
  it('takes the shared RBAC lock on a domain write and never the exclusive policy lock', async () => {
    const { auth, statements } = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL'), p05('requests.review', 'GLOBAL')] });
    await auth.withP05(crm, ['requests.review'], async ({ authorizeCity }) => {
      await authorizeCity(cityA);
      return 'ok';
    });
    expect(statements[1]?.sql).toContain('pg_advisory_xact_lock_shared');
    expect(statements.some(({ sql }) => sql.includes('pg_advisory_xact_lock('))).toBe(false);
    // A P05 domain write pins synchronous_commit for its own transaction, right after
    // the shared policy lock and before any callback statement.
    expect(statements[2]?.sql).toBe('SET LOCAL synchronous_commit=on');
  });

  it('does not pin synchronous_commit on a read-only P05 projection', async () => {
    const { auth, statements } = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL')] });
    await auth.withP05(crm, ['requests.read'], async ({ authorizeCity }) => {
      await authorizeCity(cityA);
      return 'read';
    });
    expect(statements.some(({ sql }) => sql === 'SET LOCAL synchronous_commit=on')).toBe(false);
  });

  it('requires the exact command code plus requests.read on the same target', async () => {
    const callback = vi.fn(async ({ authorizeCity }: { authorizeCity: (id: string) => Promise<void> }) => {
      await authorizeCity(cityA);
      return 'ok';
    });
    // Only read: the review command is denied.
    const readOnly = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL')] });
    await expect(readOnly.auth.withP05(crm, ['requests.review'], callback)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    expect(callback).not.toHaveBeenCalled();
    // Only the command: read is added by the port, so it is still denied.
    const commandOnly = authorizationFixture({ grants: [p05('requests.review', 'GLOBAL')] });
    await expect(commandOnly.auth.withP05(crm, ['requests.review'], callback)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    // Both exact grants succeed, and read-only access is allowed without a command code.
    const both = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL'), p05('requests.review', 'GLOBAL')] });
    await expect(both.auth.withP05(crm, ['requests.review'], callback)).resolves.toBe('ok');
    const read = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL')] });
    await expect(read.auth.withP05(crm, ['requests.read'], async ({ authorizeCity }) => {
      await authorizeCity(cityA);
      return 'read';
    })).resolves.toBe('read');
  });

  it('denies a Telegram proof and an unknown capability before any callback', async () => {
    const { auth } = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL'), p05('requests.review', 'GLOBAL')], telegram: true });
    const callback = vi.fn(() => Promise.resolve('never'));
    await expect(auth.withP05(telegram, ['requests.review'], callback)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(auth.withP05(crm, ['requests.manage' as never], callback)).rejects.toBeInstanceOf(BadRequestException);
    // An empty requirement would be a grant-less command surface: refuse it outright.
    await expect(auth.withP05(crm, [], callback)).rejects.toBeInstanceOf(BadRequestException);
    expect(callback).not.toHaveBeenCalled();
  });

  it('resolves the target first: a foreign city is 404, a missing grant is 403', async () => {
    // A CITY grant for cityA cannot reach cityB, even though the command code is held.
    const cityScoped = authorizationFixture({ grants: [p05('requests.read', 'CITY'), p05('requests.review', 'CITY')] });
    const callback = vi.fn(async ({ authorizeCity }: { authorizeCity: (id: string) => Promise<void> }) => {
      await authorizeCity(cityB);
      return 'ok';
    });
    await expect(cityScoped.auth.withP05(crm, ['requests.review'], callback))
      .rejects.toMatchObject({ status: 404 });
    // The callback did resolve the persisted target before the scope decision.
    expect(callback).toHaveBeenCalledOnce();
    // The caller's own missing grant is a 403, not a target disclosure.
    const missing = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL')] });
    await expect(missing.auth.withP05(crm, ['requests.review'], async ({ authorizeCity }) => {
      await authorizeCity(cityA);
      return 'ok';
    })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    // A city row that does not exist is the same 404 as an out-of-scope city.
    const absentCity = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL'), p05('requests.review', 'GLOBAL')], cityExists: false });
    await expect(absentCity.auth.withP05(crm, ['requests.review'], async ({ authorizeCity }) => {
      await authorizeCity(cityA);
      return 'ok';
    })).rejects.toMatchObject({ status: 404 });
  });

  it('exposes the exact locked session id and a city scope derived from the live assignment', async () => {
    const { auth } = authorizationFixture({ grants: [p05('requests.read', 'CITY'), p05('requests.review', 'GLOBAL')] });
    await expect(auth.withP05(crm, ['requests.review'], async (ctx) => {
      await ctx.authorizeCity(cityA);
      return { sessionId: ctx.sessionId, staffId: ctx.staffId, cityIds: ctx.cityIds, role: ctx.role.code };
    })).resolves.toEqual({ sessionId: 'session', staffId, cityIds: [cityA], role: 'ADMIN' });
    // All-GLOBAL grants need no assignment lookup and are not city-limited.
    const global = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL'), p05('requests.review', 'GLOBAL')] });
    await expect(global.auth.withP05(crm, ['requests.review'], async (ctx) => {
      await ctx.authorizeCity(cityA);
      return ctx.cityIds;
    })).resolves.toBeNull();
    expect(global.statements.some(({ sql }) => sql.includes('staff_admin_city_assignments'))).toBe(false);
  });

  it('fails closed when a command never names its target, and rejects a non-uuid city', async () => {
    const { auth, statements } = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL'), p05('requests.review', 'GLOBAL')] });
    await expect(auth.withP05(crm, ['requests.review'], () => Promise.resolve('forgot'))).rejects.toMatchObject({ status: 500 });
    expect(statements.at(-1)?.sql).toBe('ROLLBACK');
    await expect(auth.withP05(crm, ['requests.review'], async ({ authorizeCity }) => {
      await authorizeCity('not-a-uuid');
      return 'ok';
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it('re-reads the live proof after the callback and rolls the domain work back', async () => {
    const { auth, statements } = authorizationFixture({
      grants: [p05('requests.read', 'GLOBAL'), p05('requests.review', 'GLOBAL')], expiresAfterCallback: true,
    });
    await expect(auth.withP05(crm, ['requests.review'], async ({ client, authorizeCity }) => {
      await client.query('CALLBACK');
      await authorizeCity(cityA);
      return { secret: 'must not escape' };
    })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(statements.at(-1)?.sql).toBe('ROLLBACK');
    expect(statements.some(({ sql }) => sql === 'COMMIT')).toBe(false);
  });

  it('makes the domain deadline decision with the last staff-proof SQL clock and rolls back an expired write', async () => {
    const { auth, statements } = authorizationFixture({ grants: [p05('requests.read', 'GLOBAL'), p05('requests.review', 'GLOBAL')] });
    const expiresAt = new Date('2026-11-25T07:00:00Z');
    const decide = vi.fn((deadline: Date, clock: Date) => {
      const sample = statements.at(-1)?.sql ?? '';
      expect(sample).toContain('CROSS JOIN (SELECT clock_timestamp() AS db_now)');
      expect(sample).toContain('ws.idle_expires_at>sample.db_now AND ws.absolute_expires_at>sample.db_now');
      expect(clock.getTime()).toBe(expiresAt.getTime());
      if (deadline <= clock) { throw new BadRequestException('expired-procedure'); }
      return 'receipt';
    });
    await expect(auth.withP05(crm, ['requests.review'], async ({ authorizeCity }) => {
      await authorizeCity(cityA);
      return expiresAt;
    }, decide)).rejects.toMatchObject({ status: 400, message: 'expired-procedure' });
    expect(decide).toHaveBeenCalledOnce();
    expect(statements.at(-1)?.sql).toBe('ROLLBACK');
    expect(statements.some(({ sql }) => sql === 'COMMIT')).toBe(false);
  });

  it('signals its own unknown COMMIT for a domain write and keeps a definite rejection typed', async () => {
    const grants = [p05('requests.read', 'GLOBAL'), p05('requests.review', 'GLOBAL')];
    const callback = vi.fn(async ({ authorizeCity }: { authorizeCity: (id: string) => Promise<void> }) => {
      await authorizeCity(cityA);
      return 'receipt';
    });
    const unknown = authorizationFixture({ grants, commitError: new Error('raw driver data') });
    await expect(unknown.auth.withP05(crm, ['requests.review'], callback)).rejects.toEqual(new P05CommitUnknown());
    expect(callback).toHaveBeenCalledOnce();
    expect(unknown.statements.at(-1)?.sql).toBe('COMMIT');
    expect(unknown.statements.some(({ sql }) => sql === 'ROLLBACK')).toBe(false);
    expect(unknown.release).toHaveBeenCalledWith(true);
    // A read-only call has no receipt to be uncertain about and reports a safe 500.
    const readUnknown = authorizationFixture({ grants, commitError: new Error('raw driver data') });
    await expect(readUnknown.auth.withP05(crm, ['requests.read'], async ({ authorizeCity }) => {
      await authorizeCity(cityA);
      return 'read';
    })).rejects.toMatchObject({ status: 500 });
    // A definite serialization failure is a conflict, not an unknown commit.
    const rejected = authorizationFixture({ grants, commitError: Object.assign(new Error('raw constraint data'), { severity: 'ERROR', code: '40001' }) });
    await expect(rejected.auth.withP05(crm, ['requests.review'], callback)).rejects.toMatchObject({ status: 409 });
    expect(rejected.statements.at(-1)?.sql).toBe('ROLLBACK');
  });
});

describe('effective P05 grants on the locked snapshot', () => {
  it('reads only enabled grants of the current assignment joined to the ordinary requests catalog', async () => {
    const statements: { sql: string; params?: unknown[] }[] = [];
    const client = {
      query: (sql: string, params?: unknown[]) => {
        statements.push(params ? { sql, params } : { sql });
        return Promise.resolve({ rowCount: 3, rows: [
          { code: 'requests.read', scope: 'CITY' },
          { code: 'requests.review', scope: 'GLOBAL' },
          { code: 'requests.cancel', scope: 'GLOBAL' },
        ] });
      },
    } as unknown as PoolClient;
    const principal = { kind: 'staff-web', staffId, role: 'MANAGER', authVersion: 1 } as const;
    // A manager may store CITY only: the GLOBAL rows are drifted and ignored, never widened.
    await expect(effectiveP05Grants(client, principal, manager)).resolves.toEqual([p05('requests.read', 'CITY')]);
    const sql = statements[0]?.sql ?? '';
    expect(sql).toContain('revoked_at IS NULL');
    expect(sql).toContain('rp.enabled');
    expect(sql).toContain('p.active AND NOT p.protected AND p.module=$4');
    expect(statements[0]?.params?.[3]).toBe('requests');
    // The exact SYSTEM ADMIN role may hold the same GLOBAL grant.
    const grants = await effectiveP05Grants(client, principal, admin);
    expect(grants).toContainEqual(p05('requests.review', 'GLOBAL'));
  });

  it('grants nothing to a Telegram principal or a non-manager CUSTOM channel', async () => {
    const client = { query: () => Promise.reject(new Error('must not query')) } as unknown as PoolClient;
    await expect(effectiveP05Grants(client, { kind: 'staff-telegram', staffId, role: 'TECHNICIAN', authVersion: 1, telegramUserId: '1' }, manager))
      .resolves.toEqual([]);
    await expect(effectiveP05Grants(client, { kind: 'staff-web', staffId, role: 'ADMIN', authVersion: 1 }, custom))
      .resolves.toEqual([]);
  });
});

describe('role writer bridge for P05', () => {
  const p05Dto = (code: P05Grant['code'], scopes: readonly ('CITY' | 'GLOBAL')[] = ['CITY', 'GLOBAL']): PermissionDto => ({
    code, module: P05_MODULE, description: 'test', protected: false, scope: scopes[0] ?? 'CITY', scopes,
  });
  const catalog: PermissionDto[] = [
    { ...p05Dto('requests.read'), module: P05_MODULE },
    { ...p05Dto('requests.review'), module: P05_MODULE },
    ...STAFF_CAPABILITIES.map((code) => ({ code, scope: 'GLOBAL' as const, description: 'test', module: 'staff',
      protected: PROTECTED_CAPABILITIES.includes(code), scopes: ['GLOBAL'] as const })),
  ];
  const actor = (permissions: readonly Capability[] = ['roles.permissions.manage', 'roles.read']): AccessView =>
    ({ staffId, role: admin, permissions });

  it('parses the legacy body unchanged and validates the explicit revocation list', () => {
    expect(replacement({ permissions: [] })).toEqual([]);
    expect(replacement({ permissions: [{ code: 'staff.read', scope: 'GLOBAL' }] })).toEqual([{ code: 'staff.read', scope: 'GLOBAL' }]);
    expect(permissionReplacement({ permissions: [] })).toEqual({ grants: [], revokeP05: [] });
    expect(permissionReplacement({ permissions: [], revokeP05Permissions: ['requests.review'] }))
      .toEqual({ grants: [], revokeP05: ['requests.review'] });
    for (const body of [
      { permissions: [], revokeP05Permissions: 'requests.review' },
      { permissions: [], revokeP05Permissions: ['requests.manage'] },
      { permissions: [], revokeP05Permissions: ['requests.review', 'requests.review'] },
      { permissions: [], revokeP05Permissions: ['staff.read'] },
      { permissions: [], revokeP05Permissions: ['requests.review'], extra: true },
    ]) {
      expect(() => permissionReplacement(body)).toThrow(BadRequestException);
    }
  });

  it('refuses a new or widened P05 grant and a silent omission, with no partial effect', () => {
    const existing = [{ code: 'requests.review', scope: 'CITY' }] as const;
    // New issuance by the ordinary writer is forbidden.
    expect(() => { checkReplacement(actor(), custom, catalog, [], [{ code: 'requests.review', scope: 'CITY' }]); })
      .toThrow(ForbiddenException);
    // Widening an existing CITY grant to GLOBAL is forbidden even for an ADMIN actor.
    expect(() => { checkReplacement(actor(), admin, catalog, existing, [{ code: 'requests.review', scope: 'GLOBAL' }]); })
      .toThrow(ForbiddenException);
    // The legacy body cannot express a P05 grant, so omitting it is an incomplete
    // authority set: refuse instead of silently preserving or silently revoking it.
    expect(() => { checkReplacement(actor(), custom, catalog, existing, []); }).toThrow(ConflictException);
    expect(() => { checkReplacement(actor(), custom, catalog, existing, [{ code: 'staff.read', scope: 'GLOBAL' }]); })
      .toThrow(ConflictException);
    // The exact existing pair is retainable without becoming a delegation source.
    expect(() => { checkReplacement(actor([]), custom, catalog, existing, existing); }).not.toThrow();
    // An explicit revocation is accepted, but only for a currently enabled grant.
    expect(() => { checkReplacement(actor(), custom, catalog, existing, [], ['requests.review']); }).not.toThrow();
    expect(() => { checkReplacement(actor(), custom, catalog, existing, [], ['requests.ready']); }).toThrow(ConflictException);
    expect(() => {
      checkReplacement(actor(), custom, catalog, existing, [{ code: 'requests.review', scope: 'CITY' }], ['requests.review']);
    }).toThrow(BadRequestException);
  });

  function roleFixture(current: readonly { code: string; scope: string }[]) {
    const statements: { sql: string; params?: unknown[] }[] = [];
    // Optional statements are skipped when the next write did not need them, so the
    // same fixture proves both "no permission write" and "exactly one revoke".
    const responses: { contains: string; rows?: readonly unknown[]; optional?: boolean }[] = [
      { contains: 'FOR UPDATE', rows: [{ ...custom, name: 'role', description: '', status: 'ACTIVE', version: 2 }] },
      { contains: 'FROM foundation.permissions', rows: catalog },
      { contains: 'AND enabled ORDER BY', rows: current },
      { contains: 'SET enabled=false', optional: true },
      { contains: 'DO UPDATE SET enabled', optional: true },
      { contains: 'SET version=version+1' },
      { contains: 'INSERT INTO foundation.audit_logs' },
    ];
    let next = 0;
    const query = (sql: string, params?: unknown[]) => {
      while (next < responses.length && !sql.includes(responses[next]?.contains ?? '')) {
        if (!responses[next]?.optional) { throw new Error(`Unexpected query: ${sql}`); }
        next += 1;
      }
      const response = responses[next];
      if (!response) { throw new Error(`Unexpected query: ${sql}`); }
      next += 1;
      statements.push(params ? { sql, params } : { sql });
      const rows = response.rows ?? [];
      return Promise.resolve({ rowCount: rows.length, rows });
    };
    // No `roles.read` here: the successful write then returns the receipt-only shape,
    // which is what a write-only grantee must receive.
    const actorView = { ...actor(['roles.permissions.manage', 'staff.read']),
      role: { ...admin, id: '00000000-0000-4000-8000-000000000009' } };
    const ctx: StaffWriteContext = { ...actorView, principal: { kind: 'staff-web', role: 'ADMIN', authVersion: 1, staffId },
      client: { query } as unknown as PoolClient };
    const auth = {
      authorize: vi.fn(), inspectAccess: vi.fn(),
      authorizeForRead: vi.fn(),
      authorizeForWrite: (_p: unknown, capability: Capability, _s: unknown,
        operation: (ctx: StaffWriteContext) => Promise<unknown>) => capability === 'roles.permissions.manage'
        ? operation(ctx) : Promise.reject(new ForbiddenException()),
    };
    return { service: new RolesService(auth as unknown as AuthorizationServiceApi), statements };
  }

  it('refuses an omitted enabled P05 grant without any permission write', async () => {
    const fx = roleFixture([{ code: 'requests.review', scope: 'CITY' }]);
    await expect(fx.service.replacePermissions(crm, roleId, 2, [{ code: 'staff.read', scope: 'GLOBAL' }]))
      .rejects.toBeInstanceOf(ConflictException);
    expect(fx.statements.some(({ sql }) => sql.includes('SET enabled=false'))).toBe(false);
    expect(fx.statements.some(({ sql }) => sql.includes('INSERT INTO foundation.role_permissions'))).toBe(false);
    expect(fx.statements.some(({ sql }) => sql.includes('INSERT INTO foundation.audit_logs'))).toBe(false);
  });

  it('keeps an explicitly retained P05 grant and revokes only an explicitly named one', async () => {
    const retained = roleFixture([{ code: 'requests.review', scope: 'CITY' }]);
    await expect(retained.service.replacePermissions(crm, roleId, 2, [{ code: 'requests.review', scope: 'CITY' }]))
      .resolves.toEqual({ id: roleId, version: 3 });
    expect(retained.statements.some(({ sql }) => sql.includes('SET enabled=false'))).toBe(false);
    const revoked = roleFixture([{ code: 'requests.review', scope: 'CITY' }]);
    await expect(revoked.service.replacePermissions(crm, roleId, 2, [], ['requests.review']))
      .resolves.toEqual({ id: roleId, version: 3 });
    const removal = revoked.statements.find(({ sql }) => sql.includes('SET enabled=false'));
    expect(removal?.params).toEqual([roleId, ['requests.review']]);
    const event = revoked.statements.find(({ sql }) => sql.includes('INSERT INTO foundation.audit_logs'));
    expect(String(event?.params?.[3])).toContain('requests.review');
  });

  it('leaves an unaffected legacy replacement semantically identical', async () => {
    const fx = roleFixture([{ code: 'staff.read', scope: 'GLOBAL' }]);
    await expect(fx.service.replacePermissions(crm, roleId, 2, [{ code: 'staff.read', scope: 'GLOBAL' }]))
      .resolves.toEqual({ id: roleId, version: 3 });
    expect(fx.statements.map(({ sql }) => sql.includes('SET version=version+1') ? 'version'
      : sql.includes('INSERT INTO foundation.audit_logs') ? 'audit' : 'other')).toEqual(['other', 'other', 'other', 'version', 'audit']);
  });
});

describe('indirect P05 escalation safeguards', () => {
  it('refuses creating staff or assigning a role that already carries P05 rights', async () => {
    const statements: string[] = [];
    const responses: { contains: string; rows?: unknown[] }[] = [
      { contains: "SELECT id FROM foundation.roles WHERE code=$1", rows: [{ id: roleId }] },
      { contains: 'FROM foundation.role_permissions rp', rows: [
        { code: 'requests.review', scope: 'CITY', role_type: 'CUSTOM', role_code: 'CUSTOM_A', active: true, protected: false, module: 'requests' },
      ] },
    ];
    const query = (sql: string) => {
      const response = responses[statements.length];
      if (!response || !sql.includes(response.contains)) { throw new Error(`Unexpected query: ${sql}`); }
      statements.push(sql);
      const rows = response.rows ?? [];
      return Promise.resolve({ rowCount: rows.length, rows });
    };
    const ctx: StaffWriteContext = { staffId, role: admin, permissions: ['staff.create', 'staff.role.assign'],
      principal: { kind: 'staff-web', role: 'ADMIN', authVersion: 1, staffId }, client: { query } as unknown as PoolClient };
    const auth = {
      authorize: vi.fn(), inspectAccess: vi.fn(), authorizeForRead: vi.fn(),
      authorizeForWrite: (_p: unknown, _c: unknown, _s: unknown, operation: (ctx: StaffWriteContext) => Promise<unknown>) => operation(ctx),
    };
    const service = new StaffService(auth as never);
    await expect(service.create(crm, 'MANAGER', 'synthetic')).rejects.toBeInstanceOf(ForbiddenException);
    // The refusal happens before any staff/assignment/audit insert.
    expect(statements.some((sql) => sql.includes('INSERT INTO foundation.staff'))).toBe(false);
    expect(statements.some((sql) => sql.includes('INSERT INTO foundation.audit_logs'))).toBe(false);
  });

  it('refuses a new admin-city assignment that would widen a CITY-scoped P05 grant', async () => {
    const statements: string[] = [];
    const responses: { contains: string; rows?: unknown[] }[] = [
      { contains: 'FOR UPDATE OF s', rows: [{ id: staffId, channel_role: 'MANAGER', employment_state: 'ACTIVE', auth_version: 0,
        profile_version: 0, role_code: 'MANAGER', role_type: 'SYSTEM', has_web: true }] },
      { contains: 'SELECT lifecycle FROM foundation.service_cities', rows: [{ lifecycle: 'ACTIVE' }] },
      { contains: 'staff_admin_city_assignments WHERE staff_id=$1 AND city_id=$2', rows: [] },
      { contains: 'p03_bootstrap_permissions', rows: [] },
      { contains: 'p.module=$2', rows: [{ '?column?': 1 }] },
    ];
    const query = (sql: string) => {
      const response = responses[statements.length];
      if (!response || !sql.includes(response.contains)) { throw new Error(`Unexpected query: ${sql}`); }
      statements.push(sql);
      const rows = response.rows ?? [];
      return Promise.resolve({ rowCount: rows.length, rows });
    };
    const ctx: GeoContext = {
      staffId: '00000000-0000-4000-8000-0000000000ff',
      role: admin,
      permissions: ['staff.role.assign'],
      geoPermissions: [{ code: 'geography.manage', scope: 'GLOBAL' }] as readonly GeoGrant[],
      principal: { kind: 'staff-web', staffId: '00000000-0000-4000-8000-0000000000ff', role: 'ADMIN', authVersion: 1 },
      client: { query } as unknown as PoolClient,
      cityIds: null,
    };
    await expect(membershipCommands.adminAssign.run(ctx, { cityId: cityA, staffId }, {}, 0))
      .rejects.toBeInstanceOf(ForbiddenException);
    expect(statements.some((sql) => sql.includes('INSERT INTO foundation.staff_admin_city_assignments'))).toBe(false);
  });

  it('keeps the legacy admin-city assignment path working when no P05 grant is present', async () => {
    const statements: string[] = [];
    const responses: { contains: string; rows?: unknown[] }[] = [
      { contains: 'FOR UPDATE OF s', rows: [{ id: staffId, channel_role: 'MANAGER', employment_state: 'ACTIVE', auth_version: 0,
        profile_version: 0, role_code: 'MANAGER', role_type: 'SYSTEM', has_web: true }] },
      { contains: 'SELECT lifecycle FROM foundation.service_cities', rows: [{ lifecycle: 'ACTIVE' }] },
      { contains: 'staff_admin_city_assignments WHERE staff_id=$1 AND city_id=$2', rows: [] },
      { contains: 'p03_bootstrap_permissions', rows: [] },
      { contains: 'p.module=$2', rows: [] },
      { contains: 'INSERT INTO foundation.staff_admin_city_assignments' },
      { contains: 'SET profile_version=profile_version+1', rows: [{ auth_version: 0, profile_version: 1 }] },
    ];
    const query = (sql: string) => {
      const response = responses[statements.length];
      if (!response || !sql.includes(response.contains)) { throw new Error(`Unexpected query: ${sql}`); }
      statements.push(sql);
      const rows = response.rows ?? [];
      return Promise.resolve({ rowCount: rows.length, rows });
    };
    const ctx: GeoContext = {
      staffId: '00000000-0000-4000-8000-0000000000ff',
      role: admin,
      permissions: ['staff.role.assign'],
      geoPermissions: [{ code: 'geography.manage', scope: 'GLOBAL' }] as readonly GeoGrant[],
      principal: { kind: 'staff-web', staffId: '00000000-0000-4000-8000-0000000000ff', role: 'ADMIN', authVersion: 1 },
      client: { query } as unknown as PoolClient,
      cityIds: null,
    };
    await expect(membershipCommands.adminAssign.run(ctx, { cityId: cityA, staffId }, {}, 0))
      .resolves.toMatchObject({ version: 1 });
  });

  it('looks only at live enabled CITY grants of an active role in the requests module', async () => {
    const statements: { sql: string; params?: unknown[] }[] = [];
    const client = {
      query: (sql: string, params?: unknown[]) => {
        statements.push(params ? { sql, params } : { sql });
        return Promise.resolve({ rowCount: 0, rows: [] });
      },
    } as unknown as PoolClient;
    await requireNoP05CityExpansion({ client }, staffId);
    const sql = statements[0]?.sql ?? '';
    expect(sql).toContain("a.revoked_at IS NULL");
    expect(sql).toContain("r.status='ACTIVE'");
    expect(sql).toContain("rp.enabled AND rp.scope_type='CITY'");
    expect(sql).toContain('p.active AND NOT p.protected AND p.module=$2');
    expect(statements[0]?.params).toEqual([staffId, 'requests', [...P05_CAPABILITIES]]);
  });
});

/**
 * Real isolated-PostgreSQL proof of the S3 role bridge and the P05 staff authority
 * port. It uses the reusable configuration fixture (the full real migration chain,
 * including the operator-owned 024/S3 migration, applied to a disposable database)
 * and only reviewed synthetic rows: the fixture's bootstrap administrator, synthetic
 * cities, a CUSTOM role whose P05 grants are inserted by the migration owner exactly
 * as reviewed operator provisioning would, and web sessions opened by the fixture.
 * The ports under test only ever run through the real `fixlevelup_runtime` role.
 */
const labIntegration = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  ? configurationIntegration : describe.skip;
labIntegration('P05 role bridge and staff authority on isolated PostgreSQL S3', () => {
  let fixture: ConfigurationFixture;
  let city: { id: string };
  let otherCity: { id: string };
  let adminRoleId: string;
  let adminProof: SessionProof;
  let adminSessionId: string;
  let managerProof: SessionProof;
  let managerId: string;
  let customRoleId: string;
  let customRoleCode: string;
  let unprivilegedManagerId: string;

  /** Opens one real CRM session row for an existing staff member. The token is random
   * per call and only its SHA-256 hash is stored, exactly like the web-auth service. */
  async function openSession(staffId: string): Promise<{ proof: SessionProof; sessionId: string }> {
    const secret = randomBytes(32).toString('base64url');
    const sessionId = randomUUID();
    await fixture.migrator.query(`INSERT INTO foundation.web_sessions
      (id,staff_id,token_hash,auth_version,idle_expires_at,absolute_expires_at,channel)
      SELECT $1,$2,$3,s.auth_version,now()+interval '10 minutes',now()+interval '12 hours','CRM'
      FROM foundation.staff s WHERE s.id=$2`,
    [sessionId, staffId, createHash('sha256').update(secret).digest('hex')]);
    return { proof: { token: secret, kind: 'staff-web' }, sessionId };
  }

  async function createManager(roleId: string): Promise<string> {
    const id = randomUUID();
    const client = await fixture.migrator.connect();
    try {
      await client.query('BEGIN');
      await client.query("INSERT INTO foundation.staff (id,role,employment_state,auth_version) VALUES ($1,'MANAGER','ACTIVE',0)", [id]);
      // The canonical PHC CHECK of migration 009 requires a real argon2id hash;
      // a placeholder string is rejected by the database, not by this fixture.
      await client.query('INSERT INTO foundation.staff_web_credentials (staff_id,login,password_hash) VALUES ($1,$2,$3)',
        [id, `p05-bridge-${id}`, await hashPassword('Synthetic-P05-Bridge-Password-1')]);
      await client.query('INSERT INTO foundation.staff_role_assignments (id,staff_id,role_id) VALUES ($1,$2,$3)',
        [randomUUID(), id, roleId]);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
    return id;
  }

  /** Operator-owned synthetic provisioning: a reviewed CUSTOM role with exact P05 rows. */
  async function createCustomRole(grants: readonly { code: string; scope: string }[]): Promise<{ id: string; code: string }> {
    const id = randomUUID();
    const code = `CUSTOM_P05_${id.slice(0, 8).toUpperCase()}`;
    const client = await fixture.migrator.connect();
    try {
      await client.query('BEGIN');
      await client.query('INSERT INTO foundation.roles (id,code,name) VALUES ($1,$2,$3)', [id, code, 'P05 bridge test role']);
      for (const grant of grants) {
        await client.query('INSERT INTO foundation.role_permissions (role_id,permission_code,scope_type) VALUES ($1,$2,$3)',
          [id, grant.code, grant.scope]);
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
    return { id, code };
  }

  const auth = (): AuthorizationService => new AuthorizationService(fixture.runtime);
  const roleVersion = async (): Promise<number> => (await fixture.migrator.query<{ version: number }>(
    'SELECT version FROM foundation.roles WHERE id=$1', [customRoleId])).rows[0]?.version ?? 0;
  const grantEnabled = async (code: string): Promise<boolean | undefined> => (await fixture.migrator.query<{ enabled: boolean }>(
    'SELECT enabled FROM foundation.role_permissions WHERE role_id=$1 AND permission_code=$2', [customRoleId, code])).rows[0]?.enabled;

  beforeAll(async () => {
    fixture = await createConfigurationFixture();
    city = await createSyntheticCity(fixture);
    otherCity = await createSyntheticCity(fixture);
    const adminRole = (await fixture.migrator.query<{ id: string }>(
      "SELECT id FROM foundation.roles WHERE code='ADMIN' AND role_type='SYSTEM'")).rows[0];
    const systemManager = (await fixture.migrator.query<{ id: string }>(
      "SELECT id FROM foundation.roles WHERE code='MANAGER' AND role_type='SYSTEM'")).rows[0];
    if (!adminRole || !systemManager) { throw new Error('Missing seeded system roles'); }
    adminRoleId = adminRole.id;
    // Exact GLOBAL pair for the only role that may ever hold it.
    for (const code of ['requests.read', 'requests.review']) {
      await fixture.migrator.query('INSERT INTO foundation.role_permissions (role_id,permission_code,scope_type) VALUES ($1,$2,$3)',
        [adminRoleId, code, 'GLOBAL']);
    }
    const custom = await createCustomRole([
      { code: 'requests.read', scope: 'CITY' }, { code: 'requests.review', scope: 'CITY' },
    ]);
    customRoleId = custom.id;
    customRoleCode = custom.code;
    managerId = await createManager(customRoleId);
    unprivilegedManagerId = await createManager(systemManager.id);
    await fixture.migrator.query(`INSERT INTO foundation.staff_admin_city_assignments (id,staff_id,city_id,granted_by)
      VALUES ($1,$2,$3,$4)`, [randomUUID(), managerId, city.id, fixture.reviewer]);
    const admin = await openSession(fixture.reviewer);
    adminProof = admin.proof;
    adminSessionId = admin.sessionId;
    managerProof = (await openSession(managerId)).proof;
  }, 180_000);

  afterAll(async () => { await fixture.close(); }, 30_000);

  it('projects exactly the operator-provisioned grants and masks the same role on Telegram', async () => {
    const client = await fixture.runtime.connect();
    try {
      const adminView = await effectiveP05Grants(client,
        { kind: 'staff-web', staffId: fixture.reviewer, role: 'ADMIN', authVersion: 0 },
        { id: adminRoleId, type: 'SYSTEM', code: 'ADMIN' });
      expect(adminView).toEqual([{ code: 'requests.read', scope: 'GLOBAL' }, { code: 'requests.review', scope: 'GLOBAL' }]);
      const managerView = await effectiveP05Grants(client,
        { kind: 'staff-web', staffId: managerId, role: 'MANAGER', authVersion: 0 },
        { id: customRoleId, type: 'CUSTOM', code: customRoleCode });
      expect(managerView).toEqual([{ code: 'requests.read', scope: 'CITY' }, { code: 'requests.review', scope: 'CITY' }]);
      // The same CUSTOM role assigned to a Telegram channel grants nothing.
      await expect(effectiveP05Grants(client,
        { kind: 'staff-telegram', staffId: managerId, role: 'TECHNICIAN', authVersion: 0, telegramUserId: '1' },
        { id: customRoleId, type: 'CUSTOM', code: customRoleCode })).resolves.toEqual([]);
      // A pre-P05 catalog cannot grant authority: an unknown code in the source list is ignored.
      await expect(effectiveP05Grants(client,
        { kind: 'staff-web', staffId: managerId, role: 'MANAGER', authVersion: 0 },
        { id: customRoleId, type: 'SYSTEM', code: 'TECHNICIAN' })).resolves.toEqual([]);
    } finally {
      client.release();
    }
  });

  it('authorizes a real target city under the shared policy lock and keeps foreign/missing cities 404', async () => {
    const service = auth();
    const seen = await service.withP05(adminProof, ['requests.review'], async (ctx) => {
      await ctx.authorizeCity(city.id);
      return { sessionId: ctx.sessionId, staffId: ctx.staffId, cityIds: ctx.cityIds, role: ctx.role.code };
    });
    expect(seen).toEqual({ sessionId: adminSessionId, staffId: fixture.reviewer, cityIds: null, role: 'ADMIN' });
    // The GLOBAL administrator resolves any existing city.
    await expect(service.withP05(adminProof, ['requests.review'], async (ctx) => {
      await ctx.authorizeCity(otherCity.id);
      return 'ok';
    })).resolves.toBe('ok');
    // A nonexistent city is the same 404 as an out-of-scope one.
    await expect(service.withP05(adminProof, ['requests.review'], async (ctx) => {
      await ctx.authorizeCity(randomUUID());
      return 'ok';
    })).rejects.toMatchObject({ status: 404 });
    // The CITY-scoped manager resolves only its live administrative assignment.
    await expect(service.withP05(managerProof, ['requests.review'], async (ctx) => {
      await ctx.authorizeCity(city.id);
      return ctx.cityIds;
    })).resolves.toEqual([city.id]);
    await expect(service.withP05(managerProof, ['requests.review'], async (ctx) => {
      await ctx.authorizeCity(otherCity.id);
      return 'ok';
    })).rejects.toMatchObject({ status: 404 });
    // A command that never names its target cannot commit.
    await expect(service.withP05(managerProof, ['requests.review'], () => Promise.resolve('forgot')))
      .rejects.toMatchObject({ status: 500 });
  });

  it('refuses the legacy PUT that omits an enabled P05 grant with zero effect, then honors the explicit revoke', async () => {
    const roles = new RolesService(auth());
    expect(await roleVersion()).toBe(1);
    // The pre-P05 client cannot express the enabled pair: refuse instead of silently
    // preserving it, and write nothing at all.
    await expect(roles.replacePermissions(adminProof, customRoleId, 1, [])).rejects.toBeInstanceOf(ConflictException);
    expect(await roleVersion()).toBe(1);
    expect(await grantEnabled('requests.read')).toBe(true);
    expect(await grantEnabled('requests.review')).toBe(true);
    // The opt-in revocation is the only path that disables a P05 grant. The retained
    // grant must be named explicitly: an omission is always an incomplete set.
    await expect(roles.replacePermissions(adminProof, customRoleId, 1,
      [{ code: 'requests.read', scope: 'CITY' }], ['requests.review']))
      .resolves.toMatchObject({ version: 2 });
    expect(await roleVersion()).toBe(2);
    expect(await grantEnabled('requests.review')).toBe(false);
    expect(await grantEnabled('requests.read')).toBe(true);
    // The revocation wins for every later command: review is 403, read still works.
    await expect(auth().withP05(managerProof, ['requests.review'], async (ctx) => {
      await ctx.authorizeCity(city.id);
      return 'ok';
    })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(auth().withP05(managerProof, ['requests.read'], async (ctx) => {
      await ctx.authorizeCity(city.id);
      return 'read';
    })).resolves.toBe('read');
    // A stale version is a 412, not a second write.
    await expect(roles.replacePermissions(adminProof, customRoleId, 1,
      [{ code: 'requests.read', scope: 'CITY' }], [])).rejects.toMatchObject({ status: 412 });
  });

  it('refuses a new admin-city assignment that would widen a live CITY P05 grant', async () => {
    const expansion = async (staffId: string): Promise<'allowed' | 'forbidden'> => {
      const client = await fixture.runtime.connect();
      try {
        await client.query('BEGIN');
        await requireNoP05CityExpansion({ client }, staffId);
        await client.query('ROLLBACK');
        return 'allowed';
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        if (error instanceof ForbiddenException) { return 'forbidden'; }
        throw error;
      } finally {
        client.release();
      }
    };
    // `requests.read` is still enabled for the manager: a new city would widen it.
    await expect(expansion(managerId)).resolves.toBe('forbidden');
    // A SYSTEM MANAGER without any P05 grant keeps the legacy assignment path.
    await expect(expansion(unprivilegedManagerId)).resolves.toBe('allowed');
  });

  it('never lets the runtime role issue a P05 grant, while operator provisioning becomes effective', async () => {
    await expect(fixture.runtime.query(
      "INSERT INTO foundation.role_permissions (role_id,permission_code,scope_type) VALUES ($1,'requests.cancel','CITY')",
      [customRoleId])).rejects.toMatchObject({ code: '42501' });
    await expect(fixture.runtime.query(
      "INSERT INTO foundation.role_permissions (role_id,permission_code,scope_type) VALUES ($1,'requests.ready','GLOBAL')",
      [customRoleId])).rejects.toMatchObject({ code: '42501' });
    // The reviewed operator path can provision the exact pair, and only that pair.
    await fixture.migrator.query(
      "INSERT INTO foundation.role_permissions (role_id,permission_code,scope_type) VALUES ($1,'requests.cancel','CITY')",
      [customRoleId]);
    const client = await fixture.runtime.connect();
    try {
      const grants = await effectiveP05Grants(client,
        { kind: 'staff-web', staffId: managerId, role: 'MANAGER', authVersion: 0 },
        { id: customRoleId, type: 'CUSTOM', code: customRoleCode });
      expect(grants.map((grant) => grant.code)).toEqual(['requests.cancel', 'requests.read']);
    } finally {
      client.release();
    }
    // An issued GLOBAL grant on a non-administrator role is not authority: the stored row
    // is valid, but the projection drops it (never widened by a drifted row).
    await expect(fixture.migrator.query(
      "INSERT INTO foundation.role_permissions (role_id,permission_code,scope_type) VALUES ($1,'requests.create','GLOBAL')",
      [customRoleId])).rejects.toMatchObject({ code: '23514' });
  });
});





