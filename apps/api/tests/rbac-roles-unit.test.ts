import 'reflect-metadata';
import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { PERMISSION_CONTRACT, PROTECTED_CAPABILITIES, STAFF_CAPABILITIES } from '../src/authz/capability.js';
import type { Capability } from '../src/authz/capability.js';
import type { AuthorizationServiceApi, EffectiveRole, StaffWriteContext } from '../src/authz/authorization.service.js';
import { catalogEntry, checkReplacement, createMetadata, emptyBody, metadataPatch, replacement } from '../src/roles/role-policy.js';
import type { RoleGrant } from '../src/roles/role-policy.js';
import { RolesService } from '../src/roles/index.js';

const admin = { id: '00000000-0000-4000-8000-000000000003', type: 'SYSTEM', code: 'ADMIN' } as const;
const custom = { id: '00000000-0000-4000-8000-000000000004', type: 'CUSTOM', code: 'CUSTOM_EXAMPLE' } as const;
const staffId = '00000000-0000-4000-8000-000000000005';
const grant = (code: Capability): RoleGrant => ({ code, scope: PERMISSION_CONTRACT[code] });
const perms = STAFF_CAPABILITIES.map((code) => ({ ...grant(code), description: 'test', module: 'staff', protected: PROTECTED_CAPABILITIES.includes(code) }));
const session = { kind: 'staff-web' as const, token: 'synthetic-test-token' };
const view = (permissions: readonly Capability[] = STAFF_CAPABILITIES, role: EffectiveRole = admin) => ({ role, staffId, permissions });

/** Mock only the transaction boundary/driver. Fail on unexpected SQL; assert projections
 * cannot issue a second unguarded read, and all write/audit SQL uses that one callback. */
function fixture(permissions: readonly Capability[], responses: { contains: string; rows?: unknown[] }[], role: EffectiveRole = admin) {
  const statements: { sql: string; params?: unknown[] }[] = [];
  const query = (sql: string, params?: unknown[]) => {
    const response = responses[statements.length];
    if (!response || !sql.includes(response.contains)) { throw new Error(`Unexpected query: ${sql}`); }
    statements.push(params ? { sql, params } : { sql });
    const rows = response.rows ?? [];
    return Promise.resolve({ rowCount: rows.length, rows });
  };
  const ctx: StaffWriteContext = { ...view(permissions, role), principal: { kind: 'staff-web', role: 'ADMIN', authVersion: 1, staffId }, client: { query } as unknown as PoolClient };
  const execute = <T>(_proof: unknown, capability: Capability, _scope: unknown, callback: (ctx: StaffWriteContext) => Promise<T>) => {
    if (!permissions.includes(capability)) { return Promise.reject(new ForbiddenException()); }
    return callback(ctx);
  };
  const read = vi.fn<(capability: Capability) => void>();
  const write = vi.fn<(capability: Capability) => void>();
  const auth: AuthorizationServiceApi = { authorize: vi.fn(), inspectAccess: vi.fn(),
    authorizeForRead: (p, c, s, operation) => { read(c); return execute(p, c, s, operation); },
    authorizeForWrite: (p, c, s, operation) => { write(c); return execute(p, c, s, operation); },
  };
  return { service: new RolesService(auth), statements, read, write };
}
const customRow = { ...custom, name: 'role name', description: '', status: 'ACTIVE', version: 2 };

describe('role-management input allowlists', () => {
  it('accepts only editable metadata, normalizes text, distinguishes PATCH omission from empty description', () => {
    expect(createMetadata({ name: '  dispatcher  ', description: '' })).toEqual({ name: 'dispatcher', description: '' });
    expect(metadataPatch({ description: ' ' })).toEqual({ description: '' });
    for (const value of [{}, { name: '' }, { name: '\u202esecret' }, { name: 'x'.repeat(81) }, { description: 'x'.repeat(501) },
      { type: 'SYSTEM' }, { role_type: 'CUSTOM' }, { code: 'ADMIN' }, { permissions: [] }, { version: 9 }, { status: 'ACTIVE' },
      { name: 9 }, { description: null }, ['ok'], null, JSON.parse('{"__proto__":{"role":"ADMIN"}}') as unknown]) {
      expect(() => metadataPatch(value)).toThrow(BadRequestException);
    }
    expect(() => createMetadata({ name: 'dispatcher' })).toThrow(BadRequestException);
    expect(() => { emptyBody({ updatedBy: staffId }); }).toThrow(BadRequestException);
    expect(() => { emptyBody({}); }).not.toThrow();
  });
  it('enforces exact code/scope pairs, uniqueness, no CITY or direct grants', () => {
    expect(replacement({ permissions: [] })).toEqual([]);
    expect(replacement({ permissions: [grant('roles.read'), grant('staff.self.update')] })).toEqual([grant('roles.read'), grant('staff.self.update')]);
    for (const value of [{ scope: 'CITY', code: 'staff.read' }, { scope: 'SELF', code: 'staff.read' }, { scope: 'GLOBAL', code: 'staff.self.read' },
      { scope: 'GLOBAL', code: 'staff.manage' }, { ...grant('staff.read'), staffId }, { code: '__proto__', scope: 'GLOBAL' }, null]) {
      expect(() => replacement({ permissions: [value] })).toThrow(BadRequestException);
    }
    expect(() => replacement({ permissions: [grant('roles.read'), grant('roles.read')] })).toThrow(BadRequestException);
    expect(() => replacement({ permissions: [], role: 'ADMIN' })).toThrow(BadRequestException);
    expect(() => replacement({ permissions: 'staff.read' })).toThrow(BadRequestException);
  });
});

describe('role permission policy', () => {
  it('excludes unknown and mismarked catalog rows', () => {
    const p = { module: 'roles', description: 'test', protected: false };
    expect(catalogEntry({ ...p, code: 'roles.read' })).toMatchObject({ code: 'roles.read', scope: 'GLOBAL' });
    expect(catalogEntry({ ...p, code: 'roles.archive' })).toBeNull();
    expect(catalogEntry({ ...p, code: 'unknown.capability' })).toBeNull();
  });
  it('requires all protected grants on ADMIN and rejects all protected grants on any other role', () => {
    const protectedGrants = PROTECTED_CAPABILITIES.map(grant);
    expect(() => { checkReplacement(view(), admin, perms, protectedGrants, protectedGrants); }).not.toThrow();
    for (const omitted of PROTECTED_CAPABILITIES) {
      expect(() => { checkReplacement(view(), admin, perms, protectedGrants, protectedGrants.filter((g) => g.code !== omitted)); }).toThrow(ForbiddenException);
      expect(() => { checkReplacement(view(), custom, perms, [], [grant(omitted)]); }).toThrow(ForbiddenException);
    }
    expect(() => { checkReplacement(view(), { ...admin, code: 'MANAGER' }, perms, [], [grant('roles.create')]); }).toThrow(ForbiddenException);
  });
  it('can retain, but cannot delegate absent ordinary rights, and cannot grant a new right to own effective role', () => {
    const ordinary = grant('staff.create');
    const limited = view([...PROTECTED_CAPABILITIES, 'roles.read']);
    const mandatory = PROTECTED_CAPABILITIES.map(grant);
    expect(() => { checkReplacement(limited, admin, perms, mandatory, [...mandatory, ordinary]); }).toThrow(ForbiddenException);
    expect(() => { checkReplacement(limited, custom, perms, [], [ordinary]); }).toThrow(ForbiddenException);
    expect(() => { checkReplacement(limited, custom, perms, [ordinary], [ordinary]); }).not.toThrow();
    expect(() => { checkReplacement(limited, custom, perms, [ordinary], []); }).not.toThrow();
    for (const existing of [[], [ordinary]]) {
      expect(() => { checkReplacement(view(PROTECTED_CAPABILITIES), custom, perms, existing, [ordinary]); }).toThrow(ForbiddenException);
    }
    expect(() => { checkReplacement(view(), custom, [], [], [ordinary]); }).toThrow(BadRequestException);
  });
});

describe('role management commands', () => {
  it('creates CUSTOM only: no grants, version receipt only without read, no free-form text or session token in audit', async () => {
    const fx = fixture(['roles.create'], [{ contains: 'INSERT INTO foundation.roles', rows: [{ id: custom.id, version: 1 }] }, { contains: 'INSERT INTO foundation.audit_logs' }]);
    const meta = { name: 'TEST-PRIVATE-NAME', description: 'TEST-PRIVATE-DESCRIPTION' };
    const result = await fx.service.create(session, meta);
    expect(result).toEqual({ id: result.id, version: 1 });
    expect(fx.write).toHaveBeenCalledExactlyOnceWith('roles.create');
    expect(fx.read).not.toHaveBeenCalled();
    expect(fx.statements[0]?.params?.slice(2)).toEqual([meta.name, meta.description, staffId]);
    expect(fx.statements[0]?.params?.[1]).toMatch(/^CUSTOM_[A-F0-9]{32}$/);
    const event = fx.statements[1]?.params;
    expect(event?.[1]).toBe('ROLE_CREATED');
    expect(String(event?.[3])).toContain(staffId);
    expect(String(event?.[3])).toContain(result.id);
    for (const forbidden of [session.token, meta.name, meta.description]) { expect(JSON.stringify(event)).not.toContain(forbidden); }
  });
  it('checks version, SYSTEM/ARCHIVED status and active employee assignment before writes', async () => {
    for (const row of [{ ...admin, status: 'ACTIVE', version: 2 }, { ...customRow, status: 'ARCHIVED' }]) {
      const fx = fixture(['roles.archive'], [{ contains: 'FOR UPDATE', rows: [row] }]);
      await expect(fx.service.archive(session, row.id, 2)).rejects.toBeInstanceOf(ConflictException);
    }
    const stale = fixture(['roles.update'], [{ contains: 'FOR UPDATE', rows: [customRow] }]);
    await expect(stale.service.patch(session, custom.id, 3, { name: 'changed' })).rejects.toMatchObject({ status: 412 });
    const used = fixture(['roles.archive'], [{ contains: 'FOR UPDATE', rows: [customRow] }, { contains: "s.employment_state='ACTIVE'", rows: [{ id: staffId }] }]);
    await expect(used.service.archive(session, custom.id, 2)).rejects.toBeInstanceOf(ConflictException);
  });
  it('rejects manager mutation even if callback gave that role an invalid protected grant; roster needs actual staff.read', async () => {
    const manager = { ...admin, code: 'MANAGER' };
    const fx = fixture(['roles.create', 'roles.read'], [], manager);
    await expect(fx.service.create(session, { name: 'role', description: '' })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(fx.service.members(session, custom.id)).rejects.toBeInstanceOf(ForbiddenException);
    expect(fx.statements).toHaveLength(0);
  });
  it('returns identical receipts for write-only matching and differing metadata/grant inputs', async () => {
    for (const name of [customRow.name, 'different name']) {
      const fx = fixture(['roles.update'], [{ contains: 'FOR UPDATE', rows: [customRow] }, { contains: 'UPDATE foundation.roles SET name=' }, { contains: 'INSERT INTO foundation.audit_logs' }]);
      await expect(fx.service.patch(session, custom.id, 2, { name })).resolves.toEqual({ id: custom.id, version: 3 });
      expect(fx.statements).toHaveLength(3);
    }
    for (const desired of [[], [grant('staff.self.update')]]) {
      const fx = fixture(['roles.permissions.manage', 'staff.self.update'], [{ contains: 'FOR UPDATE', rows: [customRow] },
        { contains: 'FROM foundation.permissions', rows: perms }, { contains: 'AND enabled ORDER BY' },
        ...(desired.length ? [{ contains: 'DO UPDATE SET enabled=EXCLUDED.enabled' }] : []),
        { contains: 'SET version=version+1' }, { contains: 'INSERT INTO foundation.audit_logs' }]);
      await expect(fx.service.replacePermissions(session, custom.id, 2, desired)).resolves.toEqual({ id: custom.id, version: 3 });
    }
  });
  it('drops own roles.read without disclosing detail on the successful write', async () => {
    const mandatory = PROTECTED_CAPABILITIES.map(grant);
    const fx = fixture([...PROTECTED_CAPABILITIES, 'roles.read'], [
      { contains: 'FOR UPDATE', rows: [{ ...customRow, ...admin }] }, { contains: 'FROM foundation.permissions', rows: perms },
      { contains: 'AND enabled ORDER BY', rows: [...mandatory, grant('roles.read')] },
      { contains: 'SET enabled=false' }, { contains: 'SET version=version+1' }, { contains: 'INSERT INTO foundation.audit_logs' },
    ]);
    await expect(fx.service.replacePermissions(session, admin.id, 2, mandatory)).resolves.toEqual({ id: admin.id, version: 3 });
    expect(fx.statements[3]?.params).toEqual([admin.id, ['roles.read']]);
    expect(fx.statements).toHaveLength(6);
  });
});
