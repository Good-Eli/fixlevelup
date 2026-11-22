import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, type Access, type Grant, type P04Grant, type Permission, type Role } from '../app/crm/access/api';
import { allowedScopes, canEditGrant, delegable, holdsGlobalP04, p04GrantChanges, p04ReplacementAllowed } from '../app/crm/access/workspace';

const id = '11111111-1111-4111-8111-111111111111';
const target = '22222222-2222-4222-8222-222222222222';
const founder: Access = { staffId: id, role: { id, type: 'SYSTEM', code: 'ADMIN' }, permissions: ['roles.read', 'roles.permissions.manage'] };
const role: Role = { id: target, type: 'SYSTEM', code: 'ADMIN', name: 'Test', description: null,
  status: 'ACTIVE', version: 4, assignedCount: 0, activeAssignedCount: 0, updatedAt: 'test', updatedBy: null, permissions: [] };
const manager: Role = { ...role, code: 'MANAGER' };
const custom: Role = { ...role, type: 'CUSTOM', code: 'WEB_CUSTOM' };
const technician: Role = { ...role, code: 'TECHNICIAN' };
const city = { code: 'pricing.read', scope: 'CITY' } as const;
const global = { code: 'pricing.read', scope: 'GLOBAL' } as const;
const exact = (p04Permissions: readonly P04Grant[] = [global]): Access => ({ ...founder, p04Permissions });
const offer = (code: P04Grant['code'], scopes: Permission['scopes'] = ['GLOBAL']): Permission => ({
  code, scopes, scope: scopes[0] ?? 'GLOBAL', module: code.split('.')[0] ?? '', description: 'test', protected: false,
});
const pricing = offer('pricing.read', ['CITY', 'GLOBAL']);
const company = ['catalog.read', 'catalog.manage', 'pricing.rules.read', 'pricing.rules.manage',
  'content.externalreviews.read', 'content.externalreviews.manage', 'content.externalreviews.publish'] as const;
function stub(...responses: unknown[]) {
  const fetch = vi.fn<typeof globalThis.fetch>();
  for (const data of responses) { fetch.mockResolvedValueOnce(Response.json({ data })); }
  vi.stubGlobal('fetch', fetch);
  return api(new AbortController().signal);
}
afterEach(() => { vi.unstubAllGlobals(); });

describe('P04-03 role editor response boundary', () => {
  it('accepts an absent field and the exact nine grants, without trusting legacy strings', async () => {
    const all = [...company.map(code => ({ code, scope: 'GLOBAL' })), global, { code: 'pricing.manage', scope: 'CITY' }];
    const c = stub({ ...founder, permissions: [...founder.permissions, global.code] }, { ...founder, p04Permissions: all });
    const old = await c.access();
    expect(old).not.toHaveProperty('p04Permissions');
    expect(holdsGlobalP04(old, global.code)).toBe(false);
    expect((await c.access()).p04Permissions).toEqual(all);
  });

  it('rejects malformed, duplicate and role-inapplicable P04 grants', async () => {
    const invalid = [null, {}, [global, city], [{ code: 'pricing.write', scope: 'GLOBAL' }],
      [{ code: 'catalog.read', scope: 'CITY' }], [{ ...global, scope: 'SELF' }], [{ ...global, unchecked: true }],
      Array.from({ length: 10 }, () => global)];
    const c = stub(...invalid.map(p04Permissions => ({ ...founder, p04Permissions })),
      { ...founder, role: manager, p04Permissions: [global] },
      { ...founder, role: technician, p04Permissions: [city] },
      { ...founder, role: custom, p04Permissions: [city] });
    for (let i = 0; i < invalid.length + 2; i++) { await expect(c.access()).rejects.toThrow(); }
    expect((await c.access()).p04Permissions).toEqual([city]);
  });

  it('validates stored role grants and P04 permission catalog flags and scopes', async () => {
    const c = stub({ ...custom, permissions: [global] }, { ...role, permissions: [city, global] },
      { ...custom, permissions: [city] }, { items: [{ ...pricing, scopes: ['CITY', 'CITY'] }] },
      { items: [{ ...pricing, protected: true }] }, { items: [{ ...pricing, module: 'catalog' }] },
      { items: [pricing, pricing] }, { items: [pricing, ...company.map(code => offer(code))] });
    await expect(c.role(target)).rejects.toThrow('Invalid P04 grant');
    await expect(c.role(target)).rejects.toThrow('Invalid P04 grant');
    expect((await c.role(target)).permissions).toEqual([city]);
    for (let i = 0; i < 3; i++) { await expect(c.catalog()).rejects.toThrow('Invalid P04 catalog permission'); }
    await expect(c.catalog()).rejects.toThrow('Duplicate P04 catalog permission');
    expect(await c.catalog()).toHaveLength(8);
  });
});

describe('P04-03 role and staff projections', () => {
  it('offers both pricing scopes only to SYSTEM ADMIN; disallows company grants on every other role', () => {
    for (const code of ['pricing.read', 'pricing.manage'] as const) {
      const permission = offer(code, ['CITY', 'GLOBAL']);
      expect(allowedScopes(role, permission)).toEqual(['CITY', 'GLOBAL']);
      expect(allowedScopes(manager, permission)).toEqual(['CITY']);
      expect(allowedScopes(custom, permission)).toEqual(['CITY']);
      expect(allowedScopes(technician, permission)).toEqual([]);
    }
    for (const code of company) {
      expect(allowedScopes(role, offer(code))).toEqual(['GLOBAL']);
      for (const other of [manager, custom, { ...custom, code: 'ADMIN' }, technician]) {
        expect(allowedScopes(other, offer(code))).toEqual([]);
      }
    }
  });

  it('requires SYSTEM ADMIN, roles.permissions.manage and the exact GLOBAL code for added scopes and assignment', () => {
    const targetRole = { ...manager, permissions: [city] };
    const impostors = [founder, exact([city]), exact([{ code: 'pricing.manage', scope: 'GLOBAL' }]), exact([global, city]),
      { ...exact(), role: custom }, { ...exact(), permissions: ['roles.read'] }];
    for (const actor of impostors) {
      expect(canEditGrant(actor, manager, pricing, false)).toBe(false);
      expect(delegable(actor, targetRole)).toBe(false);
      expect(p04ReplacementAllowed(actor, manager, [city])).toBe(false);
    }
    expect(canEditGrant(exact(), manager, pricing, false)).toBe(true);
    expect(delegable(exact(), targetRole)).toBe(true);
    expect(p04ReplacementAllowed(exact(), manager, [city])).toBe(true);
    expect(p04ReplacementAllowed(exact(), manager, [global])).toBe(false);
    expect(p04ReplacementAllowed(exact(), role, [global, city])).toBe(false);
    expect(delegable(exact(), { ...targetRole, permissions: [global] })).toBe(false);
  });

  it('keeps only an exact and visible existing grant on another role without delegation authority', () => {
    const existing = { ...role, permissions: [global] };
    expect(canEditGrant(founder, existing, pricing, false)).toBe(true);
    expect(p04ReplacementAllowed(founder, existing, [global])).toBe(true);
    expect(p04ReplacementAllowed(founder, existing, [city])).toBe(false);
    expect(p04ReplacementAllowed(founder, { ...existing, id }, [global])).toBe(false);
    expect(p04ReplacementAllowed({ ...founder, permissions: ['roles.permissions.manage'] }, existing, [global])).toBe(false);
    expect(delegable(founder, existing)).toBe(false);
  });

  it('detects every addition, scope change and removal for the role-wide warning', () => {
    const old: Grant[] = [city, { code: 'catalog.read', scope: 'GLOBAL' }, { code: 'staff.read', scope: 'GLOBAL' }];
    const next: Grant[] = [global, { code: 'content.externalreviews.manage', scope: 'GLOBAL' }];
    expect(p04GrantChanges(old, next)).toEqual([
      { code: 'pricing.read', from: 'CITY', to: 'GLOBAL' },
      { code: 'catalog.read', from: 'GLOBAL', to: undefined },
      { code: 'content.externalreviews.manage', from: undefined, to: 'GLOBAL' },
    ]);
    expect(p04GrantChanges(old, old.toReversed())).toEqual([]);
  });
});
