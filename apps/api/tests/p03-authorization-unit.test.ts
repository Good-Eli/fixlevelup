import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { AuthorizationService, P03CommitUnknown } from '../src/authz/authorization.service.js';
import type { AccessView, P03Target, SessionProof } from '../src/authz/authorization.service.js';
import type { P03Capability } from '../src/authz/capability.js';
import { catalogEntry, checkReplacement, grantableScopes } from '../src/roles/role-policy.js';

const staffId = '00000000-0000-4000-8000-000000000005';
const cityA = '00000000-0000-4000-8000-0000000000a1';
const cityB = '00000000-0000-4000-8000-0000000000b1';
const crm: SessionProof = { kind: 'staff-web', token: 'a'.repeat(43) };
const telegram: SessionProof = { kind: 'staff-telegram', token: 'b'.repeat(43) };
const company = { scope: 'COMPANY' } as const;
const city = { scope: 'CITY', cityId: cityA } as const;
const admin = { id: 'admin-role', type: 'SYSTEM', code: 'ADMIN' } as const;
const custom = { id: 'custom-role', type: 'CUSTOM', code: 'CUSTOM_A' } as const;

interface Options {
  role?: typeof admin | typeof custom;
  telegram?: boolean;
  grants?: readonly { code: string; scope: string; source: string }[];
  mayEditRoles?: boolean;
  expiresAfterCallback?: boolean;
  cityExists?: boolean;
  commitError?: Error;
}
const grant = (code: P03Capability, scope: 'GLOBAL' | 'CITY', source = 'ROLE') => ({ code, scope, source });
function fixture(options: Options) {
  const statements: string[] = [];
  const role = options.role ?? admin;
  const marker = options.telegram ? 'TECHNICIAN' : role.type === 'CUSTOM' ? 'MANAGER' : 'ADMIN';
  const query = (sql: string) => {
    statements.push(sql);
    if (sql === 'COMMIT' && options.commitError) { return Promise.reject(options.commitError); }
    let rows: readonly unknown[] = [];
    if (sql.startsWith('BEGIN') || sql.includes('pg_advisory_xact_lock') || ['CALLBACK', 'RESOLVE', 'COMMIT', 'ROLLBACK'].includes(sql)) {
      // Only plumbing/sentinels need no data.
    } else if (sql.startsWith('SELECT staff_id, telegram_link_id')) {
      rows = [{ staff_id: staffId, telegram_link_id: options.telegram ? 'link' : null }];
    } else if (sql.startsWith('SELECT id, role, auth_version')) {
      rows = [{ id: staffId, role: marker, auth_version: 8 }];
    } else if (sql.startsWith('SELECT telegram_user_id')) {
      rows = [{ telegram_user_id: '12345' }];
    } else if (sql.startsWith('SELECT id FROM foundation.web_sessions')) {
      rows = [{ id: 'session' }];
    } else if (sql.includes('FROM foundation.web_sessions ws')) {
      rows = options.expiresAfterCallback ? [] : [{ id: staffId }];
    } else if (sql.includes('p03_bootstrap_permissions')) {
      rows = options.grants ?? [];
    } else if (sql.includes('geography_bootstrap_permissions')) {
      rows = [];
    } else if (sql.startsWith('SELECT r.id, r.code, r.role_type')) {
      rows = [{ ...role, role_type: role.type, permission_code: options.mayEditRoles ? 'roles.permissions.manage' : null,
        scope_type: options.mayEditRoles ? 'GLOBAL' : null, protected: options.mayEditRoles ? true : null }];
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

describe('P03 authorization on one locked transaction', () => {
  it('intersects GLOBAL manage with CITY read, never inferring read or admitting a foreign city', async () => {
    const { auth } = fixture({ grants: [grant('content.manage', 'GLOBAL'), grant('content.read', 'CITY')] });
    const callback = vi.fn(async () => Promise.resolve('ok'));
    const required = ['content.manage', 'content.read'] as const;
    await expect(auth.withP03(crm, 'write', required, company, callback)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(auth.withP03(crm, 'write', required, { scope: 'CITY', cityId: cityB }, callback)).rejects.toMatchObject({ status: 404 });
    await expect(auth.withP03(crm, 'write', [...required, 'content.publish'], city, callback)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    expect(callback).not.toHaveBeenCalled();
    await expect(auth.withP03(crm, 'write', required, city, async (ctx) => Promise.resolve(ctx.cityIds))).resolves.toEqual([cityA]);
    const noCity = fixture({ grants: [grant('content.read', 'GLOBAL')], cityExists: false });
    await expect(noCity.auth.withP03(crm, 'read', ['content.read'], city, callback)).rejects.toMatchObject({ status: 404 });
  });

  it('checks operation grants before an identity lookup; a hidden resolved target is 404', async () => {
    const resolver = vi.fn(async (): Promise<P03Target> => Promise.resolve(company));
    const callback = vi.fn(async () => Promise.resolve('ok'));
    await expect(fixture({}).auth.withP03(crm, 'read', ['content.read'], resolver, callback)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    expect(resolver).not.toHaveBeenCalled();
    const { auth } = fixture({ grants: [grant('content.read', 'CITY')] });
    await expect(auth.withP03(crm, 'read', ['content.read'], resolver, callback)).rejects.toMatchObject({ status: 404 });
    expect(resolver).toHaveBeenCalledOnce();
    expect(callback).not.toHaveBeenCalled();
  });

  it('masks the same CUSTOM role on TG, without changing the web manager matrix', async () => {
    const grants = [grant('content.read', 'CITY'), grant('content.manage', 'GLOBAL'), grant('legal.read', 'GLOBAL'),
      grant('references.paymentmethod.read', 'GLOBAL'), grant('settings.readiness.read', 'GLOBAL'),
      grant('settings.manage', 'GLOBAL', 'BOOTSTRAP'), grant('content.publish', 'CITY', 'UNKNOWN')];
    const web = fixture({ role: custom, grants });
    await expect(web.auth.inspectAccess(crm)).resolves.toMatchObject({ p03Permissions: [
      { code: 'content.read', scope: 'CITY' }, { code: 'references.paymentmethod.read', scope: 'GLOBAL' },
      { code: 'settings.readiness.read', scope: 'GLOBAL' },
    ] });
    const tg = fixture({ role: custom, grants, telegram: true });
    await expect(tg.auth.inspectAccess(telegram)).resolves.toMatchObject({ p03Permissions: [] });
    await expect(tg.auth.withP03(telegram, 'read', ['content.read'], city, async () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
    expect(tg.statements.some((sql) => sql.includes('p03_bootstrap_permissions'))).toBe(false);
  });

  it('uses the unrevoked personal source only on the current assignment and lets the wider grant win', async () => {
    const { auth, statements } = fixture({ grants: [grant('content.read', 'GLOBAL', 'BOOTSTRAP'), grant('content.read', 'CITY')] });
    await expect(auth.inspectAccess(crm)).resolves.toMatchObject({ p03Permissions: [{ code: 'content.read', scope: 'GLOBAL' }] });
    const sql = statements.find((item) => item.includes('p03_bootstrap_permissions'));
    expect(sql).toContain('b.assignment_id=ca.id');
    expect(sql).toContain('b.revoked_at IS NULL');
    expect(sql).toContain('p.active AND NOT p.protected');
    expect(sql).not.toContain('staff_bootstrap_marker');
  });

  it.each(['read', 'write'] as const)('checks the session clock after the last %s result and rolls back expired proof', async (mode) => {
    const { auth, statements } = fixture({ grants: [grant('content.read', 'GLOBAL')], expiresAfterCallback: true });
    await expect(auth.withP03(crm, mode, ['content.read'], company, async ({ client }) => {
      await client.query('CALLBACK');
      return { secret: 'must not escape' };
    })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(statements[0]).toBe('BEGIN ISOLATION LEVEL READ COMMITTED');
    expect(statements[1]).toContain(mode === 'read' ? 'pg_advisory_xact_lock_shared' : 'pg_advisory_xact_lock(');
    expect(statements.slice(-3)[0]).toBe('CALLBACK');
    expect(statements.slice(-3)[1]).toContain('ws.absolute_expires_at>clock_timestamp()');
    expect(statements.slice(-3)[1]).toContain('ws.idle_expires_at>clock_timestamp()');
    expect(statements.at(-1)).toBe('ROLLBACK');
    expect(statements).not.toContain('COMMIT');
  });

  it('signals only an uncertain write COMMIT, discards the client, and does not retry the callback', async () => {
    const grants = [grant('content.manage', 'GLOBAL'), grant('content.read', 'GLOBAL')];
    const callback = vi.fn(async () => Promise.resolve('secret receipt'));
    const { auth, statements, release } = fixture({ grants, commitError: new Error('raw driver data') });
    await expect(auth.withP03(crm, 'write', ['content.manage', 'content.read'], company, callback))
      .rejects.toEqual(new P03CommitUnknown());
    expect(callback).toHaveBeenCalledOnce();
    expect(statements.at(-1)).toBe('COMMIT');
    expect(statements.at(-2)).toContain('clock_timestamp()');
    expect(statements).not.toContain('ROLLBACK');
    expect(release).toHaveBeenCalledWith(true);
    const knownRejection = Object.assign(new Error('raw constraint data'), { severity: 'ERROR', code: '40001' });
    const conflict = fixture({ grants, commitError: knownRejection });
    await expect(conflict.auth.withP03(crm, 'write', ['content.manage', 'content.read'], company, callback))
      .rejects.toMatchObject({ status: 409 });
    expect(conflict.statements.at(-1)).toBe('ROLLBACK');
  });

  it('limits empty capability access to protected bootstrap inspection and picker access to the matching domain', async () => {
    const founder = fixture({ mayEditRoles: true });
    const callback = vi.fn(async () => Promise.resolve('ok'));
    await expect(founder.auth.withP03(crm, 'read', [], company, callback)).resolves.toBe('ok');
    await expect(founder.auth.withP03(crm, 'write', [], company, callback)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(fixture({}).auth.withP03(crm, 'read', [], company, callback)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    const manager = fixture({ role: custom, grants: [grant('content.read', 'CITY')] });
    await expect(manager.auth.withP03Discovery(crm, 'content', async (_ctx, ids) => Promise.resolve(ids))).resolves.toEqual([cityA]);
    await expect(manager.auth.withP03Discovery(crm, 'callback_interval', callback)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    expect(callback).toHaveBeenCalledOnce();
  });
});

describe('P03 role grant delegation uses exact stored scopes', () => {
  it('lets only a visible other role keep identical grants without same-code GLOBAL', () => {
    const actor: AccessView = { staffId, role: admin, permissions: ['roles.read'], p03Permissions: [{ code: 'content.read', scope: 'GLOBAL' }] };
    const row = catalogEntry({ code: 'content.manage', module: 'content', description: 'Manage', protected: false });
    if (!row) { throw new Error('expected catalog row'); }
    const cityGrant = [{ code: 'content.manage', scope: 'CITY' }] as const;
    const globalGrant = [{ code: 'content.manage', scope: 'GLOBAL' }] as const;
    expect(() => { checkReplacement(actor, custom, [row], cityGrant, cityGrant); }).not.toThrow();
    expect(() => { checkReplacement(actor, custom, [row], [], cityGrant); }).toThrow(expect.objectContaining({ status: 403 }));
    expect(() => { checkReplacement({ ...actor, permissions: [] }, custom, [row], cityGrant, cityGrant); }).toThrow(expect.objectContaining({ status: 403 }));
    expect(() => { checkReplacement(actor, custom, [row], cityGrant, globalGrant); }).toThrow(expect.objectContaining({ status: 400 }));
    expect(() => { checkReplacement({ ...actor, p03Permissions: [{ code: 'content.manage', scope: 'GLOBAL' }] },
      custom, [row], [], cityGrant); }).not.toThrow();
    expect(grantableScopes('legal.read', custom)).toEqual([]);
    expect(grantableScopes('references.paymentmethod.read', custom)).toEqual(['GLOBAL']);
    expect(catalogEntry({ ...row, module: 'staff' })).toBeNull();
    expect(catalogEntry({ ...row, protected: true })).toBeNull();
  });
});
