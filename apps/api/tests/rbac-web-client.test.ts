import { expect, it, vi } from 'vitest';
import { api } from '../../web/app/crm/access/api.js';
import { fixturePerTest, integration } from './rbac-fixture.js';

// Node fetch has no document origin or browser cookie jar. Supply just those two
// services; leave the request body, CSRF, versions and Response to the real client.
function bindBrowserTransport(port: number) {
  const network = globalThis.fetch;
  let cookie = '';
  vi.stubGlobal('fetch', async (path: string, init: RequestInit) => {
    if (!/^\/api\/v1\/[a-zA-Z0-9/-]+$/.test(path) || init.credentials !== 'same-origin' || init.mode !== 'same-origin' || init.redirect !== 'error') {
      throw new Error('Expected a same-origin CRM request');
    }
    const headers = new Headers(init.headers);
    if (init.method !== 'GET') { headers.set('Origin', 'https://crm.example.test'); }
    if (cookie) { headers.set('Cookie', cookie); }
    const reply = await network(`http://127.0.0.1:${String(port)}${path}`, { ...init, headers });
    for (const value of reply.headers.getSetCookie()) {
      const set = /^(__Host-fixlevelup_session=[A-Za-z0-9_-]{43}); Path=\/; HttpOnly; Secure; SameSite=Strict$/.exec(value);
      if (set?.[1]) { cookie = set[1]; }
      else if (value === '__Host-fixlevelup_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0') { cookie = ''; }
      else { throw new Error('Unexpected session cookie'); }
    }
    return reply;
  });
}

integration('production CRM typed client against Nest and isolated PostgreSQL', () => {
  const fixture = fixturePerTest();
  it('decodes live auth, roles and staff, commits mutations, rejects stale writes and logs out', async () => {
    const f = fixture();
    // Reuse the listener created by the isolated fixture; do not start a replacement server.
    bindBrowserTransport(f.httpPort);
    const signal = AbortSignal.timeout(20_000);
    try {
      const guest = api(signal);
      await expect(guest.me()).rejects.toMatchObject({ status: 401 });
      const identity = await guest.login(f.admin.login, f.admin.password);
      expect(identity.staffId).toBe(f.admin.id);
      const client = api(signal, identity.csrf);
      expect((await client.me()).csrf === identity.csrf).toBe(true);
      expect((await client.access()).permissions).toContain('roles.create');
      expect((await client.catalog()).find(p => p.code === 'staff.role.assign')?.protected).toBe(true);
      const technician = (await client.roles()).find(r => r.code === 'TECHNICIAN' && r.type === 'SYSTEM');
      if (!technician) { throw new Error('Missing system technician'); }
      const created = await client.createRole('CRM fixture', 'Test role');
      const original = await client.role(created.id);
      expect(original).toMatchObject({ type: 'CUSTOM', name: 'CRM fixture', version: created.version });
      const edit = await client.editRole(original, 'Edited CRM fixture', 'Test role');
      await expect(client.editRole(original, 'Stale', '')).rejects.toMatchObject({ status: 412 });
      const edited = await client.role(edit.id);
      expect(edited).toMatchObject({ name: 'Edited CRM fixture', version: edit.version });
      const grants = [{ code: 'staff.self.read', scope: 'SELF' }] as const;
      const updated = await client.permissions(edited, [...grants]);
      expect(await client.role(updated.id)).toMatchObject({ permissions: grants, version: updated.version });

      const person = await client.createPerson('TECHNICIAN', 'Test Person');
      const renamed = await client.rename(person.id, person.version, 'Renamed Person');
      expect(await client.person(person.id)).toMatchObject({ displayName: 'Renamed Person', version: renamed.version });
      await expect(client.rename(person.id, person.version, 'Stale')).rejects.toMatchObject({ status: 412 });
      const assigned = await client.assign(person.id, renamed.version, created.id);
      expect((await client.members(created.id)).map(p => p.id)).toEqual([person.id]);
      expect((await client.staff()).find(p => p.id === person.id)).toMatchObject({ roleId: created.id, version: assigned.version });
      expect(await f.count(`SELECT count(*)::int n FROM foundation.staff s JOIN foundation.staff_role_assignments a ON a.staff_id=s.id
        WHERE s.id=$1 AND a.role_id=$2 AND a.revoked_at IS NULL AND s.display_name=$3`, [person.id, created.id, 'Renamed Person'])).toBe(1);
      const restored = await client.assign(person.id, assigned.version, technician.id);
      const inactive = await client.deactivate(person.id, restored.version);
      expect(await client.person(person.id)).toMatchObject({ employmentState: 'INACTIVE', version: inactive.version });
      const archived = await client.archive(await client.role(created.id));
      expect(await client.role(created.id)).toMatchObject({ status: 'ARCHIVED', version: archived.version });
      await client.logout();
      await expect(client.access()).rejects.toMatchObject({ status: 401 });
    } finally { vi.unstubAllGlobals(); }
  }, 30_000);
});
