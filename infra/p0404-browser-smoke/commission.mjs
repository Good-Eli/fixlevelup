import { randomUUID } from 'node:crypto';
import { host, apiPort, isUuid, origin } from './isolation.mjs';
import { seedManagerCredential } from './database.mjs';

const prefix = `http://${host}:${apiPort}/api/v1`;
const hours = Array.from({ length: 7 }, () => [[540, 1080]]);
const tag = version => `"geo-v${version}"`;

export async function signIn(credential) {
  const res = await fetch(`${prefix}/auth/login`, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
    headers: { origin, 'x-csrf-token': 'login', 'content-type': 'application/json' },
    body: JSON.stringify({ login: credential.login, password: credential.password }),
  });
  const cookie = /^(__Host-fixlevelup_session=[A-Za-z0-9_-]{43}); Path=\/; HttpOnly; Secure; SameSite=Strict$/.exec(res.headers.get('set-cookie') ?? '')?.[1];
  if (res.status !== 200 || !cookie) { throw new Error('Fixture sign-in failed'); }
  const { data } = await res.json();
  if (data.staffId !== credential.id || !/^[A-Za-z0-9_-]{43}$/.test(data.csrfToken)) { throw new Error('Unexpected fixture session principal'); }
  return async (route, expected, options = {}) => {
    const { body, method = 'GET', etag, key } = options;
    const request = await fetch(prefix + route, { method, redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { cookie, origin, 'x-csrf-token': data.csrfToken,
        ...(etag ? { 'if-match': etag } : {}), ...(key ? { 'idempotency-key': key } : {}),
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (request.status !== expected || request.headers.get('cache-control') !== 'no-store') {
      // Status and route only: never a body, header or credential.
      throw new Error(`Unexpected commissioning response ${method} ${route} -> ${String(request.status)} (expected ${String(expected)}, cache-control ${String(request.headers.get('cache-control'))})`);
    }
    if (expected >= 400 || expected === 204) { await request.body?.cancel(); return {}; }
    const { data: value } = await request.json();
    return { data: value, etag: request.headers.get('etag') };
  };
}

function id(data) { if (!isUuid(data?.id)) { throw new Error('Invalid fixture result ID'); } return data.id; }

async function city(call, code, displayName, active) {
  const base = '/settings/service-cities';
  const { data } = await call(base, 201, { method: 'POST', key: randomUUID(), body: { code } });
  const selected = `${base}/${id(data)}`;
  const { data: revision } = await call(`${selected}/versions`, 201, { method: 'POST', etag: tag(data.version), key: randomUUID(),
    body: { displayName, addressDisplay: 'Synthetic street 1', timezone: 'Europe/Moscow', publicContact: '+70000000000', officeHours: hours } });
  const { data: published } = await call(`${selected}/versions/${id(revision)}/publish`, 200,
    { method: 'POST', etag: tag(revision.version), key: randomUUID(), body: {} });
  if (id(published) !== data.id) { throw new Error('Unexpected fixture city target'); }
  if (active) {
    await call(`${selected}/activate`, 200, { method: 'POST', etag: tag(published.version), key: randomUUID(), body: {} });
  }
  return data.id;
}

export async function commission(fixture, progress) {
  progress('founder login');
  const call = await signIn(fixture.administrator);
  // Exactly one ACTIVE city; the outside city's immutable reviewed revision is
  // published but the city remains DRAFT under the real SINGLE_CITY rules.
  progress('founder geographic commissioning');
  fixture.cityId = await city(call, 'p04-primary', 'P04 Primary', true);
  fixture.outsideCityId = await city(call, 'p04-outside', 'P04 Outside', false);
  progress('CITY price-only role');
  const { data: role, etag: roleTag } = await call('/roles', 201, { method: 'POST',
    body: { name: 'P04 Price Only', description: 'Synthetic browser proof' } });
  await call(`/roles/${id(role)}/permissions`, 200, { method: 'PUT', etag: roleTag,
    body: { permissions: ['pricing.read', 'pricing.manage'].map(code => ({ code, scope: 'CITY' })) } });
  progress('manager staff and role assignment');
  const { data: staff, etag: staffTag } = await call('/staff', 201, { method: 'POST', body: { role: 'MANAGER' } });
  fixture.manager.id = id(staff);
  await call(`/staff/${staff.id}/role`, 200, { method: 'PUT', etag: staffTag, body: { roleId: role.id } });
  await seedManagerCredential(fixture);
  const version = (await fixture.migrator.query(`SELECT auth_version + profile_version AS version FROM foundation.staff WHERE id=$1`, [staff.id])).rows[0]?.version;
  if (!Number.isSafeInteger(version)) { throw new Error('Staff assignment state missing'); }
  progress('manager city assignment');
  await call(`/settings/service-cities/${fixture.cityId}/administrators/${staff.id}/assignments`, 201,
    { method: 'POST', etag: tag(version), key: randomUUID(), body: {} });
  progress('manager login');
  const manager = await signIn(fixture.manager);
  progress('manager must discover exactly one pricing city');
  const cities = await manager('/pricing/cities', 200);
  if (cities.data?.items?.length !== 1 || cities.data.items[0].id !== fixture.cityId) { throw new Error('Manager pricing city isolation failed'); }
  progress('manager company catalog denial');
  await manager('/catalog/items', 403);
  progress('commissioning logout');
  await call('/auth/logout', 204, { method: 'POST', body: {} });
  await manager('/auth/logout', 204, { method: 'POST', body: {} });
}
