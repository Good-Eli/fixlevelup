import 'reflect-metadata';
import { createHmac, randomUUID } from 'node:crypto';
import type { Server } from 'node:http';
import { Test } from '@nestjs/testing';
import type { PoolClient } from 'pg';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WEB_AUTH_HTTP_CONFIG, WEB_AUTH_SERVICE } from '../src/auth/web-auth.controller.js';
import { WebAuthError } from '../src/auth/web-auth.service.js';
import { AUTHORIZATION_SERVICE } from '../src/authz/authorization.resources.js';
import { AuthorizationError } from '../src/authz/authorization.service.js';
import type { StaffWriteContext } from '../src/authz/authorization.service.js';
import { GLOBAL_SCOPE } from '../src/authz/capability.js';
import type { StaffWebPrincipal } from '../src/authz/principal.js';
import { StaffController, StaffService } from '../src/staff/staff.controller.js';

const origin = 'https://crm.example.test';
const first = 'a'.repeat(43);
const inactive = 'b'.repeat(43);
const csrfSecret = 's'.repeat(32);
const cookieName = '__Host-fixlevelup_session';
const cookie = (token: string) => `${cookieName}=${token}`;
const csrfFor = (token: string) => createHmac('sha256', csrfSecret).update('web-auth-csrf\0').update(token).digest('base64url');
const identity = { staffId: 'staff-1', role: 'ADMIN' as const, authVersion: 1,
  idleExpiresAt: new Date('2030-01-01T00:00:00Z'), absoluteExpiresAt: new Date('2030-01-01T12:00:00Z') };
const principal: StaffWebPrincipal = { kind: 'staff-web', staffId: identity.staffId, role: identity.role, authVersion: identity.authVersion };
const existingId = '9b6f6b2a-1f0e-4a3a-9c3d-111111111111';
const missingId = '9b6f6b2a-1f0e-4a3a-9c3d-222222222222';
const closers: (() => Promise<void>)[] = [];

afterEach(async () => { for (const close of closers.splice(0)) { await close(); } vi.restoreAllMocks(); });

interface StaffListRow { id: string; role: string; employment_state: string }
interface StaffDetailRow { id: string; role: string; employment_state: string; auth_version: number }
interface QueryResult<T> { rows: T[]; rowCount: number }

async function setup() {
  const listRows: StaffListRow[] = [{ id: existingId, role: 'MANAGER', employment_state: 'ACTIVE' }];
  const created: StaffDetailRow[] = [];
  const staffInserts: unknown[][] = [];
  const auditInserts: unknown[][] = [];
  const client = {
    query: vi.fn((sql: string, params?: unknown[]): QueryResult<StaffDetailRow | StaffListRow> => {
      if (sql.startsWith('SELECT id, role, employment_state FROM foundation.staff')) {
        return { rows: [...listRows], rowCount: listRows.length };
      }
      if (sql.startsWith('SELECT id, role, employment_state, auth_version FROM foundation.staff WHERE id = $1')) {
        const row = listRows.find((entry) => entry.id === params?.[0]);
        return row ? { rows: [{ ...row, auth_version: 0 }], rowCount: 1 } : { rows: [], rowCount: 0 };
      }
      if (sql.startsWith('INSERT INTO foundation.staff')) {
        const row: StaffDetailRow = { id: randomUUID(), role: String(params?.[1]), employment_state: 'ACTIVE', auth_version: 0 };
        created.push(row);
        staffInserts.push(params ?? []);
        return { rows: [row], rowCount: 1 };
      }
      if (sql.startsWith('INSERT INTO foundation.audit_logs')) {
        auditInserts.push(params ?? []);
        return { rows: [], rowCount: 1 };
      }
      throw new Error(`Unexpected query in mock: ${sql}`);
    }),
  };
  const auth = {
    authenticate: vi.fn((token: string) => { if (token !== first) { throw new WebAuthError('UNAUTHORIZED'); } return Promise.resolve(identity); }),
  };
  const authz = {
    authorize: vi.fn(() => Promise.resolve()),
    read: vi.fn(<T>(fn: (client: PoolClient) => Promise<T>) => fn(client as unknown as PoolClient)),
    authorizeForWrite: vi.fn(<T>(_token: string, _capability: string, _scope: unknown, write: (context: StaffWriteContext) => Promise<T>) =>
      write({ client: client as unknown as PoolClient, principal })),
  };
  const module = await Test.createTestingModule({ controllers: [StaffController], providers: [
    StaffService,
    { provide: WEB_AUTH_SERVICE, useValue: auth },
    { provide: AUTHORIZATION_SERVICE, useValue: authz },
    { provide: WEB_AUTH_HTTP_CONFIG, useValue: { origin, csrfSecret } },
  ] }).compile();
  // Nest models the structural options as a class without methods.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
  const app = module.createNestApplication({ logger: false });
  await app.init();
  closers.push(() => app.close());
  return { server: app.getHttpServer() as Server, auth, authz, client, created, staffInserts, auditInserts };
}

describe('staff authorization HTTP boundary', () => {
  it('rejects missing, malformed or duplicated session cookies with 401 before any authorization', async () => {
    const { server, auth, authz } = await setup();
    await request(server).get('/api/v1/staff').expect(401);
    await request(server).get('/api/v1/staff').set('Cookie', `${cookieName}=short`).expect(401);
    await request(server).get('/api/v1/staff').set('Cookie', `${cookie(first)}; ${cookie(first)}`).expect(401);
    expect(auth.authenticate).not.toHaveBeenCalled();
    expect(authz.authorize).not.toHaveBeenCalled();
  });

  it('maps an inactive session to 401 and skips the permission lookup', async () => {
    const { server, authz } = await setup();
    await request(server).get('/api/v1/staff').set('Cookie', cookie(inactive)).expect(401);
    expect(authz.authorize).not.toHaveBeenCalled();
  });

  it('returns the staff list behind the staff.read capability guard', async () => {
    const { server, authz } = await setup();
    const response = await request(server).get('/api/v1/staff').set('Cookie', cookie(first)).expect(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.body).toMatchObject({ data: { items: [{ id: existingId, role: 'MANAGER', employmentState: 'ACTIVE' }], pageInfo: { nextCursor: null, hasMore: false } } });
    expect(JSON.stringify(response.body)).not.toContain(first);
    expect(authz.authorize).toHaveBeenCalledOnce();
    expect(authz.authorize).toHaveBeenCalledWith(principal, 'staff.read', GLOBAL_SCOPE);
  });

  it('rejects a forged Origin on reads before touching the database', async () => {
    const { server, authz } = await setup();
    for (const badOrigin of ['https://sibling.example.test', 'https://crm.example.test.evil.test', 'null']) {
      await request(server).get('/api/v1/staff').set('Cookie', cookie(first)).set('Origin', badOrigin).expect(403);
    }
    expect(authz.read).not.toHaveBeenCalled();
  });

  it('denies a valid session without the capability with 403 for reads and writes', async () => {
    const { server, authz } = await setup();
    authz.authorize.mockRejectedValueOnce(new AuthorizationError('FORBIDDEN'));
    await request(server).get('/api/v1/staff').set('Cookie', cookie(first)).expect(403);
    expect(authz.read).not.toHaveBeenCalled();
    authz.authorize.mockRejectedValueOnce(new AuthorizationError('FORBIDDEN'));
    await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first))
      .set('X-CSRF-Token', csrfFor(first)).send({ role: 'TECHNICIAN' }).expect(403);
    expect(authz.authorizeForWrite).not.toHaveBeenCalled();
  });

  it('returns one staff member by id and 404/400 for missing or malformed ids', async () => {
    const { server } = await setup();
    const found = await request(server).get(`/api/v1/staff/${existingId}`).set('Cookie', cookie(first)).expect(200);
    expect(found.body).toMatchObject({ data: { id: existingId, role: 'MANAGER', employmentState: 'ACTIVE' } });
    const missing = await request(server).get(`/api/v1/staff/${missingId}`).set('Cookie', cookie(first)).expect(404);
    expect(JSON.stringify(missing.body)).not.toContain(first);
    await request(server).get('/api/v1/staff/not-a-uuid').set('Cookie', cookie(first)).expect(400);
  });

  it('requires exact Origin, JSON and the session CSRF token before any write', async () => {
    const { server, authz } = await setup();
    const body = { role: 'TECHNICIAN' };
    await request(server).post('/api/v1/staff').set('Origin', 'https://evil.test').set('Cookie', cookie(first))
      .set('X-CSRF-Token', csrfFor(first)).send(body).expect(403);
    await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first))
      .set('X-CSRF-Token', 'wrong').send(body).expect(403);
    await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first)).send(body).expect(403);
    expect(authz.authorizeForWrite).not.toHaveBeenCalled();
  });

  it('rejects roles outside the pre-registered vocabulary with 400', async () => {
    const { server, authz } = await setup();
    for (const role of ['ADMIN', 'SUPERUSER', '']) {
      await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first))
        .set('X-CSRF-Token', csrfFor(first)).send(role ? { role } : { role: '' }).expect(400);
    }
    await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first))
      .set('X-CSRF-Token', csrfFor(first)).send({ role: 'TECHNICIAN', extra: true }).expect(400);
    expect(authz.authorizeForWrite).not.toHaveBeenCalled();
  });

  it('creates a pre-registered staff row with audit under the locked write recheck', async () => {
    const { server, authz, created, auditInserts } = await setup();
    const response = await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first))
      .set('X-CSRF-Token', csrfFor(first)).send({ role: 'TECHNICIAN' }).expect(201);
    expect(response.headers['etag']).toBe('"staff-v0"');
    const row = created[0];
    expect(row).toMatchObject({ role: 'TECHNICIAN', employment_state: 'ACTIVE', auth_version: 0 });
    expect(response.body).toMatchObject({ data: { id: row?.id, role: 'TECHNICIAN', employmentState: 'ACTIVE' } });
    expect(JSON.stringify(response.body)).not.toContain(first);
    expect(authz.authorizeForWrite).toHaveBeenCalledOnce();
    expect(auditInserts.length).toBe(1);
    const details = JSON.parse(String(auditInserts[0]?.[3])) as { by: string; created: string };
    expect(details).toEqual({ by: identity.staffId, created: row?.id });
  });

  it('maps a locked-recheck denial to 403 without leaking data', async () => {
    const { server, authz, created } = await setup();
    (authz.authorizeForWrite).mockRejectedValueOnce(new AuthorizationError('FORBIDDEN'));
    const response = await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first))
      .set('X-CSRF-Token', csrfFor(first)).send({ role: 'TECHNICIAN' }).expect(403);
    expect(JSON.stringify(response.body)).not.toContain(first);
    expect(created).toEqual([]);
  });

  it('maps a locked-recheck session loss to 401', async () => {
    const { server, authz } = await setup();
    (authz.authorizeForWrite).mockRejectedValueOnce(new AuthorizationError('UNAUTHORIZED'));
    await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first))
      .set('X-CSRF-Token', csrfFor(first)).send({ role: 'MANAGER' }).expect(401);
  });
});
