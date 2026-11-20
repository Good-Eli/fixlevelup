import 'reflect-metadata';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { Server } from 'node:http';
import { Controller, Get, UseGuards } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WEB_AUTH_HTTP_CONFIG, WEB_AUTH_SERVICE } from '../src/auth/web-auth.controller.js';
import { WebAuthError } from '../src/auth/web-auth.service.js';
import { AUTHORIZATION_SERVICE } from '../src/authz/authorization.resources.js';
import { AuthorizationError } from '../src/authz/authorization.service.js';
import { StaffWebAuthGuard } from '../src/authz/authorization.guard.js';
import { GLOBAL_SCOPE } from '../src/authz/capability.js';
import { StaffController } from '../src/staff/staff.controller.js';
import { StaffService } from '../src/staff/staff.service.js';

const origin = 'https://crm.example.test';
const first = randomBytes(32).toString('base64url'); const stale = randomBytes(32).toString('base64url');
const secret = randomBytes(32).toString('hex');
const cookie = (token: string) => `__Host-fixlevelup_session=${token}`;
const csrf = createHmac('sha256', secret).update('web-auth-csrf\0').update(first).digest('base64url');
const principal = { kind: 'staff-web', staffId: randomUUID(), role: 'ADMIN', authVersion: 1 };
const closers: (() => Promise<void>)[] = [];

afterEach(async () => { for (const close of closers.splice(0)) { await close(); } });

@Controller('test/no-metadata') @UseGuards(StaffWebAuthGuard)
class NoCapabilityController { @Get() open() { return { ok: true }; } }

// Real guard, service, controller, cookies/headers and response filter mapping. No fake SQL
// or query-shape matching. Successful commits and persisted DTO/audit evidence are tested on PG.
async function setup(controllers = [StaffController, NoCapabilityController], withAuthorization = true) {
  const auth = { authenticate: vi.fn((token: string) => {
    if (token !== first) { throw new WebAuthError('UNAUTHORIZED'); } return Promise.resolve(principal);
  }) };
  const authz = { authorize: vi.fn(() => Promise.resolve()), authorizeForRead: vi.fn(), authorizeForWrite: vi.fn() };
  const mod = await Test.createTestingModule({ controllers, providers: [StaffService, StaffWebAuthGuard,
    { provide: WEB_AUTH_SERVICE, useValue: auth }, { provide: WEB_AUTH_HTTP_CONFIG, useValue: { origin, csrfSecret: secret } },
    ...(withAuthorization ? [{ provide: AUTHORIZATION_SERVICE, useValue: authz }] : []),
  ] }).compile();
  // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
  const app = mod.createNestApplication({ logger: false }); await app.init(); closers.push(() => app.close());
  const server = app.getHttpServer() as Server;
  const create = () => request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first)).set('X-CSRF-Token', csrf);
  return { server, auth, authz, create };
}

describe('staff authorization HTTP boundary', () => {
  it('rejects missing, malformed, duplicate and lost sessions before authorization', async () => {
    const { server, auth, authz } = await setup();
    await request(server).get('/api/v1/staff').expect(401);
    for (const bad of [cookie('short'), `${cookie(first)}; ${cookie(first)}`]) { await request(server).get('/api/v1/staff').set('Cookie', bad).expect(401); }
    expect(auth.authenticate).not.toHaveBeenCalled(); await request(server).get('/api/v1/staff').set('Cookie', cookie(stale)).expect(401);
    expect(authz.authorize).not.toHaveBeenCalled();
  });
  it('requires exact read and write capabilities; failed preflight never enters the transaction', async () => {
    const { server, authz, create } = await setup(); authz.authorize.mockRejectedValue(new AuthorizationError('FORBIDDEN'));
    await request(server).get('/api/v1/staff').set('Cookie', cookie(first)).expect(403);
    expect(authz.authorize).toHaveBeenLastCalledWith(principal, 'staff.read', GLOBAL_SCOPE);
    await create().send({ role: 'TECHNICIAN' }).expect(403);
    expect(authz.authorize).toHaveBeenLastCalledWith(principal, 'staff.create', GLOBAL_SCOPE);
    expect(authz.authorizeForRead).not.toHaveBeenCalled(); expect(authz.authorizeForWrite).not.toHaveBeenCalled();
  });
  it('rejects foreign origins, missing/wrong CSRF and non-JSON without reading or writing staff data', async () => {
    const { server, authz, create } = await setup();
    for (const bad of ['https://sibling.example.test', 'https://crm.example.test.evil.test', 'null']) {
      await request(server).get('/api/v1/staff').set('Origin', bad).set('Cookie', cookie(first)).expect(403);
      await create().set('Origin', bad).send({ role: 'TECHNICIAN' }).expect(403);
    }
    await create().set('X-CSRF-Token', 'wrong').send({ role: 'TECHNICIAN' }).expect(403);
    await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', cookie(first)).send({ role: 'TECHNICIAN' }).expect(403);
    await create().type('text').send('{}').expect(400);
    expect(authz.authorizeForRead).not.toHaveBeenCalled(); expect(authz.authorizeForWrite).not.toHaveBeenCalled();
  });
  it('rejects unknown roles, raw ADMIN create, malformed identifiers and extra fields', async () => {
    const { server, authz, create } = await setup();
    for (const body of [{ role: 'ADMIN' }, { role: 'SUPERUSER' }, { role: '' }, { role: 'TECHNICIAN', extra: true }]) { await create().send(body).expect(400); }
    await request(server).get('/api/v1/staff/not-a-uuid').set('Cookie', cookie(first)).expect(400);
    expect(authz.authorizeForRead).not.toHaveBeenCalled(); expect(authz.authorizeForWrite).not.toHaveBeenCalled();
  });
  it.each([['FORBIDDEN', 403], ['UNAUTHORIZED', 401]] as const)('maps locked recheck %s to %s and never leaks credentials', async (code, status) => {
    const { authz, create } = await setup(); authz.authorizeForWrite.mockRejectedValueOnce(new AuthorizationError(code));
    const r = await create().send({ role: 'TECHNICIAN' }).expect(status);
    expect(authz.authorizeForWrite).toHaveBeenCalledOnce(); expect(JSON.stringify(r.body).includes(first)).toBe(false);
  });
  it('fails closed on missing capability metadata or a missing authorization dependency', async () => {
    const { server, authz } = await setup(); await request(server).get('/test/no-metadata').set('Cookie', cookie(first)).expect(500);
    expect(authz.authorize).not.toHaveBeenCalled(); await expect(setup([StaffController], false)).rejects.toThrow(/can't resolve dependencies/i);
  });
});
