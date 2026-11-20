import 'reflect-metadata';
import type { Server } from 'node:http';
import { ConsoleLogger } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WebAuthController, WEB_AUTH_HTTP_CONFIG, WEB_AUTH_SERVICE } from '../src/auth/web-auth.controller.js';
import { WebAuthError, WebAuthService } from '../src/auth/web-auth.service.js';
import { createApi } from '../src/bootstrap/factories.js';
import { loadConfig } from '../src/runtime/config.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';

const origin = 'https://crm.example.test';
const first = 'a'.repeat(43);
const second = 'b'.repeat(43);
const name = '__Host-fixlevelup_session';
const identity = { staffId: 'staff-1', role: 'ADMIN' as const, authVersion: 1, idleExpiresAt: new Date('2030-01-01T00:00:00Z'), absoluteExpiresAt: new Date('2030-01-01T12:00:00Z') };
const cookie = (token: string) => `${name}=${token}`;
const closers: (() => Promise<void>)[] = [];
afterEach(async () => { for (const close of closers.splice(0)) { await close(); } vi.restoreAllMocks(); });

async function setup() {
  let active = first;
  const check = (token: string) => { if (token !== active) { throw new WebAuthError('UNAUTHORIZED'); } };
  const service = {
    login: vi.fn(() => Promise.resolve({ ...identity, token: first })),
    authenticate: vi.fn((token: string) => { check(token); return Promise.resolve(identity); }),
    renew: vi.fn((token: string) => { check(token); active = second; return Promise.resolve({ ...identity, token: second }); }),
    logout: vi.fn((token: string) => { check(token); active = ''; return Promise.resolve(); }),
    changePassword: vi.fn((token: string, current: string, next: string, source: string, version: number) => {
      check(token);
      if (!current || !next || !source || version !== 1) { throw new Error('Missing password input'); }
      return Promise.resolve(2);
    }),
  };
  const module = await Test.createTestingModule({ controllers: [WebAuthController], providers: [
    { provide: WEB_AUTH_SERVICE, useValue: service },
    { provide: WEB_AUTH_HTTP_CONFIG, useValue: { origin, csrfSecret: 's'.repeat(32) } },
  ] }).compile();
  // Nest models the structural options as a class without methods.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
  const app = module.createNestApplication({ logger: false });
  await app.init();
  closers.push(() => app.close());
  return { server: app.getHttpServer() as Server, service };
}

async function login(server: Server) {
  return request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login')
    .send({ login: 'admin', password: 'password-canary' }).expect(200);
}

function csrf(body: unknown): string {
  if (typeof body !== 'object' || body === null || !('data' in body) || typeof body.data !== 'object' || body.data === null || !('csrfToken' in body.data) || typeof body.data.csrfToken !== 'string') { throw new Error('Missing CSRF token'); }
  return body.data.csrfToken;
}

describe('web auth HTTP boundary', () => {
  it('uses the production JSON parser and safe error filter without touching the database', async () => {
    const loginSpy = vi.spyOn(WebAuthService.prototype, 'login').mockResolvedValue({ ...identity, token: first });
    const logger = new SafeLogger('api');
    const events = vi.spyOn(logger, 'event').mockImplementation(() => undefined);
    const output = vi.spyOn(ConsoleLogger.prototype, 'log').mockImplementation(() => undefined);
    const config = loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' });
    const app = await createApi(config, logger,
      { host: '127.0.0.1', port: 1, database: 'unused', user: 'fixlevelup_runtime', password: 'unused' },
      { origin, csrfSecret: 'a'.repeat(64), throttleSecret: 'b'.repeat(64) });
    closers.push(() => app.close());
    const server = app.getHttpServer() as Server;
    const malformed = await request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login')
      .set('Content-Type', 'application/json').send('{"password":"secret-canary"').expect(400);
    const oversized = await request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login')
      .send({ login: 'x'.repeat(5000), password: 'secret-canary' }).expect(413);
    const forged = await request(server).post('/api/v1/auth/login').set('Origin', 'https://evil.test').set('X-CSRF-Token', 'login')
      .send({ login: 'admin', password: 'secret-canary' }).expect(403);
    for (const response of [malformed, oversized, forged]) {
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(JSON.stringify(response.body)).not.toContain('secret-canary');
    }
    expect(loginSpy).not.toHaveBeenCalled();
    expect(events).not.toHaveBeenCalled();
    expect(JSON.stringify(output.mock.calls)).not.toContain('secret-canary');
  });
  it('sets host-only HTTPS security attributes, never exposes session token in JSON, and reads me', async () => {
    const { server, service } = await setup();
    const result = await login(server);
    expect(result.headers['set-cookie']).toEqual([`${cookie(first)}; Path=/; HttpOnly; Secure; SameSite=Strict`]);
    expect(result.headers['cache-control']).toBe('no-store');
    expect(result.headers['etag']).toBe('"auth-v1"');
    expect(JSON.stringify(result.body)).not.toContain(first);
    expect(service.login).toHaveBeenCalledWith('admin', 'password-canary', expect.any(String));
    const me = await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').set('Cookie', cookie(first)).expect(200);
    expect(me.body).toMatchObject({ data: { staffId: identity.staffId, role: identity.role, csrfToken: csrf(result.body) } });
    expect(JSON.stringify(me.body)).not.toContain(first);
    await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').expect(401);
  });

  it('rejects forged or unmarked me reads before session authentication', async () => {
    const { server, service } = await setup();
    await request(server).get('/api/v1/auth/me').set('Cookie', cookie(first)).expect(403);
    await request(server).get('/api/v1/auth/me').set('Cookie', cookie(first)).set('X-Auth-Request', '0').expect(403);
    // Superagent supports multiple header values; its type definition only permits this for Cookie.
    await request(server).get('/api/v1/auth/me').set('Cookie', cookie(first)).set({ 'X-Auth-Request': ['1', '1'] }).expect(400);
    for (const badOrigin of ['https://sibling.example.test', 'https://crm.example.test.evil.test', 'null']) {
      await request(server).get('/api/v1/auth/me').set('Cookie', cookie(first)).set('X-Auth-Request', '1').set('Origin', badOrigin).expect(403);
    }
    expect(service.authenticate).not.toHaveBeenCalled();
    const response = await request(server).get('/api/v1/auth/me').set('Cookie', cookie(first)).set('X-Auth-Request', '1').set('Origin', origin).expect(200);
    expect(response.headers['access-control-allow-origin']).toBeUndefined();
    expect(service.authenticate).toHaveBeenCalledExactlyOnceWith(first);
  });

  it('rejects missing and non-exact origins and login CSRF before calling service', async () => {
    const { server, service } = await setup();
    for (const badOrigin of ['', 'https://crm.example.test.evil.test', 'http://crm.example.test', 'https://crm.example.test:443', 'null']) {
      const req = request(server).post('/api/v1/auth/login').set('X-CSRF-Token', 'login').send({ login: 'admin', password: 'password-canary' });
      if (badOrigin) { req.set('Origin', badOrigin); }
      const res = await req.expect(403);
      expect(res.headers['set-cookie']).toBeUndefined();
      expect(JSON.stringify(res.body)).not.toContain('password-canary');
    }
    await request(server).post('/api/v1/auth/login').set('Origin', origin).send({ login: 'admin', password: 'x' }).expect(403);
    expect(service.login).not.toHaveBeenCalled();
    service.login.mockRejectedValueOnce(new WebAuthError('INVALID_CREDENTIALS'));
    const failed = await request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login').send({ login: 'admin', password: 'password-canary' }).expect(401);
    expect(failed.headers['set-cookie']).toBeUndefined();
    expect(JSON.stringify(failed.body)).not.toContain('password-canary');
  });

  it('requires matching CSRF, rotates session and rejects replay of old token and CSRF', async () => {
    const { server, service } = await setup();
    const initial = await login(server);
    const oldCsrf = csrf(initial.body);
    for (const supplied of ['', 'wrong']) {
      const req = request(server).post('/api/v1/auth/session/renew').set('Origin', origin).set('Cookie', cookie(first)).send({});
      if (supplied) { req.set('X-CSRF-Token', supplied); }
      await req.expect(403);
    }
    expect(service.renew).not.toHaveBeenCalled();
    const renewed = await request(server).post('/api/v1/auth/session/renew').set('Origin', origin).set('Cookie', cookie(first)).set('X-CSRF-Token', oldCsrf).send({}).expect(200);
    expect(renewed.headers['set-cookie']).toEqual([`${cookie(second)}; Path=/; HttpOnly; Secure; SameSite=Strict`]);
    expect(JSON.stringify(renewed.body)).not.toContain(second);
    const newCsrf = csrf(renewed.body);
    expect(newCsrf).not.toBe(oldCsrf);
    await request(server).post('/api/v1/auth/session/renew').set('Origin', origin).set('Cookie', cookie(second)).set('X-CSRF-Token', oldCsrf).send({}).expect(403);
    await request(server).post('/api/v1/auth/session/renew').set('Origin', origin).set('Cookie', cookie(first)).set('X-CSRF-Token', oldCsrf).send({}).expect(401);
    await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').set('Cookie', cookie(first)).expect(401);
  });

  it('protects password and logout mutations and clears the cookie', async () => {
    const { server, service } = await setup();
    const token = csrf((await login(server)).body);
    const body = { currentPassword: 'old-canary', newPassword: 'new-canary' };
    await request(server).post('/api/v1/auth/password/change').set('Origin', 'https://evil.test').set('Cookie', cookie(first)).set('X-CSRF-Token', token).send(body).expect(403);
    await request(server).post('/api/v1/auth/password/change').set('Origin', origin).set('Cookie', cookie(first)).set('X-CSRF-Token', token).send(body).expect(428);
    await request(server).post('/api/v1/auth/password/change').set('Origin', origin).set('Cookie', cookie(first)).set('X-CSRF-Token', token).set('If-Match', 'invalid').send(body).expect(400);
    expect(service.changePassword).not.toHaveBeenCalled();
    service.changePassword.mockRejectedValueOnce(new WebAuthError('STALE'));
    await request(server).post('/api/v1/auth/password/change').set('Origin', origin).set('Cookie', cookie(first)).set('X-CSRF-Token', token).set('If-Match', '"auth-v9"').send(body).expect(412);
    service.changePassword.mockClear();
    const changed = await request(server).post('/api/v1/auth/password/change').set('Origin', origin).set('Cookie', cookie(first)).set('X-CSRF-Token', token).set('If-Match', '"auth-v1"').set('X-Forwarded-For', '198.51.100.77').send(body).expect(200);
    expect(changed.headers['etag']).toBe('"auth-v2"');
    expect(changed.body).toMatchObject({ data: { ok: true, authVersion: 2 } });
    expect(service.changePassword).toHaveBeenCalledOnce();
    const passwordCall = service.changePassword.mock.calls[0];
    expect(passwordCall).toEqual([first, body.currentPassword, body.newPassword, expect.any(String), 1]);
    expect(passwordCall?.[3]).not.toBe('198.51.100.77');
    const logout = await request(server).post('/api/v1/auth/logout').set('Origin', origin).set('Cookie', cookie(first)).set('X-CSRF-Token', token).send({}).expect(204);
    expect(logout.headers['set-cookie']).toEqual([`${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`]);
    await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').set('Cookie', cookie(first)).expect(401);
  });

  it('rejects malformed input before any auth service state changes', async () => {
    const { server, service } = await setup();
    for (const body of [{ login: 1, password: 'x' }, { login: 'x', password: 'x', extra: true }, ['x'], { login: 'x'.repeat(1025), password: 'x' }]) {
      await request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login').send(body).expect(400);
    }
    await request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login').set('Content-Type', 'application/json').send('{').expect(400);
    await request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login').send({ login: 'x'.repeat(110000), password: 'x' }).expect(413);
    await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').set('Cookie', `${cookie(first)}; ${cookie(second)}`).expect(401);
    expect(service.login).not.toHaveBeenCalled();
    expect(service.authenticate).not.toHaveBeenCalled();
    expect(service.renew).not.toHaveBeenCalled();
    expect(service.logout).not.toHaveBeenCalled();
    expect(service.changePassword).not.toHaveBeenCalled();
  });
});
