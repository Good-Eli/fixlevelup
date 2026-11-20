import 'reflect-metadata';
import type { Server } from 'node:http';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { TelegramAuthController, TELEGRAM_AUTH_SERVICE } from '../src/auth/telegram-auth.controller.js';
import { TelegramAuthError } from '../src/auth/telegram-auth.service.js';

const initData = 'query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%7D&auth_date=1795204800&hash=' + 'a'.repeat(64);
const token = 't'.repeat(43);
const credential = {
  staffId: '9b6f6b2a-1f0e-4a3a-9c3d-111111111111', role: 'TECHNICIAN' as const, authVersion: 0,
  telegramUserId: '279058397', token,
  idleExpiresAt: new Date('2030-01-01T00:00:00Z'), absoluteExpiresAt: new Date('2030-01-01T12:00:00Z'),
};
const closers: (() => Promise<void>)[] = [];
afterEach(async () => { for (const close of closers.splice(0)) { await close(); } vi.restoreAllMocks(); });

async function setup() {
  const service = {
    exchange: vi.fn(() => Promise.resolve(credential)),
    authenticate: vi.fn(() => Promise.reject(new TelegramAuthError('UNAUTHORIZED'))),
  };
  const module = await Test.createTestingModule({ controllers: [TelegramAuthController], providers: [
    { provide: TELEGRAM_AUTH_SERVICE, useValue: service },
  ] }).compile();
  // Nest models the structural options as a class without methods.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
  const app = module.createNestApplication({ logger: false });
  await app.init();
  closers.push(() => app.close());
  return { server: app.getHttpServer() as Server, service };
}

describe('telegram auth HTTP boundary', () => {
  it('exchanges initData for a session token in the JSON body only', async () => {
    const { server, service } = await setup();
    const response = await request(server).post('/api/v1/auth/telegram-miniapp').send({ initData }).expect(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.body).toMatchObject({
      data: {
        sessionToken: token, staffId: credential.staffId, role: 'TECHNICIAN', authVersion: 0,
        telegramUserId: '279058397',
      },
    });
    expect(typeof (response.body as { data: { telegramUserId: unknown } }).data.telegramUserId).toBe('string');
    expect(service.exchange).toHaveBeenCalledExactlyOnceWith(initData, expect.any(String));
  });

  it('requires no Origin and no CSRF header: the token is not ambient authority', async () => {
    const { server } = await setup();
    // Absent Origin, absent Content-Type and an explicit foreign Origin all succeed.
    await request(server).post('/api/v1/auth/telegram-miniapp').send({ initData }).expect(200);
    await request(server).post('/api/v1/auth/telegram-miniapp').set('Content-Type', 'application/json').send({ initData }).expect(200);
    await request(server).post('/api/v1/auth/telegram-miniapp').set('Origin', 'https://evil.test').send({ initData }).expect(200);
  });

  it('rejects malformed bodies before the service is called', async () => {
    const { server, service } = await setup();
    for (const body of [
      {}, { initData: 1 }, { initData: 'x', extra: 'y' }, ['x'], { initData: 'x'.repeat(1025) },
    ]) {
      await request(server).post('/api/v1/auth/telegram-miniapp').send(body).expect(400);
    }
    expect(service.exchange).not.toHaveBeenCalled();
  });

  it('maps service errors to safe HTTP responses without leaking details', async () => {
    const { server, service } = await setup();
    service.exchange.mockRejectedValueOnce(new TelegramAuthError('UNAUTHORIZED'));
    await request(server).post('/api/v1/auth/telegram-miniapp').send({ initData }).expect(400);
    service.exchange.mockRejectedValueOnce(new TelegramAuthError('REPLAY'));
    const replay = await request(server).post('/api/v1/auth/telegram-miniapp').send({ initData }).expect(400);
    expect(replay.body).not.toHaveProperty('data');
    service.exchange.mockRejectedValueOnce(new TelegramAuthError('RATE_LIMITED'));
    await request(server).post('/api/v1/auth/telegram-miniapp').send({ initData }).expect(429);
    service.exchange.mockRejectedValueOnce(new TelegramAuthError('INVALID_INPUT'));
    await request(server).post('/api/v1/auth/telegram-miniapp').send({ initData }).expect(400);
    service.exchange.mockRejectedValueOnce(new TelegramAuthError('FAILED'));
    await request(server).post('/api/v1/auth/telegram-miniapp').send({ initData }).expect(500);
    service.exchange.mockRejectedValueOnce(new Error('raw driver error canary'));
    const leaked = await request(server).post('/api/v1/auth/telegram-miniapp').send({ initData }).expect(500);
    expect(JSON.stringify(leaked.body)).not.toContain('canary');
  });
});
