import 'reflect-metadata';
import type { Server } from 'node:http';
import { Controller, Get, Inject, Injectable, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApi } from '../src/bootstrap/factories.js';
import { loadConfig } from '../src/runtime/config.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { ProblemFilter } from '../src/runtime/problem.filter.js';

const TOKEN = Symbol('metadata-proof');
@Injectable()
class Dependency {
  value(): string { return 'metadata-ok'; }
}
@Injectable()
class Consumer {
  constructor(readonly dependency: Dependency, @Inject(TOKEN) readonly injected: string) {}
}
@Controller('proof')
class ProofController {
  @Get()
  fail(): never { throw new Error('synthetic-secret-canary'); }
}
@Module({
  controllers: [ProofController],
  providers: [Dependency, Consumer, { provide: TOKEN, useValue: 'token-ok' }],
})
class ProofModule {}

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) { await close(); }
  vi.restoreAllMocks();
});

describe('Nest HTTP and metadata', () => {
  it('emits constructor metadata, supports parameter injection and resolves real DI', async () => {
    const metadata: unknown = Reflect.getMetadata('design:paramtypes', Consumer);
    expect(metadata).toEqual([Dependency, String]);
    const module = await Test.createTestingModule({ imports: [ProofModule] }).compile();
    closers.push(() => module.close());
    const consumer = module.get(Consumer);
    expect(consumer.dependency.value()).toBe('metadata-ok');
    expect(consumer.injected).toBe('token-ok');
  });

  it('serves liveness independently of providers and fails readiness honestly', async () => {
    const config = loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' });
    const app = await createApi(config, new SafeLogger('api'));
    closers.push(() => app.close());
    const server = (app.getHttpServer() as Server);
    const live = await request(server).get('/health/live').expect(200);
    expect(live.body).toEqual({ status: 'ok' });
    expect(live.headers['cache-control']).toBe('no-store');
    expect(live.headers['x-powered-by']).toBeUndefined();
    const ready = await request(server).get('/health/ready').expect(503);
    expect(ready.headers['content-type']).toContain('application/problem+json');
    expect(ready.body).toMatchObject({ status: 503, code: 'NOT_READY' });
    expect(JSON.stringify(ready.body)).not.toContain('stack');
    await request(server).get('/api/v1/requests').expect(404);
    await request(server).post('/health/live').send({ token: 'synthetic-secret-canary' }).expect(404);
  });

  it('rejects an occupied port while preserving the existing listener', async () => {
    const config = loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' });
    const app = await createApi(config, new SafeLogger('api'));
    closers.push(() => app.close());
    const server = app.getHttpServer() as Server;
    const address = server.address();
    if (!address || typeof address === 'string') { throw new Error('Expected TCP listener'); }
    await expect(createApi({ ...config, port: address.port }, new SafeLogger('api')))
      .rejects.toMatchObject({ code: 'EADDRINUSE' });
    await request(server).get('/health/live').expect(200);
  });

  it('redacts errors, request payloads and client request IDs', async () => {
    const logger = new SafeLogger('api');
    const events = vi.spyOn(logger, 'event').mockImplementation(() => undefined);
    const module = await Test.createTestingModule({ imports: [ProofModule] }).compile();
    // Nest models its structural options object as a class without methods.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
    const app = module.createNestApplication({ logger, bodyParser: false });
    app.useGlobalFilters(new ProblemFilter(logger));
    await app.init();
    closers.push(() => app.close());
    const response = await request((app.getHttpServer() as Server)).get('/proof')
      .set('X-Request-Id', 'synthetic-secret-canary').expect(500);
    expect(response.body).toMatchObject({ status: 500, code: 'INTERNAL_ERROR' });
    expect(JSON.stringify(response.body)).not.toContain('synthetic-secret-canary');
    expect(events).toHaveBeenCalledExactlyOnceWith('request_failed');
  });
});
