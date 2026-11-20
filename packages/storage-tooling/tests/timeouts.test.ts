import { createServer } from 'node:http';
import type { ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import type { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { makeClient } from '../scripts/local.mjs';

// Exercise the actual handler configured by makeClient, without Garage, credentials
// from disk, or changing the client's fixed dev endpoint. Only this unsigned
// transport-level probe targets an ephemeral loopback fixture.
function testClient(): ReturnType<typeof makeClient> {
  return makeClient({
    endpoint: 'http://127.0.0.1:3900',
    region: 'garage',
    bucket: 'fixlevelup-dev-private',
    accessKeyId: `GK${'0'.repeat(24)}`,
    secretAccessKey: '0'.repeat(64),
  });
}

async function bounded<T>(action: Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      action,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { reject(new Error('Timeout regression watchdog expired.')); }, milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function fixture(respond: (response: ServerResponse) => void) {
  const sockets = new Set<Socket>();
  let resolveClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => { resolveClosed = resolve; });
  const server = createServer((_request, response) => { respond(response); });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => {
      sockets.delete(socket);
      resolveClosed();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    server.close();
    throw new Error('Expected an ephemeral loopback HTTP fixture.');
  }
  return {
    port: address.port,
    sockets,
    closed,
    async close() {
      for (const socket of sockets) { socket.destroy(); }
      await new Promise<void>((resolve, reject) => {
        server.close((error) => { if (error) { reject(error); } else { resolve(); } });
      });
    },
  };
}

function probe(port: number) {
  return {
    protocol: 'http:', hostname: '127.0.0.1', port,
    path: '/', method: 'GET', headers: {}, query: {},
  };
}

interface ProbeHandler {
  handle(request: ReturnType<typeof probe>): Promise<{
    response: { statusCode: number; body: Readable };
  }>;
}

function transport(client: ReturnType<typeof makeClient>): ProbeHandler {
  // The Node handler accepts the structural request above; the public SDK union
  // also includes platform handlers and Smithy's class-only request helpers.
  return client.config.requestHandler as ProbeHandler;
}

describe('local S3 transport timeout regressions', () => {
  it('aborts an accepted connection that never sends response headers', async () => {
    const local = await fixture(() => { /* Deliberately never send headers. */ });
    const client = testClient();
    try {
      const started = performance.now();
      const handler = transport(client);
      const result = bounded(handler.handle(probe(local.port)), 7_000);
      await expect(result).rejects.toMatchObject({ name: 'TimeoutError' });
      expect(performance.now() - started).toBeLessThan(7_000);
      await bounded(local.closed, 1_000);
      // Assert the handler released its socket before destroy()/fixture cleanup.
      expect(local.sockets.size).toBe(0);
    } finally {
      client.destroy();
      await local.close();
    }
  }, 12_000);

  it('aborts a response body that starts but never finishes', async () => {
    const local = await fixture((response) => {
      response.writeHead(200, { 'Content-Length': '100' });
      response.write('x');
      // No end(): requestTimeout alone is cleared once headers arrive.
    });
    const client = testClient();
    try {
      const started = performance.now();
      const { response } = await bounded(transport(client).handle(probe(local.port)), 1_000);
      expect(response.statusCode).toBe(200);
      const body = response.body;
      let received = 0;
      const consume = (async () => {
        for await (const chunk of body) {
          received += (chunk as Uint8Array).byteLength;
        }
      })();
      await expect(bounded(consume, 7_000)).rejects.toMatchObject({ name: 'TimeoutError' });
      expect(received).toBe(1);
      expect(performance.now() - started).toBeLessThan(7_000);
      await bounded(local.closed, 1_000);
      expect(local.sockets.size).toBe(0);
    } finally {
      client.destroy();
      await local.close();
    }
  }, 12_000);
});
