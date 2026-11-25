/**
 * Preflight item 3 (owner 24.11.2026): prove the CLIENT-side query deadline
 * (pg `query_timeout`, NOT the server statement_timeout and NOT the TCP
 * connection timeout) fires on an ESTABLISHED PostgreSQL session whose
 * server stops answering, and that the launcher admission fails closed.
 *
 * The local server speaks just enough of the PG wire protocol to complete
 * the startup handshake (AuthenticationOk + ParameterStatus + BackendKeyData
 * + ReadyForQuery) so the client's connect() SUCCEEDS and the session is
 * established; every subsequent query is black-holed. The only thing that
 * can unblock the query is the client's own read timer.
 */
import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import { expect, it } from 'vitest';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { Client } = require('pg') as typeof import('pg');

// The loopback protocol fixture never authenticates a database account.
const wireIdentity = { database: 'wire_test', user: 'wire_client', password: 'synthetic-wire-only', ssl: false } as const;

/** Minimal PG wire server: full startup handshake, then black-hole. */
function stallAfterHandshake(): Promise<{ server: Server; port: number }> {
  const server = createServer((socket: Socket) => {
    socket.on('error', () => undefined);
    // Consume the startup message; then answer the minimal ready sequence.
    socket.resume();
    let established = false;
    socket.on('data', (chunk: Buffer) => {
      if (established) { return; } // established: swallow, never answer
      // pg may first send an SSLRequest (len 8, code 80877103): answer 'N'.
      if (chunk.length >= 8 && chunk.readUInt32BE(4) === 80877103) {
        socket.write(Buffer.from('N', 'ascii'));
        return;
      }
      // Otherwise this is the startup packet: complete the handshake once.
      established = true;
      const msg = (type: string, payload: Buffer): Buffer =>
        Buffer.concat([Buffer.from(type, 'ascii'), (() => { const b = Buffer.alloc(4); b.writeInt32BE(payload.length + 4); return b; })(), payload]);
      const auth = msg('R', (() => { const b = Buffer.alloc(4); b.writeInt32BE(0); return b; })());
      const param = msg('S', Buffer.concat([Buffer.from('server_version\0', 'utf8'), Buffer.from('18.7\0', 'utf8')]));
      const key = msg('K', (() => { const b = Buffer.alloc(8); b.writeInt32BE(12345); b.writeInt32BE(54321, 4); return b; })());
      const ready = msg('Z', Buffer.from('I', 'ascii'));
      socket.write(Buffer.concat([auth, param, key, ready]));
    });
  });
  return new Promise((resolveReady) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address && typeof address !== 'string') {
        resolveReady({ server, port: address.port });
      }
    });
  });
}

it('query_timeout fires on an established session whose server never answers (client-side, not statement/connection timeout)', async () => {
  const { server, port } = await stallAfterHandshake();
  try {
    // 1. PROOF of established session: connect() resolves (the handshake
    //    completed — ReadyForQuery was delivered).
    const client = new Client({ host: '127.0.0.1', port, ...wireIdentity,
      connectionTimeoutMillis: 5_000, query_timeout: 400 });
    await client.connect();
    // 2. The stalled query: only the CLIENT read timer can unblock it.
    const started = Date.now();
    let error: unknown;
    try { await client.query('SELECT 1'); } catch (e) { error = e; }
    const elapsed = Date.now() - started;
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/Query read timeout/i);
    // Client-side timer fired ~400ms — far below any server/statement timeout
    // and below the connection timeout (which would have failed connect()).
    expect(elapsed).toBeGreaterThanOrEqual(300);
    expect(elapsed).toBeLessThan(3_000);
    await client.end().catch(() => undefined);
  } finally {
    await new Promise<void>((r) => { server.close(() => { r(); }); });
  }
}, 30_000);

it('the admission gate fails closed when the registry stalls an established session', async () => {
  // Fail-closed admission behavior: the gate's live verification query goes
  // through the same stall — the client's query read timeout must fail the
  // verification closed (never hang, never partially admit; the gate maps
  // any driver failure to the typed WITNESS_MISSING refusal).
  const { server, port } = await stallAfterHandshake();
  const { AdmissionGate } = await import('../src/infrastructure/admission/admission.js');
  const { witnessKeyForInstance } = await import('../src/infrastructure/admission/runtime-admission.js');
  const { randomUUID } = await import('node:crypto');
  const instanceId = randomUUID();
  const gate = new AdmissionGate({
    binding: {
      database: wireIdentity.database, databaseOid: 5, role: wireIdentity.user, schema: 'public',
      witnessKey: witnessKeyForInstance(instanceId), profile: 'S1',
      witnessHolderPid: 4_000_000,
      expected: { endpoint: `127.0.0.1:${String(port)}`, issuerGeneration: 1, launchNonce: randomUUID(),
        consumerKind: 'API', instanceId, channelId: randomUUID(),
        artifactDigest: 'a'.repeat(64), historyManifestDigest: 'b'.repeat(64), physicalContractDigest: 'c'.repeat(64) },
    },
    publicKeyPem: '',
  });
  const client = new Client({ host: '127.0.0.1', port, ...wireIdentity,
    connectionTimeoutMillis: 5_000, query_timeout: 400 });
  try {
    await client.connect();
    const started = Date.now();
    let gateError: unknown;
    try { await gate.verifyConnection(client, new Date()); } catch (e) { gateError = e; }
    const elapsed = Date.now() - started;
    // The stalled verification is bounded by the CLIENT read timer (≈400 ms),
    // and the gate fails closed with the typed WITNESS_MISSING refusal.
    expect(elapsed).toBeLessThan(3_000);
    expect(gateError).toBeInstanceOf(Error);
    // The gate's typed code (WITNESS_MISSING), never a raw driver error.
    expect((gateError as { code?: unknown }).code).toBe('WITNESS_MISSING');
  } finally {
    await client.end().catch(() => undefined);
    await new Promise<void>((r) => { server.close(() => { r(); }); });
  }
}, 15_000);
