import { randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { describe, expect, it } from 'vitest';
import type { LoopbackHandler } from './file-storage-fixture.js';
import * as storageExports from '../src/files/storage/index.js';
import { issueRegisteredQuarantineProbe } from '../src/files/storage/registered-proof.js';
import * as uploads from '../src/files/upload-coordinator/index.js';
import type { UploadOperationalPolicy, UploadReservedFileCommand } from '../src/files/upload-coordinator/index.js';
import { bounded, loopback, loopbackConfig, loopbackObjectStore, sha256Hex, watchUnhandledRejections } from './file-storage-fixture.js';
import { FAILURE_MARKER, PNG, command, expectRefusal, policy, wire } from './file-upload-fixture.js';

const anchor = { sessionId: randomUUID(), token: 'synthetic_unit_token_0123456789_ABCDEFG' };

function unreachablePool(): { pool: Pool; accessed(): number } {
  let touches = 0;
  return {
    pool: new Proxy(new Pool(), { get() { touches += 1; throw new Error(FAILURE_MARKER); } }),
    accessed: () => touches,
  };
}

const exploding = new Proxy({}, { ownKeys(): never { throw new Error(FAILURE_MARKER); } });

async function probeWire(handler: LoopbackHandler) {
  const socket = await loopback(handler);
  const storage = storageExports.createPrivateQuarantineStorage(loopbackConfig(socket.endpoint, { maxResponseBodyBytes: 128 }));
  const { attempt, target } = storage.prepareRegisteredQuarantineAttempt();
  const proof = issueRegisteredQuarantineProbe({ ...attempt, target, claimId: randomUUID(), claimGeneration: 1 });
  return {
    socket,
    observe(signal = new AbortController().signal) {
      return bounded(storage.inspectRegisteredQuarantineObject(proof, { maxBytes: PNG.length, signal }), 3_000, 'wire probe');
    },
    assertGet() {
      expect(socket.requests.map(({ method }) => method)).toEqual(['GET']);
      expect(socket.requests[0]?.url.split('?')[0] === `/${target.bucket}/${attempt.objectKey}`).toBe(true);
    },
    async close() { await storage.close(); await socket.close(); },
  };
}

describe('B2 loopback probe settlement evidence', () => {
  it('distinguishes a bounded complete body, bare observation of 404, and denied GET', async () => {
    for (const status of [200, 404, 403]) {
      const fixture = await probeWire((req, res) => {
        req.resume();
        const body = status === 200 ? PNG : Buffer.from(`<Error><Code>${status === 404 ? 'NoSuchKey' : 'AccessDenied'}</Code></Error>`);
        res.writeHead(status, { 'Content-Length': String(body.length) });
        res.end(body);
      });
      try {
        expect(await fixture.observe()).toEqual(status === 200
          ? { observation: 'PRESENT', actualBytes: PNG.length, sha256: sha256Hex(PNG), transportSettled: true }
          : { observation: status === 404 ? 'NOT_OBSERVED' : 'INDETERMINATE', transportSettled: true });
        fixture.assertGet();
      } finally { await fixture.close(); }
    }
  });

  it('refuses bounded-overflow error bodies and malformed object range responses without exposing their content', async () => {
    for (const status of [404, 200]) {
      const fixture = await probeWire((req, res) => {
        req.resume();
        if (status === 404) {
          res.writeHead(404, { 'Content-Type': 'application/xml' });
          res.end(Buffer.alloc(1_024, 0x78));
        } else {
          res.writeHead(200, { 'Content-Range': `bytes 0-1/${String(PNG.length)}` });
          res.end(PNG);
        }
      });
      try {
        expect(await fixture.observe()).toEqual({ observation: 'INDETERMINATE', transportSettled: true });
        fixture.assertGet();
      } finally { await fixture.close(); }
    }
  });

  it('aborts stalled 200 and 404 bodies after headers and proves socket closure', async () => {
    for (const status of [200, 404]) {
      const fixture = await probeWire((req, res) => {
        req.resume();
        res.writeHead(status, { 'Content-Type': status === 404 ? 'application/xml' : 'application/octet-stream' });
        res.write(status === 404 ? '<' : PNG.subarray(0, 1));
      });
      try {
        expect(await fixture.observe()).toEqual({ observation: 'INDETERMINATE', transportSettled: true });
        await fixture.socket.waitForSocketsClosed(1_000);
        fixture.assertGet();
      } finally { await fixture.close(); }
    }
  });

  it('reports no closure evidence if headers never arrive, without dialing on a pre-aborted probe', async () => {
    const fixture = await probeWire((req) => { req.resume(); });
    try {
      expect(await fixture.observe(AbortSignal.abort())).toEqual({ observation: 'INDETERMINATE', transportSettled: true });
      expect(fixture.socket.requests).toHaveLength(0);
      expect(await fixture.observe()).toEqual({ observation: 'INDETERMINATE', transportSettled: false });
      fixture.assertGet();
    } finally { await fixture.close(); }
  });
});

describe('B2 closed command and operator config boundaries', () => {
  it('denies missing/invalid policy and limits before source, PostgreSQL or storage', async () => {
    const pg = unreachablePool();
    const transport = await wire(loopbackObjectStore().handler);
    let started = false;
    const byKey = command(anchor, randomUUID(), { body: () => {
      started = true;
      throw new Error(FAILURE_MARKER);
    } });
    try {
      const cases: unknown[] = [undefined, {}, exploding, { ...policy(), mode: 'production' }, {
        ...policy(), maxAttemptsPerOwner: 0,
      }, { ...policy(), maxPhysicalBytesPerOwner: Number.MAX_SAFE_INTEGER + 1 }, {
        ...policy(), maxLiveOperationsPerOwner: -1,
      }, { ...policy(), leaseMs: 1_500 }, {
        ...policy(), allowedMimeTypes: ['image/png', 'image/png'],
      }, { ...policy(), maxSourceChunkBytes: 128 * 1024 }];
      for (const invalid of cases) {
        await expectRefusal(uploads.uploadReservedFile(pg.pool, transport.storage, invalid as UploadOperationalPolicy, byKey), 'NOT_CONFIGURED');
      }
      expect(started).toBe(false);
      expect(pg.accessed()).toBe(0);
      expect(transport.socket.requests).toHaveLength(0);
    } finally { await transport.close(); }
  });

  it('rejects caller-injected target/key and reflected private diagnostics before IO', async () => {
    const pg = unreachablePool();
    const transport = await wire(loopbackObjectStore().handler);
    const valid = command(anchor, randomUUID());
    let invokedGetter = 0;
    const accessor = { ...valid, get body() { invokedGetter += 1; throw new Error(FAILURE_MARKER); } };
    try {
      const cases: unknown[] = [exploding, { ...valid, objectKey: FAILURE_MARKER }, { ...valid, session: { ...valid.session, target: FAILURE_MARKER } }, accessor];
      for (const invalid of cases) {
        await expectRefusal(uploads.uploadReservedFile(pg.pool, transport.storage, policy(), invalid as UploadReservedFileCommand), 'INVALID_INPUT');
      }
      expect(invokedGetter).toBe(0);
      expect(pg.accessed()).toBe(0);
      expect(transport.socket.requests).toHaveLength(0);
    } finally { await transport.close(); }
  });

  it('keeps probe issuance private; neither forged grant nor real grant for another target sends a request', async () => {
    const first = await wire(loopbackObjectStore().handler);
    const second = await wire(loopbackObjectStore().handler);
    const rejections = watchUnhandledRejections();
    try {
      expect(Object.hasOwn(storageExports, 'issueRegisteredQuarantineProbe')).toBe(false);
      expect(Object.hasOwn(uploads, 'reconcileUploadAttempts')).toBe(false);
      const { attempt, target } = first.storage.prepareRegisteredQuarantineAttempt();
      const probe = issueRegisteredQuarantineProbe({ ...attempt, target, claimId: randomUUID(), claimGeneration: 1 });
      const input = { maxBytes: PNG.byteLength, signal: new AbortController().signal };
      await expectRefusal(second.storage.inspectRegisteredQuarantineObject(probe, input), 'ATTEMPT_TARGET_MISMATCH');
      await expectRefusal(first.storage.inspectRegisteredQuarantineObject({ ...probe }, input), 'ATTEMPT_INVALID');
      expect(first.socket.requests).toHaveLength(0);
      expect(second.socket.requests).toHaveLength(0);
      expect(rejections.rejections).toEqual([]);
    } finally {
      rejections.stop();
      await first.close();
      await second.close();
    }
  });
});
