import { describe, expect, it } from 'vitest';
import * as lifecycle from '../src/files/file-lifecycle/index.js';
import * as storage from '../src/files/storage/index.js';
import { epoch, expectRefusal, processingPolicy, signal, uploadPolicy } from './file-lifecycle-fixture.js';
import { loopbackConfig } from './file-storage-fixture.js';
import type { Pool } from 'pg';
import type { ProcessingContext } from '../src/files/file-lifecycle/contract.js';
import { randomUUID } from 'node:crypto';

const privateMarker = 'fixture-private-caller-proxy-marker';

describe('C command boundary', () => {
  it('public barrels do not give F callers issuer or operations authority', () => {
    for (const key of ['createFileReadBudget', 'issueRawGetGrant', 'issueReadyGetGrant', 'releaseProcessingClaim', 'cleanupReadClaim']) {
      expect(Object.hasOwn(lifecycle, key)).toBe(false);
      expect(Object.hasOwn(storage, key)).toBe(false);
    }
  });

  it.each(['reflective command', 'accessor command', 'extra field', 'fake abort signal'] as const)(
    'rejects %s without checkout or surfaced caller diagnostics', async (scenario) => {
      let checkouts = 0;
      const cmd = { session: { sessionId: randomUUID(), token: 'a-valid-looking-but-not-actually-authoritative-token' }, intentId: randomUUID(), signal: signal() };
      const invalid = scenario === 'reflective command' ? new Proxy(cmd, { ownKeys() { throw new Error(privateMarker); } })
        : scenario === 'accessor command' ? Object.defineProperty({ ...cmd }, 'session', { get() { throw new Error(privateMarker); } })
        : scenario === 'fake abort signal' ? { ...cmd, signal: Object.create(AbortSignal.prototype) as AbortSignal }
        : { ...cmd, target: privateMarker };
      const adapter = storage.createPrivateQuarantineStorage(loopbackConfig('http://127.0.0.1:43210'));
      const pool = { connect() { checkouts++; throw new Error(privateMarker); } } as unknown as Pool;
      const ctx: ProcessingContext = { pool, storage: adapter, epoch, policy: processingPolicy(), uploadPolicy: uploadPolicy(),
        processor: { process: () => Promise.resolve({ kind: 'INDETERMINATE', reason: 'SCAN_FAILED' }), isEvidenceCurrent: () => false } };
      try {
        await expectRefusal(lifecycle.processQuarantine(ctx, invalid), 'INVALID_INPUT', [privateMarker, cmd.session.token]);
        expect(checkouts).toBe(0);
        // A syntactically valid command reaches this intentionally unavailable pool.
        await expectRefusal(lifecycle.processQuarantine(ctx, cmd), 'CONFLICT');
        expect(checkouts).toBe(1);
      } finally { await adapter.close(); }
    },
  );
});
