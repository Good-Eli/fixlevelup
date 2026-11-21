import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPrivateQuarantineStorage } from '../src/files/storage/index.js';
import { uploadReservedFile } from '../src/files/upload-coordinator/index.js';
import type { FileReservationsFixture } from './file-reservations-fixture.js';
import { garageConfig, loadGarageCredentials, sha256Hex } from './file-storage-fixture.js';
import { PNG, assertUploadEventPairs, attempts, bindings, command, expectRefusal, policy, reserve, startUploadDb, uploadEvents } from './file-upload-fixture.js';

const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' && process.env['FIXLEVELUP_STORAGE_S3_TESTS'] === '1'
  ? describe : describe.skip;

integration('B2 end-to-end with real PostgreSQL and private Garage', () => {
  let db: FileReservationsFixture;
  let dispose: (() => Promise<void>) | undefined;
  beforeAll(async () => { db = await startUploadDb(); dispose = () => db.close(); }, 180_000);
  afterAll(async () => { await dispose?.(); });

  it('binds one independently re-read PNG-signature payload and returns only QUARANTINED', async () => {
    const config = garageConfig();
    const storage = createPrivateQuarantineStorage(config);
    const readonlyInspector = new S3Client({
      endpoint: config.endpoint, region: config.region, forcePathStyle: true, maxAttempts: 1,
      credentials: loadGarageCredentials(true), requestHandler: {
        connectionTimeout: config.connectionTimeoutMs, requestTimeout: config.requestTimeoutMs,
        socketTimeout: config.socketTimeoutMs, throwOnRequestTimeout: true,
      },
    });
    try {
      const { anchor, intent } = await reserve(db, { exactLogicalQuota: true });
      const sourceBuffer = Buffer.from(PNG);
      const byKey = command(anchor, intent.intentId, { body: () => (async function* () {
        // Signature spans chunks and the source reuses/overwrites caller memory.
        await Promise.resolve();
        yield sourceBuffer.subarray(0, 4);
        sourceBuffer.fill(0, 0, 4);
        yield sourceBuffer.subarray(4);
        sourceBuffer.fill(0);
      })() });
      const p = policy({ maxAttemptsPerOwner: 1, maxPhysicalBytesPerOwner: PNG.byteLength, maxLiveOperationsPerOwner: 1 });
      const result = await uploadReservedFile(db.runtime, storage, p, byKey);
      expect(Object.keys(result).sort()).toEqual(['intentId', 'quarantineId', 'replayed', 'state']);
      expect(result).toMatchObject({ intentId: intent.intentId, state: 'QUARANTINED', replayed: false });
      const allAttempts = await attempts(db, intent.intentId);
      expect(allAttempts).toHaveLength(1);
      const [attempt] = allAttempts;
      if (attempt === undefined) { throw new Error('Missing end-to-end attempt'); }
      expect(attempt.object_key.startsWith(`quarantine/${attempt.id}/`)).toBe(true);
      expect(attempt.state).toBe('VERIFIED');
      const controller = new AbortController();
      const timeout = setTimeout(() => { controller.abort(); }, 5_000);
      try {
        const response = await readonlyInspector.send(new GetObjectCommand({ Bucket: config.bucket, Key: attempt.object_key }), {
          abortSignal: controller.signal,
        });
        if (response.Body === undefined || !(Symbol.asyncIterator in response.Body)) {
          throw new Error('Garage returned no inspectable object body');
        }
        const received: Buffer[] = [];
        let total = 0;
        for await (const value of response.Body as AsyncIterable<unknown>) {
          if (!(value instanceof Uint8Array) || (total += value.byteLength) > PNG.byteLength) {
            throw new Error('Garage fixture object exceeded reserved bytes');
          }
          received.push(Buffer.from(value));
        }
        const bytes = Buffer.concat(received);
        expect(bytes).toEqual(PNG);
        expect(await bindings(db, intent.intentId)).toEqual([{
          id: result.quarantineId, attempt_id: attempt.id, actual_bytes: String(bytes.length), sha256: sha256Hex(bytes),
        }]);
      } finally { clearTimeout(timeout); }
      const raw = JSON.stringify(result);
      for (const marker of [attempt.object_key, attempt.id, sha256Hex(PNG), config.accessKeyId, config.secretAccessKey, config.endpoint, anchor.token]) {
        // Boolean assertion means failure output cannot print fixture credentials.
        expect(raw.includes(marker)).toBe(false);
      }
      const before = await uploadEvents(db, intent.intentId);
      const doNotOpen = () => { throw new Error('Replay unexpectedly opens source'); };
      expect(await uploadReservedFile(db.runtime, storage, p, { ...byKey, body: doNotOpen })).toEqual({ ...result, replayed: true });
      await expectRefusal(uploadReservedFile(db.runtime, storage, p, command(anchor, intent.intentId, { body: doNotOpen })), 'ALREADY_QUARANTINED');
      expect(await uploadEvents(db, intent.intentId)).toEqual(before);
      expect((await bindings(db, intent.intentId)).length).toBe(1);
      const aState = await db.migrator.query<{ state: string }>('SELECT state FROM foundation.file_upload_intents WHERE id=$1', [intent.intentId]);
      expect(aState.rows[0]?.state).toBe('RESERVED');
      await assertUploadEventPairs(db, intent.intentId);
      // Retain synthetic object evidence; no test has DELETE or grant-changing behavior.
    } catch (error: unknown) {
      // Production tests above already assert the coordinator's safe errors. Never
      // print SDK diagnostics from the independent read-only inspector.
      if (typeof error === 'object' && error !== null && '$metadata' in error) {
        // eslint-disable-next-line preserve-caught-error -- test must not expose raw SDK diagnostics
        throw new Error('Garage read-only inspection failed');
      }
      throw error;
    } finally {
      readonlyInspector.destroy();
      await storage.close();
    }
  }, 30_000);
});
