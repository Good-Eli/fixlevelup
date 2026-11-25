/** Compiled synthetic T fixture; no operator credentials or bytes endpoints. */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import sharp from 'sharp';
import type { Pool } from 'pg';
import { processQuarantine } from '../src/files/file-lifecycle/index.js';
import type { RuntimeEpoch } from '../src/files/file-lifecycle/contract.js';
import { createLocalFileProcessor } from '../src/files/file-processing/processor.js';
import type { DefinitionEpoch, FileProcessingLauncher } from '../src/files/file-processing/processor.js';
import { reserveFileUpload } from '../src/files/reservations/index.js';
import { createPrivateQuarantineStorage } from '../src/files/storage/index.js';
import type { PrivateQuarantineStorageConfig } from '../src/files/storage/config.js';
import { uploadReservedFile } from '../src/files/upload-coordinator/index.js';
import type { UploadOperationalPolicy } from '../src/files/upload-coordinator/index.js';
import { beginLegalTransaction } from '../src/settings/legal/index.js';

interface EngineModule {
  createFileProcessingTestLauncher(config: unknown): Promise<{ launcher: FileProcessingLauncher; epoch: DefinitionEpoch }>;
}

/** This is the same genuine reservation/B/C path as the TLS lifecycle proof. */
export async function nativeReady(pool: Pool, epoch: RuntimeEpoch, session: { sessionId: string; token: string },
  target: PrivateQuarantineStorageConfig, bridge: string, descriptor: string) {
  const engineModule = await import(bridge) as EngineModule;
  const descriptorData: unknown = JSON.parse(readFileSync(descriptor, 'utf8'));
  const engine = await engineModule.createFileProcessingTestLauncher(descriptorData);
  const image = await sharp({ create: { width: 9, height: 5, channels: 3, background: '#f03412' } })
    .withMetadata({ orientation: 6 }).withExifMerge({
      IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '1/1 2/1 3/1', GPSLongitudeRef: 'E', GPSLongitude: '4/1 5/1 6/1' },
      IFD0: { Artist: 'SYNTHETIC_PRIVACY_MARKER' },
    }).png().toBuffer();
  const storage = createPrivateQuarantineStorage(target);
  try {
    const client = await pool.connect();
    const expires = (ms: number) => new Date(Date.now() + ms);
    const intent = await (async () => {
      try {
        await beginLegalTransaction(client);
        const created = await reserveFileUpload(client, { session,
          policy: { versionId: randomUUID(), sourceRef: 'synthetic://native-t-ready', allowedMimeTypes: ['image/png'],
            expiresAt: expires(300_000), maxFileBytes: 64_000, maxOwnerBytes: 512_000, maxOwnerFiles: 8 },
          declaredMime: 'image/png', declaredBytes: image.length, expiresAt: expires(240_000), idempotencyKey: randomUUID() });
        await client.query('COMMIT');
        return created.intentId;
      } catch (error) { await client.query('ROLLBACK'); throw error; }
      finally { client.release(); }
    })();
    const file = { session, intentId: intent };
    const uploadPolicy: UploadOperationalPolicy = { mode: 'local-synthetic', maxAttemptsPerOwner: 8,
      maxPhysicalBytesPerOwner: 512_000, maxLiveOperationsPerOwner: 4, leaseMs: 8_000,
      prefixTimeoutMs: 1500, maxSourceChunkBytes: 64_000, allowedMimeTypes: ['image/png'] };
    const signal = AbortSignal.timeout(90_000);
    const upload = await uploadReservedFile(pool, storage, uploadPolicy, { ...file, signal,
      idempotencyKey: randomUUID(), body: () => (async function* () { await Promise.resolve(); yield image; })() });
    assert.equal(upload.state, 'QUARANTINED');
    const processor = createLocalFileProcessor(engine.launcher,
      { epoch: engine.epoch, maxRawBytes: 64_000, maxOutputBytes: 64_000, maxJobs: 1, maxWallMs: 90_000 });
    assert.deepEqual(await processQuarantine({ pool, epoch, storage, processor, uploadPolicy,
      policy: { mode: 'local-synthetic', versionId: randomUUID(), expiresAt: expires(240_000), allowedMimeTypes: ['image/png'],
        maxRawBytes: 64_000, maxOutputBytes: 64_000, maxWidth: 128, maxHeight: 128, maxPixels: 16_384, maxChannels: 4,
        leaseMs: 120_000, wallMs: 90_000, maxDefsAgeMs: 7 * 24 * 60 * 60 * 1_000 } }, { ...file, signal }),
    { intentId: intent, completed: true });
    const publication = await pool.query<{ id: string }>('SELECT id FROM foundation.file_publications WHERE intent_id=$1', [intent]);
    assert.equal(publication.rowCount, 1);
    const id = publication.rows[0]?.id;
    assert(id);
    return id;
  } finally { await storage.close(); }
}
