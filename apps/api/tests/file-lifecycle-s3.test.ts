import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import sharp from 'sharp';
import { expect, it } from 'vitest';
import { closeReadyStream, createFileReadBudget, openReadyStream, readReadyChunk, readReadyMetadata } from '../src/files/file-access/index.js';
import { processQuarantine } from '../src/files/file-lifecycle/index.js';
import { createLocalFileProcessor } from '../src/files/file-processing/processor.js';
import type { DefinitionEpoch, FileProcessingLauncher } from '../src/files/file-processing/processor.js';
import { createPrivateQuarantineStorage } from '../src/files/storage/index.js';
import { garageConfig, sha256Hex } from './file-storage-fixture.js';
import { poolWithCommitHook, waitForDbExpiry } from './file-upload-fixture.js';
import {
  accessPolicy, assertProcessReceipt, epoch, expectRefusal, expiresIn, lifecycleRealIntegration, maxLiveOperationsPerOwner,
  processingContext, provision, publications, sanitized, signal, startLifecycleDb,
} from './file-lifecycle-fixture.js';

interface TestLauncherModule {
  createFileProcessingTestLauncher(config: unknown): Promise<{ launcher: FileProcessingLauncher; epoch: DefinitionEpoch }>;
}

async function pinnedFixture() {
  const path = process.env['FIXLEVELUP_FILE_PROCESSING_FIXTURE'];
  if (path === undefined) {throw new Error('Real C test requires the explicitly prepared FIXLEVELUP_FILE_PROCESSING_FIXTURE');}
  const config: unknown = JSON.parse(await readFile(resolve(path), 'utf8'));
  const launcherUrl = new URL('../../../infra/file-processing/docker-test-launcher.mjs', import.meta.url);
  const fixtureModule = await import(launcherUrl.href) as TestLauncherModule;
  return fixtureModule.createFileProcessingTestLauncher(config);
}

lifecycleRealIntegration('C complete PG + Garage + pinned ClamAV and Sharp pipeline', () => {
  it('publishes exactly the two scanned digests, preserves raw bytes and serves oriented metadata-free PNG', async () => {
    const engine = await pinnedFixture();
    const raw = await sharp({ create: { width: 9, height: 5, channels: 3, background: '#f03412' } })
      .withMetadata({ orientation: 6 }).withExifMerge({ IFD3: {
        GPSLatitudeRef: 'N', GPSLatitude: '1/1 2/1 3/1', GPSLongitudeRef: 'E', GPSLongitude: '4/1 5/1 6/1',
      }, IFD0: { Artist: 'SYNTHETIC_PRIVACY_MARKER' } }).png().toBuffer();
    const original = await sharp(raw).metadata();
    expect(original.orientation).toBe(6);
    expect(original.exif?.includes(Buffer.from('SYNTHETIC_PRIVACY_MARKER'))).toBe(true);
    // GPS latitude/longitude tags (little-endian EXIF from native Sharp) must exist in the input.
    expect(original.exif).toBeDefined();
    expect(original.exif?.includes(Buffer.from([0x25, 0x88])) || original.exif?.includes(Buffer.from([0x88, 0x25]))).toBe(true);

    const config = garageConfig({ maxConcurrentOperations: 4 });
    const realStorage = createPrivateQuarantineStorage(config);
    let sanitizedPuts = 0;
    const storage = new Proxy(realStorage, {
      get(target, key): unknown {
        if (key === 'putSanitized') {
          return (...args: Parameters<typeof target.putSanitized>) => {
            sanitizedPuts++;
            return target.putSanitized(...args);
          };
        }
        const value: unknown = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const inspector = new S3Client({ endpoint: config.endpoint, region: config.region, forcePathStyle: true, maxAttempts: 1,
      credentials: { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey } });
    const db = await startLifecycleDb();
    try {
      const { file } = await provision(db, storage, raw);
      const scanned: string[] = [];
      const processor = createLocalFileProcessor({
        scan: async (bytes, definition, abort) => {
          scanned.push(sha256Hex(bytes));
          return engine.launcher.scan(bytes, definition, abort);
        }, decode: engine.launcher.decode.bind(engine.launcher),
      }, { epoch: engine.epoch, maxRawBytes: 64_000, maxOutputBytes: 64_000, maxJobs: 1, maxWallMs: 90_000 });
      const maxBufferedBytes = 2_200_000;
      const access = { pool: db.runtime, storage, epoch, policy: accessPolicy({ maxBufferedBytes }),
        budget: createFileReadBudget({ mode: 'local-synthetic', namespace: epoch.namespace, singleProcess: true,
          maxBufferedBytes, maxActiveStreams: 2, maxLiveOperationsPerOwner }) };
      let finalAckLost = false;
      let readWindow: Date | undefined;
      const pool = poolWithCommitHook(db.runtime, async (_n, client, commit) => {
        const pending = (await client.query<{ present: boolean }>(`SELECT EXISTS
          (SELECT 1 FROM foundation.file_publications WHERE intent_id=$1) AS present`, [file.intentId])).rows[0];
        const result = await commit();
        if (pending?.present === true && !finalAckLost) {
          // Confirm the new publication was independently readable, then hold the
          // real COMMIT acknowledgement until only that access-policy window ends.
          const deadline = expiresIn(1_200);
          const shortAccess = { ...access, policy: { ...access.policy, expiresAt: deadline } };
          expect((await readReadyMetadata(shortAccess, file)).state).toBe('READY');
          await waitForDbExpiry(db, deadline);
          await expectRefusal(readReadyMetadata(shortAccess, file), 'NOT_CONFIGURED');
          readWindow = deadline;
          finalAckLost = true;
          throw new Error('synthetic final COMMIT reply lost');
        }
        return result;
      });
      const ctx = processingContext(db, storage, processor, { pool });
      const receipt = await processQuarantine(ctx, { ...file, signal: signal() });
      expect(finalAckLost).toBe(true);
      expect(readWindow).toBeDefined();
      assertProcessReceipt(receipt, file.intentId);
      const rows = await publications(db, file.intentId);
      expect(rows).toHaveLength(1);
      const [pub] = rows;
      if (pub === undefined) {throw new Error('No publication');}
      const fetchExact = async (key: string): Promise<Uint8Array> => {
        const result = await inspector.send(new GetObjectCommand({ Bucket: config.bucket, Key: key }),
          { abortSignal: AbortSignal.timeout(15_000) });
        if (result.Body === undefined) {throw new Error('No Garage object body');}
        return result.Body.transformToByteArray();
      };
      const retainedRaw = await fetchExact(pub.raw_key);
      const stored = await fetchExact(pub.object_key);
      expect(Buffer.from(retainedRaw)).toEqual(raw);
      expect(scanned).toEqual([sha256Hex(raw), sha256Hex(stored)]);
      expect(pub).toMatchObject({ raw_bytes: String(raw.length), served_bytes: String(stored.length),
        raw_sha256: scanned[0], served_sha256: scanned[1], defs_sha256: engine.epoch.defsSha256,
        engine_version: engine.epoch.engineVersion, engine_image_sha256: engine.epoch.engineImageSha256,
        processing_policy_id: ctx.policy.versionId });
      expect(await readReadyMetadata(access, file)).toStrictEqual({ fileId: pub.id, state: 'READY', mime: 'image/png', bytes: stored.length });
      const ticket = await openReadyStream(access, { ...file, signal: signal() });
      let served: Buffer;
      try {
        const chunks: Uint8Array[] = [];
        for (;;) {
          const part = await readReadyChunk(ticket);
          if (part.kind === 'EOF') {break;}
          chunks.push(part.bytes);
          expect(chunks.length).toBeLessThanOrEqual(stored.length);
        }
        served = Buffer.concat(chunks);
      } finally { await closeReadyStream(ticket); }
      expect(served).toEqual(Buffer.from(stored));
      const filtered = await sharp(served).metadata();
      expect(filtered).toMatchObject({ format: 'png', width: 5, height: 9 });
      for (const key of ['orientation', 'exif', 'xmp', 'iptc', 'icc', 'comments'] as const) {
        expect((filtered as unknown as Record<string, unknown>)[key]).toBeUndefined();
      }
      assertProcessReceipt(await processQuarantine(ctx, { ...file, signal: signal() }), file.intentId);
      expect(await sanitized(db, file.intentId)).toMatchObject([{ state: 'VERIFIED', object_key: pub.object_key }]);
      expect(sanitizedPuts).toBe(1);
      expect(scanned).toHaveLength(2);
    } finally { await Promise.all([storage.close(), db.close()]); inspector.destroy(); }
  }, 170_000);
});
