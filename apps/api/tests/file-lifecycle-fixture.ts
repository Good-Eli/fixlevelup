import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { describe, expect } from 'vitest';
import type {
  FFile, FileAccessPolicy, FileProcessingPolicy, ImageMime, LifecycleStorage, ProcessingContext, RuntimeEpoch, WorkerClean,
} from '../src/files/file-lifecycle/contract.js';
import { reserveFileUpload } from '../src/files/reservations/index.js';
import { createPrivateQuarantineStorage } from '../src/files/storage/index.js';
import { uploadReservedFile } from '../src/files/upload-coordinator/index.js';
import type { UploadOperationalPolicy } from '../src/files/upload-coordinator/index.js';
import { authFixtureMigrations } from './auth-db-fixture.js';
import { newConsentedAnchor, proof } from './file-reservations-fixture.js';
import type { FileReservationsFixture } from './file-reservations-fixture.js';
import { bindings, expectRefusal, policy, startUploadDb } from './file-upload-fixture.js';
import { asyncChunks, loopback, loopbackConfig, loopbackObjectStore, sha256Hex } from './file-storage-fixture.js';
import type { LoopbackHandler } from './file-storage-fixture.js';

const pgEnabled = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';
export const lifecycleIntegration = pgEnabled ? describe : describe.skip;
export const lifecycleRealIntegration = pgEnabled && process.env['FIXLEVELUP_STORAGE_S3_TESTS'] === '1'
  && process.env['FIXLEVELUP_FILE_PROCESSING_TESTS'] === '1' ? describe : describe.skip;
const namespace = randomUUID();
const fixtureTtlMs = 300_000;
export const epoch: RuntimeEpoch = Object.freeze({ namespace, epoch: 1n });
export const maxLiveOperationsPerOwner = 4;
export const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAAEklEQVQImWMIKJgQUDCBAUIBACPOBUGVw0ybAAAAAElFTkSuQmCC', 'base64');

export async function closeFixture(fixture: { close(): Promise<void> } | undefined): Promise<void> {
  await fixture?.close();
}

export function expiresIn(ms = fixtureTtlMs): Date { return new Date(Date.now() + ms); }
export function signal(): AbortSignal { return new AbortController().signal; }
export function assertProcessReceipt(value: unknown, intentId: string): void {
  expect(value).toStrictEqual({ intentId, completed: true });
  if (typeof value !== 'object' || value === null) { throw new Error('Missing process command receipt'); }
  expect(Reflect.ownKeys(value).sort()).toEqual(['completed', 'intentId']);
}
export function processingPolicy(overrides: Partial<FileProcessingPolicy> = {}): FileProcessingPolicy {
  return {
    mode: 'local-synthetic', versionId: randomUUID(), expiresAt: expiresIn(), allowedMimeTypes: ['image/png'],
    maxRawBytes: 64_000, maxOutputBytes: 64_000, maxWidth: 128, maxHeight: 128, maxPixels: 16_384,
    maxChannels: 4, leaseMs: 120_000, wallMs: 90_000, maxDefsAgeMs: 7 * 24 * 60 * 60 * 1_000,
    ...overrides,
  };
}
export function accessPolicy(overrides: Partial<FileAccessPolicy> = {}): FileAccessPolicy {
  return {
    mode: 'local-synthetic', expiresAt: expiresIn(), maxAccessAgeMs: fixtureTtlMs, maxChunkBytes: 17,
    maxBufferedBytes: 512_000, maxActiveStreams: 2, ticketMs: 15_000, ...overrides,
  };
}
export function uploadPolicy(overrides: Partial<UploadOperationalPolicy> = {}): UploadOperationalPolicy {
  return policy({ maxPhysicalBytesPerOwner: 512_000, maxLiveOperationsPerOwner, maxSourceChunkBytes: 64_000, ...overrides });
}

export async function startLifecycleDb(): Promise<FileReservationsFixture> {
  if (!authFixtureMigrations.some((name) => name === '20261122000200_file_processing_access')) {
    throw new Error('C tests require actual migration 016 in the auth fixture chain');
  }
  const db = await startUploadDb();
  try {
    await db.migrator.query(`INSERT INTO foundation.file_runtime_epochs
      (singleton,namespace_id,epoch,mode) VALUES (true,$1,$2,'ACTIVE')`,
    [epoch.namespace, epoch.epoch.toString()]);
    return db;
  } catch (error) {
    await db.close();
    throw error;
  }
}

export async function provision(
  db: FileReservationsFixture, storage: LifecycleStorage, bytes: Uint8Array = png,
  options: { sessionExpiry?: Date; intentExpiry?: Date; originalPolicyExpiry?: Date; anchor?: FixtureOwner; mime?: ImageMime } = {},
) {
  const anchor = options.anchor ?? await newConsentedAnchor(db, options.sessionExpiry ?? expiresIn());
  const mime = options.mime ?? 'image/png';
  const intent = await db.inTransaction((client) => reserveFileUpload(client, {
    session: proof(anchor),
    policy: {
      versionId: randomUUID(), sourceRef: 'synthetic://c-lifecycle-test', allowedMimeTypes: [mime],
      maxFileBytes: 64_000, maxOwnerBytes: 512_000, maxOwnerFiles: 8,
      expiresAt: options.originalPolicyExpiry ?? expiresIn(),
    },
    declaredMime: mime, declaredBytes: bytes.byteLength,
    expiresAt: options.intentExpiry ?? expiresIn(fixtureTtlMs - 1_000), idempotencyKey: randomUUID(),
  }));
  const file: FFile = { session: proof(anchor), intentId: intent.intentId };
  await uploadReservedFile(db.runtime, storage, uploadPolicy({ allowedMimeTypes: [mime] }), {
    ...file, idempotencyKey: randomUUID(), signal: signal(), body: () => asyncChunks([bytes]),
  });
  const binding = (await bindings(db, intent.intentId))[0];
  if (binding === undefined) {throw new Error('C fixture missing raw binding from real B upload');}
  return { file, anchor, intent, binding };
}

type FixtureOwner = Awaited<ReturnType<typeof newConsentedAnchor>>;
export function processingContext(
  db: FileReservationsFixture, storage: LifecycleStorage, processor: ProcessingContext['processor'],
  overrides: Partial<ProcessingContext> = {},
): ProcessingContext {
  return { pool: db.runtime, epoch, storage, processor, uploadPolicy: uploadPolicy(), policy: processingPolicy(), ...overrides };
}

export async function wireStore(intercept?: (path: string, method: string) => LoopbackHandler | undefined) {
  const store = loopbackObjectStore();
  const socket = await loopback((request, response, record) => {
    const path = record.url.split('?')[0] ?? '';
    (intercept?.(path, record.method) ?? store.handler)(request, response, record);
  }, { captureBody: true });
  const config = loopbackConfig(socket.endpoint, {
    maxChunkBytes: 64_000, maxResponseBodyBytes: 128_000, maxConcurrentOperations: 4,
    socketTimeoutMs: 7_000, requestTimeoutMs: 7_000, operationTimeoutMs: 8_000,
  });
  const storage = createPrivateQuarantineStorage(config);
  return {
    config, storage, socket, store,
    sanitizedPuts: () => socket.requests.filter(({ method, url }) => method === 'PUT' && url.includes('/sanitized/')),
    sanitizedGets: () => socket.requests.filter(({ method, url }) => method === 'GET' && url.includes('/sanitized/')),
    async close() { await storage.close(); await socket.close(); },
  };
}

export interface ProcessingRow { id: string; state: string; object_key: string; generation: number; charged_bytes: string }
export async function sanitized(db: FileReservationsFixture, intentId: string) {
  return (await db.migrator.query<ProcessingRow>(`SELECT id,state,object_key,generation,charged_bytes
    FROM foundation.file_sanitized_attempts WHERE intent_id=$1 ORDER BY generation`, [intentId])).rows;
}
export interface PublicationRow {
  id: string; raw_bytes: string; raw_sha256: string; served_bytes: string; served_sha256: string;
  defs_sha256: string; engine_version: string; engine_image_sha256: string; processing_policy_id: string;
  object_key: string; raw_key: string;
}
export async function publications(db: FileReservationsFixture, intentId: string) {
  return (await db.migrator.query<PublicationRow>(`SELECT p.id,p.raw_bytes,p.raw_sha256,p.served_bytes,p.served_sha256,
    p.defs_sha256,p.engine_version,p.engine_image_sha256,p.processing_policy_id,s.object_key,r.object_key AS raw_key
    FROM foundation.file_publications p JOIN foundation.file_sanitized_attempts s ON s.id=p.sanitized_attempt_id
    JOIN foundation.file_quarantine_objects q ON q.id=p.quarantine_id
    JOIN foundation.file_upload_attempts r ON r.id=q.attempt_id WHERE p.intent_id=$1`, [intentId])).rows;
}
export async function control(db: FileReservationsFixture, intentId: string) {
  return (await db.migrator.query<{
    read_lease_id: string | null; read_expires_at: Date | null; read_generation: number;
    processing_lease_id: string | null; processing_expires_at: Date | null; processing_generation: number;
  }>(`SELECT read_lease_id,read_expires_at,read_generation,processing_lease_id,processing_expires_at,processing_generation
    FROM foundation.file_privacy_controls WHERE intent_id=$1`, [intentId])).rows[0];
}
export async function assertNoReady(db: FileReservationsFixture, intentId: string): Promise<void> {
  expect(await publications(db, intentId)).toEqual([]);
}

export type QueryHook = (sql: string, client: PoolClient, query: () => Promise<unknown>) => Promise<unknown>;
/** Only the selected exchange is delayed/faulted; the statements and locks remain real PG. */
export function withQueryHook(pool: Pool, matches: (sql: string) => boolean, hook: QueryHook): Pool {
  return new Proxy(pool, {
    get(target, key): unknown {
      if (key !== 'connect') {
        const member: unknown = Reflect.get(target, key, target);
        return typeof member === 'function' ? member.bind(target) : member;
      }
      return async () => {
        const client = await target.connect();
        return new Proxy(client, {
          get(backend, member): unknown {
            if (member !== 'query') {
              const value: unknown = Reflect.get(backend, member, backend);
              return typeof value === 'function' ? value.bind(backend) : value;
            }
            return (...args: unknown[]): unknown => {
              const run = (): unknown => Reflect.apply(backend.query.bind(backend), backend, args);
              const sql = args[0];
              return typeof sql === 'string' && matches(sql) ? hook(sql, backend, async () => await run()) : run();
            };
          },
        });
      };
    },
  });
}

/** Access-only fixtures purposefully do not pretend a scanner passed: use independent SQL to construct
 * an exact published tuple on a unique test target, then prove serving against that tuple. The one
 * full READY pipeline test instead uses both actual engines, actual B/C/F ports and real Garage. */
export async function seedReadFixture(db: FileReservationsFixture, wire: Awaited<ReturnType<typeof wireStore>>, output = png,
  owner?: FixtureOwner) {
  const fixture = await provision(db, wire.storage, png, owner === undefined ? {} : { anchor: owner });
  const { intentId } = fixture.file;
  const attempt = randomUUID();
  const lease = randomUUID();
  const pub = randomUUID();
  const key = `sanitized/${attempt}/${randomUUID()}`;
  const hash = sha256Hex(output);
  const client = await db.migrator.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO foundation.file_privacy_controls (intent_id) VALUES ($1)', [intentId]);
    await client.query(`UPDATE foundation.file_privacy_controls SET processing_generation=1,
      processing_lease_id=$2,processing_expires_at=clock_timestamp()+interval '120 seconds' WHERE intent_id=$1`, [intentId, lease]);
    await client.query(`INSERT INTO foundation.file_sanitized_attempts
      (id,intent_id,owner_request_session_id,quarantine_id,generation,lease_id,lease_expires_at,object_key,
       storage_endpoint,storage_bucket,storage_region,mime,charged_bytes,expected_sha256,state)
      SELECT $1,$2,$3,$4,1,$5,processing_expires_at,$6,$7,$8,$9,'image/png',$10,$11,'REGISTERED'
      FROM foundation.file_privacy_controls WHERE intent_id=$2`, [attempt, intentId, fixture.anchor.sessionId,
      fixture.binding.id, lease, key, wire.config.endpoint, wire.config.bucket, wire.config.region, output.length, hash]);
    await client.query(`UPDATE foundation.file_sanitized_attempts SET state='IN_FLIGHT' WHERE id=$1`, [attempt]);
    await client.query(`UPDATE foundation.file_sanitized_attempts SET state='VERIFIED',
      verified_bytes=charged_bytes,verified_sha256=expected_sha256 WHERE id=$1`, [attempt]);
    await client.query(`INSERT INTO foundation.file_publications
      (id,intent_id,quarantine_id,raw_bytes,raw_sha256,sanitized_attempt_id,mime,served_bytes,served_sha256,
       processing_policy_id,processing_policy_sha256,engine_version,engine_image_sha256,defs_sha256,defs_built_at)
      VALUES ($1,$2,$3,$4,$5,$6,'image/png',$7,$8,$9,$10,'1.4.7',$11,$12,clock_timestamp())`,
    [pub, intentId, fixture.binding.id, fixture.binding.actual_bytes, fixture.binding.sha256, attempt, output.length, hash,
      randomUUID(), 'd'.repeat(64), 'e'.repeat(64), 'f'.repeat(64)]);
    await client.query(`UPDATE foundation.file_privacy_controls SET processing_lease_id=NULL,processing_expires_at=NULL
      WHERE intent_id=$1`, [intentId]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
  wire.store.seed(`/${wire.config.bucket}/${key}`, output);
  return { ...fixture, pub, key, output };
}

export function digest(bytes: Uint8Array) { return { bytes: bytes.byteLength, sha256: sha256Hex(bytes) }; }
export function faultEvidence(bytes: Uint8Array, raw: WorkerClean['raw']): WorkerClean {
  return { kind: 'CLEAN', raw, served: digest(bytes), output: bytes, mime: 'image/png', engineVersion: '1.4.7',
    engineImageSha256: 'e'.repeat(64), defsSha256: 'f'.repeat(64), defsBuiltAt: new Date().toISOString() };
}
export { expectRefusal };
