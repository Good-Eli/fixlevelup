import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { expect } from 'vitest';
import { reserveFileUpload } from '../src/files/reservations/index.js';
import type { FileMimeType, FileUploadReservation } from '../src/files/reservations/index.js';
import { createPrivateQuarantineStorage } from '../src/files/storage/index.js';
import type { UploadOperationalPolicy, UploadReservedFileCommand } from '../src/files/upload-coordinator/index.js';
import { newConsentedAnchor, proof, startFileReservationsDatabase } from './file-reservations-fixture.js';
import type { Anchor, FileReservationsFixture } from './file-reservations-fixture.js';
import { assertSafeFailure, asyncChunks, bounded, loopback, loopbackConfig, sleep, storageCode } from './file-storage-fixture.js';
import type { LoopbackHandler } from './file-storage-fixture.js';

const MIGRATION_015 = '20261122000100_file_upload_attempts';
const WAIT_MS = 6_000;
export const FAILURE_MARKER = 'synthetic-private-pg-source-diagnostic';
export const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x42, 0x43, 0x44, 0x45]);

export async function startUploadDb(): Promise<FileReservationsFixture> {
  const { authFixtureMigrations } = await import('./auth-db-fixture.js');
  if (!authFixtureMigrations.includes(MIGRATION_015)) {
    throw new Error('B2 tests require migration 015 in the isolated auth fixture');
  }
  return startFileReservationsDatabase();
}

/** Explicit synthetic fixture values; no business defaults. */
export function policy(overrides: Partial<UploadOperationalPolicy> = {}): UploadOperationalPolicy {
  return {
    mode: 'local-synthetic',
    maxAttemptsPerOwner: 8,
    maxPhysicalBytesPerOwner: 384,
    maxLiveOperationsPerOwner: 4,
    leaseMs: 8_000,
    prefixTimeoutMs: 1_500,
    maxSourceChunkBytes: 64,
    allowedMimeTypes: ['image/png'],
    ...overrides,
  };
}

export async function reserve(
  db: FileReservationsFixture, options: { anchor?: Anchor; bytes?: number; mime?: FileMimeType; ttlMs?: number; exactLogicalQuota?: boolean } = {},
): Promise<{ anchor: Anchor; intent: FileUploadReservation }> {
  const anchor = options.anchor ?? await newConsentedAnchor(db);
  const bytes = options.bytes ?? PNG.byteLength;
  const mime = options.mime ?? 'image/png';
  const intent = await db.inTransaction((client) => reserveFileUpload(client, {
    session: proof(anchor),
    policy: {
      versionId: randomUUID(), sourceRef: 'synthetic://b2-test', allowedMimeTypes: [mime],
      maxFileBytes: bytes, maxOwnerBytes: options.exactLogicalQuota === true ? bytes : 1_000,
      maxOwnerFiles: options.exactLogicalQuota === true ? 1 : 8,
      expiresAt: new Date(Date.now() + 60_000),
    },
    declaredMime: mime, declaredBytes: bytes,
    expiresAt: new Date(Date.now() + (options.ttlMs ?? 40_000)), idempotencyKey: randomUUID(),
  }));
  return { anchor, intent };
}

export function command(anchor: Anchor, intentId: string, overrides: Partial<UploadReservedFileCommand> = {}): UploadReservedFileCommand {
  return {
    session: proof(anchor), intentId, idempotencyKey: randomUUID(),
    body: () => asyncChunks([PNG.subarray(0, 3), PNG.subarray(3)]), signal: new AbortController().signal,
    ...overrides,
  };
}

export function gate(): { open(): void; wait(): Promise<void> } {
  let release: (() => void) | undefined;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { open() { release?.(); }, wait: () => bounded(promise, WAIT_MS, 'test checkpoint') };
}

export interface AttemptRow {
  id: string; generation: number; object_key: string; state: string;
  charged_bytes: string; dispatched_at: Date | null; verified_bytes: string | null; verified_sha256: string | null;
  upload_lease_expires_at: Date; probe_lease_expires_at: Date | null;
  probe_held_slots: number; probe_generation: number; observation: string | null;
  observed_bytes: string | null; observed_sha256: string | null;
}

export async function attempts(db: FileReservationsFixture, intentId: string): Promise<AttemptRow[]> {
  return (await db.migrator.query<AttemptRow>(`
    SELECT id,generation,object_key,state,charged_bytes,dispatched_at,verified_bytes,verified_sha256,
      upload_lease_expires_at,probe_lease_expires_at,probe_held_slots,probe_generation,observation,observed_bytes,observed_sha256
    FROM foundation.file_upload_attempts WHERE intent_id=$1 ORDER BY generation`, [intentId])).rows;
}

export interface BindingRow { id: string; attempt_id: string; actual_bytes: string; sha256: string }
export async function bindings(db: FileReservationsFixture, intentId: string): Promise<BindingRow[]> {
  return (await db.migrator.query<BindingRow>(`
    SELECT id,attempt_id,actual_bytes,sha256 FROM foundation.file_quarantine_objects WHERE intent_id=$1`, [intentId])).rows;
}

export interface UploadEvent { operation: string; details: Record<string, unknown> }
export async function uploadEvents(db: FileReservationsFixture, intentId: string): Promise<UploadEvent[]> {
  return (await db.migrator.query<UploadEvent>(`
    SELECT operation, details FROM foundation.audit_logs
      WHERE details->>'intentId'=$1 AND operation LIKE 'FILE_UPLOAD_%'
      ORDER BY occurred_at`, [intentId])).rows.filter(({ details }) => Object.hasOwn(details, 'attemptId'));
}

export async function assertUploadEventPairs(db: FileReservationsFixture, intentId: string): Promise<void> {
  const audit = await uploadEvents(db, intentId);
  const outbox = (await db.migrator.query<{ operation: string; details: Record<string, unknown> }>(`
    SELECT event_type AS operation, payload AS details FROM foundation.outbox_events
      WHERE payload->>'intentId'=$1 AND event_type LIKE 'FILE_UPLOAD_%'`, [intentId])).rows
    .filter(({ details }) => Object.hasOwn(details, 'attemptId'));
  expect(outbox).toHaveLength(audit.length);
  expect(outbox).toEqual(expect.arrayContaining(audit));
  for (const { details } of audit) {
    expect(Object.keys(details).sort()).toEqual(['attemptId', 'generation', 'intentId', 'status']);
  }
}

/** Delay/fault only the COMMIT exchange; all data/locks/visibility remain real PostgreSQL. */
export function poolWithCommitHook(
  real: Pool, onCommit: (ordinal: number, client: PoolClient, commit: () => Promise<unknown>) => Promise<unknown>,
  onCheckout?: (client: PoolClient) => void,
): Pool {
  let ordinal = 0;
  const connect = async (): Promise<PoolClient> => {
    const client = await real.connect();
    onCheckout?.(client);
    return new Proxy(client, {
      get(target, key): unknown {
        if (key === 'query') {
          return (...args: unknown[]): unknown => {
            const query = (): unknown => Reflect.apply(target.query.bind(target), target, args);
            if (typeof args[0] === 'string' && /^\s*COMMIT\s*;?\s*$/iu.test(args[0])) {
              ordinal += 1;
              return onCommit(ordinal, target, async () => await query());
            }
            return query();
          };
        }
        const item: unknown = Reflect.get(target, key, target);
        return typeof item === 'function' ? item.bind(target) : item;
      },
    });
  };
  return new Proxy(real, {
    get(target, key): unknown {
      if (key === 'connect') {
        return connect;
      }
      const item: unknown = Reflect.get(target, key, target);
      return typeof item === 'function' ? item.bind(target) : item;
    },
  });
}

export async function pid(client: PoolClient): Promise<number> {
  const row = (await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0];
  if (row === undefined) {
    throw new Error('No PostgreSQL backend PID');
  }
  return row.pid;
}

export async function until(check: () => Promise<boolean>, label: string): Promise<void> {
  const deadline = performance.now() + WAIT_MS;
  while (!await check()) {
    if (performance.now() >= deadline) {
      throw new Error(`PostgreSQL checkpoint not reached: ${label}`);
    }
    await sleep(20);
  }
}

export async function waitForBlockingPid(db: FileReservationsFixture, blockingPid: number, waitingPid: number): Promise<void> {
  await until(async () => (await db.migrator.query<{ waiting: boolean }>(
    'SELECT $1=ANY(pg_blocking_pids($2)) AS waiting', [blockingPid, waitingPid],
  )).rows[0]?.waiting === true, 'distinct backends are blocked');
}

export async function waitForDbExpiry(db: FileReservationsFixture, timestamp: Date | string): Promise<void> {
  await until(async () => (await db.migrator.query<{ expired: boolean }>(
    'SELECT clock_timestamp() > $1::timestamptz AS expired', [timestamp],
  )).rows[0]?.expired === true, 'DB-clock expiry');
}

export async function wire(handler: LoopbackHandler) {
  const socket = await loopback(handler, { captureBody: true });
  const newAdapter = () => createPrivateQuarantineStorage(loopbackConfig(socket.endpoint, {
    requestTimeoutMs: 7_000, socketTimeoutMs: 7_000, operationTimeoutMs: 8_000,
  }));
  const storage = newAdapter();
  return { socket, storage, newAdapter, async close() {
    await storage.close();
    await socket.close();
  } };
}

export async function expectRefusal(action: Promise<unknown>, codes: string | readonly string[], forbidden: readonly string[] = []): Promise<void> {
  assertRefusal(await action.then(() => undefined, (error: unknown) => error), codes, forbidden);
}

export function assertRefusal(value: unknown, codes: string | readonly string[], forbidden: readonly string[] = []): void {
  expect(value).toBeInstanceOf(Error);
  expect(typeof value === 'object' && value !== null && 'cause' in value).toBe(false);
  const code = storageCode(value);
  expect(typeof codes === 'string' ? [codes] : codes).toContain(code);
  if (value instanceof Error && value.name === 'UploadCoordinatorError') {
    expect(value.message === code).toBe(true);
    expect(Object.getOwnPropertyNames(value).sort()).toEqual(['code', 'message', 'name', 'stack']);
  }
  // Stack function names may legitimately include checkAuthorization; only the
  // fixed error surface is a diagnostic/secret boundary.
  assertSafeFailure(value instanceof Error ? `${value.name}:${value.message}:${JSON.stringify(value)}` : value, [FAILURE_MARKER, ...forbidden]);
}
