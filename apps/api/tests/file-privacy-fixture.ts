import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { Pool } from 'pg';
import { labGarageCli } from '../../../infra/file-restore/resources.mjs';
import {
  bootstrapFileLedgerNamespace, createFileLedgerVerifier, createPgFileLedger, createPgFloorStore,
} from '../src/files/file-ledger/index.js';
import { headMessage } from '../src/files/file-ledger/codec.js';
import type { DurableFloorStore, FileLedger, LedgerScope } from '../src/files/file-ledger/contract.js';
import { createSyntheticDeleteBroker, makeFilePrivacyGrant, revokeDeleteBroker } from '../src/files/file-privacy/index.js';
import { describe, expect } from 'vitest';
import type { AggregateOnly, RetentionPolicy } from '../src/files/file-privacy/contract.js';
import { createPrivateQuarantineStorage } from '../src/files/storage/index.js';
import { uploadReservedFile } from '../src/files/upload-coordinator/index.js';
import { authFixtureMigrations } from './auth-db-fixture.js';
import { withQueryHook } from './file-lifecycle-fixture.js';
import type { FileReservationsFixture } from './file-reservations-fixture.js';
import { attempts, command, FAILURE_MARKER, gate, PNG, policy, reserve, startUploadDb } from './file-upload-fixture.js';
import {
  GARAGE_ENDPOINT, GARAGE_REGION, loopback, loopbackConfig, settle, sha256Hex, storageCode, TECHNICAL_TIMEOUTS,
} from './file-storage-fixture.js';
import type { GarageCredentials, LoopbackHandler, StorageTestConfig } from './file-storage-fixture.js';

const pg = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';
const privacy = process.env['FIXLEVELUP_FILE_PRIVACY_TESTS'] === '1';
export const privacyDb = pg && privacy ? describe : describe.skip;
export const privacyGarage = pg && privacy && process.env['FIXLEVELUP_STORAGE_S3_TESTS'] === '1' ? describe : describe.skip;
export const signal = () => new AbortController().signal;

export async function startPrivacyMain(namespace: string) {
  // The shared fixture independently verifies the exact full migration chain.
  if (!privacy || authFixtureMigrations[17] !== '20261122000400_settings_management') {
    throw new Error('D tests require explicit opt-in and the verified full chain including 018');
  }
  const db = await startUploadDb();
  try {
    await db.migrator.query(`INSERT INTO foundation.file_runtime_epochs (singleton,namespace_id,epoch,mode)
      VALUES (true,$1,1,'ACTIVE')`, [namespace]);
    return db;
  } catch (error) {
    await db.close();
    throw error;
  }
}

export async function dbTime(db: Pick<FileReservationsFixture, 'migrator'>, deltaMs: number): Promise<Date> {
  const { rows } = await db.migrator.query<{ t: Date }>(
    "SELECT clock_timestamp()+$1::int*interval '1 millisecond' AS t", [deltaMs]);
  const row = rows[0];
  if (row === undefined) { throw new Error('DB clock unavailable'); }
  return row.t;
}

export async function retentionPolicy(db: FileReservationsFixture, overrides: Partial<RetentionPolicy> = {}): Promise<RetentionPolicy> {
  return {
    mode: 'local-synthetic', versionId: randomUUID(), expiresAt: await dbTime(db, 120_000),
    rawBoundMs: 1, readyMs: 1, quarantinedMs: 1, orphanMs: 1, maxBatch: 32, maxItemsPerIntent: 8, claimMs: 10_000,
    ...overrides,
  };
}

interface Control {
  row_version: string; access_epoch: string; hold_active: boolean; hold_actor_id: string | null;
  hold_reason: string | null; hold_at: Date | null; delete_state: string; delete_event_id: string | null;
  delete_at: Date | null; delete_policy_id: string | null; delete_writer_epoch: string | null;
  ledger_seq: string | null; ledger_hash: string | null;
  delete_graph_sha256: string | null;
}
export async function control(db: FileReservationsFixture, intentId: string): Promise<Control> {
  const row = (await db.migrator.query<Control>(`SELECT row_version,access_epoch,hold_active,hold_actor_id,hold_reason,hold_at,
    delete_state,delete_event_id,delete_at,delete_policy_id,delete_writer_epoch,ledger_seq,ledger_hash,delete_graph_sha256
    FROM foundation.file_privacy_controls WHERE intent_id=$1`, [intentId])).rows[0];
  if (row === undefined) { throw new Error('Expected fixture control'); }
  return row;
}

interface Item {
  event_id: string; attempt_id: string; attempt_kind: 'RAW' | 'SANITIZED'; object_key: string;
  target_endpoint: string; target_bucket: string; target_region: string;
  state: string; write_proof: string; claim_id: string | null; claim_expires_at: Date | null;
  claim_generation: number; verified_at: Date | null;
}
export async function items(db: FileReservationsFixture, intentId: string): Promise<Item[]> {
  return (await db.migrator.query<Item>(`SELECT event_id,attempt_id,attempt_kind,object_key,target_endpoint,target_bucket,
    target_region,state,write_proof,claim_id,claim_expires_at,claim_generation,verified_at
    FROM foundation.file_delete_items WHERE intent_id=$1 ORDER BY attempt_kind,attempt_id`, [intentId])).rows;
}

export async function auditPairs(db: FileReservationsFixture, intentId: string) {
  type Row = { operation: string; payload: Record<string, unknown> };
  const audit = (await db.migrator.query<Row>(`SELECT operation,details AS payload FROM foundation.audit_logs
    WHERE details->>'intentId'=$1 AND details ? 'phase' ORDER BY occurred_at`, [intentId])).rows;
  const outbox = (await db.migrator.query<Row>(`SELECT event_type AS operation,payload FROM foundation.outbox_events
    WHERE payload->>'intentId'=$1 AND payload ? 'phase'`, [intentId])).rows;
  expect(outbox).toHaveLength(audit.length);
  expect(outbox).toEqual(expect.arrayContaining(audit));
  for (const row of audit) {
    expect(Object.keys(row.payload).sort()).toEqual(['intentId', 'operationId', 'phase']);
    expect(row.payload['operationId']).toMatch(/^[a-f0-9-]{36}$/u);
    expect(row.payload['phase']).toMatch(/^[A-Z_0-9]+$/u);
  }
  return audit;
}

export function aggregate(value: AggregateOnly): void {
  expect(Object.keys(value).sort()).toEqual(['advanced','deferred','examined']);
  for (const count of Object.values(value)) {
    expect(Number.isSafeInteger(count) && count >= 0).toBe(true);
  }
}

export async function refusal(action: Promise<unknown>, codes: string | readonly string[], forbidden: readonly string[] = []): Promise<void> {
  const settled = await settle(action);
  expect(settled.ok).toBe(false);
  if (settled.ok) { return; }
  const err = settled.error;
  expect(err).toBeInstanceOf(Error);
  expect(typeof err === 'object' && err !== null && 'cause' in err).toBe(false);
  const code = storageCode(err);
  expect(typeof codes === 'string' ? [codes] : codes).toContain(code);
  if (!(err instanceof Error)) { return; }
  expect(err.message).toBe(code);
  const text = `${err.message}\n${err.stack ?? ''}\n${JSON.stringify(err)}`;
  // Boolean diagnostics only: never print a key, source exception or credential on failure.
  expect([FAILURE_MARKER, 'http://', 'X-Amz-', 'AWS4-HMAC', ...forbidden].some((s) => text.includes(s))).toBe(false);
}

/** New wire target per fixture. Writes on this endpoint are synthetic and unique; the fixture refuses
 * delete of any path never registered by this test. The real broker still performs all D deletes. */
export async function privacyWire(namespace: string, suffix = 'raw', intercept?: (record: Parameters<LoopbackHandler>[2]) => LoopbackHandler | undefined) {
  const bucket = `p0304-${namespace}-${suffix}`;
  const objects = new Map<string, Buffer>();
  const allowed = new Set<string>();
  const defaultHandler: LoopbackHandler = (req, res, record) => {
    const path = (record.url.split('?')[0] ?? '');
    req.resume();
    req.once('end', () => {
      const found = objects.get(path);
      if (typeof record.headers['authorization'] !== 'string' || !path.startsWith(`/${bucket}/`)) {
        res.writeHead(403).end('<Error><Code>AccessDenied</Code></Error>');
      } else if (record.method === 'PUT') {
        allowed.add(path);
        objects.set(path, Buffer.concat(record.bodyChunks));
        res.writeHead(200, { ETag: '"synthetic"' }).end();
      } else if (record.method === 'DELETE' && allowed.has(path)) {
        objects.delete(path);
        res.writeHead(204).end();
      } else if ((record.method === 'GET' || record.method === 'HEAD') && found !== undefined) {
        res.writeHead(200, { 'Content-Length': found.length }).end(record.method === 'HEAD' ? undefined : found);
      } else if (record.method === 'GET' || record.method === 'HEAD') {
        res.writeHead(404, { 'Content-Type': 'application/xml' }).end('<Error><Code>NoSuchKey</Code></Error>');
      } else { res.writeHead(403).end('<Error><Code>AccessDenied</Code></Error>'); }
    });
  };
  const socket = await loopback((req, res, record) => {
    (intercept?.(record) ?? defaultHandler)(req, res, record);
  }, { captureBody: true });
  const config = loopbackConfig(socket.endpoint, { ...TECHNICAL_TIMEOUTS, bucket });
  const storage = createPrivateQuarantineStorage(config);
  const path = (key: string) => `/${bucket}/${key}`;
  return {
    socket, config, storage, objects, path, defaultHandler,
    allow(key: string) { allowed.add(path(key)); },
    seed(key: string, bytes: Uint8Array) { allowed.add(path(key)); objects.set(path(key), Buffer.from(bytes)); },
    deletes: () => socket.requests.filter(({ method }) => method === 'DELETE'),
    async close() { await storage.close(); await socket.close(); },
  };
}

export async function rawFixture(db: FileReservationsFixture, storage: ReturnType<typeof createPrivateQuarantineStorage>) {
  const { anchor, intent } = await reserve(db);
  const upload = command(anchor, intent.intentId);
  await uploadReservedFile(db.runtime, storage, policy(), upload);
  const [raw] = await attempts(db, intent.intentId);
  if (raw === undefined || raw.state !== 'VERIFIED') { throw new Error('Expected actual B fixture write'); }
  return { anchor, intent, upload, raw };
}

/** Use the real B registration/dispatch, but intentionally lose the PUT acknowledgement after
 * receiving the body at the controlled wire. This creates UNKNOWN without changing DB history. */
export async function orphanRaw(db: FileReservationsFixture, wire: Awaited<ReturnType<typeof privacyWire>>,
  fixture?: Awaited<ReturnType<typeof reserve>>) {
  const { anchor, intent } = fixture ?? await reserve(db);
  const upload = command(anchor, intent.intentId);
  await refusal(uploadReservedFile(db.runtime, wire.storage, policy(), upload), 'WRITE_OUTCOME_UNKNOWN');
  const raw = (await attempts(db, intent.intentId)).find(({ state }) => state === 'UNKNOWN');
  if (raw === undefined) { throw new Error('Expected real dispatched UNKNOWN write'); }
  wire.allow(raw.object_key);
  return { anchor, intent, upload, raw };
}

/** Exact FK-checked publication only for testing D technique, not scanner/engine evidence. */
export async function seedSanitized(db: FileReservationsFixture, fixture: Awaited<ReturnType<typeof rawFixture>>,
  config: StorageTestConfig, options: { publish: boolean; dispatched: boolean }) {
  const attempt = randomUUID();
  const lease = randomUUID();
  const intentId = fixture.intent.intentId;
  const objectKey = `sanitized/${attempt}/${randomUUID()}`;
  const digest = sha256Hex(PNG);
  const client = await db.migrator.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO foundation.file_privacy_controls (intent_id) VALUES ($1) ON CONFLICT DO NOTHING', [intentId]);
    const { rows } = await client.query<{ processing_generation: number }>(`UPDATE foundation.file_privacy_controls
      SET processing_generation=processing_generation+1,processing_lease_id=$2,
      processing_expires_at=clock_timestamp()+interval '120 seconds' WHERE intent_id=$1 RETURNING processing_generation`, [intentId, lease]);
    const generation = rows[0]?.processing_generation;
    await client.query(`INSERT INTO foundation.file_sanitized_attempts
      (id,intent_id,owner_request_session_id,quarantine_id,generation,lease_id,lease_expires_at,object_key,
       storage_endpoint,storage_bucket,storage_region,mime,charged_bytes,expected_sha256,state)
      SELECT $1,$2,$3,q.id,$4,$5,c.processing_expires_at,$6,$7,$8,$9,'image/png',$10,$11,'REGISTERED'
      FROM foundation.file_privacy_controls c JOIN foundation.file_quarantine_objects q USING(intent_id)
      WHERE c.intent_id=$2`, [attempt, intentId, fixture.anchor.sessionId, generation, lease,
      objectKey, config.endpoint, config.bucket, config.region, PNG.length, digest]);
    if (options.dispatched) {
      await client.query("UPDATE foundation.file_sanitized_attempts SET state='IN_FLIGHT' WHERE id=$1", [attempt]);
      if (options.publish) {
        await client.query(`UPDATE foundation.file_sanitized_attempts SET state='VERIFIED',
          verified_bytes=charged_bytes,verified_sha256=expected_sha256 WHERE id=$1`, [attempt]);
        await client.query(`INSERT INTO foundation.file_publications
          (id,intent_id,quarantine_id,raw_bytes,raw_sha256,sanitized_attempt_id,mime,served_bytes,served_sha256,
           processing_policy_id,processing_policy_sha256,engine_version,engine_image_sha256,defs_sha256,defs_built_at)
          SELECT $1,$2,q.id,q.actual_bytes,q.sha256,$3,'image/png',$4,$5,$6,$7,'1.4.7',$8,$9,clock_timestamp()
          FROM foundation.file_quarantine_objects q WHERE intent_id=$2`, [randomUUID(), intentId, attempt, PNG.length,
          digest, randomUUID(), 'a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)]);
      } else {
        await client.query("UPDATE foundation.file_sanitized_attempts SET state='UNKNOWN' WHERE id=$1", [attempt]);
      }
    } else {
      await client.query("UPDATE foundation.file_sanitized_attempts SET state='FAILED_NOBYTES' WHERE id=$1", [attempt]);
    }
    await client.query(`UPDATE foundation.file_privacy_controls SET processing_lease_id=NULL,processing_expires_at=NULL
      WHERE intent_id=$1`, [intentId]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
  return { attempt, objectKey };
}

export function observeBackend(pool: Pool) {
  const connected = gate();
  let pid = 0;
  const watched = withQueryHook(pool, (sql) => /^BEGIN/iu.test(sql.trim()), async (_sql, client, query) => {
    pid = (await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid ?? 0;
    connected.open();
    return query();
  });
  return { pool: watched, async pid() { await connected.wait(); return pid; } };
}

export async function rejectOutbox(db: FileReservationsFixture, intentId: string, operationId?: string) {
  const name = `p0304d_${randomUUID().replaceAll('-', '')}`;
  // The intent/operation UUIDs are generated by this fixture. Reject only a D transition, only
  // AFTER seeing its paired audit in the same transaction. Retain the fixture DB for inspection.
  await db.migrator.query(`CREATE FUNCTION foundation.${name}() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,foundation AS $$
    BEGIN
      IF NEW.payload->>'intentId'=TG_ARGV[0] AND NEW.payload ? 'phase'
        AND (TG_ARGV[1]='' OR NEW.payload->>'operationId'=TG_ARGV[1]) THEN
        IF NOT EXISTS (SELECT 1 FROM foundation.audit_logs WHERE details=NEW.payload) THEN
          RAISE EXCEPTION 'synthetic missing same-transaction audit';
        END IF;
        RAISE EXCEPTION '${FAILURE_MARKER}';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER ${name} BEFORE INSERT ON foundation.outbox_events FOR EACH ROW EXECUTE FUNCTION foundation.${name}('${intentId}','${operationId ?? ''}')`);
}

/** Lab mode (P05-02 S4): the real Garage CLI at the pinned path and config.
 * Dev mode keeps the historical Docker-exec path unchanged. */
function garage(...args: string[]): string {
  if (process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1') {
    return labGarageCli('privacy-garage', ...args);
  }
  try {
    return execFileSync('docker', ['exec','fixlevelup-dev-s3','/garage', ...args], {
      encoding: 'utf8', timeout: 15_000, stdio: ['ignore','pipe','pipe'], windowsHide: true,
    });
  } catch { throw new Error('Isolated Garage fixture provisioning failed'); }
}

function garageKey(bucket: string, role: string, write: boolean): GarageCredentials {
  const name = `${bucket}-${role}`;
  const output = garage('key','create',name);
  const accessKeyId = /\bGK[a-f0-9]{24}\b/u.exec(output)?.[0];
  const secretAccessKey = /\b[a-f0-9]{64}\b/u.exec(output)?.[0];
  if (accessKeyId === undefined || secretAccessKey === undefined) { throw new Error('Missing new synthetic Garage credential'); }
  garage('bucket','allow','--read', ...(write ? ['--write'] : []), '--key', accessKeyId, bucket);
  return { accessKeyId, secretAccessKey };
}

export function garageTarget(namespace: string) {
  if (!(pg && privacy && process.env['FIXLEVELUP_STORAGE_S3_TESTS'] === '1') || !/^[0-9a-f-]{36}$/u.test(namespace)) {
    throw new Error('Refusing non-isolated Garage fixture');
  }
  const bucket = `p0304-${namespace}-d`;
  garage('bucket','create',bucket);
  const publisher = garageKey(bucket, 'publisher', true);
  const observer = garageKey(bucket, 'observer', false);
  const broker = garageKey(bucket, 'broker', true);
  const config = (credentials: GarageCredentials): StorageTestConfig => ({
    endpoint: GARAGE_ENDPOINT, allowedEndpoint: GARAGE_ENDPOINT, region: GARAGE_REGION,
    bucket, mode: 'local-synthetic', ...TECHNICAL_TIMEOUTS, ...credentials,
  });
  const client = (credentials: GarageCredentials) => new S3Client({ endpoint: GARAGE_ENDPOINT, region: GARAGE_REGION,
    forcePathStyle: true, maxAttempts: 1, credentials, requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED' });
  const reader = client(observer);
  const writer = client(publisher);
  const storage = createPrivateQuarantineStorage(config(publisher));
  const own = new Set<string>();
  const keyArg = (key: string) => {
    if (!own.has(key)) { throw new Error('Refusing unknown Garage fixture key'); }
    return { Bucket: bucket, Key: key };
  };
  return {
    config: config(broker), storage,
    allow(key: string) { own.add(key); },
    async putSanitizedFixture(key: string) {
      try { await writer.send(new PutObjectCommand({ ...keyArg(key), Body: PNG }), { abortSignal: AbortSignal.timeout(5_000) }); }
      catch { throw new Error('Synthetic Garage fixture PUT failed'); }
    },
    async observe(key: string) {
      const result = await settle(reader.send(new GetObjectCommand(keyArg(key)), { abortSignal: AbortSignal.timeout(5_000) }));
      if (result.ok) {
        const body = result.value.Body;
        if (body === undefined) { throw new Error('Garage fixture GET returned no body'); }
        return { http: result.value.$metadata.httpStatusCode, digest: sha256Hex(await body.transformToByteArray()) };
      }
      return { http: (result.error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode,
        code: (result.error as { name?: string }).name };
    },
    async readOnlyDeleteStatus(key: string) {
      const result = await settle(reader.send(new DeleteObjectCommand(keyArg(key)), { abortSignal: AbortSignal.timeout(5_000) }));
      return result.ok ? result.value.$metadata.httpStatusCode
        : (result.error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
    },
    async close() { reader.destroy(); writer.destroy(); await storage.close(); },
  };
}

export async function privacyFixture() {
  const config = readFileSync(resolve(import.meta.dirname, '../../../infra/file-ledger/.env'), 'utf8');
  function role(user: string, database: string, port: number): Pool {
    const password = new RegExp(`^${user.toUpperCase()}_PASSWORD=([^\\r\\n]+)$`, 'm').exec(config)?.[1];
    if (password === undefined) { throw new Error('Missing isolated ledger fixture role'); }
    return new Pool({ host: '127.0.0.1', port, database, user, password, max: 3, connectionTimeoutMillis: 3_000 });
  }
  const writer = role('file_ledger_writer', 'fixlevelup_file_ledger', 55433);
  const signer = role('file_ledger_signer', 'fixlevelup_file_ledger', 55433);
  const operator = role('file_ledger_operator', 'fixlevelup_file_ledger', 55433);
  const floorVerifier = role('file_floor_verifier', 'fixlevelup_file_floor', 55434);
  const floorOperator = role('file_floor_operator', 'fixlevelup_file_floor', 55434);
  const closeLedger = () => Promise.all([writer, signer, operator, floorVerifier, floorOperator].map((pool) => pool.end()));
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const limits = { maxItems: 64, maxProofEvents: 64 };
  try {
    const genesis = await bootstrapFileLedgerNamespace({ mode: 'local-synthetic', ledgerOperatorPool: operator,
      floorOperatorPool: floorOperator, signerPublicKey: publicKey, initialEpoch: 1n });
    const scope: LedgerScope = { namespace: genesis.namespace, incarnation: genesis.incarnation, writerEpoch: 1n };
    const db = await startPrivacyMain(scope.namespace);
    const epoch = { namespace: scope.namespace, epoch: 1n };
    const floor = createPgFloorStore(floorVerifier);
    const createLedger = (pool: Pool) => createPgFileLedger(pool, { mode: 'local-synthetic', signerPool: signer,
      privateKey, limits, operatorPool: operator });
    const ledger = createLedger(writer);
    const verifier = createFileLedgerVerifier({ ledger, signerPublicKey: publicKey, floor, limits });
    const actorId = randomUUID();
    const op = (role: 'RETENTION' | 'HOLD' | 'DELETE') =>
      makeFilePrivacyGrant({ mode: 'local-synthetic', namespace: scope.namespace, role, actorId });
    return {
      db, epoch, scope, actorId, ledger, verifier, floor,
      withFloor: (other: DurableFloorStore) => createFileLedgerVerifier({ ledger, signerPublicKey: publicKey, floor: other, limits }),
      holdOperator: op('HOLD'),
      hold: (policy: RetentionPolicy, pool = db.runtime) => ({ pool, epoch, policy }),
      plan: (policy: RetentionPolicy, pool = db.runtime) => ({ pool, epoch, policy, scope, grant: op('RETENTION') }),
      delete: (policy: RetentionPolicy, broker: ReturnType<typeof createSyntheticDeleteBroker>) =>
        ({ pool: db.runtime, epoch, policy, scope, grant: op('DELETE'), ledger, verifier, broker }),
      broker: (...targets: StorageTestConfig[]) => createSyntheticDeleteBroker({ mode: 'local-synthetic', namespace: scope.namespace, epoch: 1n, targets }),
      events: () => signer.query<{ event_id: string; intent_id: string; seq: string; sha256: string }>(
        'SELECT event_id,intent_id,seq,sha256 FROM file_ledger.events WHERE namespace_id=$1 ORDER BY seq', [scope.namespace]).then(({ rows }) => rows),
      rollbackVerifier: () => {
        const oldHead = { ...scope, seq: genesis.seq, hash: genesis.hash };
        const rolledBack: FileLedger = { ...ledger, getHead: (_scope, challenge) => Promise.resolve({ ...oldHead, v: 1,
          challenge, signature: sign(null, headMessage(oldHead, challenge), privateKey).toString('hex') }), getEvents: () => Promise.resolve([]) };
        return createFileLedgerVerifier({ ledger: rolledBack, signerPublicKey: publicKey, floor, limits });
      },
      async close() { await db.close(); await closeLedger(); },
    };
  } catch (error) { await closeLedger(); throw error; }
}

export { revokeDeleteBroker };
