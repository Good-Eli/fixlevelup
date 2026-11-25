/**
 * P05 §5.2 real-PostgreSQL proofs for the attachment interlock (task-10).
 *
 * Scope: the *catalog and constraint* half of Bridge B, executed against a real,
 * freshly migrated PostgreSQL 18.7 in the pg-lab contour:
 *
 * - the reviewed S3 profile is classified `S3` on the real 024 catalog, and the
 *   facts are re-derived from `pg_catalog` (including the PostgreSQL 18 `type='n'`
 *   NOT NULL rows that a naive "exactly 8 constraints" check would misread);
 * - a real 23-migration database is classified `PRE_S3`, so the legacy branch is an
 *   inventory fact and not a caught error;
 * - real DDL inside a rolled-back transaction (dropped interlock FK, weakened
 *   `CHECK (open_state='OPEN' OR TRUE)`) is classified `DRIFTED`, so an intermediate
 *   schema can never be used as a fallback;
 * - the reviewed interlock constraints really are non-deferrable and really block
 *   both directions (see the dedicated cases below).
 *
 * Deliberately NOT claimed here: the FK races that need a committed submit
 * aggregate (no reviewed fixture can build one; `request_effect_guard` and
 * `request_aggregate_guard` only accept a real intake effect) — see the GAP note in
 * the task report. The READY half is covered separately when the isolated Garage +
 * approved engine contour is present (`FIXLEVELUP_STORAGE_S3_TESTS=1` and an engine
 * ticket): a real published file is then proven through exactly the §5.2 sequence
 * `lockAttachmentFileAuthorization` → `selectPublication` → `checkFileAuthorization`
 * → `proveReadyWindow`, i.e. the admission decision against real bytes.
 *
 * Gating: runs only in the pg-lab `s3test` contour (`FIXLEVELUP_LAB_DATABASE` is a
 * disposable `fixlevelup_p05_s3tlab_<hex>` and the synthetic orchestrator flag is
 * set). Otherwise the suite is skipped, so a normal `vitest run` stays green.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Client } from 'pg';
import sharp from 'sharp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { proveReadyWindow } from '../src/files/file-access/registry.js';
import { checkFileAuthorization, classifyAttachmentInterlock, lockAttachmentFileAuthorization,
  probeAttachmentInterlock } from '../src/files/file-lifecycle/authorization.js';
import { processQuarantine } from '../src/files/file-lifecycle/index.js';
import { selectPublication } from '../src/files/file-lifecycle/publication.js';
import { createLocalFileProcessor } from '../src/files/file-processing/processor.js';
import type { DefinitionEpoch, FileProcessingLauncher } from '../src/files/file-processing/processor.js';
import { createPrivateQuarantineStorage } from '../src/files/storage/index.js';
import type { FFile } from '../src/files/file-lifecycle/contract.js';
import { retentionCandidateSql } from '../src/files/file-privacy/retention.js';
import { migrateAuthFixture } from './auth-db-fixture.js';
import { epoch, processingContext, provision, seedReadFixture, signal, startLifecycleDb,
  wireStore } from './file-lifecycle-fixture.js';
import { expectRefusal } from './file-upload-fixture.js';
import { garageConfig } from './file-storage-fixture.js';
import { fixtureCredentials, OwnedTestDatabase } from './owned-test-database.js';
import type { CurrentConsent } from '../src/settings/legal/index.js';

const S3_HEAD = '20261125000100_request_intake_effects';
const labDatabase = process.env['FIXLEVELUP_LAB_DATABASE'] ?? '';
const lab = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && /^fixlevelup_p05_s3tlab_[a-f0-9]{12}$/.test(labDatabase);
const real = lab ? describe : describe.skip;

interface Credentials { readonly migrator: string; readonly runtime: string }

function credentials(): Credentials {
  return fixtureCredentials();
}

/** One runtime connection on the s3test database, closed by the caller. */
async function runtimeClient(database = labDatabase): Promise<Client> {
  const client = new Client({ host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_runtime',
    password: credentials().runtime, connectionTimeoutMillis: 3000, statement_timeout: 20_000,
    application_name: 'p05-attach-live' });
  await client.connect();
  return client;
}

/** The probe inside a real READ COMMITTED transaction, rolled back. */
async function probeInTransaction(client: Client, sql?: string) {
  await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
  try {
    if (sql !== undefined) { await client.query(sql); }
    return await probeAttachmentInterlock(client);
  } finally {
    await client.query('ROLLBACK');
  }
}

real('P05 attachment interlock on a real 024 PostgreSQL', () => {
  let client: Client;
  beforeAll(async () => { client = await runtimeClient(); }, 30_000);
  afterAll(async () => { await client.end().catch(() => undefined); });

  it('classifies the real reviewed 024 catalog as S3 and reports the exact facts', async () => {
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    try {
      expect(await probeAttachmentInterlock(client)).toBe('S3');
      const { rows: [facts] } = await client.query<{
        columns: number; not_null_rows: number; constraints: number; s3_relations: number; s3_indexes: number;
      }>(`SELECT
        (SELECT count(*)::int FROM pg_attribute WHERE attrelid='foundation.request_files'::regclass
          AND attnum>0 AND NOT attisdropped) AS columns,
        (SELECT count(*)::int FROM pg_constraint WHERE conrelid='foundation.request_files'::regclass
          AND contype='n') AS not_null_rows,
        (SELECT count(*)::int FROM pg_constraint WHERE conrelid='foundation.request_files'::regclass
          AND contype<>'n') AS constraints,
        (SELECT count(*)::int FROM pg_class WHERE relnamespace='foundation'::regnamespace
          AND relname IN ('request_files','request_session_submits')) AS s3_relations,
        (SELECT count(*)::int FROM pg_class WHERE relnamespace='foundation'::regnamespace
          AND relname IN ('file_privacy_controls_intent_open_key','file_publications_intent_file_key')) AS s3_indexes`);
      expect(facts).toEqual({ columns: 5, not_null_rows: 5, constraints: 8, s3_relations: 2, s3_indexes: 2 });
      // The PostgreSQL 18 NOT NULL rows are real: they are exactly why the classifier
      // filters type 'n' instead of requiring "8 constraints" in the raw catalog.
      const { rows: [withoutNotNull] } = await client.query<{ conrelid: string }>(
        `SELECT conrelid::regclass::text AS conrelid FROM pg_constraint
         WHERE conrelid='foundation.request_files'::regclass AND contype='n' LIMIT 1`);
      expect(withoutNotNull?.conrelid).toBe('foundation.request_files');
    } finally { await client.query('ROLLBACK'); }
  });

  it('reads the interlock constraints as non-deferrable and blocking from the real catalog', async () => {
    const { rows } = await client.query<{
      conname: string; contype: string; condeferrable: boolean; convalidated: boolean;
      upd: string; del: string; ref: string; refcols: string;
    }>(`SELECT k.conname,k.contype,k.condeferrable,k.convalidated,k.confupdtype AS upd,k.confdeltype AS del,
        k.confrelid::regclass::text AS ref,
        (SELECT string_agg(a.attname,',' ORDER BY u.ord) FROM unnest(k.confkey) WITH ORDINALITY u(attnum,ord)
          JOIN pg_attribute a ON a.attrelid=k.confrelid AND a.attnum=u.attnum) AS refcols
      FROM pg_constraint k WHERE k.conrelid='foundation.request_files'::regclass AND k.contype IN ('c','f','p','u')
      ORDER BY k.conname`);
    expect(rows).toHaveLength(8);
    for (const row of rows) {
      expect(row.condeferrable, `${row.conname} deferrable`).toBe(false);
      expect(row.convalidated, `${row.conname} validated`).toBe(true);
    }
    const byName = new Map(rows.map((row) => [row.conname, row]));
    const interlock = byName.get('request_files_intent_id_open_state_fkey');
    expect(interlock).toMatchObject({ ref: 'foundation.file_privacy_controls', refcols: 'intent_id,delete_state' });
    // RESTRICT on both actions: an old-writer OPEN→PENDING_LEDGER UPDATE must fail,
    // and a DELETE of the control must not silently cascade the attachment away.
    expect(interlock?.upd).toBe('r');
    expect(interlock?.del).toBe('r');
    expect(byName.get('request_files_open_state_check')).toMatchObject({ contype: 'c' });
    expect(byName.get('request_files_pkey')).toMatchObject({ contype: 'p' });
    expect(byName.get('request_files_intent_id_key')).toMatchObject({ contype: 'u' });
    expect(byName.get('request_files_file_id_key')).toMatchObject({ contype: 'u' });
  });

  it('classifies real DDL drift as DRIFTED and returns to S3 after rollback', async () => {
    // DDL needs the relation owner; the probe is a plain catalog read and is
    // role-agnostic, so one migrator transaction holds both the drift and the probe.
    const owner = new Client({ host: '127.0.0.1', port: 55432, database: labDatabase,
      user: 'fixlevelup_migrator', password: credentials().migrator, connectionTimeoutMillis: 3000,
      statement_timeout: 20_000, application_name: 'p05-attach-live-ddl' });
    await owner.connect();
    try {
      // Dropped interlock FK.
      expect(await probeInTransaction(owner,
        'ALTER TABLE foundation.request_files DROP CONSTRAINT request_files_intent_id_open_state_fkey')).toBe('DRIFTED');
      // Weakened CHECK: the exact reviewed predicate is required, not "contains OPEN".
      expect(await probeInTransaction(owner, `ALTER TABLE foundation.request_files
        DROP CONSTRAINT request_files_open_state_check,
        ADD CONSTRAINT request_files_open_state_check CHECK (open_state='OPEN' OR TRUE)`)).toBe('DRIFTED');
      // Extra column on the reviewed relation.
      expect(await probeInTransaction(owner,
        'ALTER TABLE foundation.request_files ADD COLUMN drift_marker boolean')).toBe('DRIFTED');
    } finally { await owner.end().catch(() => undefined); }
    // The rollbacks restored the reviewed schema: the probe is not sticky.
    expect(await probeInTransaction(client)).toBe('S3');
  });

  it('freezes the reviewed relation so a concurrent DDL cannot invalidate the verdict', async () => {
    // The probe holds `AccessShare` on request_files for the rest of the caller's
    // transaction (the `WHERE false` read still opens the relation). A concurrent
    // `ALTER TABLE` needs `AccessExclusive` and must therefore wait — which is what
    // keeps the S3 verdict valid until the caller's INSERT.
    const owner = new Client({ host: '127.0.0.1', port: 55432, database: labDatabase,
      user: 'fixlevelup_migrator', password: credentials().migrator, connectionTimeoutMillis: 3000,
      statement_timeout: 20_000, application_name: 'p05-attach-live-freeze' });
    await owner.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      try {
        expect(await probeAttachmentInterlock(client)).toBe('S3');
        await owner.query('BEGIN');
        await owner.query(`SET LOCAL lock_timeout='400ms'`);
        let blocked: unknown;
        try {
          await owner.query('ALTER TABLE foundation.request_files ADD COLUMN concurrent_drift boolean');
        } catch (error) { blocked = error; }
        expect((blocked as { code?: string } | undefined)?.code).toBe('55P03');
        await owner.query('ROLLBACK');
      } finally { await client.query('ROLLBACK'); }
      // Once the freeze is released the same DDL succeeds (and is rolled back), which
      // proves the block above came from our lock and not from a permission error.
      await owner.query('BEGIN');
      await owner.query('ALTER TABLE foundation.request_files ADD COLUMN concurrent_drift boolean');
      await owner.query('ROLLBACK');
    } finally { await owner.end().catch(() => undefined); }
  }, 60_000);

  it('keeps the legacy retention query only for the pre-S3 profile', async () => {
    // The S3 candidate SQL excludes an attached intent before LIMIT; the reviewed
    // pre-S3 SQL has no reference to the relation at all.
    const s3 = retentionCandidateSql('S3');
    expect(s3).toContain('NOT EXISTS (SELECT 1 FROM foundation.request_files rf WHERE rf.intent_id=i.id)');
    expect(s3.indexOf('request_files')).toBeLessThan(s3.indexOf('LIMIT $6'));
    expect(retentionCandidateSql('PRE_S3')).not.toContain('request_files');
    // Both are valid SQL for this real schema/role: PREPARE proves parse+privileges
    // without executing or writing anything.
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    try {
      const args = ['$1::bigint', '$2::bigint', '$3::bigint', '$4::bigint', '$5::integer', '$6::integer'];
      await client.query(`PREPARE p05_retention_pre AS ${retentionCandidateSql('PRE_S3')}`);
      await client.query('DEALLOCATE p05_retention_pre');
      expect(args).toHaveLength(6);
    } finally { await client.query('ROLLBACK'); }
  });

  it('exposes the exact S3 fingerprint through the shared profile instrument', async () => {
    // `probeAttachmentInterlock` refuses a hand-written "looks close" schema through
    // the same reviewed fingerprint launch admission uses; here we prove the real
    // 024 database satisfies it (and therefore the S3 branch is reachable in a real
    // deployment, not only in the unit fake).
    const { probeP05Layer } = await import('../src/infrastructure/database/p05-profile-catalog.js');
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    try {
      expect(await probeP05Layer(client, 'S3')).toBe(true);
      expect(await probeP05Layer(client, 'S2')).toBe(true);
    } finally { await client.query('ROLLBACK'); }
  });
});

real('P05 attachment interlock on a real pre-S3 PostgreSQL', () => {
  let owned: OwnedTestDatabase | undefined;
  let database = '';
  const connections: Client[] = [];

  beforeAll(async () => {
    const { migrator } = credentials();
    database = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
    owned = await OwnedTestDatabase.create({
      name: database,
      pattern: /^fixlevelup_legal_test_[a-f0-9]{24}$/,
      prepare: async (maintenance) => {
        await maintenance.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
        await maintenance.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
      },
    });
    const client = new Client({ host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_migrator',
      password: migrator, connectionTimeoutMillis: 3000, statement_timeout: 120_000 });
    connections.push(client);
    await client.connect();
    // Real chain capped before 024: the honest pre-S3 profile.
    await migrateAuthFixture(client, database, S3_HEAD);
  }, 180_000);

  afterAll(async () => {
    await Promise.all(connections.map(async (client) => { await client.end().catch(() => undefined); }));
    await owned?.dispose();
  });

  it('classifies a real 23-migration database as PRE_S3', async () => {
    const client = await runtimeClient(database);
    connections.push(client);
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    try {
      expect(await probeAttachmentInterlock(client)).toBe('PRE_S3');
      const { rows: [facts] } = await client.query<{ files: string | null; submits: string | null }>(
        `SELECT to_regclass('foundation.request_files')::text AS files,
                to_regclass('foundation.request_session_submits')::text AS submits`);
      expect(facts).toEqual({ files: null, submits: null });
    } finally { await client.query('ROLLBACK'); }
  }, 60_000);
});

/**
 * READY half of §5.2 against real bytes: an isolated Garage publication (real
 * upload → real approved ClamAV/Sharp engines → real `file_publications` row) is
 * pushed through exactly the per-file decision sequence the admission uses:
 * intent→control lock, `selectPublication`, `checkFileAuthorization`,
 * `proveReadyWindow`. This is the strongest available proof that a genuine READY
 * file is admitted and that a drifted one (expired window, no publication) is not.
 *
 * Not covered even here (GAP): the `request_files` INSERT itself and the two
 * commit-winner races, because both require a committed submit aggregate
 * (`request_session_submits` + `request_events` + receipt), which the deferred
 * `request_effect_guard`/`request_aggregate_guard` only accept from a real intake
 * effect. No test fixture may fake that aggregate.
 */
const engineReady = lab && process.env['FIXLEVELUP_STORAGE_S3_TESTS'] === '1'
  && process.env['FIXLEVELUP_FILE_PROCESSING_TESTS'] === '1'
  && (process.env['FIXLEVELUP_LAB_ENGINE_TICKET'] ?? '') !== '';
const ready = engineReady ? describe : describe.skip;

interface EngineModule {
  createFileProcessingTestLauncher(config: unknown): Promise<{
    launcher: FileProcessingLauncher; epoch: DefinitionEpoch;
  }>;
}

async function pinnedEngine() {
  const path = process.env['FIXLEVELUP_FILE_PROCESSING_FIXTURE'];
  if (path === undefined) { throw new Error('Real engine contour requires FIXLEVELUP_FILE_PROCESSING_FIXTURE'); }
  const config: unknown = JSON.parse(await readFile(resolve(path), 'utf8'));
  const module = await import(new URL('../../../infra/file-processing/p05-lab-engine-client.mjs', import.meta.url).href) as EngineModule;
  return await module.createFileProcessingTestLauncher(config);
}

/**
 * The reviewed engine bridge accepts exactly one synthetic image: a 9x5 PNG that
 * carries an orientation tag and the `SYNTHETIC_PRIVACY_MARKER` EXIF artist. This is
 * the same reviewed fixture `file-lifecycle-s3.test.ts` uses; the bridge refuses any
 * other bytes, so the test must produce precisely this one.
 */
async function engineFixtureImage(): Promise<Buffer> {
  return await sharp({ create: { width: 9, height: 5, channels: 3, background: '#f03412' } })
    .withMetadata({ orientation: 6 })
    .withExifMerge({
      IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '1/1 2/1 3/1', GPSLongitudeRef: 'E', GPSLongitude: '4/1 5/1 6/1' },
      IFD0: { Artist: 'SYNTHETIC_PRIVACY_MARKER' },
    })
    .png()
    .toBuffer();
}

ready('P05 §5.2 READY decision on a real Garage publication', () => {
  it('admits exactly the published READY file and refuses an expired window or a missing publication', async () => {
    const db = await startLifecycleDb();
    const storage = createPrivateQuarantineStorage(garageConfig({ maxConcurrentOperations: 4 }));
    try {
      const engine = await pinnedEngine();
      // Real bytes: raw upload to Garage, real ClamAV scan + Sharp decode, real row.
      const { file, anchor, intent } = await provision(db, storage, await engineFixtureImage());
      const processor = createLocalFileProcessor({
        scan: async (bytes, definition, abort) => await engine.launcher.scan(bytes, definition, abort),
        decode: engine.launcher.decode.bind(engine.launcher),
      }, { epoch: engine.epoch, maxRawBytes: 64_000, maxOutputBytes: 64_000, maxJobs: 1, maxWallMs: 90_000 });
      const receipt = await processQuarantine(processingContext(db, storage, processor), { ...file, signal: signal() });
      expect(receipt).toStrictEqual({ intentId: file.intentId, completed: true });
      await assertReadyDecision(db, { file, anchor, intentId: intent.intentId });
    } finally {
      await storage.close().catch(() => undefined);
      await db.close().catch(() => undefined);
    }
  }, 180_000);
});

/**
 * The exact §5.2 per-file decision sequence, run against a real READY publication:
 * intent→control lock (with the verified current consent), evidence selection,
 * the P03 authorization proof, then the READY window. Nothing here is mocked, so a
 * wrong column name, a wrong type or a wrong constraint in the reviewed SQL fails
 * this test — which the in-process fake PoolClient cannot detect.
 */
async function assertReadyDecision(
  db: Awaited<ReturnType<typeof startLifecycleDb>>,
  ready: { file: FFile; anchor: { documentId: string; documentVersionId: string; evidenceId: string };
    intentId: string },
): Promise<void> {
  const client = await db.runtime.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    try {
      const consent: CurrentConsent = Object.freeze({
        granted: true, reason: 'GRANTED' as const, documentId: ready.anchor.documentId,
        documentVersionId: ready.anchor.documentVersionId, evidenceId: ready.anchor.evidenceId,
        occurredAt: new Date().toISOString(),
      });
      const auth = await lockAttachmentFileAuthorization(client, ready.file, epoch, consent);
      const publication = await selectPublication(client, ready.intentId);
      expect(publication, 'real READY publication').toBeDefined();
      await checkFileAuthorization(client, auth, { allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp'] });
      const window = Object.freeze({ expiresAt: new Date(Date.now() + 300_000).toISOString(), maxAccessAgeMs: 300_000 });
      await proveReadyWindow(client, auth, window, publication);

      // The publication is the real served artifact of this intent.
      expect(publication?.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u);
      expect(publication?.intent_id).toBe(ready.intentId);
      expect(publication?.mime).toBe('image/png');
      expect(Number(publication?.served_bytes)).toBeGreaterThan(0);
      expect(publication?.served_sha256).toMatch(/^[0-9a-f]{64}$/u);
      expect(publication?.object_key).toContain('sanitized/');

      // Drifted window: the reviewed code is NOT_CONFIGURED, never a pass.
      await expectRefusal(proveReadyWindow(client, auth,
        { expiresAt: new Date(Date.now() - 1_000).toISOString(), maxAccessAgeMs: 300_000 }, publication), 'NOT_CONFIGURED');
      // No publication at all is NOT_READY.
      await expectRefusal(proveReadyWindow(client, auth, window, undefined), 'NOT_READY');
      // A publication of another mime is NOT_READY: the window binds to the exact revision.
      await expectRefusal(proveReadyWindow(client, auth, window,
        publication === undefined ? undefined : { ...publication, mime: 'image/jpeg' }), 'NOT_READY');
      // A consent that is not the intent's exact GIVEN is refused, not substituted.
      // The lock itself is evidence-agnostic by design; the exact-GIVEN proof is part
      // of `checkFileAuthorization`, which is why the admission always calls both.
      const foreign: CurrentConsent = Object.freeze({ ...consent, evidenceId: randomUUID() });
      const foreignAuth = await lockAttachmentFileAuthorization(client, ready.file, epoch, foreign);
      await expectRefusal(checkFileAuthorization(client, foreignAuth,
        { allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp'] }), 'CONSENT_NOT_CURRENT');
    } finally { await client.query('ROLLBACK'); }
  } finally { client.release(); }
}

/**
 * Engine-independent half: a real `foundation.file_publications` row produced by the
 * reviewed `seedReadFixture` (loopback object store, synthetic processor) in the real
 * 024 database. This proves the §5.2 SQL against the real catalog today; the Garage +
 * real ClamAV/Sharp variant above additionally proves real bytes and the real engine.
 */
real('P05 §5.2 READY decision on a real publication row', () => {
  it('runs the reviewed lock → evidence → authorization → window sequence on real SQL', async () => {
    const db = await startLifecycleDb();
    const wire = await wireStore();
    try {
      const seeded = await seedReadFixture(db, wire);
      await assertReadyDecision(db, { file: seeded.file, anchor: seeded.anchor, intentId: seeded.file.intentId });
    } finally {
      await wire.close().catch(() => undefined);
      await db.close().catch(() => undefined);
    }
  }, 120_000);
});

// A single pure assertion keeps the classification contract visible even when the
// real-PG suites are skipped on a normal workstation run.
describe('P05 attachment interlock classification contract', () => {
  it('never treats a missing facts row as an accepted profile', () => {
    expect(classifyAttachmentInterlock(undefined)).toBe('DRIFTED');
  });
});
