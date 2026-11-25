import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3ServiceException } from '@aws-sdk/client-s3';
import { Client, Pool } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { freshGarageBucket, newArchives, restoreDbOptions, restoreReviewedExpressions } from '../../../infra/file-restore/resources.mjs';
import { closeReadyStream, createFileReadBudget, openReadyStream, readReadyChunk, readReadyMetadata } from '../src/files/file-access/index.js';
import { bootstrapFileLedgerNamespace, createFileLedgerVerifier, createPgFileLedger, createPgFloorStore } from '../src/files/file-ledger/index.js';
import type { FileLedgerVerifier, LedgerHead } from '../src/files/file-ledger/contract.js';
import { processQuarantine } from '../src/files/file-lifecycle/index.js';
import type { LocalFileProcessor } from '../src/files/file-lifecycle/contract.js';
import { reserveFileUpload } from '../src/files/reservations/index.js';
import { uploadReservedFile } from '../src/files/upload-coordinator/index.js';
import { createRestoredDeleteBroker, createSyntheticDeleteBroker, requireDeleteBroker, revokeDeleteBroker } from '../src/files/file-privacy/broker.js';
import { drainFencedFileDecisions, reconcileFileDeletion } from '../src/files/file-privacy/deletion.js';
import { makeFilePrivacyGrant, makeHoldGrant } from '../src/files/file-privacy/grants.js';
import { changeFileHold, planRetention } from '../src/files/file-privacy/retention.js';
import type { RetentionPolicy } from '../src/files/file-privacy/contract.js';
import type { RestoreContext, RestoreGateReceipt, RestoreLimits, SnapshotManifest } from '../src/files/file-restore/contract.js';
import { AUTHORITY_TABLES, readAuthorityInventory, readRestoreInventory } from '../src/files/file-restore/inventory.js';
import { observeFencedSource } from '../src/files/file-restore/p05-source-fence.js';
import { createRestoreObjectIO } from '../src/files/file-restore/objects.js';
import { readSnapshot, sha256, signApproval, signAuthority, signSnapshot } from '../src/files/file-restore/records.js';
import { createRestoredReadyStorage, rescrubFileRestore } from '../src/files/file-restore/rescrub.js';
import { verifyClosedBase } from '../src/infrastructure/database/closed-profile-base.js';
import { readP05Metadata } from '../src/infrastructure/database/p05-profile-catalog.js';
import { createS3Client, validateConfig, type PrivateQuarantineStorageConfig } from '../src/files/storage/config.js';
import { createPrivateQuarantineStorage } from '../src/files/storage/index.js';
import { authFixtureMigrations, installPinnedMigrationHistory } from './auth-db-fixture.js';
import { accessPolicy, faultEvidence, png, processingPolicy, provision, uploadPolicy, withQueryHook } from './file-lifecycle-fixture.js';
import { revokeConsent, startFileReservationsDatabase } from './file-reservations-fixture.js';
import { inRuntimeTransaction } from './legal-fixture.js';
import type { FileReservationsFixture } from './file-reservations-fixture.js';
import { pinFreshFileDatabase } from './owned-test-database.js';
import { TECHNICAL_TIMEOUTS } from './file-storage-fixture.js';

const enabled = process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] === '1';
const live = enabled ? describe : describe.skip;
const limits: RestoreLimits = { maxObjects: 80, maxIntents: 20, maxObjectBytes: 65_536, maxTotalObjectBytes: 524_288,
  maxManifestBytes: 524_288, maxDumpBytes: 8_388_608 };
const proofLimits = { maxItems: 80, maxProofEvents: 80 };
const expiry = () => new Date(Date.now() + 300_000);
const restorePolicy = (): RetentionPolicy => ({ mode: 'local-synthetic', versionId: randomUUID(), expiresAt: expiry(), rawBoundMs: 1,
  readyMs: 1, quarantinedMs: 1, orphanMs: 1, maxBatch: 16, maxItemsPerIntent: 16, claimMs: 15_000 });

function ledgerPool(role: string): Pool {
  const keyName = `${role.toUpperCase()}_PASSWORD`;
  const env = readFileSync(resolve(import.meta.dirname, '../../../infra/file-ledger/.env'), 'utf8');
  const password = new RegExp(`^${keyName}=([a-f0-9]{64})\\r?$`, 'm').exec(env)?.[1];
  if (password === undefined) {throw new Error(`Missing isolated credential: ${keyName}`);}
  const floor = role.startsWith('file_floor_');
  return new Pool({ host: '127.0.0.1', port: floor ? 55434 : 55433, user: role, password,
    database: floor ? 'fixlevelup_file_floor' : 'fixlevelup_file_ledger', connectionTimeoutMillis: 5_000,
    statement_timeout: 12_000, max: 2 });
}
const storageConfig = (target: ReturnType<typeof freshGarageBucket>, write: boolean): PrivateQuarantineStorageConfig => ({
  mode: 'local-synthetic', ...target.target, allowedEndpoint: target.target.endpoint, ...TECHNICAL_TIMEOUTS, ...(write ? target.rw : target.ro),
});

/** Install an exact synthetic published tuple, not a claim that these bytes passed a real engine.
 * The separate C suite owns that proof; this suite proves old published bytes survive a real restore. */
async function published(db: FileReservationsFixture, config: PrivateQuarantineStorageConfig,
  storage: ReturnType<typeof createPrivateQuarantineStorage>, sig: AbortSignal) {
  const reserved = await provision(db, storage);
  const served = new Uint8Array(png);
  const digest = sha256(served);
  const id = randomUUID();
  const claim = randomUUID();
  const key = `sanitized/${id}/${randomUUID()}`;
  const intentId = reserved.file.intentId;
  const s3 = createS3Client(validateConfig(config));
  try {
    await s3.send(new PutObjectCommand({ Bucket: config.bucket, Key: key, Body: served,
      ContentLength: served.byteLength, IfNoneMatch: '*' }), { abortSignal: sig });
  } finally { s3.destroy(); }
  const client = await db.migrator.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO foundation.file_privacy_controls (intent_id) VALUES ($1) ON CONFLICT DO NOTHING', [intentId]);
    await client.query(`UPDATE foundation.file_privacy_controls SET processing_generation=processing_generation+1,
      processing_lease_id=$2,processing_expires_at=clock_timestamp()+interval '120 seconds' WHERE intent_id=$1`, [intentId, claim]);
    await client.query(`INSERT INTO foundation.file_sanitized_attempts
      (id,intent_id,owner_request_session_id,quarantine_id,generation,lease_id,lease_expires_at,object_key,storage_endpoint,
      storage_bucket,storage_region,mime,charged_bytes,expected_sha256) SELECT $1,$2,$3,$4,processing_generation,$5,
      processing_expires_at,$6,$7,$8,$9,'image/png',$10,$11 FROM foundation.file_privacy_controls WHERE intent_id=$2`,
    [id, intentId, reserved.anchor.sessionId, reserved.binding.id, claim, key, config.endpoint, config.bucket, config.region, served.byteLength, digest]);
    await client.query(`UPDATE foundation.file_sanitized_attempts SET state='IN_FLIGHT' WHERE id=$1`, [id]);
    await client.query(`UPDATE foundation.file_sanitized_attempts SET state='VERIFIED',verified_bytes=charged_bytes,
      verified_sha256=expected_sha256 WHERE id=$1`, [id]);
    await client.query(`INSERT INTO foundation.file_publications (id,intent_id,quarantine_id,raw_bytes,raw_sha256,sanitized_attempt_id,
      mime,served_bytes,served_sha256,processing_policy_id,processing_policy_sha256,engine_version,engine_image_sha256,defs_sha256,defs_built_at)
      VALUES ($1,$2,$3,$4,$5,$6,'image/png',$7,$8,$9,$10,'1.4.7',$11,$12,clock_timestamp())`,
    [randomUUID(), intentId, reserved.binding.id, reserved.binding.actual_bytes, reserved.binding.sha256, id, served.byteLength,
      digest, randomUUID(), 'd'.repeat(64), 'e'.repeat(64), 'f'.repeat(64)]);
    await client.query(`UPDATE foundation.file_privacy_controls SET processing_lease_id=NULL,processing_expires_at=NULL WHERE intent_id=$1`, [intentId]);
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
  return { ...reserved, served, key };
}

const expectCode = async (run: Promise<unknown>, code: string): Promise<void> => { await expect(run).rejects.toMatchObject({ code }); };

type Completion = 'confirmed' | 'committed-unacknowledged' | 'aborted-unacknowledged';

async function finishRestoreRun(failures: unknown[], releases: readonly (() => void | Promise<void>)[]): Promise<void> {
  for (const release of releases) {
    try { await release(); } catch (error) { failures.push(error); }
  }
  if (failures.length === 1) { throw failures[0]; }
  if (failures.length > 1) { throw new AggregateError(failures, 'Restore scenario or cleanup failed'); }
}

// Redacted diagnostics for a real source/destination mismatch, no row values.
async function schemaMeasurement(connection: Pick<Client, 'query'>) {
  return { legacy: await verifyClosedBase(connection), S1: await readP05Metadata(connection, 'S1'),
    S2: await readP05Metadata(connection, 'S2') };
}

/** Only the target's terminal COMMIT is faulted. A real PG transaction is
 * committed or aborted and the driver adapter hides the reply. An independent
 * backend observes the result, but never supplies a receipt to the installer. */
async function checkUncertainCompletion(ctx: RestoreContext, manifest: ReturnType<typeof signSnapshot>,
  mode: Exclude<Completion, 'confirmed'>, sig: AbortSignal): Promise<void> {
  const observer = new Client(restoreDbOptions(ctx.destinationDatabase, 'migrator'));
  let checkedOutPid = 0;
  let casCount = 0;
  let commits = 0;
  let rollbacks = 0;
  let issued: RestoreGateReceipt | undefined;
  let before: unknown;
  let hiddenCommand: unknown;
  const state = async () => (await observer.query<{ mode: string; epoch: string; connect: boolean; independent: boolean }>(
    `SELECT mode,epoch::text,has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT') AS connect,
      pg_backend_pid()<>$1 AS independent FROM foundation.file_runtime_epochs WHERE singleton`, [checkedOutPid])).rows;
  const controlled = withQueryHook(ctx.targetOperatorPool, sql => /^(UPDATE foundation\.file_runtime_epochs|COMMIT$|ROLLBACK$)/u.test(sql),
    async (sql, client, send) => {
      if (sql.startsWith('UPDATE')) { casCount++; return send(); }
      if (sql === 'ROLLBACK') { rollbacks++; return send(); }
      commits++;
      checkedOutPid = (await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid ?? 0;
      await observer.connect();
      before = await state();
      // Do not inject a fake CommandComplete: record the real command tag,
      // conceal it only from restore, and assert it outside the error boundary.
      const reply: unknown = mode === 'committed-unacknowledged' ? await send() : await client.query('ROLLBACK');
      hiddenCommand = typeof reply === 'object' && reply !== null && 'command' in reply ? reply.command : undefined;
      throw new Error('Synthetic lost target completion');
    });
  const faulted = { ...ctx, targetOperatorPool: controlled };
  try {
    await expectCode(rescrubFileRestore(faulted, manifest, sig).then(result => { issued = result; }), 'RESTORE_COMMIT_UNKNOWN');
    expect(issued).toBeUndefined();
    expect(checkedOutPid).toBeGreaterThan(0);
    expect(before).toEqual([{ mode: 'RESTORE_CLOSED', epoch: String(ctx.oldScope.writerEpoch), connect: false, independent: true }]);
    expect([casCount, commits, rollbacks]).toEqual([1, 1, 0]);
    expect(ctx.targetOperatorPool.totalCount).toBe(0);
    const didCommit = mode === 'committed-unacknowledged';
    expect(hiddenCommand).toBe(didCommit ? 'COMMIT' : 'ROLLBACK');
    expect(await state()).toEqual([{ mode: didCommit ? 'ACTIVE' : 'RESTORE_CLOSED',
      epoch: String(didCommit ? ctx.nextEpoch : ctx.oldScope.writerEpoch), connect: false, independent: true }]);
    const restore = vi.fn(ctx.restoreArchives);
    await expectCode(rescrubFileRestore(faulted, manifest, sig), 'RESTORE_INPUT');
    await expectCode(rescrubFileRestore({ ...faulted, restoreArchives: restore }, manifest, sig), 'RESTORE_CLOSED');
    expect(restore).not.toHaveBeenCalled();
    expect([casCount, commits, rollbacks]).toEqual([1, 1, 0]);
  } finally { await observer.end(); }
}

live('P03-04D copy-only isolated restore', () => {
  it.each(['confirmed', 'committed-unacknowledged', 'aborted-unacknowledged'] as const)('uses real archives, Garage copy, fenced overlay and independent ledger: %s', async mode => {
    const sig = AbortSignal.timeout(170_000);
    const policy = restorePolicy();
    expect(process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS']).toBe('1');
    expect(process.env['FIXLEVELUP_STORAGE_S3_TESTS']).toBe('1');
    const schemaVersion = authFixtureMigrations.at(-1) ?? '';
    expect(authFixtureMigrations[17]).toBe('20261122000400_settings_management');
    expect(authFixtureMigrations[18]).toBe('20261122000500_catalog_fixed_prices');
    expect(authFixtureMigrations[19]).toBe('20261122000600_pricing_rules_ranges');
    expect(authFixtureMigrations[20]).toBe('20261122000700_catalog_management');
    expect(authFixtureMigrations[21]).toBe('20261123000100_request_intake_foundation');
    // The restore contour now runs on the S2 profile (023 form session
    // foundation over the 022 request intake); its source-side P05 fact is
    // SCHEMA-verified through the new callback.
    expect(schemaVersion).toBe('20261124000100_form_session_foundation');
    const [ops, writer, nextWriter, signer, floorOps, floorRuntime] = [ledgerPool('file_ledger_operator'), ledgerPool('file_ledger_writer'),
      ledgerPool('file_ledger_writer_next'), ledgerPool('file_ledger_signer'), ledgerPool('file_floor_operator'), ledgerPool('file_floor_verifier')] as const;
    const maintenance = new Pool(restoreDbOptions('postgres', 'maintenance'));
    const ledgerKeys = generateKeyPairSync('ed25519');
    const snapshotKeys = generateKeyPairSync('ed25519');
    const approvalKeys = generateKeyPairSync('ed25519');
    const authorityKeys = generateKeyPairSync('ed25519');
    const destination = `fixlevelup_file_restore_${randomBytes(12).toString('hex')}`;
    // Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse
    // guard: an existing name is a hard error, so a successful CREATE proves this
    // run owns the disposable destination — the flag plus the strict disposable-name
    // pattern gate the teardown drop).
    let destinationCreated = false;
    let disposeDestination: Awaited<ReturnType<typeof pinFreshFileDatabase>> | undefined;
    const targetOps = new Pool({ ...restoreDbOptions(destination, 'migrator'), max: 1 });
    const pools = [ops, writer, nextWriter, signer, floorOps, floorRuntime, maintenance, targetOps];
    const cleanups: (() => void | Promise<void>)[] = [];
    /** Drops exactly the destination database this run created, after every pool of
     * this run was ended. A busy target is retained and reported, never FORCE-dropped. */
    const dropDestination = async (): Promise<void> => {
      if (!destinationCreated) { return; }
      if (!/^fixlevelup_file_restore_[a-f0-9]{24}$/.test(destination)) {
        throw new Error('Refusing to drop a non-fixture database');
      }
      destinationCreated = false;
      const dropper = new Pool(restoreDbOptions('postgres', 'maintenance'));
      try {
        if (!disposeDestination) { throw new Error('Missing fresh restore target identity'); }
        await disposeDestination(dropper);
      } finally {
        await dropper.end();
      }
    };
    const failures: unknown[] = [];
    const sourceDb = await startFileReservationsDatabase();
    try {
      const genesis = await bootstrapFileLedgerNamespace({ mode: 'local-synthetic', ledgerOperatorPool: ops, floorOperatorPool: floorOps,
        signerPublicKey: ledgerKeys.publicKey, initialEpoch: 1n });
      const { namespace, incarnation, writerEpoch } = genesis;
      const scope = { namespace, incarnation, writerEpoch };
      const base: LedgerHead = { ...scope, seq: genesis.seq, hash: genesis.hash };
      const nextScope = { ...scope, writerEpoch: 2n };
      const epoch = { namespace, epoch: writerEpoch };
      const ledger = createPgFileLedger(writer, { mode: 'local-synthetic', signerPool: signer, privateKey: ledgerKeys.privateKey,
        limits: proofLimits, operatorPool: ops });
      const targetLedger = createPgFileLedger(nextWriter, { mode: 'local-synthetic', signerPool: signer, privateKey: ledgerKeys.privateKey,
        limits: proofLimits, operatorPool: ops });
      const floor = createPgFloorStore(floorRuntime);
      const verifier = createFileLedgerVerifier({ ledger, floor, signerPublicKey: ledgerKeys.publicKey, limits: proofLimits });
      const staleVerifier: FileLedgerVerifier = createFileLedgerVerifier({ ledger: {
        getEvents: (s, from, to) => ledger.getEvents(s, from, to), getHead: (_scope, nonce) => ledger.getHead(scope, nonce),
      }, floor, signerPublicKey: ledgerKeys.publicKey, limits: proofLimits });
      await installPinnedMigrationHistory(sourceDb.migrator);
      await sourceDb.migrator.query(`INSERT INTO foundation.file_runtime_epochs (singleton,namespace_id,epoch,mode) VALUES (true,$1,1,'ACTIVE')`, [namespace]);
      const sourceTarget = freshGarageBucket(namespace);
      const fresh = freshGarageBucket();
      const sourceConfig = storageConfig(sourceTarget, true);
      const sourceStorage = createPrivateQuarantineStorage(sourceConfig);
      let sourceClosing: Promise<void> | undefined;
      const closeSourceStorage = () => (sourceClosing ??= sourceStorage.close());
      cleanups.push(closeSourceStorage);
      const readyStorage = createPrivateQuarantineStorage(storageConfig(fresh, false));
      const reader = createS3Client(validateConfig(storageConfig(fresh, false)));
      const sourceReader = createS3Client(validateConfig(storageConfig(sourceTarget, false)));
      const writerStorage = createPrivateQuarantineStorage(storageConfig(fresh, true));
      cleanups.push(() => { sourceReader.destroy(); }, () => writerStorage.close());
      const io = createRestoreObjectIO({ source: storageConfig(sourceTarget, false), destination: storageConfig(fresh, true),
        maxObjectBytes: limits.maxObjectBytes });
      cleanups.push(() => readyStorage.close(), () => { reader.destroy(); io.close(); });
      const survivor = await published(sourceDb, sourceConfig, sourceStorage, sig);
      const held = await published(sourceDb, sourceConfig, sourceStorage, sig);
      const retired = await published(sourceDb, sourceConfig, sourceStorage, sig);
      const withdrawn = await published(sourceDb, sourceConfig, sourceStorage, sig);
      const quarantined = await provision(sourceDb, sourceStorage); // Real B binding, never processed or published.
      // Real commit-before-byte history for an unbound, already dispatched orphan. Its UNKNOWN remains charged.
      const orphan = randomUUID();
      const orphanKey = `quarantine/${orphan}/${randomUUID()}`;
      await sourceDb.migrator.query(`INSERT INTO foundation.file_upload_attempts (id,intent_id,owner_request_session_id,idempotency_key,generation,
        upload_lease_id,upload_lease_expires_at,object_key,storage_endpoint,storage_bucket,storage_region,charged_bytes)
        VALUES ($1,$2,$3,$4,2,$5,clock_timestamp()+interval '2 minutes',$6,$7,$8,$9,$10)`,
      [orphan, retired.file.intentId, retired.anchor.sessionId, randomUUID(), randomUUID(), orphanKey, sourceConfig.endpoint, sourceConfig.bucket,
        sourceConfig.region, png.byteLength]);
      await sourceDb.migrator.query(`UPDATE foundation.file_upload_attempts SET state='IN_FLIGHT' WHERE id=$1`, [orphan]);
      await sourceDb.migrator.query(`UPDATE foundation.file_upload_attempts SET state='UNKNOWN' WHERE id=$1`, [orphan]);
      const oldInventory = await readRestoreInventory(sourceDb.migrator, limits);
      const archives = newArchives(sourceDb.database, destination, AUTHORITY_TABLES.map(([table]) => table), limits.maxDumpBytes);
      expect((await verifier.verifyLineage(scope, base)).head).toEqual(base);
      const sourceRowsSql = `SELECT assignment_id,permission_code,row_version,revoked_at,revoked_by
        FROM foundation.p03_bootstrap_permissions ORDER BY assignment_id,permission_code COLLATE "C"`;
      const originalFounderSources = (await sourceDb.migrator.query(sourceRowsSql)).rows;
      expect(originalFounderSources).toHaveLength(18);
      const dumpHash = archives.dump();
      for (const item of oldInventory) {if (item.disposition === 'COPY') {archives.artifact(item, await io.exportSource(item, sig));}}
      const payload: SnapshotManifest = { sourceDatabase: sourceDb.database, destinationDatabase: destination, schemaVersion,
        dumpSha256: dumpHash, base, aliases: [{ source: sourceTarget.target, destination: fresh.target }], inventory: oldInventory };
      const manifest = signSnapshot(payload, snapshotKeys.privateKey);
      archives.manifest(manifest);
      const authHash = readSnapshot(manifest, snapshotKeys.publicKey, limits).hash;

      const operator = (role: 'HOLD' | 'RETENTION' | 'SOURCE_DRAIN' | 'DELETE') => makeFilePrivacyGrant({ mode: 'local-synthetic', namespace,
        role, actorId: sourceDb.reviewer });
      const sourcePrivacy = { pool: sourceDb.runtime, epoch, policy };
      for (const candidate of [held, survivor, withdrawn, quarantined]) {
        const version = (await sourceDb.migrator.query<{ row_version: string }>(`SELECT coalesce((SELECT row_version::text FROM foundation.file_privacy_controls WHERE intent_id=$1),'1') AS row_version`,
          [candidate.file.intentId])).rows[0]?.row_version;
        if (version === undefined) {throw new Error('No durable hold subject');}
        const result = await changeFileHold(sourcePrivacy, makeHoldGrant(operator('HOLD'), { intentId: candidate.file.intentId,
          expectedRowVersion: BigInt(version), action: 'PLACE', reason: 'LEGAL_HOLD' }));
        expect(result.applied).toBe(true);
      }
      await revokeConsent(sourceDb, withdrawn.anchor, withdrawn.anchor.evidenceId);
      const retention = await planRetention({ ...sourcePrivacy, grant: operator('RETENTION'), scope }, sig);
      expect(retention.advanced).toBe(1);
      await expectCode(Promise.resolve().then(() => readAuthorityInventory(sourceDb.migrator, limits)), 'RESTORE_AUTHORITY');
      // The historical read-ticket smoke needs one serving namespace per process.
      // The two independent COMMIT probes never serve a file or allocate a read budget.
      const sourceAccess = mode === 'confirmed' ? { pool: sourceDb.runtime, epoch, storage: sourceStorage,
        policy: accessPolicy({ maxBufferedBytes: 2_200_000 }),
        budget: createFileReadBudget({ mode: 'local-synthetic', namespace, singleProcess: true, maxBufferedBytes: 2_200_000,
          maxActiveStreams: 2, maxLiveOperationsPerOwner: 4 }) } : undefined;
      const oldTicket = sourceAccess ? await openReadyStream(sourceAccess, { ...survivor.file, signal: sig }) : undefined;
      if (oldTicket) { expect((await readReadyChunk(oldTicket)).kind).toBe('CHUNK'); }
      const broker = mode === 'confirmed'
        ? createSyntheticDeleteBroker({ mode: 'local-synthetic', namespace, epoch: epoch.epoch, targets: [sourceConfig] }) : undefined;
      await sourceDb.migrator.query(`UPDATE foundation.file_runtime_epochs SET mode='FENCED' WHERE singleton AND namespace_id=$1 AND epoch=1 AND mode='ACTIVE'`, [namespace]);
      if (broker && oldTicket && sourceAccess) {
        await revokeDeleteBroker(broker);
        await expectCode(Promise.resolve().then(() => requireDeleteBroker(broker, namespace, epoch.epoch)), 'NOT_CONFIGURED');
        await expect(readReadyChunk(oldTicket)).rejects.toBeDefined();
        await closeReadyStream(oldTicket);
        await expectCode(readReadyMetadata(sourceAccess, survivor.file), 'NOT_CONFIGURED');
      }
      expect((await drainFencedFileDecisions({ ...sourcePrivacy, grant: operator('SOURCE_DRAIN'), scope, ledger, verifier }, sig)).advanced).toBe(1);
      const fenceRow = await maintenance.query(`REVOKE CONNECT ON DATABASE "${sourceDb.database}" FROM fixlevelup_runtime`);
      expect(fenceRow.command).toBe('REVOKE');
      // Only this fixture's runtime service is shut down; the dev DB/roles and other fixtures are not touched.
      await closeSourceStorage();
      const oldRuntime = new Client(restoreDbOptions(sourceDb.database, 'runtime'));
      try { await expect(oldRuntime.connect()).rejects.toMatchObject({ code: '42501' }); }
      finally { await oldRuntime.end(); }
      const head = await ledger.fenceLedgerWriter(scope, nextScope.writerEpoch, 'file_ledger_writer_next');
      expect(head.seq).toBe(1n);
      const inventorySha256 = await readAuthorityInventory(sourceDb.migrator, limits);
      const overlaySha256 = archives.overlay();
      const sourceObserver = new Client({ ...restoreDbOptions(sourceDb.database, 'migrator'),
        options: '-c default_transaction_read_only=on' });
      cleanups.push(async () => { await sourceObserver.end(); });
      await sourceObserver.connect();
      const sourceOid = (await sourceObserver.query<{ oid: string }>(
        'SELECT oid::text AS oid FROM pg_database WHERE datname=current_database()',
      )).rows[0]?.oid;
      const sourceDatabaseOid = Number(sourceOid);
      if (!Number.isSafeInteger(sourceDatabaseOid) || sourceDatabaseOid <= 0) { throw new Error('Missing pinned source database OID'); }
      const sourcePin = { database: sourceDb.database, databaseOid: sourceDatabaseOid, scope, profile: 'S2' as const,
        manifestSha256: authHash, challenge: randomBytes(32).toString('hex') };
      // The restore core independently checks the hard fence and compares the
      // inventory digest before trusting this manifest/challenge-bound signature.
      const authorityNonces: string[] = [];
      const currentAuthority: RestoreContext['currentAuthority'] = async ({ challenge, manifestSha256 }) => {
        if (manifestSha256 !== authHash || await readAuthorityInventory(sourceObserver, limits) !== inventorySha256) {
          throw new Error('Current authority is not fenced');
        }
        authorityNonces.push(challenge);
        return signAuthority({ challenge, manifestSha256, overlaySha256, inventorySha256, head }, authorityKeys.privateKey);
      };
      const heldSession = new Client(restoreDbOptions(sourceDb.database, 'migrator'));
      await heldSession.connect();
      try {
        await sourceDb.drainPools();
        await maintenance.query(`ALTER DATABASE "${sourceDb.database}" ALLOW_CONNECTIONS false`);
        const rejectedObserver = new Client(restoreDbOptions(sourceDb.database, 'migrator'));
        try { await expect(rejectedObserver.connect()).rejects.toMatchObject({ code: '55000' }); }
        finally { await rejectedObserver.end(); }
        await expectCode(observeFencedSource(sourceObserver, sourcePin, limits), 'RESTORE_AUTHORITY');
      } finally { await heldSession.end(); }
      await expect(observeFencedSource(sourceObserver, sourcePin, limits)).resolves.toMatchObject({ profile: 'S2',
        fact: 'P05_EMPTY_AFTER_DRAIN', nonce: sourcePin.challenge, manifestSha256: authHash, inventorySha256 });
      const sourceSchema = await schemaMeasurement(sourceObserver);
      const ctx: RestoreContext = {
        mode: 'local-synthetic', schemaVersion, sourceDatabase: sourceDb.database, destinationDatabase: destination, oldScope: scope,
        nextEpoch: nextScope.writerEpoch, limits, targetOperatorPool: targetOps, snapshotKey: snapshotKeys.publicKey,
        approvalKey: approvalKeys.publicKey, authorityKey: authorityKeys.publicKey, verifier, currentAuthority,
        sourceObserver, sourceDatabaseOid,
        async restoreArchives(snapshot, authority) {
          await archives.restore(snapshot.dumpSha256, authority.overlaySha256, async () => {
            await maintenance.query(`CREATE DATABASE "${destination}" OWNER fixlevelup_migrator TEMPLATE template0 ALLOW_CONNECTIONS false`);
            destinationCreated = true;
            disposeDestination = await pinFreshFileDatabase(maintenance, destination);
            await maintenance.query(`REVOKE ALL ON DATABASE "${destination}" FROM PUBLIC,fixlevelup_runtime`);
            await maintenance.query(`ALTER DATABASE "${destination}" ALLOW_CONNECTIONS true`);
          }, async () => {
            const restored = await targetOps.connect();
            try {
              await restoreReviewedExpressions(sourceObserver, restored, snapshot.destinationDatabase);
              expect(await schemaMeasurement(restored)).toEqual(sourceSchema);
              await restored.query(`INSERT INTO foundation.file_runtime_epochs (singleton,namespace_id,epoch,mode)
                VALUES (true,$1,$2,'RESTORE_CLOSED')`, [namespace, epoch.epoch.toString()]);
            } finally { restored.release(); }
          });
        },
        openBackupObject: (item) => Promise.resolve(archives.object(item, limits.maxObjectBytes)),
        copyToFreshTarget: io.copyToFreshTarget,
        async approve(binding) {
          const probe = new Client(restoreDbOptions(destination, 'runtime'));
          try { await expect(probe.connect()).rejects.toMatchObject({ code: '42501' }); }
          finally { await probe.end(); }
          return signApproval(binding, approvalKeys.privateKey);
        },
      };
      if (mode !== 'confirmed') {
        await checkUncertainCompletion(ctx, manifest, mode, sig);
        expect(authorityNonces).toHaveLength(2);
        archives.evidence({ terminalCompletion: mode, receipt: false, runtimeConnect: false, automaticRetry: false });
        return;
      }
      if (!sourceAccess) { throw new Error('Missing confirmed serving namespace'); }
      await expectCode(rescrubFileRestore({ ...ctx }, { ...manifest, payload: manifest.payload + ' ' }, sig), 'RESTORE_INPUT');
      const noAuthority = vi.fn(currentAuthority);
      const noObject = vi.fn(ctx.openBackupObject);
      await expectCode(rescrubFileRestore({ ...ctx, sourceDatabaseOid: sourceDatabaseOid + 1,
        currentAuthority: noAuthority, openBackupObject: noObject }, manifest, sig), 'RESTORE_AUTHORITY');
      expect(noAuthority).not.toHaveBeenCalled();
      expect(noObject).not.toHaveBeenCalled();
      await expectCode(rescrubFileRestore({ ...ctx, currentAuthority: () => Promise.reject(new Error('Unavailable source')) }, manifest, sig), 'RESTORE_AUTHORITY');
      await expectCode(rescrubFileRestore({ ...ctx, verifier: staleVerifier }, manifest, sig), 'RESTORE_LEDGER');
      const missingFloor = createFileLedgerVerifier({ ledger, floor: {
        read: () => Promise.reject(new Error('Unavailable independent floor')), compareAndPin: () => Promise.resolve(false),
      }, signerPublicKey: ledgerKeys.publicKey, limits: proofLimits });
      await expectCode(rescrubFileRestore({ ...ctx, verifier: missingFloor }, manifest, sig), 'RESTORE_LEDGER');
      await expectCode(rescrubFileRestore({ ...ctx, openBackupObject(item) {
        const altered = archives.object(item, limits.maxObjectBytes).slice();
        altered[0] = (altered[0] ?? 0) ^ 1;
        return Promise.resolve(altered);
      } }, manifest, sig), 'RESTORE_OBJECT');
      authorityNonces.length = 0;
      const receipt = await rescrubFileRestore(ctx, manifest, sig);
      expect(receipt).toMatchObject({ mode: 'ACTIVE', epoch: { namespace, epoch: 2n }, copied: 7, tombstoned: 3, unresolved: 0 });
      expect(authorityNonces).toHaveLength(2);
      expect(new Set(authorityNonces).size).toBe(2);
      // The physical dump/restore must carry 018, not just claim its name in the manifest.
      // The synthetic founder was commissioned, but no management commands ran.
      expect((await targetOps.query(sourceRowsSql)).rows).toEqual(originalFounderSources);
      expect((await targetOps.query(`SELECT
        (SELECT count(*)::int FROM foundation.p03_command_receipts) AS receipts,
        to_regprocedure('foundation.issue_first_p03_permissions()') IS NOT NULL AS issuer`)).rows)
        .toEqual([{ receipts: 0, issuer: true }]);
      await maintenance.query(`GRANT CONNECT ON DATABASE "${destination}" TO fixlevelup_runtime`);
      const runtime = new Pool(restoreDbOptions(destination, 'runtime'));
      pools.push(runtime);
      // A remains no-byte: a fresh intent on the current restored authority is valid, but B/C cannot write.
      const reserved = await inRuntimeTransaction(runtime, (client) => reserveFileUpload(client, {
        session: survivor.file.session, policy: { versionId: randomUUID(), sourceRef: 'synthetic://restore-write-fence',
          allowedMimeTypes: ['image/png'], maxFileBytes: 64_000, maxOwnerBytes: 512_000, maxOwnerFiles: 8, expiresAt: expiry() },
        declaredMime: 'image/png', declaredBytes: png.byteLength, expiresAt: new Date(Date.now() + 240_000), idempotencyKey: randomUUID(),
      }));
      expect(reserved.state).toBe('RESERVED');
      const freshFile = { session: survivor.file.session, intentId: reserved.intentId };
      const listed = async () => {
        const out = await Promise.all([reader.send(new ListObjectsV2Command({ Bucket: fresh.target.bucket }), { abortSignal: sig }),
          sourceReader.send(new ListObjectsV2Command({ Bucket: sourceTarget.target.bucket }), { abortSignal: sig })]);
        return out.map((result) => {
          expect(result.IsTruncated).not.toBe(true);
          return result.Contents?.map(({ Key, ETag, Size }) => [Key, ETag, Size]).sort();
        });
      };
      const objectBaseline = await listed();
      expect(objectBaseline.map((objects) => objects?.length)).toEqual([7, 9]);
      const dbBaseline = await readAuthorityInventory(targetOps, limits);
      const counters = [vi.spyOn(writerStorage, 'putQuarantined'), vi.spyOn(writerStorage, 'fetchRawBytes'),
        vi.spyOn(writerStorage, 'prepareSanitizedAttempt'), vi.spyOn(writerStorage, 'putSanitized')];
      const pulls = vi.fn((): Promise<IteratorResult<Uint8Array>> => Promise.resolve({ value: png, done: false }));
      const factory = vi.fn((): AsyncIterable<Uint8Array> => ({ [Symbol.asyncIterator]: () => ({ next: pulls }) }));
      const upload = uploadPolicy();
      for (const file of [freshFile, quarantined.file]) {
        await expectCode(uploadReservedFile(runtime, writerStorage, upload, { ...file, idempotencyKey: randomUUID(), body: factory, signal: sig }),
          'NOT_CONFIGURED');
      }
      const process = vi.fn((input: Parameters<LocalFileProcessor['process']>[0]) => Promise.resolve(faultEvidence(png, input.raw)));
      const isEvidenceCurrent = vi.fn(() => true);
      const processor: LocalFileProcessor = { process, isEvidenceCurrent };
      const processing = { pool: runtime, epoch: receipt.epoch, storage: writerStorage, processor, uploadPolicy: upload, policy: processingPolicy() };
      for (const file of [quarantined.file, survivor.file]) {
        await expectCode(processQuarantine(processing, { ...file, signal: sig }), 'NOT_CONFIGURED');
      }
      for (const ignored of [...counters, factory, pulls, process, isEvidenceCurrent]) {
        expect(ignored).not.toHaveBeenCalled();
      }
      // The exact hash includes attempts, bindings, processing claims, publications, audit and outbox rows.
      expect(await readAuthorityInventory(targetOps, limits)).toBe(dbBaseline);
      expect(await listed()).toEqual(objectBaseline);
      const routed = createRestoredReadyStorage(receipt, [{ target: fresh.target, reader: readyStorage }]);
      const access = { ...sourceAccess, pool: runtime, epoch: receipt.epoch, storage: routed };
      expect(await readReadyMetadata(access, survivor.file)).toMatchObject({ state: 'READY' });
      const liveTicket = await openReadyStream(access, { ...survivor.file, signal: sig });
      try {
        const received: Uint8Array[] = [];
        for (let i = 0; i < 16; i++) {
          const part = await readReadyChunk(liveTicket);
          if (part.kind === 'EOF') {break;}
          received.push(part.bytes);
        }
        expect(Buffer.concat(received)).toEqual(Buffer.from(survivor.served));
      } finally { await closeReadyStream(liveTicket); }
      await expectCode(readReadyMetadata(access, retired.file), 'NOT_FOUND');
      await expectCode(readReadyMetadata(access, withdrawn.file), 'CONSENT_REVOKED');
      const targetPrivacy = { pool: runtime, epoch: receipt.epoch, policy };
      const restoredRetention = { ...targetPrivacy, scope: nextScope, grant: operator('RETENTION') };
      await expectCode(planRetention(restoredRetention, sig), 'NOT_CONFIGURED');
      const decisions = await planRetention({ ...restoredRetention, restore: receipt }, sig);
      expect(decisions.advanced).toBe(0);
      const { rows: [protectedRow] } = await targetOps.query<{ hold_active: boolean; delete_state: string; row_version: string }>(`SELECT hold_active,delete_state,row_version::text FROM foundation.file_privacy_controls WHERE intent_id=$1`, [held.file.intentId]);
      expect(protectedRow).toMatchObject({ hold_active: true, delete_state: 'OPEN' });
      for (const item of oldInventory.filter(o => o.intentId === retired.file.intentId)) {
        await expect(reader.send(new GetObjectCommand({ Bucket: fresh.target.bucket, Key: item.key }), { abortSignal: sig }))
          .rejects.toMatchObject({ $metadata: { httpStatusCode: 404 } } satisfies Partial<S3ServiceException>);
        if (item.disposition === 'COPY') {expect(sha256(await io.exportSource(item, sig))).toBe(item.sha256);}
      }
      const { rows: [debt] } = await targetOps.query<{ state: string; write_proof: string; delete_state: string }>(`SELECT a.state,d.write_proof,d.state AS delete_state FROM foundation.file_upload_attempts a
        JOIN foundation.file_delete_items d ON d.attempt_id=a.id WHERE a.id=$1`, [orphan]);
      expect(debt).toMatchObject({ state: 'UNKNOWN', write_proof: 'UNKNOWN', delete_state: 'AUTHORIZED' });
      expect((await floor.read(namespace)).writerEpoch).toBe(2n);
      expect((await floor.read(namespace)).seq).toBe(1n);
      const event = (await ledger.getEvents(nextScope, 0n, 1n))[0];
      if (event === undefined) {throw new Error('Missing current ledger graph');}
      await expect(ledger.append(event.graph)).rejects.toBeDefined();
      expect(() => createSyntheticDeleteBroker({ mode: 'local-synthetic', namespace, epoch: 2n, targets: [sourceConfig] }))
        .toThrow(expect.objectContaining({ code: 'NOT_CONFIGURED' }));
      expect(() => createRestoredDeleteBroker(receipt, [sourceConfig])).toThrow(expect.objectContaining({ code: 'NOT_CONFIGURED' }));
      expect(() => createRestoredDeleteBroker({ ...receipt }, [storageConfig(fresh, true)]))
        .toThrow(expect.objectContaining({ code: 'NOT_CONFIGURED' }));
      const restoredBroker = createRestoredDeleteBroker(receipt, [storageConfig(fresh, true)]);
      cleanups.push(() => revokeDeleteBroker(restoredBroker));
      const deleteContext = { ...targetPrivacy, policy: { ...policy, maxBatch: 1 }, scope: nextScope, ledger: targetLedger, verifier,
        grant: operator('DELETE'), broker: restoredBroker };
      // The old ledger event remains verified at its original writer epoch; no skipped old object can be deleted.
      expect(await reconcileFileDeletion(deleteContext, sig)).toEqual({ examined: 0, advanced: 0, deferred: 0 });
      if (protectedRow === undefined) { throw new Error('No current post-backup hold'); }
      const released = await changeFileHold({ ...targetPrivacy, restore: receipt }, makeHoldGrant(operator('HOLD'),
        { intentId: held.file.intentId, action: 'RELEASE', expectedRowVersion: BigInt(protectedRow.row_version) }));
      expect(released.applied).toBe(true);
      expect((await planRetention({ ...restoredRetention, restore: receipt }, sig)).advanced).toBe(1);
      // Try the real old LOGIN with a new writerEpoch and a fresh event id before the target drain.
      await expect(ledger.append({ ...event.graph, ...nextScope, eventId: randomUUID() })).rejects.toBeDefined();
      // One candidate per sweep: a historical LEDGERED graph with no aliases must not starve either current copy.
      expect((await reconcileFileDeletion(deleteContext, sig)).advanced).toBe(1);
      expect((await reconcileFileDeletion(deleteContext, sig)).advanced).toBe(1);
      expect(await reconcileFileDeletion(deleteContext, sig)).toEqual({ examined: 0, advanced: 0, deferred: 0 });
      expect((await floor.read(namespace)).seq).toBe(2n);
      for (const item of oldInventory.filter(o => o.intentId === held.file.intentId)) {
        await expect(reader.send(new GetObjectCommand({ Bucket: fresh.target.bucket, Key: item.key }), { abortSignal: sig }))
          .rejects.toMatchObject({ $metadata: { httpStatusCode: 404 } } satisfies Partial<S3ServiceException>);
        expect(sha256(await io.exportSource(item, sig))).toBe(item.sha256);
      }
      const afterDelete = (await targetOps.query<{ delete_state: string }>(`SELECT delete_state FROM foundation.file_privacy_controls WHERE intent_id=$1`,
        [held.file.intentId])).rows[0];
      expect(afterDelete?.delete_state).toBe('CONFIRMED_ABSENT');
      expect(await readReadyMetadata(access, survivor.file)).toMatchObject({ state: 'READY' });
      archives.evidence({ copied: receipt.copied, skippedTombstoned: receipt.tombstoned, ledgerSeq: '2', epoch: '2',
        survivor: 'ready-stream-exact-bytes', revoked: 'denied', hold: 'post-backup-current-open-protected',
        pending: 'drained-before-handoff', oldWriter: 'fenced', unresolvedDebt: 'unchanged', maxReconcileBatch: 1,
        originalObjectDeletes: 0, restoredCopiesConfirmedAbsent: 2 });
    } catch (error) { failures.push(error); }
    finally {
      // End the source observer before disposing the fenced source. Each owned
      // target has a distinct random name, checked by its successful CREATE.
      await finishRestoreRun(failures, [...cleanups.reverse(), ...pools.map(pool => () => pool.end()), () => sourceDb.close(), dropDestination]);
    }
  }, 175_000);
});