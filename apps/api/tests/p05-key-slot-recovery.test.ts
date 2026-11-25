/** Isolated synthetic PostgreSQL + slot backup rehearsal, not an activation path
 * for the P05 file-restore contour. No HTTP server, credential-file discovery,
 * shared DB writes, fixture role bypasses, or disabling of target constraints. */
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { lstat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import type { PoolClient } from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import { decodeP05Address } from '@fixlevelup/p03-contracts/p05';
import type { P05Address } from '@fixlevelup/p03-contracts/p05';
import { restoreReviewedExpressions } from '../../../infra/file-restore/resources.mjs';
import { admittedPool, requireRequestEffectsPool } from '../src/infrastructure/admission/pool-guard.js';
import type { AdmittedHandle } from './admission-fixture.js';
import { admitVerifiedTestInstance } from './admission-fixture.js';
import { authFixtureMigrations, installPinnedMigrationHistory, verifyOperatorMigrationHistory } from './auth-db-fixture.js';
import { OwnedTestDatabase, fixtureCredentials } from './owned-test-database.js';
import { createSyntheticKeySlots } from './p05-key-slot-fixture.js';
import { attestDisposableFixture, seedRequestFixtures } from './p05-request-fixtures.js';
import type { RequestFixtures } from './p05-request-fixtures.js';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { loadKeyring } from '../src/requests/crypto/keyring.js';
import type { KeyringConfig } from '../src/requests/crypto/keyring.js';
import { MANAGED_PAYLOAD_KEY_MARKER } from '../src/requests/crypto/payload-cipher.js';
import { openPayloadKeyDirectory } from '../src/requests/crypto/payload-key-directory.js';
import type { PayloadKeySlotRef, PayloadKeySlots } from '../src/requests/crypto/payload-key-directory.js';
import { capturePayloadKeyBackup, restorePayloadKeyBackup } from '../src/requests/crypto/payload-key-recovery.js';
import { dbClock, geoFence } from '../src/requests/intake/basis.js';
import { readCoverageBasis, recordCoverageAssessment, requestEffectsAuditStore, validateCoverageSelection } from '../src/requests/intake/coverage.js';
import type { CoverageReviewEvidence } from '../src/requests/intake/coverage.js';
import { lockStaffCommandKey, writeEffect } from '../src/requests/intake/effects.js';
import { createRequestRow, insertStaffEvidence, requestRow, updateRequestRow, writeAddress, writeAppliance,
  writeContact, writePhone, writePreference } from '../src/requests/intake/store.js';

const enabled = process.env['FIXLEVELUP_P05_KEY_SLOT_RECOVERY_TESTS'] === '1'
  && process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';
const ROOT = resolve(import.meta.dirname, '../../..');
const DATABASE = /^fixlevelup_configuration_test_[a-f0-9]{24}$/u;
const CONNECTION = { host: '127.0.0.1' as const, port: 55432 };
const RUNTIME = 'fixlevelup_runtime' as const;
const OWNER = 'fixlevelup_migrator';
const ENVIRONMENT = 'p05-key-slot-recovery';
const STREET = 'Synthetic recovery sentinel';
const CONTACT = Object.freeze({ name: 'Synthetic recovery contact', phone: '+15550100022' });
const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const cellDigest = (rows: readonly Cell[]): string => sha256(Buffer.from(JSON.stringify(rows), 'utf8'));

async function slotFacts(directory: string, refs: readonly PayloadKeySlotRef[]) {
  return await Promise.all(refs.map(async ({ cellId }) => {
    const stats = await lstat(join(directory, `${cellId}.slot`), { bigint: true });
    return { regular: stats.isFile(), mode: Number(stats.mode & 0o7777n), links: Number(stats.nlink), size: Number(stats.size),
      uid: stats.uid, dev: stats.dev, ino: stats.ino, mtimeNs: stats.mtimeNs, ctimeNs: stats.ctimeNs };
  }));
}

type OwnedFixture = { name: string; db: Pool; oid: string };
interface Cell {
  id: string; request_id: string; kind: PayloadKeySlotRef['kind']; revision: number; key_id: string;
  wrapped: string; nonce: string; ciphertext: string; tag: string; aad_context: string; created_at: string;
}

async function pin(client: PoolClient, name: string, role: string, oid?: string): Promise<string> {
  if (!DATABASE.test(name) || await attestDisposableFixture(client, role === OWNER ? 'WRITE' : 'READ') !== name) {
    throw new Error('Wrong recovery rehearsal database');
  }
  const { rows: [fact] } = await client.query<{ oid: string }>(`SELECT oid::text AS oid FROM pg_catalog.pg_database
    WHERE datname=$1 AND datname=current_database() AND current_user=$2 AND datdba=$3::regrole`, [name, role, OWNER]);
  if (!fact || (oid !== undefined && fact.oid !== oid)) { throw new Error('Wrong recovery rehearsal ownership'); }
  return fact.oid;
}

async function transaction<T>(pool: Pool, action: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const value = await action(client);
    await client.query('COMMIT');
    return value;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}

function pgTool(tool: 'pg_dump' | 'pg_restore', fixture: OwnedFixture, args: readonly string[], input?: Buffer): Buffer {
  const runId = process.env['FIXLEVELUP_SESSION_RUN_ID'] ?? '';
  if (!DATABASE.test(fixture.name) || !/^[a-f0-9]{12}$/u.test(runId) || process.platform !== 'linux') {
    throw new Error('Invalid recovery rehearsal archive binding');
  }
  const env = { LANG: 'C.UTF-8', LD_LIBRARY_PATH: '/opt/p05-lab/lib', PGHOST: CONNECTION.host,
    PGPORT: String(CONNECTION.port), PGAPPNAME: `fixlevelup-p05s4-${runId}`, PGDATABASE: fixture.name,
    PGUSER: OWNER, PGPASSWORD: fixtureCredentials().migrator, PGCONNECT_TIMEOUT: '5', PGTZ: 'UTC' };
  const run = (argv: readonly string[], archive?: Buffer): Buffer => {
    const result = spawnSync(`/opt/p05-lab/bin/${tool}`, argv, {
      env, stdio: ['pipe', 'pipe', 'pipe'], timeout: 30000, maxBuffer: 8 * 1024 * 1024, input: archive,
    });
    if (result.status !== 0 || result.error !== undefined || !Buffer.isBuffer(result.stdout)) {
      // Do not surface command environment, tool stderr, or archive bytes.
      throw new Error(`Recovery rehearsal ${tool} failed`);
    }
    return result.stdout;
  };
  if (!/^pg_(?:dump|restore) \(PostgreSQL\) 18\.7(?:\s|$)/u.test(run(['--version']).toString('utf8'))) {
    throw new Error('Unexpected recovery rehearsal PostgreSQL tool');
  }
  return run(['--no-password', `--dbname=${fixture.name}`, ...args], input);
}

async function attestClosed(client: PoolClient, fixture: OwnedFixture): Promise<void> {
  await pin(client, fixture.name, OWNER, fixture.oid);
  // Allow our own just-closed libpq/admission sessions to drain, without
  // signaling any backend or waiting on ordinary business work.
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const { rows: [state] } = await client.query<{ closed: boolean; drained: boolean }>(`SELECT
      NOT has_database_privilege('fixlevelup_runtime', current_database(), 'CONNECT') AS closed,
      NOT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
        AND pid<>pg_backend_pid() AND backend_type='client backend')
      AND NOT EXISTS (SELECT 1 FROM pg_prepared_xacts WHERE database=current_database()) AS drained`);
    if (state?.closed !== true) { break; }
    if (state.drained) { return; }
    await delay(25);
  }
  throw new Error('Recovery rehearsal not closed and drained');
}

async function cells(client: Pick<PoolClient, 'query'>): Promise<Cell[]> {
  const result = await client.query<Cell>(`SELECT id,request_id,kind,revision,key_id,encode(wrapped_dek,'hex') AS wrapped,
    encode(nonce,'hex') AS nonce,encode(ciphertext,'hex') AS ciphertext,encode(auth_tag,'hex') AS tag,aad_context,
    to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US') AS created_at
    FROM foundation.request_payload_cells ORDER BY id LIMIT 4`);
  return result.rows;
}

async function guarded(fixture: OwnedFixture, kind: 'source' | 'target') {
  const admission: AdmittedHandle = await admitVerifiedTestInstance(fixture.db, fixture.name, { profile: 'S3' });
  const endpoint = { ...CONNECTION, database: fixture.name, user: RUNTIME, password: fixtureCredentials().runtime };
  const deps = { authorization: admission.authorization, kind: 'TEST' as const };
  const pool = admittedPool(deps, endpoint, { max: 1, application_name: `p05-slots-${kind}`, statement_timeout: 5000 });
  const audit = admittedPool(deps, endpoint, { max: 1, application_name: `p05-slots-audit-${kind}`, statement_timeout: 5000 });
  requireRequestEffectsPool(pool);
  return { pool, audit, async close() {
    try { await Promise.all([pool.end(), audit.end()]); }
    finally { await admission.release(); }
  } };
}

/** The real store/effect ports create the immutable aggregate through the
 * admitted runtime role. Separate commits keep all deferred guards in force. */
async function writeRepair(pool: Pool, fixture: OwnedFixture, basis: RequestFixtures,
  staffId: string, ring: KeyringConfig, keySlots: PayloadKeySlots, address: P05Address) {
  const requestId = randomUUID();
  const revisions = { contact: randomUUID(), address: randomUUID(), appliance: randomUUID(),
    preference: randomUUID(), assessment: null };
  const actor = { kind: 'STAFF' as const, id: staffId };
  await transaction(pool, async (client) => {
    await pin(client, fixture.name, RUNTIME, fixture.oid);
    await client.query('SET LOCAL synchronous_commit=on');
    await geoFence(client);
    const key = randomUUID();
    const evidenceId = randomUUID();
    const phoneEvidenceId = randomUUID();
    const eventId = randomUUID();
    const validUntil = new Date((await dbClock(client)).getTime() + 3600000);
    await lockStaffCommandKey(client, actor, 'CreateManualRequest', key);
    const row = await createRequestRow(client, { id: requestId, customerId: randomUUID(), cityId: basis.cityId,
      cityVersionId: basis.cityVersionId, policyId: basis.policyId, type: 'REPAIR', status: 'NEW', revisions });
    const config = { ring, keySlots, environment: ENVIRONMENT };
    await writeContact(client, config, row.id, revisions.contact, 1, 'PHONE', CONTACT);
    await writeAddress(client, config, row, revisions.address, 1, address);
    const appliance = { categoryId: basis.categoryId };
    const fault = { faultIds: [basis.faultId], description: 'Synthetic details sentinel' };
    await writeAppliance(client, config, row.id, revisions.appliance, 1, appliance, fault);
    await writePreference(client, row.id, revisions.preference, 1, 'PHONE', basis.timezone);
    await client.query(`INSERT INTO foundation.request_intake_provenance (request_id,source_entry_id,source_version_id)
      SELECT $1,id,current_version_id FROM foundation.reference_entries WHERE id=$2`, [row.id, basis.formSourceEntryId]);
    await insertStaffEvidence(client, row.id, staffId, 'MANUAL_INTAKE', { id: evidenceId, procedureRevision: 'key-rehearsal-v1', validUntil });
    await insertStaffEvidence(client, row.id, staffId, 'PHONE_GIVE', { id: phoneEvidenceId, procedureRevision: 'key-rehearsal-v1', validUntil });
    await writeEffect(client, ring, row, { actor, command: 'CreateRepair', key, target: null, match: null,
      body: { type: 'REPAIR', sourceEntryId: basis.formSourceEntryId, evidenceId, address, appliance, fault,
        contact: { ...CONTACT, mode: 'PHONE', phonePermission: true, phoneEvidenceId } },
    }, eventId, randomUUID());
    await writePhone(client, row, eventId, 'GIVEN', randomUUID(), phoneEvidenceId);
  });
  const reviewed = await transaction(pool, async (client) => {
    await geoFence(client);
    const row = await requestRow(client, requestId, true);
    if (row?.status !== 'NEW') { throw new Error('Missing initial request'); }
    const key = randomUUID();
    await lockStaffCommandKey(client, actor, 'StartReview', key);
    const next = await updateRequestRow(client, row, 'MANAGER_REVIEW', 'REPAIR', revisions);
    await writeEffect(client, ring, next, { actor, command: 'StartReview', key, target: row.id, match: null, body: {} }, randomUUID(), randomUUID());
    return next;
  });
  expect(reviewed.row_version).toBe(2);
  return { requestId, cityId: basis.cityId, addressRevisionId: revisions.address, expectedVersion: reviewed.row_version };
}

describe.runIf(enabled)('P05 managed key slot snapshot / restore rehearsal', () => {
  const cleanup: (() => Promise<void>)[] = [];
  const generation = async (environment = ENVIRONMENT) => {
    const result = await createSyntheticKeySlots(environment);
    cleanup.push(() => result.close());
    return result;
  };
  const owned = async (runtime: boolean): Promise<OwnedFixture> => {
    const name = `fixlevelup_configuration_test_${randomBytes(12).toString('hex')}`;
    const fixture = await OwnedTestDatabase.create({ name, pattern: DATABASE, async prepare(client) {
      await client.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC, ${RUNTIME}`);
      if (runtime) { await client.query(`GRANT CONNECT ON DATABASE "${name}" TO ${RUNTIME}`); }
    } });
    const db = new Pool({ ...CONNECTION, user: OWNER, database: name, password: fixtureCredentials().migrator,
      max: 3, statement_timeout: 10000, connectionTimeoutMillis: 3000 });
    cleanup.push(async () => { await fixture.dispose(async () => { await db.end(); }); });
    const client = await db.connect();
    try { return { name, db, oid: await pin(client, name, OWNER) }; }
    finally { client.release(); }
  };

  afterAll(async () => {
    const problems: unknown[] = [];
    for (const close of cleanup.reverse()) {
      try { await close(); } catch (error) { problems.push(error); }
    }
    if (problems.length) { throw new AggregateError(problems, 'Recovery rehearsal fixture cleanup failed'); }
  }, 45000);

  it('restores a fenced PG archive and compares production ciphertext using only the rotated KEK', async () => {
    const source = await owned(true);
    const target = await owned(false);
    expect(target.oid).not.toBe(source.oid);
    await source.db.query(`CREATE SCHEMA foundation AUTHORIZATION ${OWNER}`);
    for (const migration of authFixtureMigrations) {
      await source.db.query(readFileSync(resolve(ROOT, 'prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
    const { historyManifestDigest } = await installPinnedMigrationHistory(source.db);
    const { staffId } = await bootstrapFirstAdmin(source.db, { login: randomBytes(24).toString('hex'), password: randomBytes(24).toString('hex') });
    const basis = await seedRequestFixtures(source, { reviewerId: staffId });
    const candidateAddress = Object.freeze(decodeP05Address({ street: STREET, building: '19', districtId: basis.districtId }));
    const hmac = [{ keyId: 'rehearsal-hmac', secretHex: randomBytes(32).toString('hex') }];
    const ring = (keyId: string) => loadKeyring({ activeKekId: keyId, activeHmacKeyId: 'rehearsal-hmac', hmac,
      kek: [{ keyId, secretHex: randomBytes(32).toString('hex') }] });
    const previous = ring('rehearsal-kek-old');
    const next = ring('rehearsal-kek-new');
    const old = await generation();
    const rotated = await generation();
    const writer = await guarded(source, 'source');
    const request = await (async () => {
      try { return await writeRepair(writer.pool, source, basis, staffId, previous, old.slots, candidateAddress); }
      finally { await writer.close(); }
    })();
    await source.db.query(`REVOKE CONNECT ON DATABASE "${source.name}" FROM ${RUNTIME}`);
    const client = await source.db.connect();
    const archive = await (async () => {
      try {
        await attestClosed(client, source);
        await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
        const snapshot = (await client.query<{ snapshot: string }>('SELECT pg_export_snapshot() AS snapshot')).rows[0]?.snapshot;
        if (!snapshot || !/^[0-9A-F]{8}-[0-9A-F]{8}-[0-9]+$/u.test(snapshot)) { throw new Error('Missing exported recovery snapshot'); }
        const stored = await cells(client);
        expect(stored.map(row => row.kind).sort()).toEqual(['ADDRESS', 'CONTACT', 'DETAILS']);
        expect(stored.every(row => row.request_id === request.requestId && row.revision === 1
          && row.key_id === MANAGED_PAYLOAD_KEY_MARKER && row.wrapped === '')).toBe(true);
        const refs = Object.freeze(stored.map(row => Object.freeze({ environment: ENVIRONMENT, cellId: row.id,
          requestId: row.request_id, kind: row.kind, revision: row.revision })));
        const backup = await capturePayloadKeyBackup(refs, old.slots);
        // Use a full DB archive: a schema-only selection can omit the trusted
        // btree_gist extension needed by the restored foundation constraints.
        const dump = pgTool('pg_dump', source, ['--format=custom', `--snapshot=${snapshot}`]);
        expect(dump.subarray(0, 5).toString('ascii')).toBe('PGDMP');
        await client.query('COMMIT');
        await attestClosed(client, source);
        // Trusted synthetic issuer binds digest + exact inventory to this exact
        // exported PG snapshot while source runtime and writers are drained.
        return { refs, stored, backup, dump, expectedDumpSha: sha256(dump), sourceSlots: await slotFacts(old.directory, refs) };
      } finally { await client.query('ROLLBACK').finally(() => { client.release(); }); }
    })();
    const assertTargetClosed = async () => {
      const check = await target.db.connect();
      try { await attestClosed(check, target); } finally { check.release(); }
    };
    await assertTargetClosed();
    expect(sha256(archive.dump)).toBe(archive.expectedDumpSha);
    pgTool('pg_restore', target, ['--single-transaction', '--exit-on-error', '--no-owner'], archive.dump);
    // PostgreSQL logically restores the expressions, but may normalize their
    // catalog spellings. Restore only reviewed, pinned definitions before the
    // ordinary S3 admission; preserve every source cell and target closure.
    const sourceCatalog = await source.db.connect();
    try {
      const targetCatalog = await target.db.connect();
      try {
        await attestClosed(sourceCatalog, source);
        await attestClosed(targetCatalog, target);
        await restoreReviewedExpressions(sourceCatalog, targetCatalog, target.name, undefined, 'synthetic-key-rehearsal');
        await attestClosed(targetCatalog, target);
      } finally { targetCatalog.release(); }
    } finally { sourceCatalog.release(); }
    expect(await verifyOperatorMigrationHistory(target.db)).toEqual({ ok: true, historyManifestDigest });
    expect(await cells(target.db)).toEqual(archive.stored);

    const restore = { ...archive.backup, refs: archive.refs, destination: rotated.slots, previous, next };
    const refuse = 'Payload key recovery unavailable';
    const badRef = archive.refs.at(-1);
    if (!badRef) { throw new Error('Missing source slot'); }
    await expect(restorePayloadKeyBackup({ ...restore, refs: archive.refs.slice(1) })).rejects.toThrow(refuse);
    await expect(restorePayloadKeyBackup({ ...restore, refs: [...archive.refs.slice(0, -1), { ...badRef, revision: 2 }] })).rejects.toThrow(refuse);
    await expect(restorePayloadKeyBackup({ ...restore, next: previous })).rejects.toThrow(refuse);
    const foreign = await generation('p05-key-slot-foreign');
    await expect(restorePayloadKeyBackup({ ...restore, destination: foreign.slots })).rejects.toThrow(refuse);
    const originalWrapHex = (await old.slots.read(badRef)).wrappedDek.toString('hex');
    const alteredWrapHex = `${originalWrapHex.slice(0, -1)}${originalWrapHex.endsWith('0') ? '1' : '0'}`;
    const corrupt = Buffer.from(archive.backup.bytes.toString('utf8').replace(`"${originalWrapHex}"`, `"${alteredWrapHex}"`));
    expect(corrupt.equals(archive.backup.bytes)).toBe(false);
    await expect(restorePayloadKeyBackup({ ...restore, bytes: corrupt })).rejects.toThrow(refuse);
    // Recomputing a digest does not make a modified AEAD wrap authentic. This
    // corrupts the last sorted wrap, probing validation-before-publish.
    await expect(restorePayloadKeyBackup({ ...restore, bytes: corrupt, sha256: sha256(corrupt) })).rejects.toThrow(refuse);
    await assertTargetClosed();
    const asEmpty = await openPayloadKeyDirectory(rotated.directory, ENVIRONMENT);
    for (const ref of archive.refs) { await expect(asEmpty.read(ref)).rejects.toThrow('Payload key slot unavailable'); }
    await restorePayloadKeyBackup(restore);
    const reopened = await openPayloadKeyDirectory(rotated.directory, ENVIRONMENT);
    for (const ref of archive.refs) {
      const original = await old.slots.read(ref);
      const replacement = await reopened.read(ref);
      expect(original.keyId).toBe(previous.activeKeyId);
      expect(replacement.keyId).toBe(next.activeKeyId);
      expect(replacement.wrappedDek.equals(original.wrappedDek)).toBe(false);
    }
    const targetSlots = await slotFacts(rotated.directory, archive.refs);
    expect(targetSlots).toHaveLength(3);
    for (const [index, targetSlot] of targetSlots.entries()) {
      const sourceSlot = archive.sourceSlots[index];
      if (!sourceSlot) { throw new Error('Missing source slot stats'); }
      for (const stat of [sourceSlot, targetSlot]) {
        expect({ regular: stat.regular, mode: stat.mode, links: stat.links, uid: stat.uid }).toEqual({
          regular: true, mode: 0o600, links: 1, uid: BigInt(process.geteuid?.() ?? -1),
        });
        expect(stat.size).toBeGreaterThan(120);
        expect(stat.size).toBeLessThanOrEqual(384);
      }
      expect(targetSlot.dev !== sourceSlot.dev || targetSlot.ino !== sourceSlot.ino).toBe(true);
    }
    expect(await slotFacts(old.directory, archive.refs)).toEqual(archive.sourceSlots);
    expect((await capturePayloadKeyBackup(archive.refs, old.slots)).sha256).toBe(archive.backup.sha256);
    await assertTargetClosed();
    expect(await cells(target.db)).toEqual(archive.stored);
    await target.db.query(`GRANT CONNECT ON DATABASE "${target.name}" TO ${RUNTIME}`);

    const targetRuntime = await guarded(target, 'target');
    try {
      const audit = requestEffectsAuditStore(targetRuntime.audit);
      const selection = { outcome: 'IN_ZONE', areaId: basis.areaId } as const;
      // Prove the restored selection/basis before exercising the slot failures.
      await transaction(targetRuntime.pool, async (connection) => {
        await pin(connection, target.name, RUNTIME, target.oid);
        await geoFence(connection);
        await requestRow(connection, request.requestId, true);
        const restoredBasis = await readCoverageBasis(connection, request.cityId, request.addressRevisionId, 64);
        expect(restoredBasis.address.districtId).toBe(basis.districtId);
        expect(restoredBasis.mappings).toEqual([{ areaId: basis.areaId, areaVersionId: basis.areaVersionId,
          districtId: basis.districtId, relation: 'FULL' }]);
        expect(validateCoverageSelection(restoredBasis, selection)).toMatchObject({ outcome: 'IN_ZONE', areaId: basis.areaId });
      });
      const compare = async (evidenceId: string, keySlots: PayloadKeySlots, useRing: KeyringConfig, candidate = candidateAddress) =>
        await transaction(targetRuntime.pool, async (connection) => {
          await pin(connection, target.name, RUNTIME, target.oid);
          await geoFence(connection);
          await requestRow(connection, request.requestId, true);
          const proof: CoverageReviewEvidence = { evidenceId, issuer: 'T', purpose: 'COVERAGE_REVIEW', staffId,
            requestId: request.requestId, addressRevisionId: request.addressRevisionId, candidate,
            expiresAt: new Date((await dbClock(connection)).getTime() + 60000) };
          return await recordCoverageAssessment({ client: connection, ring: useRing, environment: ENVIRONMENT, keySlots,
            actor: { staffId }, request, evidenceHandle: evidenceId, cap: 64, selection,
            evidence: { verify: () => Promise.resolve(proof) }, audit, recheck: () => dbClock(connection) });
        });
      const missing = await generation();
      const swapped = await generation();
      const address = archive.refs.find(ref => ref.kind === 'ADDRESS');
      const contact = archive.refs.find(ref => ref.kind === 'CONTACT');
      if (!address || !contact) { throw new Error('Missing typed slot fixture'); }
      await swapped.slots.create(address, await reopened.read(contact));
      const outcomes: { scenario: string; result: string; audits: number; cellSha256: string }[] = [];
      const expectedCellSha = cellDigest(archive.stored);
      const verifyAttempt = async (scenario: string, result: string, evidenceId: string, correlationId?: string) => {
        const { rows } = await target.db.query<{ correlation_id: string }>(`SELECT correlation_id
          FROM foundation.request_address_review_attempts WHERE evidence_id=$1 AND staff_id=$2 AND request_id=$3
          AND address_revision_id=$4 AND purpose='COVERAGE_REVIEW'`, [evidenceId, staffId, request.requestId, request.addressRevisionId]);
        expect(rows).toHaveLength(1);
        if (correlationId !== undefined) { expect(rows[0]?.correlation_id).toBe(correlationId); }
        const cellSha256 = cellDigest(await cells(target.db));
        expect(cellSha256).toBe(expectedCellSha);
        outcomes.push({ scenario, result, audits: rows.length, cellSha256 });
      };
      for (const [scenario, keySlots] of [['missing-slot', missing.slots], ['foreign-environment', foreign.slots],
        ['swapped-wrap', swapped.slots], ['retired-kek', old.slots]] as const) {
        const evidenceId = randomUUID();
        await expect(compare(evidenceId, keySlots, next)).rejects.toMatchObject({ code: 'DEPENDENCY_UNAVAILABLE' });
        await verifyAttempt(scenario, 'DEPENDENCY_UNAVAILABLE', evidenceId);
      }
      expect(next.keys.filter(key => key.purpose === 'PAYLOAD_KEK').map(key => key.keyId)).toEqual([next.activeKeyId]);
      const positiveId = randomUUID();
      const comparison = await compare(positiveId, reopened, next);
      expect(comparison).toMatchObject({ outcome: 'IN_ZONE', areaId: basis.areaId, addressRevisionId: request.addressRevisionId });
      expect(JSON.stringify(comparison)).not.toContain(STREET);
      await verifyAttempt('rotated-kek', comparison.outcome, positiveId, comparison.attemptCorrelationId);
      const mismatchId = randomUUID();
      await expect(compare(mismatchId, reopened, next, { ...candidateAddress, building: '20' })).rejects.toMatchObject({ code: 'FORBIDDEN' });
      await verifyAttempt('nonmatching-address', 'FORBIDDEN', mismatchId);
      const { rows: [effects] } = await target.db.query<{ audits: number; assessments: number }>(`SELECT
        (SELECT count(*)::int FROM foundation.request_address_review_attempts WHERE request_id=$1) AS audits,
        (SELECT count(*)::int FROM foundation.request_coverage_assessments WHERE request_id=$1) AS assessments`, [request.requestId]);
      expect(effects).toEqual({ audits: 6, assessments: 0 });
      expect(await cells(target.db)).toEqual(archive.stored);
      expect(await slotFacts(rotated.directory, archive.refs)).toEqual(targetSlots);
      process.stdout.write(`P05_KEY_SLOT_RECOVERY ${JSON.stringify({ dumpSha256: archive.expectedDumpSha,
        backupSha256: archive.backup.sha256, historyManifestDigest, privateSlots: targetSlots.length, outcomes })}\n`);
    } finally { await targetRuntime.close(); }
  }, 120000);
});
