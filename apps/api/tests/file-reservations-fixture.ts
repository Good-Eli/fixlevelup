/**
 * Isolated PostgreSQL fixture for the P03-04A file reservation ports.
 *
 * Independent of the P03-03 legal/configuration fixtures: this file owns its own
 * disposable database, its own migration application and its own synthetic
 * legal/consent rows. It follows the accepted fixture contract of those suites:
 *
 * - opt-in only (`FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1`), checked before any
 *   database is created, so a normal test run cannot provision anything;
 * - the database name is `fixlevelup_legal_test_<24 random hex>`: the crypto-random
 *   suffix means a run never reuses a previous database, and the existing
 *   `fixlevelup_(...|legal)_test_...` guard in `auth-db-fixture.ts` already accepts
 *   it, so no extra allowlist entry is needed;
 * - the maintenance role only reaches `postgres` and one CREATE/GRANT block
 *   (owned lifecycle in owned-test-database.ts, which also drops this run's own
 *   database when provisioning fails midway);
 *   migrations run as the migrator role, the ports under test run as the real
 *   `fixlevelup_runtime` role;
 * - nothing drops rows or touches the working dev database; the only database
 *   this fixture deletes is the one it created itself.
 *
 * The migration chain is the shared `authFixtureMigrations` list (the file-proof
 * task adds migration 014 to it). This fixture requires 014 to be present and
 * fails loudly otherwise, instead of silently proving the ports against an older
 * schema.
 *
 * All synthetic rows (reviewed staff, city, legal documents, consent evidence) are
 * written by the migration owner, never by the port under test, so a port cannot
 * authorize itself. Credentials come from the shared fixture policy (lab process
 * env in lab mode, local ignored env files otherwise) and are never printed.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { Client, Pool } from 'pg';
import type { PoolClient } from 'pg';
import { describe } from 'vitest';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import {
  beginLegalTransaction, createLegalDocument, createRequestSession, findLegalDocument, hashSessionSecret,
  publishLegalDocumentVersion, recordConsentGiven, recordConsentRevoked,
} from '../src/settings/legal/index.js';
import { authFixtureMigrations, migrateAuthFixture } from './auth-db-fixture.js';
import { OwnedTestDatabase, fixtureCredentials } from './owned-test-database.js';

const FILE_RESERVATIONS_MIGRATION = '20261121000500_file_upload_reservations';
const connection = { host: '127.0.0.1' as const, port: 55432 };

/** `describe` only when the isolated-PostgreSQL suites were explicitly opted in. */
export const fileReservationsIntegration =
  process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;

if (!authFixtureMigrations.includes(FILE_RESERVATIONS_MIGRATION)) {
  // Fail loudly instead of silently proving the ports against a schema without 014.
  throw new Error('File reservation fixture requires migration 014 in the shared auth fixture chain');
}

export interface FixtureCity {
  readonly cityId: string;
  readonly cityVersionId: string;
}

export interface FileReservationsFixture {
  readonly database: string;
  readonly migrator: Pool;
  readonly runtime: Pool;
  /** The bootstrapped first administrator, used as the reviewed_by FK target. */
  readonly reviewer: string;
  readonly city: FixtureCity;
  /** Runs `run` inside one explicit runtime transaction, rolling back on failure. */
  inTransaction<T>(run: (client: PoolClient) => Promise<T>): Promise<T>;
  /** End both application pools once; the operator may keep the closed database for a restore handoff. */
  drainPools(): Promise<void>;
  close(): Promise<void>;
}

export const FILE_RESTORE_S0_CAP = '20261123000100_request_intake_foundation';

/** Creates one isolated database, applies the real chain and seeds reviewed rows.
 * Only the synthetic full-archive restore proof may opt in to the exact S0 cap. */
export async function startFileReservationsDatabase(capBefore?: typeof FILE_RESTORE_S0_CAP): Promise<FileReservationsFixture> {
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1') {
    throw new Error('File reservation fixture requires FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1');
  }
  if (capBefore !== undefined && (!Object.is(capBefore, FILE_RESTORE_S0_CAP)
    || process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] !== '1'
    || process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1')) {
    throw new Error('Legacy file restore requires the exact synthetic S0 cap');
  }
  // Credentials follow the shared fixture policy: lab mode reads only the lab
  // process env (never the dev `.env` files, no partial-env fallback).
  const { migrator: migratorPassword, runtime: runtimePassword } = fixtureCredentials();
  // The existing auth fixture guard already accepts this prefix; the random suffix
  // makes CREATE DATABASE the reuse check (an existing name is a hard error).
  const database = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
  if (!/^fixlevelup_legal_test_[a-f0-9]{24}$/.test(database)) {
    throw new Error('Invalid file reservation fixture database name');
  }
  // Owned lifecycle: the maintenance role only reaches `postgres` for this one
  // CREATE/REVOKE/GRANT block, and any failure from here to the returned fixture
  // drops exactly this run's database (see owned-test-database.ts).
  const owned = await OwnedTestDatabase.create({
    name: database,
    gracefulFileDrop: true,
    pattern: /^fixlevelup_legal_test_[a-f0-9]{24}$/,
    prepare: async (maintenance) => {
      await maintenance.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
      await maintenance.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
    },
  });
  const migrator = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword, max: 4 });
  const runtime = new Pool({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword, max: 6 });
  let drained: Promise<void> | undefined;
  const drainPools = (): Promise<void> => (drained ??= (async () => {
    const results = await Promise.allSettled([runtime.end(), migrator.end()]);
    const errors = results.filter(result => result.status === 'rejected').map(result => result.reason as unknown);
    if (errors.length) { throw new AggregateError(errors, 'File reservation fixture pool drain failed'); }
  })());
  try {
    const migrationClient = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
    await migrationClient.connect();
    try {
      await migrateAuthFixture(migrationClient, database, capBefore);
    } finally {
      await migrationClient.end();
    }
    const reviewer = (await bootstrapFirstAdmin(migrator, {
      login: `files-${randomBytes(12).toString('hex')}`,
      password: `Synthetic-Files-${randomBytes(12).toString('hex')}!`,
    })).staffId;
    const city = await seedCity(migrator, reviewer);
    return {
      database,
      migrator,
      runtime,
      reviewer,
      city,
      async inTransaction<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
        const client = await runtime.connect();
        try {
          await beginLegalTransaction(client);
          const result = await run(client);
          await client.query('COMMIT');
          return result;
        } catch (error) {
          await client.query('ROLLBACK').catch(() => undefined);
          throw error;
        } finally {
          client.release();
        }
      },
      drainPools,
      async close(): Promise<void> {
        // Ends this run's pools first, then drops exactly this run's database.
        await owned.dispose(drainPools);
      },
    };
  } catch (error) {
    // Provisioning failed after CREATE: close this run's pools, drop exactly this
    // run's database, and surface a teardown failure instead of swallowing it
    // (AggregateError carries both errors).
    throw await owned.failure(error, drainPools);
  }
}

/** One city with one published reviewed version, inserted as the migrator under
 * the unified GEO/CFG writer fence on one pinned client. */
async function seedCity(db: Pool, staffId: string): Promise<FixtureCity> {
  const cityId = randomUUID();
  const cityVersionId = randomUUID();
  const hours = JSON.stringify(Array.from({ length: 7 }, () => [[540, 1080]]));
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(734305,1)');
    await client.query("INSERT INTO foundation.service_cities (id,code,lifecycle) VALUES ($1,$2,'DRAFT')",
      [cityId, `files-${cityId.slice(0, 8)}`]);
    await client.query(`INSERT INTO foundation.service_city_versions
        (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
      VALUES ($1,$2,1,'File fixture city','Europe/Moscow','+70000000000',$3::jsonb,$4)`,
    [cityVersionId, cityId, hours, staffId]);
    await client.query('UPDATE foundation.service_cities SET current_version_id=$2 WHERE id=$1', [cityId, cityVersionId]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return { cityId, cityVersionId };
}

/** Raw pre-submit anchor: the raw token is issued here once and never stored. */
export interface Anchor {
  readonly sessionId: string;
  readonly token: string;
}

export function token(): string {
  return randomUUID().replace(/-/g, '') + randomUUID().slice(0, 8);
}

/** Creates one request_sessions anchor through the real legal port (runtime role). */
export async function newAnchor(
  fixture: FileReservationsFixture,
  expiresAt: Date = new Date(Date.now() + 3_600_000),
): Promise<Anchor> {
  const raw = token();
  const created = await fixture.inTransaction((client) => createRequestSession(client, {
    secretHash: hashSessionSecret(raw),
    intakeCityId: fixture.city.cityId,
    intakeCityVersionId: fixture.city.cityVersionId,
    expiresAt,
  }));
  return { sessionId: created.sessionId, token: raw };
}

export function proof(anchor: Anchor): { sessionId: string; token: string } {
  return { sessionId: anchor.sessionId, token: anchor.token };
}

/**
 * The current REQUEST_PROCESSING consent form. Created and published on first use
 * by the migration owner (runtime role through the legal port, but as a reviewed
 * synthetic document), never by the file reservation port.
 */
export async function ensureProcessingConsentForm(
  fixture: FileReservationsFixture,
): Promise<{ documentId: string; versionId: string; version: number }> {
  const existing = await fixture.inTransaction((client) => findLegalDocument(client, 'REQUEST_PROCESSING', 'CONSENT_FORM'));
  if (existing !== null && existing.currentVersionId !== null) {
    return { documentId: existing.id, versionId: existing.currentVersionId, version: existing.version };
  }
  const created = existing === null
    ? await fixture.inTransaction((client) => createLegalDocument(client, { purpose: 'REQUEST_PROCESSING', kind: 'CONSENT_FORM' }))
    : { documentId: existing.id, version: existing.version };
  const published = await fixture.inTransaction((client) => publishLegalDocumentVersion(client, {
    documentId: created.documentId,
    expectedVersion: created.version,
    title: 'Synthetic request processing consent',
    body: `Synthetic REQUEST_PROCESSING consent text ${randomUUID()}`,
    legalBasis: 'Synthetic legal basis',
    sourceRef: 'synthetic://files/consent',
    reviewedBy: fixture.reviewer,
  }));
  return { documentId: published.documentId, versionId: published.versionId, version: published.version };
}

/** Appends and publishes one newer CONSENT_FORM revision (stale-basis scenarios). */
export async function publishNextConsentForm(
  fixture: FileReservationsFixture,
  expectedVersion: number,
): Promise<{ documentId: string; versionId: string; version: number }> {
  const form = await ensureProcessingConsentForm(fixture);
  const published = await fixture.inTransaction((client) => publishLegalDocumentVersion(client, {
    documentId: form.documentId,
    expectedVersion,
    title: 'Synthetic request processing consent v2',
    body: `Synthetic REQUEST_PROCESSING consent text v2 ${randomUUID()}`,
    legalBasis: 'Synthetic legal basis',
    sourceRef: 'synthetic://files/consent',
    reviewedBy: fixture.reviewer,
  }));
  return { documentId: published.documentId, versionId: published.versionId, version: published.version };
}

/** A new anchor that already gave the *current* REQUEST_PROCESSING consent. */
export async function newConsentedAnchor(
  fixture: FileReservationsFixture,
  expiresAt?: Date,
): Promise<Anchor & { documentId: string; documentVersionId: string; evidenceId: string }> {
  const form = await ensureProcessingConsentForm(fixture);
  const anchor = await newAnchor(fixture, expiresAt);
  const given = await fixture.inTransaction((client) => recordConsentGiven(client, {
    session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: form.versionId,
    evidenceRef: randomUUID(), accepted: true,
  }));
  return { ...anchor, documentId: form.documentId, documentVersionId: form.versionId, evidenceId: given.evidenceId };
}

/** Withdraws exactly the GIVEN event that the anchor obtained. */
export async function revokeConsent(
  fixture: FileReservationsFixture,
  anchor: Anchor,
  evidenceId: string,
): Promise<void> {
  await fixture.inTransaction((client) => recordConsentRevoked(client, {
    session: proof(anchor), purpose: 'REQUEST_PROCESSING', evidenceRef: randomUUID(), supersedesEvidenceId: evidenceId,
  }));
}

/**
 * An anchor that becomes expired on the database clock: `expires_at > created_at`
 * is enforced at insert, so an already-expired row cannot be constructed; the
 * fixture creates a very short-lived anchor and waits past its expiry.
 */
export async function expiredAnchor(fixture: FileReservationsFixture): Promise<Anchor> {
  const anchor = await newAnchor(fixture, new Date(Date.now() + 1_200));
  await new Promise((resolve) => { setTimeout(resolve, 1_600); });
  return anchor;
}

export async function intentCount(fixture: FileReservationsFixture, sessionId?: string): Promise<number> {
  const result = sessionId === undefined
    ? await fixture.migrator.query<{ n: number }>('SELECT count(*)::int AS n FROM foundation.file_upload_intents')
    : await fixture.migrator.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM foundation.file_upload_intents WHERE owner_request_session_id=$1', [sessionId]);
  return result.rows[0]?.n ?? -1;
}

export async function auditOutboxCount(fixture: FileReservationsFixture): Promise<{ audit: number; outbox: number }> {
  const audit = await fixture.migrator.query<{ n: number }>('SELECT count(*)::int AS n FROM foundation.audit_logs');
  const outbox = await fixture.migrator.query<{ n: number }>('SELECT count(*)::int AS n FROM foundation.outbox_events');
  return { audit: audit.rows[0]?.n ?? -1, outbox: outbox.rows[0]?.n ?? -1 };
}

/**
 * Makes every audit INSERT fail for the duration of one test, so the suite can
 * prove that a failed audit rolls the reservation back. A temporary trigger is
 * created by the migration owner and always dropped again; no grant is touched.
 */
export async function installFailingAuditTrigger(fixture: FileReservationsFixture): Promise<void> {
  const client = await fixture.migrator.connect();
  try {
    await client.query(`CREATE FUNCTION foundation.file_reservations_test_fail_audit() RETURNS trigger
      LANGUAGE plpgsql SET search_path=pg_catalog AS $$
      BEGIN RAISE EXCEPTION 'synthetic audit failure' USING ERRCODE='23514'; END $$`);
    await client.query(`CREATE TRIGGER file_reservations_test_fail_audit BEFORE INSERT ON foundation.audit_logs
      FOR EACH ROW EXECUTE FUNCTION foundation.file_reservations_test_fail_audit()`);
  } finally {
    client.release();
  }
}

export async function removeFailingAuditTrigger(fixture: FileReservationsFixture): Promise<void> {
  const client = await fixture.migrator.connect();
  try {
    await client.query('DROP TRIGGER IF EXISTS file_reservations_test_fail_audit ON foundation.audit_logs');
    await client.query('DROP FUNCTION IF EXISTS foundation.file_reservations_test_fail_audit()');
  } finally {
    client.release();
  }
}
