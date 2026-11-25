/**
 * Integration proof of the P03-03 legal ports against a real PostgreSQL runtime.
 *
 * Opt-in (`FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1`): the fixture creates a fresh
 * throwaway database, applies the real migration chain as the migrator role and
 * then exercises the ports as `fixlevelup_runtime`, so the assertions cover the
 * actual grants, triggers and CHECKs rather than a test-side reimplementation.
 *
 * The purpose vocabulary is closed and `(purpose,kind)` is unique, so the suite
 * shares one document per pair and appends a new immutable revision where a test
 * needs new text. Tests in a file run sequentially, and each test uses its own
 * anchor, so evidence never leaks between cases.
 *
 * What is proved here, deliberately independent of the port's own JS checks where
 * the database is the authority:
 *
 * - publish is insert + CAS, and a stale expected version is refused;
 * - the database itself refuses a wrong body checksum;
 * - GIVEN requires exactly `true` acceptance (refused before SQL), a live anchor,
 *   a CONSENT_FORM document and the *current* version (stale text refused);
 * - purposes are separate; a POLICY is not a consent;
 * - revoke affects exactly one GIVEN event, a replay never resurrects it, and a
 *   re-GIVEN of the same or a newer text is a new event;
 * - wrong token, foreign session and expired/revoked anchors are refused;
 * - every write appends exactly one audit + outbox row in the caller transaction,
 *   with no legal text, PII or secret in the payload, and a rollback removes both;
 * - concurrent publishes and concurrent GIVEN replays serialize on the documented
 *   locks (anchor → document);
 * - every guarded call runs in an explicit READ COMMITTED transaction: a stronger
 *   session default is overridden, an unsnapshotted REPEATABLE READ transaction is
 *   switched before its first data read, and a transaction that already pinned a
 *   stale snapshot (two independent backends: A pins, B revokes and commits) fails
 *   closed with a typed `CONFLICT` instead of answering `GRANTED`; the same guard
 *   covers the GIVEN replay, the revoke and the trusted-proof routes;
 * - a revoke whose document-lock wait crosses the anchor expiry is refused by the
 *   post-lock clock check, with no consent, audit or outbox row left behind;
 * - a current grant or a consent replay refuses when its evidence read waits
 *   across expiry, without changing consent, audit or outbox state.
 */
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { LegalPortError } from '../src/settings/legal/legal-contract.js';
import type { LegalDocumentKind, LegalErrorCode, LegalPurpose, LegalSqlClient } from '../src/settings/legal/legal-contract.js';
import { trustedSessionProof } from '../src/settings/legal/legal-contract.js';
import {
  LEGAL_BEGIN_SQL, LEGAL_ISOLATION_SQL, beginLegalTransaction, createLegalDocument, createRequestSession,
  currentPurposeConsent, findLegalDocument, hashSessionSecret, listSessionConsent, publishLegalDocumentVersion,
  recordConsentGiven, recordConsentRevoked, revokeRequestSession, sha256Hex,
} from '../src/settings/legal/index.js';
import { legalIntegration, seedCity, startLegalDatabase } from './legal-fixture.js';
import type { FixtureCity, LegalFixtureDatabase } from './legal-fixture.js';

let db: LegalFixtureDatabase;
let city: FixtureCity;
let started = false;

beforeAll(async () => {
  db = await startLegalDatabase();
  city = await seedCity(db.migrator, db.staffId);
  started = true;
}, 120_000);

afterAll(async () => {
  // A failed `beforeAll` still runs `afterAll`; only a started fixture owns pools.
  if (started) {
    await db.close();
  }
});

const token = (): string => randomUUID().replace(/-/g, '') + randomUUID().slice(0, 8);

/** Runs one port call in its own caller transaction (explicit READ COMMITTED). */
async function tx<T>(run: (client: LegalSqlClient) => Promise<T>): Promise<T> {
  const client = await db.runtime.connect();
  try {
    await beginLegalTransaction(client);
    try {
      const result = await run(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  } finally {
    client.release();
  }
}

/** Runs one port call and expects a typed refusal. */
async function refusal<T>(run: (client: LegalSqlClient) => Promise<T>): Promise<LegalErrorCode> {
  try {
    await tx(run);
  } catch (error) {
    if (error instanceof LegalPortError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a LegalPortError');
}

/** The single stable document of one (purpose,kind) pair, created on first use. */
async function ensureDocument(purpose: LegalPurpose, kind: LegalDocumentKind): Promise<{ documentId: string; version: number }> {
  const existing = await tx((client) => findLegalDocument(client, purpose, kind));
  if (existing !== null) {
    // The read view names the identity `id`; normalise to the write-side field name.
    return { documentId: existing.id, version: existing.version };
  }
  const created = await tx((client) => createLegalDocument(client, { purpose, kind }));
  return { documentId: created.documentId, version: created.version };
}

/** Appends and publishes one immutable revision; returns the receipt (current version). */
async function publishNext(
  purpose: LegalPurpose, kind: LegalDocumentKind, body = `Synthetic ${kind} text for ${purpose} ${randomUUID()}`,
  legalBasis = 'Synthetic legal basis',
) {
  const document = await ensureDocument(purpose, kind);
  return tx((client) => publishLegalDocumentVersion(client, {
    documentId: document.documentId,
    expectedVersion: document.version,
    title: `Synthetic ${kind}`,
    body,
    legalBasis,
    sourceRef: 'synthetic-source',
    reviewedBy: db.staffId,
  }));
}

async function newAnchor(expiresAt = new Date(Date.now() + 3_600_000)): Promise<{ sessionId: string; token: string }> {
  const raw = token();
  const created = await tx((client) => createRequestSession(client, {
    secretHash: hashSessionSecret(raw),
    intakeCityId: city.cityId,
    intakeCityVersionId: city.cityVersionId,
    expiresAt,
  }));
  return { sessionId: created.sessionId, token: raw };
}

/**
 * An anchor that becomes expired on the database clock.
 *
 * `created_at` and `expires_at` are both immutable after insert (the 013 guard
 * refuses an UPDATE, and INSERT stamps `created_at` from the database clock), so an
 * already-expired row cannot be constructed: `expires_at > created_at` must hold at
 * insert. The fixture therefore creates a very short-lived anchor and waits past
 * its expiry, which is the same state a real abandoned form reaches.
 */
async function expiredAnchor(): Promise<{ sessionId: string; token: string }> {
  const anchor = await newAnchor(new Date(Date.now() + 1_200));
  await new Promise((resolve) => { setTimeout(resolve, 1_600); });
  return anchor;
}

function proof(anchor: { sessionId: string; token: string }) {
  return { sessionId: anchor.sessionId, token: anchor.token };
}

async function evidenceCount(sessionId: string): Promise<number> {
  const result = await db.migrator.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM foundation.consent_records WHERE session_id=$1', [sessionId]);
  return result.rows[0]?.n ?? -1;
}

async function auditOutboxCount(client: LegalSqlClient = db.migrator): Promise<{ audit: number; outbox: number }> {
  const audit = await client.query<{ n: number }>('SELECT count(*)::int AS n FROM foundation.audit_logs');
  const outbox = await client.query<{ n: number }>('SELECT count(*)::int AS n FROM foundation.outbox_events');
  return { audit: audit.rows[0]?.n ?? -1, outbox: outbox.rows[0]?.n ?? -1 };
}

async function consentState(client: LegalSqlClient, sessionId: string) {
  const evidence = await client.query(
    'SELECT * FROM foundation.consent_records WHERE session_id=$1 ORDER BY id', [sessionId]);
  return { evidence: evidence.rows, ...await auditOutboxCount(client) };
}

async function untilObserved<T>(observe: () => Promise<T | undefined>, description: string): Promise<T> {
  const deadline = performance.now() + 10_000;
  while (performance.now() < deadline) {
    const found = await observe();
    if (found !== undefined) {
      return found;
    }
    await delay(25);
  }
  throw new Error(`Did not observe ${description}`);
}

async function acrossEvidenceExpiry<T>(
  sessionId: string, queryFragment: string, act: (client: LegalSqlClient) => Promise<T>,
) {
  const blocker = await db.migrator.connect();
  try {
    await blocker.query('BEGIN');
    const blockerPid = (await blocker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
    expect(blockerPid).toBeDefined();
    await blocker.query('LOCK TABLE ONLY foundation.consent_records IN ACCESS EXCLUSIVE MODE');
    const caller = await db.runtime.connect();
    const name = `legal-expiry-${randomUUID()}`;
    try {
      await beginLegalTransaction(caller);
      await caller.query("SELECT set_config('application_name',$1,true)", [name]);
      await caller.query("SET LOCAL statement_timeout = '25s'");
      // Attach rejection handling now: the caller must not produce an unhandled
      // rejection if a regression refuses too early or the observation times out.
      const pending = act(caller).then(
        (value) => ({ value }),
        (error: unknown) => {
          if (error instanceof LegalPortError) {
            return { error: error.code };
          }
          return { unexpected: error };
        },
      );
      try {
        const waiting = await untilObserved(async () => {
          const observed = await db.runtime.query<{ query: string; live: boolean }>(
            `SELECT a.query, s.expires_at > clock_timestamp() AS live
             FROM pg_stat_activity a
             JOIN pg_locks l ON l.pid=a.pid AND l.relation='foundation.consent_records'::regclass
               AND l.locktype='relation' AND l.mode='AccessShareLock' AND NOT l.granted
             CROSS JOIN foundation.request_sessions s
             WHERE a.application_name=$1 AND a.datname=current_database()
               AND a.wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(a.pid)) AND s.id=$3`,
            [name, blockerPid, sessionId]);
          return observed.rows[0];
        }, 'the named caller waiting on the consent_records relation lock');
        expect(waiting.query).toContain(queryFragment);
        expect(waiting.live).toBe(true);
        // The unblock is driven by the persisted expiry on PostgreSQL's clock,
        // not a guessed elapsed delay after launching the port.
        await untilObserved(async () => {
          const clock = await blocker.query<{ expired: boolean }>(
            'SELECT expires_at <= clock_timestamp() AS expired FROM foundation.request_sessions WHERE id=$1', [sessionId]);
          return clock.rows[0]?.expired ? true : undefined;
        }, 'anchor expiry on the database clock');
      } finally {
        await blocker.query('ROLLBACK');
      }
      const outcome = await pending;
      return { outcome, inTransaction: await consentState(caller, sessionId) };
    } finally {
      try {
        await caller.query('ROLLBACK');
      } finally {
        caller.release();
      }
    }
  } finally {
    try {
      await blocker.query('ROLLBACK');
    } finally {
      blocker.release();
    }
  }
}

/**
 * Runs `act` on a client that already pinned a REPEATABLE READ snapshot, after
 * `commitElsewhere` committed a change that this snapshot cannot see.
 *
 * The pin query is a real read of consent evidence, i.e. exactly where a naive
 * implementation would take its decision. PostgreSQL then refuses the port's
 * `SET TRANSACTION ISOLATION LEVEL READ COMMITTED` with 25001, so the call must fail
 * closed; the caller transaction is aborted and rolled back by the helper.
 */
async function againstStaleSnapshot(
  commitElsewhere: () => Promise<void>,
  act: (client: PoolClient) => Promise<unknown>,
): Promise<LegalErrorCode | 'OK'> {
  const client = await db.runtime.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
    await client.query('SELECT count(*)::int AS n FROM foundation.consent_records');
    await commitElsewhere();
    try {
      await act(client);
      return 'OK';
    } catch (error) {
      if (error instanceof LegalPortError) {
        return error.code;
      }
      throw error;
    }
  } finally {
    try {
      await client.query('ROLLBACK');
    } catch {
      // The guard's 25001 already aborted the transaction; ROLLBACK still ends it.
    }
    client.release();
  }
}

legalIntegration('P03-03 legal documents and consent ports on real PostgreSQL runtime', () => {
  it('publishes immutable revisions with a CAS pointer and refuses a stale expected version', async () => {
    const document = await tx((client) => createLegalDocument(client, { purpose: 'MARKETING', kind: 'POLICY' }));
    expect(document.version).toBe(1);
    const body = 'Synthetic policy text v1';
    const v1 = await tx((client) => publishLegalDocumentVersion(client, {
      documentId: document.documentId,
      expectedVersion: document.version,
      title: 'Policy v1',
      body,
      legalBasis: 'Synthetic basis',
      sourceRef: 'synthetic',
      reviewedBy: db.staffId,
    }));
    expect(v1.sequence).toBe(1);
    expect(v1.checksum).toBe(sha256Hex(body));
    expect(v1.version).toBe(2);

    // The database re-computed the same digest from the stored body.
    const stored = await db.migrator.query<{ checksum: string; body: string }>(
      'SELECT checksum,body FROM foundation.legal_document_versions WHERE id=$1', [v1.versionId]);
    expect(stored.rows[0]?.checksum).toBe(sha256Hex(stored.rows[0]?.body ?? ''));
    expect(stored.rows[0]?.body).toBe(body);

    // A second publish with the *old* token must not be rebased onto the new state.
    expect(await refusal((client) => publishLegalDocumentVersion(client, {
      documentId: document.documentId,
      expectedVersion: document.version,
      title: 'Stale',
      body: 'Synthetic policy text v2',
      legalBasis: 'Synthetic basis',
      sourceRef: 'synthetic',
      reviewedBy: db.staffId,
    }))).toBe('STALE_VERSION');
    expect((await db.migrator.query('SELECT 1 FROM foundation.legal_document_versions WHERE document_id=$1',
      [document.documentId])).rowCount).toBe(1);

    // The same purpose may carry a POLICY and a CONSENT_FORM as separate documents.
    const form = await tx((client) => createLegalDocument(client, { purpose: 'MARKETING', kind: 'CONSENT_FORM' }));
    expect(form.documentId).not.toBe(document.documentId);
    // A duplicate (purpose,kind) is refused by the unique identity, not merged.
    expect(await refusal((client) => createLegalDocument(client, { purpose: 'MARKETING', kind: 'POLICY' })))
      .toBe('ALREADY_EXISTS');
  }, 60_000);

  it('refuses a wrong body checksum in the database, not only in TypeScript', async () => {
    const document = await ensureDocument('MARKETING', 'POLICY');
    // Deliberately bypasses the port and writes with direct SQL: the proof is that
    // the *database* CHECK rejects a body/checksum mismatch, so a caller that skips
    // the TypeScript digest still cannot persist text whose checksum does not match.
    const client: PoolClient = await db.runtime.connect();
    let sqlState: string | undefined;
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO foundation.legal_document_versions
           (id,document_id,purpose,kind,version,title,body,checksum,legal_basis,source_ref,reviewed_by)
         VALUES ($1,$2,'MARKETING','POLICY',99,'T','Synthetic body',$3,'Basis','source',$4)`,
        [randomUUID(), document.documentId, sha256Hex('a different body'), db.staffId],
      );
    } catch (error) {
      sqlState = (error as { code?: string }).code;
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
    // 23514 = check_violation, the named legal_document_versions_checksum_check.
    expect(sqlState).toBe('23514');
    expect((await db.migrator.query('SELECT 1 FROM foundation.legal_document_versions WHERE document_id=$1 AND version=99',
      [document.documentId])).rowCount).toBe(0);
  }, 60_000);

  it('records GIVEN only with exact true acceptance, a live anchor and the current CONSENT_FORM', async () => {
    const form = await publishNext('REQUEST_PROCESSING', 'CONSENT_FORM');
    const policy = await publishNext('REQUEST_PROCESSING', 'POLICY');
    const anchor = await newAnchor();

    // A POLICY acknowledgement is not a consent, even with a valid anchor.
    expect(await refusal((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentId: policy.documentId,
      documentVersionId: policy.versionId, evidenceRef: randomUUID(), accepted: true,
    }))).toBe('KIND_NOT_CONSENT_FORM');

    // `accepted` is strict: a string or a number never becomes an acceptance.
    for (const accepted of ['true', 1]) {
      expect(await refusal((client) => recordConsentGiven(client, {
        session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: form.versionId,
        evidenceRef: randomUUID(), accepted,
      }))).toBe('INVALID_INPUT');
    }
    expect(await evidenceCount(anchor.sessionId)).toBe(0);

    const evidenceRef = randomUUID();
    const given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: form.versionId,
      evidenceRef, accepted: true,
    }));
    expect(given.action).toBe('GIVEN');
    expect(given.documentVersionId).toBe(form.versionId);
    expect(given.replayed).toBe(false);
    expect(Number.isNaN(Date.parse(given.occurredAt))).toBe(false);

    const current = await tx((client) => currentPurposeConsent(client, {
      session: proof(anchor), purpose: 'REQUEST_PROCESSING',
    }));
    expect(current).toMatchObject({ granted: true, reason: 'GRANTED', documentVersionId: form.versionId });

    // An idempotent retry of the same event replays instead of duplicating.
    const replay = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: form.versionId,
      evidenceRef, accepted: true,
    }));
    expect(replay).toMatchObject({ evidenceId: given.evidenceId, replayed: true });
    expect(await evidenceCount(anchor.sessionId)).toBe(1);

    // Same evidence key, different accepted revision: a mismatch, not a silent upgrade.
    const newer = await publishNext('REQUEST_PROCESSING', 'CONSENT_FORM');
    expect(await refusal((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: newer.versionId,
      evidenceRef, accepted: true,
    }))).toBe('REPLAY_MISMATCH');

    // A stale text is refused explicitly: no silent upgrade to the current revision.
    expect(await refusal((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }))).toBe('DOCUMENT_NOT_CURRENT');
    // The old acceptance is no longer a valid consent for the current text.
    expect(await tx((client) => currentPurposeConsent(client, {
      session: proof(anchor), purpose: 'REQUEST_PROCESSING',
    }))).toMatchObject({ granted: false, reason: 'DOCUMENT_NOT_CURRENT' });
  }, 60_000);

  it('keeps purposes separate and reports a purpose with no consent form as not published', async () => {
    // This case runs before any ADDRESS_COVERAGE consent form exists in the suite.
    const anchor = await newAnchor();
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'ADDRESS_COVERAGE' })))
      .toMatchObject({ granted: false, reason: 'DOCUMENT_NOT_PUBLISHED' });
    // An OPT_IN_NOTICE is not a consent form either.
    const notice = await publishNext('ADDRESS_COVERAGE', 'OPT_IN_NOTICE');
    expect(await refusal((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'ADDRESS_COVERAGE', documentId: notice.documentId,
      documentVersionId: notice.versionId, evidenceRef: randomUUID(), accepted: true,
    }))).toBe('KIND_NOT_CONSENT_FORM');

    // One purpose never authorizes another; an optional purpose is simply not given.
    const processing = await publishNext('REQUEST_PROCESSING', 'CONSENT_FORM');
    await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: processing.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    const marketing = await publishNext('MARKETING', 'CONSENT_FORM');
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'MARKETING' })))
      .toMatchObject({ granted: false, reason: 'NOT_GIVEN' });
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'REQUEST_PROCESSING' })))
      .toMatchObject({ granted: true, documentVersionId: processing.versionId });

    // Accepting the other purpose is a separate event and does not widen the first.
    await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: marketing.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'MARKETING' })))
      .toMatchObject({ granted: true, documentVersionId: marketing.versionId });
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'REQUEST_PROCESSING' })))
      .toMatchObject({ granted: true, documentVersionId: processing.versionId });
    expect(await evidenceCount(anchor.sessionId)).toBe(2);
  }, 60_000);

  it('allows accepting the new current version without revoking the old acceptance', async () => {
    const form = await publishNext('ADDRESS_COVERAGE', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const v1Given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'ADDRESS_COVERAGE', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    const v2 = await publishNext('ADDRESS_COVERAGE', 'CONSENT_FORM');
    // The database scopes the duplicate-active-GIVEN rule to the exact version, so a
    // still-unrevoked GIVEN of the older text does not block the new acceptance.
    const v2Given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'ADDRESS_COVERAGE', documentVersionId: v2.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    expect(v2Given.evidenceId).not.toBe(v1Given.evidenceId);
    expect(await tx((client) => currentPurposeConsent(client, {
      session: proof(anchor), purpose: 'ADDRESS_COVERAGE',
    }))).toMatchObject({ granted: true, documentVersionId: v2.versionId });

    // A second active GIVEN of the *same* version is refused by the DB guard.
    expect(await refusal((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'ADDRESS_COVERAGE', documentVersionId: v2.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }))).toBe('CONSENT_ALREADY_ACTIVE');
  }, 60_000);

  it('revokes exactly one GIVEN event, never resurrects it on replay, and allows a later new acceptance', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const givenRef = randomUUID();
    const given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: givenRef, accepted: true,
    }));
    const revokeRef = randomUUID();
    const revoked = await tx((client) => recordConsentRevoked(client, {
      session: proof(anchor), purpose: 'MARKETING', evidenceRef: revokeRef, supersedesEvidenceId: given.evidenceId,
    }));
    expect(revoked).toMatchObject({ action: 'REVOKED', replayed: false });
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'MARKETING' })))
      .toMatchObject({ granted: false, reason: 'REVOKED' });

    // The revoke itself is idempotent.
    expect(await tx((client) => recordConsentRevoked(client, {
      session: proof(anchor), purpose: 'MARKETING', evidenceRef: revokeRef, supersedesEvidenceId: given.evidenceId,
    }))).toMatchObject({ evidenceId: revoked.evidenceId, replayed: true });

    // Replaying the original GIVEN must not resurrect the withdrawn consent.
    expect(await refusal((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: givenRef, accepted: true,
    }))).toBe('CONSENT_REVOKED');

    // A second revoke of the same event is refused (one revoke per GIVEN).
    expect(await refusal((client) => recordConsentRevoked(client, {
      session: proof(anchor), purpose: 'MARKETING', evidenceRef: randomUUID(), supersedesEvidenceId: given.evidenceId,
    }))).toBe('CONSENT_REVOKED');

    // History stays readable after the withdrawal — the person is entitled to see
    // what they accepted — while a wrong token is still refused.
    expect((await tx((client) => listSessionConsent(client, proof(anchor)))).map((event) => event.action))
      .toEqual(['GIVEN', 'REVOKED']);
    expect(await refusal((client) => listSessionConsent(client, { sessionId: anchor.sessionId, token: token() })))
      .toBe('NOT_FOUND');

    // A genuinely new acceptance of the same text is a new event and is granted again;
    // the old revoke does not affect it.
    const reGiven = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    expect(reGiven.evidenceId).not.toBe(given.evidenceId);
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'MARKETING' })))
      .toMatchObject({ granted: true, reason: 'GRANTED', evidenceId: reGiven.evidenceId });
    // History keeps both events plus the withdrawal.
    expect(await evidenceCount(anchor.sessionId)).toBe(3);
    const history = await tx((client) => listSessionConsent(client, proof(anchor)));
    expect(history.map((event) => event.action)).toEqual(['GIVEN', 'REVOKED', 'GIVEN']);
  }, 60_000);

  it('refuses a wrong token, a foreign session and an expired or revoked anchor', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const other = await newAnchor();

    // A wrong raw token is indistinguishable from a missing anchor.
    expect(await refusal((client) => recordConsentGiven(client, {
      session: { sessionId: anchor.sessionId, token: token() }, purpose: 'MARKETING',
      documentVersionId: form.versionId, evidenceRef: randomUUID(), accepted: true,
    }))).toBe('NOT_FOUND');
    // A browser-supplied id without a token is refused by the parser, not trusted.
    expect(await refusal((client) => recordConsentGiven(client, {
      session: { sessionId: anchor.sessionId }, purpose: 'MARKETING',
      documentVersionId: form.versionId, evidenceRef: randomUUID(), accepted: true,
    }))).toBe('INVALID_INPUT');

    // Evidence of another anchor cannot be revoked through this anchor.
    const given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    expect(await refusal((client) => recordConsentRevoked(client, {
      session: proof(other), purpose: 'MARKETING', evidenceRef: randomUUID(), supersedesEvidenceId: given.evidenceId,
    }))).toBe('NOT_FOUND');
    expect(await evidenceCount(other.sessionId)).toBe(0);

    // A revoked anchor refuses new evidence and reports the withdrawal to intake.
    await tx((client) => revokeRequestSession(client, proof(anchor)));
    expect(await refusal((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }))).toBe('SESSION_REVOKED');
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'MARKETING' })))
      .toMatchObject({ granted: false, reason: 'SESSION_REVOKED' });

    // An anchor whose expiry has passed on the database clock refuses evidence.
    const expired = await expiredAnchor();
    expect(await refusal((client) => recordConsentGiven(client, {
      session: proof(expired), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }))).toBe('SESSION_EXPIRED');
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(expired), purpose: 'MARKETING' })))
      .toMatchObject({ granted: false, reason: 'SESSION_EXPIRED' });
    expect(await evidenceCount(expired.sessionId)).toBe(0);
  }, 60_000);

  it('refuses to write outside an explicit caller transaction', async () => {
    const client: PoolClient = await db.runtime.connect();
    try {
      // Autocommit: each statement is its own implicit transaction, so the
      // transaction-local marker is gone before the probe can read it.
      await expect(createLegalDocument(client, { purpose: 'MARKETING', kind: 'OPT_IN_NOTICE' }))
        .rejects.toMatchObject({ code: 'CONFLICT' });
      expect((await db.migrator.query(
        "SELECT 1 FROM foundation.legal_documents WHERE purpose='MARKETING' AND kind='OPT_IN_NOTICE'")).rowCount).toBe(0);
    } finally {
      client.release();
    }
  }, 60_000);

  it('writes one safe audit and outbox row per event and rolls both back with the caller transaction', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    // Created before the baseline snapshot: anchor creation itself is an audited event.
    const rollbackAnchor = await newAnchor();
    const before = await auditOutboxCount();
    await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    const after = await auditOutboxCount();
    expect(after.audit - before.audit).toBe(1);
    expect(after.outbox - before.outbox).toBe(1);

    // No legal text, legal basis, raw token or secret hash may reach an event payload.
    // `audit_logs` stores the safe projection in `details`; `outbox_events` in `payload`.
    const audit = await db.migrator.query<{ details: string; operation: string }>(
      'SELECT details::text AS details,operation FROM foundation.audit_logs ORDER BY occurred_at DESC LIMIT 1');
    expect(audit.rows[0]?.operation).toBe('CONSENT_GIVEN');
    const outbox = await db.migrator.query<{ payload: string; event_type: string }>(
      'SELECT payload::text AS payload,event_type FROM foundation.outbox_events ORDER BY created_at DESC LIMIT 1');
    expect(outbox.rows[0]?.event_type).toBe('CONSENT_GIVEN');
    for (const event of [audit.rows[0]?.details ?? '', outbox.rows[0]?.payload ?? '']) {
      expect(event).not.toContain('Synthetic CONSENT_FORM text');
      expect(event).not.toContain('Synthetic legal basis');
      expect(event).not.toContain(anchor.token);
      expect(event).not.toContain(hashSessionSecret(anchor.token));
      // Only the documented identifier/scalar keys are present.
      const parsed = JSON.parse(event) as Record<string, unknown>;
      expect(Object.keys(parsed).sort()).toEqual(
        ['action', 'documentId', 'evidenceId', 'purpose', 'sessionId', 'source', 'versionId']);
    }

    // The publish audit names the reviewing staff member as the "who", and still
    // carries no legal text.
    const publishAudit = await db.migrator.query<{ details: string }>(
      `SELECT details::text AS details FROM foundation.audit_logs
       WHERE operation='LEGAL_DOCUMENT_VERSION_PUBLISHED' AND details->>'documentId'=$1
       ORDER BY occurred_at DESC LIMIT 1`, [form.documentId]);
    const publishDetails = JSON.parse(publishAudit.rows[0]?.details ?? '{}') as Record<string, unknown>;
    expect(publishDetails['reviewedBy']).toBe(db.staffId);
    expect(publishAudit.rows[0]?.details ?? '').not.toContain('Synthetic CONSENT_FORM text');

    // A failure after the domain write rolls the audit/outbox back with it: the
    // caller transaction is the atomic unit. A fresh anchor is used because the
    // previous GIVEN is already the active event for the first anchor.
    const failing = await db.runtime.connect();
    try {
      await failing.query('BEGIN');
      try {
        await recordConsentGiven(failing, {
          session: proof(rollbackAnchor), purpose: 'MARKETING', documentVersionId: form.versionId,
          evidenceRef: randomUUID(), accepted: true,
        });
      } finally {
        await failing.query('ROLLBACK');
      }
    } finally {
      failing.release();
    }
    expect(await auditOutboxCount()).toEqual(after);
    expect(await evidenceCount(anchor.sessionId)).toBe(1);
    expect(await evidenceCount(rollbackAnchor.sessionId)).toBe(0);
  }, 60_000);

  it('refuses a GIVEN whose document-lock wait crosses the anchor expiry', async () => {
    // A short-lived anchor: the port samples the database clock when it locks the
    // anchor, then blocks on the document row lock, and that wait crosses expiry.
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor(new Date(Date.now() + 1_500));

    // Hold the document row from another session so the port's `FOR UPDATE OF d`
    // really waits, and prove it is waiting on that backend rather than sleeping.
    const blocker = await db.runtime.connect();
    const giver = await db.runtime.connect();
    let outcome: string;
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT id FROM foundation.legal_documents WHERE id=$1 FOR UPDATE', [form.documentId]);
      const blockerPid = (await blocker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      if (!blockerPid) {
        throw new Error('Missing blocker backend pid');
      }

      await giver.query('BEGIN');
      // The giver's own backend id must be captured *before* it blocks: a statement
      // queued on the blocked client would never return.
      const giverPid = (await giver.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      if (!giverPid) {
        throw new Error('Missing giver backend pid');
      }
      const pending = recordConsentGiven(giver, {
        session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
        evidenceRef: randomUUID(), accepted: true,
      }).then(
        () => 'OK',
        (error: unknown) => error instanceof LegalPortError ? error.code : 'UNEXPECTED',
      );
      // Wait until the giver is actually blocked by the blocker on this database.
      const deadline = Date.now() + 5_000;
      let blocked = false;
      while (Date.now() < deadline) {
        const wait = await db.migrator.query<{ n: number }>(
          'SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid=$1 AND $2=ANY(pg_blocking_pids(pid))',
          [giverPid, blockerPid]);
        if ((wait.rows[0]?.n ?? 0) === 1) {
          blocked = true;
          break;
        }
        await new Promise((resolve) => { setTimeout(resolve, 25); });
      }
      expect(blocked).toBe(true);
      // Still blocked past the anchor expiry, then release the document lock.
      await new Promise((resolve) => { setTimeout(resolve, 1_700); });
      await blocker.query('ROLLBACK');
      outcome = await pending;
    } finally {
      try {
        await giver.query('ROLLBACK');
      } catch {
        // The port may already have rolled the transaction back; the pool client is
        // released either way.
      } finally {
        giver.release();
        blocker.release();
      }
    }
    // The port re-checked the database clock after acquiring the document lock, so
    // the event is refused instead of being written for an expired anchor.
    expect(outcome).toBe('SESSION_EXPIRED');
    expect(await evidenceCount(anchor.sessionId)).toBe(0);
  }, 60_000);

  it('serializes concurrent publishes and concurrent GIVEN replays on the documented locks', async () => {
    // Two publishers with the same expected token: one wins, one is STALE_VERSION.
    // The document is shared across the suite, so the new revision is identified by
    // a unique body prefix rather than by "the only version of this document".
    const document = await ensureDocument('MARKETING', 'POLICY');
    const marker = `Concurrent body ${randomUUID()}`;
    const publish = (client: LegalSqlClient) => publishLegalDocumentVersion(client, {
      documentId: document.documentId,
      expectedVersion: document.version,
      title: 'Concurrent',
      body: marker,
      legalBasis: 'Basis',
      sourceRef: 'source',
      reviewedBy: db.staffId,
    });
    // Each call resolves to its own outcome code, so the assertion never inspects a
    // rejected promise's `any` value.
    const attempt = (): Promise<string> => tx(publish).then(
      () => 'OK',
      (error: unknown) => error instanceof LegalPortError ? error.code : 'UNEXPECTED',
    );
    const codes = await Promise.all([attempt(), attempt()]);
    expect(codes.filter((code) => code === 'OK')).toHaveLength(1);
    expect(codes.filter((code) => code === 'STALE_VERSION')).toHaveLength(1);
    // Exactly one revision of the concurrent body exists: the loser did not insert.
    expect((await db.migrator.query(
      'SELECT 1 FROM foundation.legal_document_versions WHERE document_id=$1 AND body=$2',
      [document.documentId, marker])).rowCount).toBe(1);
    // The winner moved the pointer exactly once.
    const pointer = await db.migrator.query<{ row_version: number; current_version_id: string }>(
      'SELECT row_version,current_version_id FROM foundation.legal_documents WHERE id=$1', [document.documentId]);
    expect(pointer.rows[0]?.row_version).toBe(document.version + 1);

    // Two concurrent retries of one GIVEN event: the anchor lock serializes them, so
    // exactly one row exists and the other call is reported as a replay.
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const evidenceRef = randomUUID();
    const give = (client: LegalSqlClient) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef, accepted: true,
    });
    const [first, second] = await Promise.all([tx(give), tx(give)]);
    expect(await evidenceCount(anchor.sessionId)).toBe(1);
    expect(first.evidenceId).toBe(second.evidenceId);
    expect([first.replayed, second.replayed].filter(Boolean)).toHaveLength(1);
  }, 60_000);

  it('fails closed on a stale REPEATABLE READ snapshot instead of reporting a revoked consent as GRANTED', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    // Baseline: before any revoke exists the port answers GRANTED on a current
    // READ COMMITTED transaction, so the later failure is about isolation only.
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'MARKETING' })))
      .toMatchObject({ granted: true, reason: 'GRANTED', evidenceId: given.evidenceId });

    // A is an independent backend that pins a REPEATABLE READ snapshot on real
    // consent evidence *before* B commits the revoke.
    const stale = await db.runtime.connect();
    const writer = await db.runtime.connect();
    try {
      await stale.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
      // The snapshot is pinned by reading the evidence that a decision depends on:
      // A sees no REVOKED event for the GIVEN yet (it does not exist).
      const pinned = await stale.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM foundation.consent_records
         WHERE supersedes_id=$1 AND action='REVOKED'`, [given.evidenceId]);
      expect(pinned.rows[0]?.n).toBe(0);
      // Two distinct backends, so the proof is not an artifact of one connection.
      const stalePid = (await stale.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      const writerPid = (await writer.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      expect(stalePid).toBeDefined();
      expect(writerPid).toBeDefined();
      expect(stalePid).not.toBe(writerPid);

      // B records and commits the REVOKED event while A's snapshot stays pinned.
      await beginLegalTransaction(writer);
      await recordConsentRevoked(writer, {
        session: proof(anchor), purpose: 'MARKETING', evidenceRef: randomUUID(), supersedesEvidenceId: given.evidenceId,
      });
      await writer.query('COMMIT');

      // The revoke is committed and visible to a fresh READ COMMITTED reader, while
      // A's pinned snapshot still reports zero REVOKED events: the snapshot is
      // provably stale, and deciding on it would answer GRANTED.
      const committed = await db.migrator.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM foundation.consent_records
         WHERE supersedes_id=$1 AND action='REVOKED'`, [given.evidenceId]);
      expect(committed.rows[0]?.n).toBe(1);
      const staleRevokes = await stale.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM foundation.consent_records
         WHERE supersedes_id=$1 AND action='REVOKED'`, [given.evidenceId]);
      expect(staleRevokes.rows[0]?.n).toBe(0);

      // The port must refuse to decide on that snapshot. The guard's 25001 becomes a
      // typed CONFLICT; the outcome is never GRANTED.
      const answer = await currentPurposeConsent(stale, { session: proof(anchor), purpose: 'MARKETING' }).then(
        (result) => result.reason,
        (error: unknown) => error instanceof LegalPortError ? error.code : 'UNEXPECTED');
      expect(answer).toBe('CONFLICT');
    } finally {
      try {
        await stale.query('ROLLBACK');
      } catch {
        // The guard's 25001 already aborted A's transaction; ROLLBACK still ends it.
      } finally {
        stale.release();
        writer.release();
      }
    }

    // A correct READ COMMITTED decision sees the committed revoke (not a generic
    // failure): the typed answer is REVOKED for the exact withdrawn event.
    expect(await tx((client) => currentPurposeConsent(client, { session: proof(anchor), purpose: 'MARKETING' })))
      .toMatchObject({ granted: false, reason: 'REVOKED', evidenceId: given.evidenceId });
  }, 60_000);

  it('refuses stale-snapshot replay, revoke and trusted-proof routes instead of trusting old state', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');

    // Route 1: replaying the original GIVEN from a stale snapshot must not be
    // accepted as a replay after the revoke committed.
    const replayAnchor = await newAnchor();
    const givenRef = randomUUID();
    const replayGiven = await tx((client) => recordConsentGiven(client, {
      session: proof(replayAnchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: givenRef, accepted: true,
    }));
    expect(await againstStaleSnapshot(
      async () => {
        await tx((client) => recordConsentRevoked(client, {
          session: proof(replayAnchor), purpose: 'MARKETING', evidenceRef: randomUUID(),
          supersedesEvidenceId: replayGiven.evidenceId,
        }));
      },
      (client) => recordConsentGiven(client, {
        session: proof(replayAnchor), purpose: 'MARKETING', documentVersionId: form.versionId,
        evidenceRef: givenRef, accepted: true,
      }),
    )).toBe('CONFLICT');

    // Route 2: a stale snapshot must not decide a revoke either.
    const revokeAnchor = await newAnchor();
    const revokeGiven = await tx((client) => recordConsentGiven(client, {
      session: proof(revokeAnchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    expect(await againstStaleSnapshot(
      async () => {
        await tx((client) => recordConsentRevoked(client, {
          session: proof(revokeAnchor), purpose: 'MARKETING', evidenceRef: randomUUID(),
          supersedesEvidenceId: revokeGiven.evidenceId,
        }));
      },
      (client) => recordConsentRevoked(client, {
        session: proof(revokeAnchor), purpose: 'MARKETING', evidenceRef: randomUUID(),
        supersedesEvidenceId: revokeGiven.evidenceId,
      }),
    )).toBe('CONFLICT');

    // Route 3: the trusted-server proof path is guarded exactly like a raw token.
    const trustedAnchor = await newAnchor();
    const trustedGiven = await tx((client) => recordConsentGiven(client, {
      session: proof(trustedAnchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    expect(await againstStaleSnapshot(
      async () => {
        await tx((client) => recordConsentRevoked(client, {
          session: proof(trustedAnchor), purpose: 'MARKETING', evidenceRef: randomUUID(),
          supersedesEvidenceId: trustedGiven.evidenceId,
        }));
      },
      (client) => currentPurposeConsent(client, {
        session: trustedSessionProof(trustedAnchor.sessionId), purpose: 'MARKETING',
      }),
    )).toBe('CONFLICT');

    // No route wrote evidence from the stale snapshot: each anchor has exactly the
    // original GIVEN plus the revoke committed by the fresh transaction.
    for (const sessionId of [replayAnchor.sessionId, revokeAnchor.sessionId, trustedAnchor.sessionId]) {
      expect(await evidenceCount(sessionId)).toBe(2);
    }
  }, 60_000);

  it('switches an unsnapshotted REPEATABLE READ transaction to READ COMMITTED before the first data read', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    await tx((client) => recordConsentRevoked(client, {
      session: proof(anchor), purpose: 'MARKETING', evidenceRef: randomUUID(), supersedesEvidenceId: given.evidenceId,
    }));

    const client = await db.runtime.connect();
    const statements: string[] = [];
    try {
      const recorder = {
        query: (text: string, values?: unknown[]) => {
          statements.push(text);
          return client.query(text, values);
        },
      } as unknown as LegalSqlClient;
      // A caller opened a stronger level but has not read anything yet, so no
      // snapshot is pinned and PostgreSQL still allows the explicit switch. The
      // guard must make that switch before its first data read.
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
      expect(await currentPurposeConsent(recorder, { session: proof(anchor), purpose: 'MARKETING' }))
        .toMatchObject({ granted: false, reason: 'REVOKED', evidenceId: given.evidenceId });
      // The level actually in force, read from the server rather than assumed.
      const isolation = await client.query<{ transaction_isolation: string }>('SHOW transaction_isolation');
      expect(isolation.rows[0]?.transaction_isolation).toBe('read committed');
      // Guard order: the explicit isolation SET precedes every data statement.
      expect(statements[0]).toBe(LEGAL_ISOLATION_SQL);
      const firstData = statements.findIndex((text) => text.includes('foundation.'));
      expect(firstData).toBeGreaterThan(0);
      expect(statements.slice(0, firstData).some((text) => text.includes('fixlevelup.legal_tx'))).toBe(true);
    } finally {
      try {
        await client.query('ROLLBACK');
      } catch {
        // The transaction may already be aborted; the client is released either way.
      }
      client.release();
    }
  }, 60_000);

  it('opens an explicit READ COMMITTED transaction before any data statement when using the helper', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    await tx((client) => recordConsentRevoked(client, {
      session: proof(anchor), purpose: 'MARKETING', evidenceRef: randomUUID(), supersedesEvidenceId: given.evidenceId,
    }));

    const client = await db.runtime.connect();
    const statements: string[] = [];
    try {
      const recorder = {
        query: (text: string, values?: unknown[]) => {
          statements.push(text);
          return client.query(text, values);
        },
      } as unknown as LegalSqlClient;
      await beginLegalTransaction(recorder);
      expect(await currentPurposeConsent(recorder, { session: proof(anchor), purpose: 'MARKETING' }))
        .toMatchObject({ granted: false, reason: 'REVOKED', evidenceId: given.evidenceId });
      // BEGIN ... READ COMMITTED first, then the guard's SET, then the marker, then data.
      expect(statements[0]).toBe(LEGAL_BEGIN_SQL);
      expect(statements[1]).toBe(LEGAL_ISOLATION_SQL);
      const firstData = statements.findIndex((text) => text.includes('foundation.'));
      expect(firstData).toBeGreaterThan(1);
      expect(statements.slice(0, firstData).some((text) => text.includes('fixlevelup.legal_tx'))).toBe(true);
    } finally {
      try {
        await client.query('ROLLBACK');
      } catch {
        // The transaction may already be aborted; the client is released either way.
      }
      client.release();
    }
  }, 60_000);

  it('overrides a stronger session default with an explicit READ COMMITTED begin', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    await tx((client) => recordConsentRevoked(client, {
      session: proof(anchor), purpose: 'MARKETING', evidenceRef: randomUUID(), supersedesEvidenceId: given.evidenceId,
    }));

    const client = await db.runtime.connect();
    try {
      // A caller that relies on the session default would otherwise pin a snapshot.
      await client.query("SET SESSION default_transaction_isolation = 'repeatable read'");
      const sessionDefault = await client.query<{ default_transaction_isolation: string }>(
        'SHOW default_transaction_isolation');
      expect(sessionDefault.rows[0]?.default_transaction_isolation).toBe('repeatable read');

      await beginLegalTransaction(client);
      expect(await currentPurposeConsent(client, { session: proof(anchor), purpose: 'MARKETING' }))
        .toMatchObject({ granted: false, reason: 'REVOKED', evidenceId: given.evidenceId });
      const isolation = await client.query<{ transaction_isolation: string }>('SHOW transaction_isolation');
      expect(isolation.rows[0]?.transaction_isolation).toBe('read committed');
      await client.query('ROLLBACK');
    } finally {
      try {
        await client.query('RESET default_transaction_isolation');
      } catch {
        // The connection is discarded by the pool anyway.
      }
      client.release();
    }
  }, 60_000);

  it('keeps a legacy explicit READ COMMITTED transaction with an earlier read safe', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    await tx((client) => recordConsentRevoked(client, {
      session: proof(anchor), purpose: 'MARKETING', evidenceRef: randomUUID(), supersedesEvidenceId: given.evidenceId,
    }));

    const client = await db.runtime.connect();
    try {
      // A legacy caller that opened READ COMMITTED explicitly (never relying on a
      // session default) and read before calling the port: re-setting the same level
      // is allowed, so the port still decides on current evidence.
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await client.query('SELECT 1 AS earlier_read');
      expect(await currentPurposeConsent(client, { session: proof(anchor), purpose: 'MARKETING' }))
        .toMatchObject({ granted: false, reason: 'REVOKED', evidenceId: given.evidenceId });
      await client.query('COMMIT');
    } finally {
      client.release();
    }
  }, 60_000);

  it('refuses a revoke whose document-lock wait crosses the anchor expiry without partial rows', async () => {
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor(new Date(Date.now() + 1_500));
    const given = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    // Baseline after the GIVEN commit: the failed revoke must add no audit/outbox row.
    const baseline = await auditOutboxCount();

    const blocker = await db.runtime.connect();
    const revoker = await db.runtime.connect();
    const observed = await (async (): Promise<{
      outcome: string;
      inTransaction: { consent: number; audit: number; outbox: number };
    }> => {
      try {
        await blocker.query('BEGIN');
        await blocker.query('SELECT id FROM foundation.legal_documents WHERE id=$1 FOR UPDATE', [given.documentId]);
        const blockerPid = (await blocker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
        if (!blockerPid) {
          throw new Error('Missing blocker backend pid');
        }

        await beginLegalTransaction(revoker);
        // Capture the revoker's backend id before it blocks on the document lock.
        const revokerPid = (await revoker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
        if (!revokerPid) {
          throw new Error('Missing revoker backend pid');
        }
        const pending = recordConsentRevoked(revoker, {
          session: proof(anchor), purpose: 'MARKETING', evidenceRef: randomUUID(), supersedesEvidenceId: given.evidenceId,
        }).then(
          () => 'OK',
          (error: unknown) => error instanceof LegalPortError ? error.code : 'UNEXPECTED',
        );
        const deadline = Date.now() + 5_000;
        let blocked = false;
        while (Date.now() < deadline) {
          const wait = await db.migrator.query<{ n: number }>(
            'SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid=$1 AND $2=ANY(pg_blocking_pids(pid))',
            [revokerPid, blockerPid]);
          if ((wait.rows[0]?.n ?? 0) === 1) {
            blocked = true;
            break;
          }
          await new Promise((resolve) => { setTimeout(resolve, 25); });
        }
        expect(blocked).toBe(true);
        // The anchor was still live when the revoke reached the document lock; only the
        // wait crosses the expiry, so the post-lock re-check is what refuses it.
        const live = await db.migrator.query<{ live: boolean }>(
          'SELECT expires_at > clock_timestamp() AS live FROM foundation.request_sessions WHERE id=$1',
          [anchor.sessionId]);
        expect(live.rows[0]?.live).toBe(true);

        await new Promise((resolve) => { setTimeout(resolve, 1_700); });
        await blocker.query('ROLLBACK');
        const outcome = await pending;
        // Inspect the *same* transaction after the refusal but before ROLLBACK: a
        // rollback at the end would mask a partial write, so the counts must already be
        // clean while the failed transaction is still open.
        const consent = await revoker.query<{ n: number }>(
          'SELECT count(*)::int AS n FROM foundation.consent_records WHERE session_id=$1', [anchor.sessionId]);
        const audit = await revoker.query<{ n: number }>('SELECT count(*)::int AS n FROM foundation.audit_logs');
        const outbox = await revoker.query<{ n: number }>('SELECT count(*)::int AS n FROM foundation.outbox_events');
        return {
          outcome,
          inTransaction: {
            consent: consent.rows[0]?.n ?? -1,
            audit: audit.rows[0]?.n ?? -1,
            outbox: outbox.rows[0]?.n ?? -1,
          },
        };
      } finally {
        try {
          await revoker.query('ROLLBACK');
        } catch {
          // The port already refused; the client is released either way.
        } finally {
          revoker.release();
          blocker.release();
        }
      }
    })();
    // The post-lock clock check refuses the revoke: a dead anchor cannot withdraw.
    expect(observed.outcome).toBe('SESSION_EXPIRED');
    // No partial state inside the failed transaction itself, before any rollback.
    expect(observed.inTransaction).toEqual({ consent: 1, audit: baseline.audit, outbox: baseline.outbox });
    // And nothing was persisted after the rollback either: no new consent, audit or
    // outbox row, and the original GIVEN is unchanged with no REVOKED event naming it.
    expect(await evidenceCount(anchor.sessionId)).toBe(1);
    expect(await auditOutboxCount()).toEqual(baseline);
    const revokes = await db.migrator.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM foundation.consent_records WHERE supersedes_id=$1', [given.evidenceId]);
    expect(revokes.rows[0]?.n).toBe(0);
    const original = await db.migrator.query<{ action: string; supersedes_id: string | null }>(
      'SELECT action,supersedes_id FROM foundation.consent_records WHERE id=$1', [given.evidenceId]);
    expect(original.rows[0]).toMatchObject({ action: 'GIVEN', supersedes_id: null });
  }, 60_000);

  it('locks exactly one document row and reads the current revision only after that lock', async () => {
    // MUST 2 regression: the document lock is a single-table `FOR UPDATE` on one
    // `legal_documents` row, and `current_version_id`/`legal_basis` are read in a
    // *separate* statement issued after the lock. Proof by outcome: a publish is
    // queued on the same row *ahead* of the GIVEN, so it commits during the GIVEN's
    // lock wait and moves the pointer. If the revision were read before the wait
    // (joined into the locking statement), the GIVEN would accept the old text;
    // reading after the lock must refuse it as DOCUMENT_NOT_CURRENT.
    const form = await publishNext('MARKETING', 'CONSENT_FORM');
    const anchor = await newAnchor();
    const blocker = await db.runtime.connect();
    const publisher = await db.runtime.connect();
    const giver = await db.runtime.connect();
    let published: string;
    let given: string;
    try {
      // 1. A third session holds the document row, so both waiters below block.
      await blocker.query('BEGIN');
      await blocker.query('SELECT id FROM foundation.legal_documents WHERE id=$1 FOR UPDATE', [form.documentId]);
      const blockerPid = (await blocker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      if (!blockerPid) {
        throw new Error('Missing blocker backend pid');
      }

      // 2. The publish joins the lock queue FIRST: PostgreSQL grants the row lock
      //    in queue order, so the pointer moves before the GIVEN is let through.
      await beginLegalTransaction(publisher);
      const publisherPid = (await publisher.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      if (!publisherPid) {
        throw new Error('Missing publisher backend pid');
      }
      const publishedOutcome = publishLegalDocumentVersion(publisher, {
        documentId: form.documentId,
        expectedVersion: form.version,
        title: 'Concurrent republish during the document-lock wait',
        body: `Republished during lock wait ${randomUUID()}`,
        legalBasis: 'Synthetic republished basis',
        sourceRef: 'synthetic-source',
        reviewedBy: db.staffId,
      }).then(
        () => 'OK',
        (error: unknown) => error instanceof LegalPortError ? error.code : 'UNEXPECTED',
      );

      // 3. The GIVEN joins the same queue SECOND and names the OLD revision.
      await beginLegalTransaction(giver);
      const giverPid = (await giver.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      if (!giverPid) {
        throw new Error('Missing giver backend pid');
      }
      const givenOutcome = recordConsentGiven(giver, {
        session: proof(anchor), purpose: 'MARKETING', documentVersionId: form.versionId,
        evidenceRef: randomUUID(), accepted: true,
      }).then(
        () => 'OK',
        (error: unknown) => error instanceof LegalPortError ? error.code : 'UNEXPECTED',
      );

      // 4. Both waiters must really be blocked (not sleeping): the publisher is
      //    blocked by the blocker, the GIVEN is queued behind the publisher.
      const blockersOf = async (pid: number): Promise<number[]> => {
        const wait = await db.migrator.query<{ pids: number[] }>('SELECT pg_blocking_pids($1) AS pids', [pid]);
        return wait.rows[0]?.pids ?? [];
      };
      const deadline = Date.now() + 5_000;
      let queued = false;
      while (Date.now() < deadline) {
        if ((await blockersOf(publisherPid)).includes(blockerPid) && (await blockersOf(giverPid)).length > 0) {
          queued = true;
          break;
        }
        await delay(25);
      }
      expect(queued).toBe(true);

      // The document lock is a single-row `FOR UPDATE` on `legal_documents` only:
      // the waiting GIVEN queues one tuple lock on that table and none on the
      // immutable revision table (a joined locking read would queue there too).
      const queuedLocks = await db.migrator.query<{ table: string }>(
        `SELECT c.relname AS table FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
         WHERE l.pid=$1 AND l.locktype='tuple'`, [giverPid]);
      expect(queuedLocks.rows.filter((row) => row.table === 'legal_documents')).toHaveLength(1);
      expect(queuedLocks.rows.filter((row) => row.table === 'legal_document_versions')).toHaveLength(0);

      // 5. Release the blocker. The publisher finishes its statements while still
      //    holding the row lock, then COMMITs and releases it; only then can the
      //    GIVEN acquire the lock and read the document state.
      await blocker.query('ROLLBACK');
      published = await publishedOutcome;
      await publisher.query('COMMIT');
      given = await givenOutcome;
    } finally {
      // Every connection is rolled back before release: a client returned to the
      // pool with an open transaction would keep its row locks and stall the suite.
      for (const client of [giver, publisher, blocker]) {
        try {
          await client.query('ROLLBACK');
        } catch {
          // The transaction may already be committed or rolled back.
        }
      }
      giver.release();
      publisher.release();
      blocker.release();
    }

    // The publish won the wait and moved the pointer.
    expect(published).toBe('OK');
    // The GIVEN naming the superseded revision is refused after the lock, so the
    // revision/legal-basis read provably happened *after* the wait.
    expect(given).toBe('DOCUMENT_NOT_CURRENT');
    expect(await evidenceCount(anchor.sessionId)).toBe(0);
    // The stored revision is the publisher's, and the old one is no longer current.
    const pointer = await db.migrator.query<{ current_version_id: string }>(
      'SELECT current_version_id FROM foundation.legal_documents WHERE id=$1', [form.documentId]);
    expect(pointer.rows[0]?.current_version_id).not.toBe(form.versionId);
  }, 60_000);

  it.each(['current GRANTED', 'GIVEN replay', 'REVOKED replay'] as const)(
    'refuses %s when the evidence SELECT waits across anchor expiry',
    async (path) => {
      const form = await publishNext('MARKETING', 'CONSENT_FORM');
      const expiry = await db.migrator.query<{ at: Date }>("SELECT clock_timestamp() + interval '3 seconds' AS at");
      const expiresAt = expiry.rows[0]?.at;
      if (!expiresAt) {
        throw new Error('Missing fixture database clock');
      }
      const anchor = await newAnchor(expiresAt);
      const scope = { session: proof(anchor), purpose: 'MARKETING' };
      const give = {
        ...scope, documentVersionId: form.versionId, evidenceRef: randomUUID(), accepted: true,
      };
      const given = await tx((client) => recordConsentGiven(client, give));
      const revoke = { ...scope, evidenceRef: randomUUID(), supersedesEvidenceId: given.evidenceId };
      if (path === 'REVOKED replay') {
        await tx((client) => recordConsentRevoked(client, revoke));
      }
      const before = await consentState(db.migrator, anchor.sessionId);
      expect(before.evidence).toHaveLength(path === 'REVOKED replay' ? 2 : 1);
      if (path === 'current GRANTED') {
        const { outcome, inTransaction } = await acrossEvidenceExpiry(anchor.sessionId, 'c.action=\'GIVEN\'',
          (client) => currentPurposeConsent(client, scope));
        expect(inTransaction).toEqual(before);
        expect(outcome).toEqual({ value: {
          granted: false, reason: 'SESSION_EXPIRED', documentId: null, documentVersionId: null,
          evidenceId: null, occurredAt: null,
        } });
      } else {
        const { outcome, inTransaction } = await acrossEvidenceExpiry(anchor.sessionId, 'evidence_ref=$2',
          (client) => path === 'GIVEN replay' ? recordConsentGiven(client, give) : recordConsentRevoked(client, revoke));
        expect(inTransaction).toEqual(before);
        expect(outcome).toEqual({ error: 'SESSION_EXPIRED' });
      }
      expect(await consentState(db.migrator, anchor.sessionId)).toEqual(before);
    }, 60_000,
  );
});
