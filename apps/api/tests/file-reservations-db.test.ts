/**
 * Real-PostgreSQL integration proof of the P03-04A file reservation ports.
 *
 * Opt-in only (`FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1`). The fixture creates a
 * fresh throwaway database (`fixlevelup_legal_test_<24 random hex>`), applies the
 * real migration chain as the migrator role and then exercises the ports as the
 * real `fixlevelup_runtime` role, so the assertions cover the actual grants,
 * triggers and CHECKs instead of a test-side reimplementation. No mock, no fake
 * adapter and no production source is touched by this file.
 *
 * What is proved, independently of the port's own TypeScript checks where the
 * database is the authority:
 *
 * - a guarded call only runs in an explicit caller-owned READ COMMITTED
 *   transaction (the legal `beginLegalTransaction` helper), never autocommit;
 * - a missing/empty policy is refused with `NOT_CONFIGURED` before any intent,
 *   audit or outbox row exists — proved on an autocommit client, i.e. before the
 *   transaction guard could even reach the database;
 * - a reservation writes exactly one intent, one audit row and one outbox row in
 *   the caller transaction; the DTO carries no token, secret hash, object key,
 *   URL or legal text; the state vocabulary is only RESERVED/CANCELLED and the
 *   runtime role cannot set READY or delete the row;
 * - an identical replay returns the same intent, consumes no second quota slot and
 *   writes no second audit/outbox pair; a changed payload under the same key is an
 *   `IDEMPOTENCY_CONFLICT`;
 * - wrong token, missing token, foreign owner, staff owner, no consent, expired
 *   anchor, revoked anchor, revoked consent and a stale current document are typed
 *   refusals that leave no rows behind;
 * - the intent is bound to the exact GIVEN evidence that reserved it: GIVEN →
 *   REVOKED → new GIVEN never revives or re-binds the old intent;
 * - the last quota slot and the last quota bytes are each taken by exactly one of
 *   two concurrent backends, with the loser observed *waiting* on the winner's
 *   session row lock (not just a `Promise.all` race), and the loser refused with
 *   `QUOTA_EXCEEDED`;
 * - quota is computed on the database clock: an expired reservation frees its slot;
 * - the clock is re-checked *after* the last lock wait: a read blocked on the
 *   intent row while the reservation expires is refused with `INTENT_EXPIRED`;
 * - cancel is a one-way CAS (`STALE_VERSION` on a stale token), an idempotent
 *   replay on the current version, requires no new consent, and releases quota;
 * - the same policy version id with a different snapshot for one owner is a
 *   `POLICY_VERSION_CONFLICT`;
 * - a failing audit insert rolls the intent, audit and outbox rows back together.
 *
 * Deliberately absent: any byte IO, S3 adapter, scanner, READY/access port or
 * HTTP surface. Slice A is reservation only (see docs/P03-04-PLAN.md).
 */
import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, expect, it } from 'vitest';
import * as reservations from '../src/files/reservations/index.js';
import {
  FILE_INTENT_STATES, FileReservationError, cancelFileUploadIntent, fileIntentBodySha256, filePolicySha256,
  readFileUploadIntent, reserveFileUpload,
} from '../src/files/reservations/index.js';
import type {
  FileReservationErrorCode, FileReservationPolicy, FileReservationSqlClient, FileUploadReservation,
} from '../src/files/reservations/index.js';
import {
  beginLegalTransaction, hashSessionSecret, recordConsentGiven, revokeRequestSession,
} from '../src/settings/legal/index.js';
import {
  auditOutboxCount, ensureProcessingConsentForm, fileReservationsIntegration,
  installFailingAuditTrigger, intentCount, newAnchor, newConsentedAnchor, proof, publishNextConsentForm,
  removeFailingAuditTrigger, revokeConsent, startFileReservationsDatabase, token,
} from './file-reservations-fixture.js';
import type { Anchor, FileReservationsFixture } from './file-reservations-fixture.js';

let db: FileReservationsFixture;
let started = false;

beforeAll(async () => {
  db = await startFileReservationsDatabase();
  started = true;
}, 180_000);

afterAll(async () => {
  // A failed `beforeAll` still runs `afterAll`; only a started fixture owns pools.
  if (started) {
    await db.close();
  }
});

const MIME = 'image/jpeg' as const;

/** One synthetic trusted policy snapshot; every numeric value is a test fixture. */
function policy(overrides: Partial<FileReservationPolicy> = {}): FileReservationPolicy {
  return {
    versionId: overrides.versionId ?? randomUUID(),
    sourceRef: overrides.sourceRef ?? 'synthetic://upload-policy/2026-11-21',
    allowedMimeTypes: overrides.allowedMimeTypes ?? [MIME],
    maxFileBytes: overrides.maxFileBytes ?? 400,
    maxOwnerBytes: overrides.maxOwnerBytes ?? 1_000,
    maxOwnerFiles: overrides.maxOwnerFiles ?? 3,
    expiresAt: overrides.expiresAt ?? new Date(Date.now() + 3_600_000),
  };
}

interface ReserveOptions {
  readonly policy?: FileReservationPolicy;
  readonly mime?: string;
  readonly bytes?: number;
  readonly expiresAt?: Date;
  readonly idempotencyKey?: string;
}

/** A syntactically valid reserve input; the port re-validates every field. */
function reserveInput(anchor: Anchor, options: ReserveOptions = {}): Record<string, unknown> {
  return {
    session: proof(anchor),
    policy: options.policy ?? policy(),
    declaredMime: options.mime ?? MIME,
    declaredBytes: options.bytes ?? 100,
    expiresAt: options.expiresAt ?? new Date(Date.now() + 600_000),
    idempotencyKey: options.idempotencyKey ?? randomUUID(),
  };
}

/** Runs one port call in its own explicit READ COMMITTED caller transaction. */
async function tx<T>(run: (client: FileReservationSqlClient) => Promise<T>): Promise<T> {
  return db.inTransaction((client) => run(client));
}

/** Runs one port call and expects a typed refusal. */
async function refusal(run: (client: FileReservationSqlClient) => Promise<unknown>): Promise<FileReservationErrorCode> {
  try {
    await tx(run);
  } catch (error) {
    if (error instanceof FileReservationError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a FileReservationError');
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms); });
}

async function backendPid(client: PoolClient): Promise<number> {
  const result = await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
  const pid = result.rows[0]?.pid;
  if (!pid) {
    throw new Error('Missing backend pid');
  }
  return pid;
}

/**
 * Waits until PostgreSQL reports `waitingPid` blocked by `blockingPid` on this
 * database. The proof of serialization is the observed wait edge, not merely two
 * promises started together.
 */
async function waitUntilBlocked(blockingPid: number, waitingPid: number): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const wait = await db.migrator.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid=$1 AND $2=ANY(pg_blocking_pids(pid))',
      [waitingPid, blockingPid]);
    if ((wait.rows[0]?.n ?? 0) === 1) {
      return;
    }
    await sleep(25);
  }
  throw new Error('Expected the second backend to wait on the first backend');
}

interface IntentRow {
  readonly state: string;
  readonly row_version: number;
  readonly consent_record_id: string | null;
  readonly consent_document_version_id: string | null;
  readonly declared_mime: string;
  readonly declared_bytes: string;
  readonly policy_version_id: string;
  readonly policy_sha256: string;
  readonly policy_expires_at: Date | null;
  readonly body_sha256: string;
  readonly expires_at: Date;
  readonly created_at: Date;
  readonly cancelled_at: string | null;
  readonly owner_staff_id: string | null;
}

async function intentRow(intentId: string): Promise<IntentRow> {
  const result = await db.migrator.query<IntentRow>(
    `SELECT state,row_version,consent_record_id,consent_document_version_id,declared_mime,declared_bytes,
            policy_version_id,policy_sha256,policy_expires_at,body_sha256,expires_at,created_at,cancelled_at,owner_staff_id
       FROM foundation.file_upload_intents WHERE id=$1`, [intentId]);
  const row = result.rows[0];
  if (!row) {
    throw new Error('Missing file upload intent row');
  }
  return row;
}

/**
 * The cancel receipt is deliberately minimal: it must carry the withdrawal fact and
 * nothing the read guard would have refused at that moment. This is the exact key
 * set both the first cancel and a replay have to return.
 */
const CANCELLATION_KEYS = ['cancelledAt', 'intentId', 'replayed', 'rowVersion', 'state'];

fileReservationsIntegration('P03-04A file reservations on real PostgreSQL runtime', () => {
  it('refuses to reserve outside an explicit caller READ COMMITTED transaction or on a pinned stale snapshot', async () => {
    const anchor = await newConsentedAnchor(db);
    const client = await db.runtime.connect();
    try {
      // Autocommit: every statement is its own implicit transaction, so the
      // transaction-local marker is gone before the guard can read it back.
      const outcome = await reserveFileUpload(client, reserveInput(anchor)).then(
        () => 'OK',
        (error: unknown) => error instanceof FileReservationError ? error.code : 'UNEXPECTED');
      expect(outcome).toBe('CONFLICT');
    } finally {
      client.release();
    }
    expect(await intentCount(db, anchor.sessionId)).toBe(0);

    // A stronger snapshot pinned *before* another backend withdrew the consent must
    // fail closed: the guard cannot switch to READ COMMITTED (25001) and the call is
    // a typed CONFLICT, never an approval on stale state.
    const staleAnchor = await newConsentedAnchor(db);
    const stale = await db.runtime.connect();
    try {
      await stale.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
      // Pin the snapshot by reading the evidence a decision depends on.
      await stale.query('SELECT count(*)::int AS n FROM foundation.consent_records');
      // A separate backend commits the revoke while the snapshot stays pinned.
      await revokeConsent(db, staleAnchor, staleAnchor.evidenceId);
      const answer = await reserveFileUpload(stale, reserveInput(staleAnchor)).then(
        () => 'OK',
        (error: unknown) => error instanceof FileReservationError ? error.code : 'UNEXPECTED');
      expect(answer).toBe('CONFLICT');
    } finally {
      try {
        await stale.query('ROLLBACK');
      } catch {
        // The guard's 25001 already aborted the transaction; ROLLBACK still ends it.
      }
      stale.release();
    }
    expect(await intentCount(db, staleAnchor.sessionId)).toBe(0);
  }, 60_000);

  it('refuses an absent, empty or expired policy with zero intent, audit and outbox rows', async () => {
    const anchor = await newConsentedAnchor(db);
    const baseline = await auditOutboxCount(db);
    const intentsBefore = await intentCount(db, anchor.sessionId);
    const client = await db.runtime.connect();
    try {
      // A bare autocommit client is used on purpose: `NOT_CONFIGURED` (rather than
      // the transaction guard's `CONFLICT`) proves the refusal happens before any
      // database access, hence before any intent/audit/outbox INSERT.
      const preDatabaseCases: Record<string, unknown>[] = [
        {
          session: proof(anchor), declaredMime: MIME, declaredBytes: 10,
          expiresAt: new Date(Date.now() + 600_000), idempotencyKey: randomUUID(),
        },
        reserveInput(anchor, { policy: policy({ allowedMimeTypes: [] }) }),
        reserveInput(anchor, { policy: policy({ maxOwnerFiles: 0 }) }),
        reserveInput(anchor, { policy: policy({ maxFileBytes: 500, maxOwnerBytes: 100 }) }),
      ];
      for (const input of preDatabaseCases) {
        const outcome = await reserveFileUpload(client, input).then(
          () => 'OK',
          (error: unknown) => error instanceof FileReservationError ? error.code : 'UNEXPECTED');
        expect(outcome).toBe('NOT_CONFIGURED');
      }
    } finally {
      client.release();
    }
    // An expired policy snapshot is a configuration failure too: the request expiry
    // is inside the snapshot, so the parser accepts the shape and the port refuses
    // `NOT_CONFIGURED` after the proof, before any intent/audit/outbox write.
    expect(await refusal((txClient) => reserveFileUpload(txClient, reserveInput(anchor, {
      policy: policy({ expiresAt: new Date(Date.now() - 60_000) }),
      expiresAt: new Date(Date.now() - 120_000),
    })))).toBe('NOT_CONFIGURED');
    expect(await intentCount(db, anchor.sessionId)).toBe(intentsBefore);
    expect(await auditOutboxCount(db)).toEqual(baseline);
  }, 60_000);

  it('reserves one intent, returns a safe DTO and makes READY or DELETE unreachable', async () => {
    const anchor = await newConsentedAnchor(db);
    const snapshot = policy();
    const input = reserveInput(anchor, { policy: snapshot, bytes: 120 });
    const reserved: FileUploadReservation = await tx((client) => reserveFileUpload(client, input));
    expect(reserved).toMatchObject({
      state: 'RESERVED',
      replayed: false,
      declaredMime: MIME,
      declaredBytes: 120,
      policyVersionId: snapshot.versionId,
      policySourceRef: snapshot.sourceRef,
      consentEvidenceId: anchor.evidenceId,
      consentDocumentVersionId: anchor.documentVersionId,
      consentPurpose: 'REQUEST_PROCESSING',
      cancelledAt: null,
    });
    expect(reserved.rowVersion).toBe(1);
    expect(Number.isNaN(Date.parse(reserved.createdAt))).toBe(false);
    expect(Number.isNaN(Date.parse(reserved.expiresAt))).toBe(false);

    // The exact stored row: one RESERVED intent bound to the exact GIVEN evidence.
    const row = await intentRow(reserved.intentId);
    expect(row).toMatchObject({
      state: 'RESERVED', row_version: 1, consent_record_id: anchor.evidenceId,
      consent_document_version_id: anchor.documentVersionId, declared_mime: MIME, owner_staff_id: null,
    });
    expect(Number(row.declared_bytes)).toBe(120);
    expect(row.policy_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(row.body_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(row.cancelled_at).toBeNull();

    // Read returns the same intent projection and no secret/IO material.
    const view = await tx((client) => readFileUploadIntent(client, {
      session: proof(anchor), intentId: reserved.intentId,
    }));
    expect(view).toMatchObject({
      intentId: reserved.intentId, state: 'RESERVED', rowVersion: 1, declaredBytes: 120,
      policyVersionId: reserved.policyVersionId, consentEvidenceId: anchor.evidenceId,
    });
    expect(Object.keys(view).sort()).toEqual([
      'cancelledAt', 'consentDocumentVersionId', 'consentEvidenceId', 'consentPurpose', 'createdAt',
      'declaredBytes', 'declaredMime', 'expiresAt', 'intentId', 'policySha256', 'policySourceRef',
      'policyVersionId', 'rowVersion', 'state',
    ]);
    const serialized = JSON.stringify(view);
    for (const forbidden of [anchor.token, hashSessionSecret(anchor.token), 'objectKey', 'signedUrl', 'READY']) {
      expect(serialized).not.toContain(forbidden);
    }

    // The state vocabulary is closed and this slice has no IO/READY surface.
    expect(FILE_INTENT_STATES).toEqual(['RESERVED', 'CANCELLED']);
    expect(Object.keys(reservations).filter((name) => /ready|download|presign|stream|objectKey|signedUrl|s3/i.test(name)))
      .toEqual([]);
    const objectColumns = await db.migrator.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema='foundation' AND table_name='file_upload_intents'
          AND (column_name ILIKE '%object%' OR column_name ILIKE '%url%' OR column_name ILIKE '%ready%')`);
    expect(objectColumns.rowCount).toBe(0);

    // The runtime role cannot move the intent to READY or delete it: the database,
    // not only the TypeScript port, owns the single RESERVED -> CANCELLED transition.
    const direct = await db.runtime.connect();
    try {
      await expect(direct.query("UPDATE foundation.file_upload_intents SET state='READY' WHERE id=$1",
        [reserved.intentId])).rejects.toBeTruthy();
      await expect(direct.query('DELETE FROM foundation.file_upload_intents WHERE id=$1',
        [reserved.intentId])).rejects.toBeTruthy();
    } finally {
      direct.release();
    }
    expect((await intentRow(reserved.intentId)).state).toBe('RESERVED');
  }, 60_000);

  it('replays an identical request as one intent with no extra quota and no second audit/outbox pair', async () => {
    const anchor = await newConsentedAnchor(db);
    const key = randomUUID();
    // maxOwnerFiles=1: a second quota-consuming row would be impossible, so a
    // successful replay proves the replay does not consume a second slot.
    const snapshot = policy({ maxOwnerFiles: 1, maxOwnerBytes: 200, maxFileBytes: 200 });
    // One exact request object: the idempotency payload includes the declared
    // expiry, so a retry must resend the same values (not a re-sampled timestamp).
    const firstInput = reserveInput(anchor, { policy: snapshot, bytes: 200, idempotencyKey: key });
    const first = await tx((client) => reserveFileUpload(client, firstInput));
    const baseline = await auditOutboxCount(db);
    const replay = await tx((client) => reserveFileUpload(client, firstInput));
    expect(replay).toMatchObject({ intentId: first.intentId, state: 'RESERVED', replayed: true, rowVersion: 1 });
    expect(await intentCount(db, anchor.sessionId)).toBe(1);
    expect(await auditOutboxCount(db)).toEqual(baseline);

    // Same owner+key with a different payload is a conflict, not a silent update.
    expect(await refusal((client) => reserveFileUpload(client, { ...firstInput, declaredBytes: 199 })))
      .toBe('IDEMPOTENCY_CONFLICT');
    // The same key with a different declared MIME is also a changed payload.
    const bothMimes = policy({ allowedMimeTypes: [MIME, 'image/png'], maxOwnerFiles: 2, maxOwnerBytes: 400 });
    const jpegKey = randomUUID();
    const jpegInput = reserveInput(anchor, { policy: bothMimes, bytes: 100, idempotencyKey: jpegKey });
    const jpeg = await tx((client) => reserveFileUpload(client, jpegInput));
    expect(jpeg.state).toBe('RESERVED');
    expect(await refusal((client) => reserveFileUpload(client, {
      ...jpegInput, declaredMime: 'image/png',
    }))).toBe('IDEMPOTENCY_CONFLICT');
    expect(await intentCount(db, anchor.sessionId)).toBe(2);

    // One immutable policy version id cannot arrive with two different snapshots
    // for the same owner: that would silently re-define an already stored policy.
    const versionId = randomUUID();
    const versionAnchor = await newConsentedAnchor(db);
    const versionA = policy({ versionId, sourceRef: 'synthetic://upload-policy/a' });
    await tx((client) => reserveFileUpload(client, reserveInput(versionAnchor, { policy: versionA })));
    const versionB = policy({ versionId, sourceRef: 'synthetic://upload-policy/b' });
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(versionAnchor, { policy: versionB }))))
      .toBe('POLICY_VERSION_CONFLICT');
    expect(await intentCount(db, versionAnchor.sessionId)).toBe(1);
  }, 60_000);

  it('refuses a wrong token, a foreign owner, a staff owner and a missing consent without writing rows', async () => {
    const owner = await newConsentedAnchor(db);
    const other = await newConsentedAnchor(db);
    // Created before the baseline: anchor creation itself is an audited event.
    const noConsent = await newAnchor(db);
    const snapshot = policy();
    const intent = await tx((client) => reserveFileUpload(client, reserveInput(owner, { policy: snapshot })));
    const baseline = await auditOutboxCount(db);
    const intentsBefore = await intentCount(db);

    // A wrong but well-formed raw token is indistinguishable from a missing anchor:
    // the semantic answer is one `NOT_FOUND` (no existence oracle).
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: { sessionId: owner.sessionId, token: token() }, intentId: intent.intentId,
    }))).toBe('NOT_FOUND');
    // A browser-supplied id with no token is a *syntactic* failure, so it is
    // `INVALID_INPUT` before any proof lookup; it is never treated as authority.
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: { sessionId: owner.sessionId }, intentId: intent.intentId,
    }))).toBe('INVALID_INPUT');
    // A foreign owner gets the same typed NOT_FOUND: no existence oracle.
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: proof(other), intentId: intent.intentId,
    }))).toBe('NOT_FOUND');
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: proof(owner), intentId: randomUUID(),
    }))).toBe('NOT_FOUND');
    // A staff owner is not a credential and is refused before any database access.
    expect(await refusal((client) => reserveFileUpload(client, {
      ...reserveInput(other, { policy: snapshot }), staffId: randomUUID(),
    }))).toBe('UNSUPPORTED_OWNER');
    // No consent at all: the request-processing basis is mandatory.
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(noConsent)))).toBe('CONSENT_NOT_GIVEN');

    expect(await intentCount(db)).toBe(intentsBefore);
    expect(await auditOutboxCount(db)).toEqual(baseline);
  }, 60_000);

  it('refuses an expired and a revoked anchor without writing rows', async () => {
    const expired = await newConsentedAnchor(db, new Date(Date.now() + 2_500));
    const revoked = await newConsentedAnchor(db);
    await tx((client) => revokeRequestSession(client, proof(revoked)));
    await sleep(2_800);
    // Snapshot after the anchor/consent/revoke events, so only the refused calls
    // can move the counters.
    const baseline = await auditOutboxCount(db);
    const intentsBefore = await intentCount(db);

    expect(await refusal((client) => reserveFileUpload(client, reserveInput(expired)))).toBe('SESSION_EXPIRED');
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(revoked)))).toBe('SESSION_REVOKED');
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: proof(revoked), intentId: randomUUID(),
    }))).toBe('SESSION_REVOKED');

    expect(await intentCount(db)).toBe(intentsBefore);
    expect(await auditOutboxCount(db)).toEqual(baseline);
  }, 60_000);

  it('refuses a revoked consent and a stale current consent document', async () => {
    // A withdrawn GIVEN of the still-current text is reported as REVOKED, not as a
    // stale document: the reason must name the actual basis failure.
    const revoked = await newConsentedAnchor(db);
    await revokeConsent(db, revoked, revoked.evidenceId);
    const revokedBaseline = await auditOutboxCount(db);
    const revokedIntents = await intentCount(db);
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(revoked)))).toBe('CONSENT_REVOKED');
    expect(await intentCount(db)).toBe(revokedIntents);
    expect(await auditOutboxCount(db)).toEqual(revokedBaseline);

    // A GIVEN on the then-current text stops authorizing once a newer revision is
    // published: the port refuses instead of silently accepting the new text.
    const form = await ensureProcessingConsentForm(db);
    const stale = await newConsentedAnchor(db);
    const newer = await publishNextConsentForm(db, form.version);
    expect(newer.versionId).not.toBe(form.versionId);
    // Snapshot after the consent/publish events, so only the refused call can move
    // the counters.
    const staleBaseline = await auditOutboxCount(db);
    const staleIntents = await intentCount(db);
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(stale)))).toBe('CONSENT_NOT_CURRENT');
    expect(await intentCount(db)).toBe(staleIntents);
    expect(await auditOutboxCount(db)).toEqual(staleBaseline);
  }, 60_000);

  it('keeps the intent bound to its exact GIVEN basis: revoke then new GIVEN never revives it', async () => {
    const anchor = await newConsentedAnchor(db);
    const snapshot = policy();
    const key = randomUUID();
    // One literal request object, reused for the replay: same `expiresAt` instant,
    // same key, same policy snapshot.
    const input = reserveInput(anchor, { policy: snapshot, idempotencyKey: key });
    const intent = await tx((client) => reserveFileUpload(client, input));
    // Withdraw exactly the evidence that backed the intent, then accept the same
    // current text again: the new GIVEN is a new event, not a resurrection.
    await revokeConsent(db, anchor, anchor.evidenceId);
    const form = await ensureProcessingConsentForm(db);
    const reGiven = await tx((client) => recordConsentGiven(client, {
      session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: form.versionId,
      evidenceRef: randomUUID(), accepted: true,
    }));
    expect(reGiven.evidenceId).not.toBe(anchor.evidenceId);

    // The stored intent still names the revoked evidence, so it is neither revived
    // nor re-bound to the new GIVEN: the current basis is now the new evidence, and
    // the stored one is refused.
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId,
    }))).toBe('CONSENT_NOT_CURRENT');
    // The replay is literally the same original input, so the basis check — not a
    // payload difference — must be the only refusal: `CONSENT_NOT_CURRENT`, never
    // `IDEMPOTENCY_CONFLICT` or a generic `CONSENT_REVOKED`.
    expect(await refusal((client) => reserveFileUpload(client, input))).toBe('CONSENT_NOT_CURRENT');
    expect(await intentRow(intent.intentId)).toMatchObject({
      state: 'RESERVED', row_version: 1, consent_record_id: anchor.evidenceId,
    });

    // A genuinely new reservation under the new GIVEN is a new intent, so the old
    // one is dead without blocking future uploads.
    const fresh = await tx((client) => reserveFileUpload(client, reserveInput(anchor, { policy: snapshot })));
    expect(fresh.intentId).not.toBe(intent.intentId);
    expect(await intentCount(db, anchor.sessionId)).toBe(2);
  }, 60_000);

  it('lets exactly one of two concurrent backends take the last owner file slot', async () => {
    const anchor = await newConsentedAnchor(db);
    // One committed reservation already occupies the first of two slots.
    const snapshot = policy({ maxOwnerFiles: 2, maxOwnerBytes: 100_000, maxFileBytes: 1_000 });
    await tx((client) => reserveFileUpload(client, reserveInput(anchor, { policy: snapshot, bytes: 10 })));
    const intentsBefore = await intentCount(db, anchor.sessionId);

    const winner = await db.runtime.connect();
    const loser = await db.runtime.connect();
    try {
      await beginLegalTransaction(winner);
      const first = await reserveFileUpload(winner, reserveInput(anchor, { policy: snapshot, bytes: 10 }));
      const winnerPid = await backendPid(winner);

      await beginLegalTransaction(loser);
      // The loser's pid is captured before it blocks: a statement queued behind the
      // row lock would never return.
      const loserPid = await backendPid(loser);
      const pending = reserveFileUpload(loser, reserveInput(anchor, { policy: snapshot, bytes: 10 })).then(
        () => 'OK',
        (error: unknown) => error instanceof FileReservationError ? error.code : 'UNEXPECTED');
      // The proof is the observed wait edge on the winner's session row lock.
      await waitUntilBlocked(winnerPid, loserPid);
      await winner.query('COMMIT');

      expect(await pending).toBe('QUOTA_EXCEEDED');
      expect(first.state).toBe('RESERVED');
    } finally {
      try {
        await winner.query('ROLLBACK');
      } catch {
        // The transaction may already be committed; the client is released anyway.
      }
      try {
        await loser.query('ROLLBACK');
      } catch {
        // The loser's transaction is already aborted by the refusal.
      }
      winner.release();
      loser.release();
    }
    // Exactly one of the two concurrent attempts committed.
    expect(await intentCount(db, anchor.sessionId)).toBe(intentsBefore + 1);
  }, 60_000);

  it('lets exactly one of two concurrent backends take the last owner bytes', async () => {
    const anchor = await newConsentedAnchor(db);
    // 300 bytes total, 100 already reserved: two 150-byte attempts cannot both fit,
    // while the file count stays far below its limit.
    const snapshot = policy({ maxOwnerFiles: 10, maxOwnerBytes: 300, maxFileBytes: 200 });
    await tx((client) => reserveFileUpload(client, reserveInput(anchor, { policy: snapshot, bytes: 100 })));
    const intentsBefore = await intentCount(db, anchor.sessionId);

    const winner = await db.runtime.connect();
    const loser = await db.runtime.connect();
    try {
      await beginLegalTransaction(winner);
      const first = await reserveFileUpload(winner, reserveInput(anchor, { policy: snapshot, bytes: 150 }));
      const winnerPid = await backendPid(winner);
      await beginLegalTransaction(loser);
      const loserPid = await backendPid(loser);
      const pending = reserveFileUpload(loser, reserveInput(anchor, { policy: snapshot, bytes: 150 })).then(
        () => 'OK',
        (error: unknown) => error instanceof FileReservationError ? error.code : 'UNEXPECTED');
      await waitUntilBlocked(winnerPid, loserPid);
      await winner.query('COMMIT');
      expect(await pending).toBe('QUOTA_EXCEEDED');
      expect(first.declaredBytes).toBe(150);
    } finally {
      try {
        await winner.query('ROLLBACK');
      } catch {
        // Already committed; release only.
      }
      try {
        await loser.query('ROLLBACK');
      } catch {
        // Already aborted by the refusal; release only.
      }
      winner.release();
      loser.release();
    }
    expect(await intentCount(db, anchor.sessionId)).toBe(intentsBefore + 1);
    // The committed bytes still fit the policy snapshot.
    const sum = await db.migrator.query<{ total: string }>(
      `SELECT COALESCE(sum(declared_bytes),0)::text AS total FROM foundation.file_upload_intents
        WHERE owner_request_session_id=$1 AND state='RESERVED' AND expires_at>clock_timestamp()`,
      [anchor.sessionId]);
    expect(Number(sum.rows[0]?.total ?? '0')).toBe(250);
  }, 60_000);

  it('counts only unexpired reservations on the database clock', async () => {
    const anchor = await newConsentedAnchor(db);
    const snapshot = policy({ maxOwnerFiles: 1, maxOwnerBytes: 500, maxFileBytes: 500 });
    const first = await tx((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 100, expiresAt: new Date(Date.now() + 1_200),
    })));
    // While it is live, the single allowed slot is taken.
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 100,
    })))).toBe('QUOTA_EXCEEDED');
    await sleep(1_600);
    // Once the database clock passes its expiry the reservation no longer counts.
    const second = await tx((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 100,
    })));
    expect(second).toMatchObject({ state: 'RESERVED', replayed: false });
    expect(second.intentId).not.toBe(first.intentId);
  }, 60_000);

  it('re-checks the database clock after the last lock wait and refuses an expired intent', async () => {
    const anchor = await newConsentedAnchor(db);
    const snapshot = policy({ maxOwnerFiles: 5, maxOwnerBytes: 5_000, maxFileBytes: 1_000 });
    const intent = await tx((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 100, expiresAt: new Date(Date.now() + 1_500),
    })));

    const blocker = await db.runtime.connect();
    const reader = await db.runtime.connect();
    try {
      // Hold the intent row so the read really waits on it (session lock first,
      // intent row second — the last wait before the decision).
      await blocker.query('BEGIN');
      await blocker.query('SELECT id FROM foundation.file_upload_intents WHERE id=$1 FOR UPDATE', [intent.intentId]);
      const blockerPid = await backendPid(blocker);

      await beginLegalTransaction(reader);
      const readerPid = await backendPid(reader);
      const pending = readFileUploadIntent(reader, {
        session: proof(anchor), intentId: intent.intentId,
      }).then(
        () => 'OK',
        (error: unknown) => error instanceof FileReservationError ? error.code : 'UNEXPECTED');
      await waitUntilBlocked(blockerPid, readerPid);
      // Still live when the read reached the lock; only the wait crosses expiry.
      const live = await db.migrator.query<{ live: boolean }>(
        'SELECT expires_at > clock_timestamp() AS live FROM foundation.file_upload_intents WHERE id=$1',
        [intent.intentId]);
      expect(live.rows[0]?.live).toBe(true);

      await sleep(1_700);
      await blocker.query('ROLLBACK');
      expect(await pending).toBe('INTENT_EXPIRED');
    } finally {
      try {
        await reader.query('ROLLBACK');
      } catch {
        // The port already refused; release only.
      }
      reader.release();
      blocker.release();
    }
    // The row is untouched: no revive, no state change from the failed read.
    expect(await intentRow(intent.intentId)).toMatchObject({ state: 'RESERVED', row_version: 1 });
  }, 60_000);

  it('cancels with a one-way CAS, replays the current version and releases the quota', async () => {
    const anchor = await newConsentedAnchor(db);
    const key = randomUUID();
    const snapshot = policy({ maxOwnerFiles: 1, maxOwnerBytes: 200, maxFileBytes: 200 });
    const intent = await tx((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 200, idempotencyKey: key,
    })));
    // The single slot and all bytes are now taken.
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 10,
    })))).toBe('QUOTA_EXCEEDED');

    // A stale CAS token is refused and changes nothing.
    expect(await refusal((client) => cancelFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId, expectedVersion: 2,
    }))).toBe('STALE_VERSION');
    expect(await intentRow(intent.intentId)).toMatchObject({ state: 'RESERVED', row_version: 1 });

    const cancelled = await tx((client) => cancelFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId, expectedVersion: 1,
    }));
    expect(cancelled).toMatchObject({ intentId: intent.intentId, state: 'CANCELLED', rowVersion: 2, replayed: false });
    expect(cancelled.cancelledAt).not.toBeNull();
    expect(await intentRow(intent.intentId)).toMatchObject({ state: 'CANCELLED', row_version: 2 });

    // One-way: the state is terminal and the same idempotency key cannot revive it.
    expect(await tx((client) => readFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId,
    }))).toMatchObject({ state: 'CANCELLED', rowVersion: 2 });
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 200, idempotencyKey: key,
    })))).toBe('INTENT_CANCELLED');
    // Cancelling again with the current version is an idempotent replay; an old token
    // stays a stale version.
    expect(await tx((client) => cancelFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId, expectedVersion: 2,
    }))).toMatchObject({ state: 'CANCELLED', rowVersion: 2, replayed: true });
    expect(await refusal((client) => cancelFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId, expectedVersion: 1,
    }))).toBe('STALE_VERSION');

    // The cancelled reservation no longer consumes the slot or the bytes.
    const replacement = await tx((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 200,
    })));
    expect(replacement).toMatchObject({ state: 'RESERVED', declaredBytes: 200 });

    // A pending reservation stays cancellable after the person withdraws consent:
    // cancel needs owner proof and a live anchor only, never a new GIVEN.
    const withdrawn = await newConsentedAnchor(db);
    const pendingIntent = await tx((client) => reserveFileUpload(client, reserveInput(withdrawn)));
    await revokeConsent(db, withdrawn, withdrawn.evidenceId);
    const cancelledAfterRevoke = await tx((client) => cancelFileUploadIntent(client, {
      session: proof(withdrawn), intentId: pendingIntent.intentId, expectedVersion: pendingIntent.rowVersion,
    }));
    expect(cancelledAfterRevoke).toMatchObject({ state: 'CANCELLED', replayed: false });
    expect(await intentRow(pendingIntent.intentId)).toMatchObject({ state: 'CANCELLED' });

    // Withdrawal also works for a *historical* reservation: once the intent and its
    // policy snapshot have expired, cancel still succeeds (live owner proof + CAS
    // only). A dead reservation must not become impossible to withdraw.
    const historical = await newConsentedAnchor(db);
    const shortPolicy = policy({ expiresAt: new Date(Date.now() + 1_500) });
    const staleIntent = await tx((client) => reserveFileUpload(client, reserveInput(historical, {
      policy: shortPolicy, expiresAt: new Date(Date.now() + 1_000),
    })));
    await sleep(1_800);
    const historicalCancel = await tx((client) => cancelFileUploadIntent(client, {
      session: proof(historical), intentId: staleIntent.intentId, expectedVersion: staleIntent.rowVersion,
    }));
    expect(historicalCancel).toMatchObject({ state: 'CANCELLED', rowVersion: 2, replayed: false });
    expect(await intentRow(staleIntent.intentId)).toMatchObject({ state: 'CANCELLED', row_version: 2 });
  }, 60_000);

  it('returns only the minimal cancellation receipt after withdrawal while the ordinary read is denied', async () => {
    const anchor = await newConsentedAnchor(db);
    const snapshot = policy();
    const key = randomUUID();
    const intent = await tx((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 120, idempotencyKey: key,
    })));
    // The person withdraws exactly the GIVEN that backed the reservation.
    await revokeConsent(db, anchor, anchor.evidenceId);
    // The ordinary read through the same owner proof is denied on the withdrawn
    // basis: this is the projection the cancel receipt must not hand back.
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId,
    }))).toBe('CONSENT_REVOKED');
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, idempotencyKey: key,
    })))).toBe('CONSENT_REVOKED');

    // Withdrawal still succeeds (owner proof + CAS only) and returns the minimal
    // receipt: identity, terminal state, version, database-stamped time, replay flag.
    const cancelled = await tx((client) => cancelFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId, expectedVersion: intent.rowVersion,
    }));
    expect(Object.keys(cancelled).sort()).toEqual(CANCELLATION_KEYS);
    expect(cancelled).toMatchObject({
      intentId: intent.intentId, state: 'CANCELLED', rowVersion: 2, replayed: false,
    });
    expect(typeof cancelled.cancelledAt).toBe('string');
    expect(Number.isNaN(Date.parse(cancelled.cancelledAt))).toBe(false);
    // No read metadata, no token, no policy/consent basis leaks through cancel.
    const serialized = JSON.stringify(cancelled);
    for (const forbidden of [
      anchor.token, hashSessionSecret(anchor.token), 'declaredMime', 'declaredBytes', 'policyVersionId',
      'policySourceRef', 'policySha256', 'consentEvidenceId', 'consentDocumentVersionId', 'createdAt',
      'expiresAt',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }

    // A repeat immediately after the withdrawal, with the current version, returns
    // the identical minimal receipt: the same exact key set, the same values and
    // only the replay flag flipped. Nothing about the withdrawn basis or the read
    // projection is added on the replay path.
    const repeat = await tx((client) => cancelFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId, expectedVersion: cancelled.rowVersion,
    }));
    expect(Object.keys(repeat).sort()).toEqual(CANCELLATION_KEYS);
    expect(repeat).toEqual({ ...cancelled, replayed: true });
    expect(repeat.cancelledAt).toBe(cancelled.cancelledAt);
    expect(repeat.rowVersion).toBe(cancelled.rowVersion);
    const repeatSerialized = JSON.stringify(repeat);
    for (const forbidden of [
      anchor.token, hashSessionSecret(anchor.token), 'declaredMime', 'declaredBytes', 'policyVersionId',
      'policySourceRef', 'policySha256', 'consentEvidenceId', 'consentDocumentVersionId', 'createdAt',
      'expiresAt',
    ]) {
      expect(repeatSerialized).not.toContain(forbidden);
    }
    // The ordinary read stays denied after the repeat as well: the receipt never
    // becomes a read path, and the withdrawal did not restore any consent.
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId,
    }))).toBe('CONSENT_REVOKED');
    expect(await refusal((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, idempotencyKey: key,
    })))).toBe('CONSENT_REVOKED');

    // The stored row keeps the full evidence; only the receipt is minimal.
    expect(await intentRow(intent.intentId)).toMatchObject({
      state: 'CANCELLED', row_version: 2, declared_mime: MIME, consent_record_id: anchor.evidenceId,
    });
  }, 60_000);

  it('returns the exact same minimal receipt on a repeated cancel, including after the policy and intent expired', async () => {
    const anchor = await newConsentedAnchor(db);
    const snapshot = policy({ expiresAt: new Date(Date.now() + 1_500) });
    const intent = await tx((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: snapshot, bytes: 100, expiresAt: new Date(Date.now() + 1_000),
    })));
    // Wait past both the reservation expiry and the policy snapshot expiry.
    await sleep(1_800);
    // The read guard refuses the expired policy snapshot; cancel must still work.
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId,
    }))).toBe('NOT_CONFIGURED');
    const first = await tx((client) => cancelFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId, expectedVersion: intent.rowVersion,
    }));
    expect(Object.keys(first).sort()).toEqual(CANCELLATION_KEYS);
    expect(first).toMatchObject({ state: 'CANCELLED', rowVersion: 2, replayed: false });

    // A repeat with the current version returns the identical receipt; only the
    // replay flag changes. Nothing about the expired policy leaks into the answer.
    const repeat = await tx((client) => cancelFileUploadIntent(client, {
      session: proof(anchor), intentId: intent.intentId, expectedVersion: first.rowVersion,
    }));
    expect(Object.keys(repeat).sort()).toEqual(CANCELLATION_KEYS);
    expect(repeat).toEqual({ ...first, replayed: true });
    expect(repeat.cancelledAt).toBe(first.cancelledAt);
    expect(repeat.rowVersion).toBe(first.rowVersion);
    expect(JSON.stringify(repeat)).not.toContain(snapshot.versionId);

    // The same holds for an expired reservation under a still-live policy: the read
    // is `INTENT_EXPIRED`, the cancel receipt stays minimal.
    const live = await newConsentedAnchor(db);
    const livePolicy = policy({ expiresAt: new Date(Date.now() + 3_600_000) });
    const expiredIntent = await tx((client) => reserveFileUpload(client, reserveInput(live, {
      policy: livePolicy, bytes: 100, expiresAt: new Date(Date.now() + 1_000),
    })));
    await sleep(1_500);
    expect(await refusal((client) => readFileUploadIntent(client, {
      session: proof(live), intentId: expiredIntent.intentId,
    }))).toBe('INTENT_EXPIRED');
    const expiredCancel = await tx((client) => cancelFileUploadIntent(client, {
      session: proof(live), intentId: expiredIntent.intentId, expectedVersion: expiredIntent.rowVersion,
    }));
    expect(Object.keys(expiredCancel).sort()).toEqual(CANCELLATION_KEYS);
    expect(expiredCancel).toMatchObject({ state: 'CANCELLED', rowVersion: 2, replayed: false });
  }, 60_000);

  it('hashes and stores the original Date snapshots even when the caller mutates both inputs while the call waits', async () => {
    const anchor = await newConsentedAnchor(db);
    // Original instants: the reservation expiry is inside the policy snapshot and
    // both are inside the session expiry, so the *mutated* values below would also
    // be accepted by every guard. That is deliberate: without the snapshot the bug
    // would persist wrong-but-valid timestamps instead of failing loudly.
    const policyExpiresAt = new Date(Date.now() + 3_600_000);
    const intentExpiresAt = new Date(Date.now() + 600_000);
    const snapshot = policy({ expiresAt: policyExpiresAt });
    const key = randomUUID();
    const input = reserveInput(anchor, {
      policy: snapshot, bytes: 100, expiresAt: intentExpiresAt, idempotencyKey: key,
    });
    const originalPolicyIso = policyExpiresAt.toISOString();
    const originalIntentIso = intentExpiresAt.toISOString();
    // Independent expectations, computed from the ORIGINAL instants and the known
    // basis rather than from anything the port returns.
    const expectedPolicySha = filePolicySha256({
      versionId: snapshot.versionId,
      sourceRef: snapshot.sourceRef,
      allowedMimeTypes: snapshot.allowedMimeTypes,
      maxFileBytes: snapshot.maxFileBytes,
      maxOwnerBytes: snapshot.maxOwnerBytes,
      maxOwnerFiles: snapshot.maxOwnerFiles,
      policyExpiresAt: originalPolicyIso,
    });
    const expectedBodySha = fileIntentBodySha256({
      consentDocumentVersionId: anchor.documentVersionId,
      consentEvidenceId: anchor.evidenceId,
      consentPurpose: 'REQUEST_PROCESSING',
      declaredBytes: 100,
      declaredMime: MIME,
      expiresAt: originalIntentIso,
      idempotencyKey: key,
      policySha256: expectedPolicySha,
      policyVersionId: snapshot.versionId,
    });

    const blocker = await db.runtime.connect();
    const waiter = await db.runtime.connect();
    const reserved = await (async (): Promise<FileUploadReservation> => {
      try {
        // Hold the session row: `requireLiveAnchor` locks it first, so the reserve
        // parses its inputs (taking the snapshots) and then blocks before hashing or
        // inserting anything.
        await blocker.query('BEGIN');
        await blocker.query('SELECT id FROM foundation.request_sessions WHERE id=$1 FOR UPDATE', [anchor.sessionId]);
        const blockerPid = await backendPid(blocker);

        await beginLegalTransaction(waiter);
        const waiterPid = await backendPid(waiter);
        const pending = reserveFileUpload(waiter, input);
        // The wait is observed on the real lock edge before anything is mutated.
        await waitUntilBlocked(blockerPid, waiterPid);

        // Mutate both caller-owned Date objects while the call is still in flight.
        // Both new instants stay valid (future, inside the session and policy), so a
        // non-snapshotting implementation would store them instead of refusing.
        const mutatedPolicyIso = new Date(Date.now() + 7_200_000).toISOString();
        const mutatedIntentIso = new Date(Date.now() + 1_200_000).toISOString();
        policyExpiresAt.setTime(Date.parse(mutatedPolicyIso));
        intentExpiresAt.setTime(Date.parse(mutatedIntentIso));
        expect(policyExpiresAt.toISOString()).toBe(mutatedPolicyIso);
        expect(intentExpiresAt.toISOString()).toBe(mutatedIntentIso);
        expect(mutatedPolicyIso).not.toBe(originalPolicyIso);
        expect(mutatedIntentIso).not.toBe(originalIntentIso);

        await blocker.query('ROLLBACK');
        const result = await pending;
        await waiter.query('COMMIT');
        return result;
      } finally {
        try {
          await waiter.query('ROLLBACK');
        } catch {
          // Already committed (or aborted by a refusal); release only.
        }
        waiter.release();
        blocker.release();
      }
    })();

    // The stored row carries the original instants and the original canonical
    // hashes — never the mutated ones.
    const row = await intentRow(reserved.intentId);
    expect(row.policy_sha256).toBe(expectedPolicySha);
    expect(row.body_sha256).toBe(expectedBodySha);
    expect(row.policy_expires_at?.toISOString()).toBe(originalPolicyIso);
    expect(row.expires_at.toISOString()).toBe(originalIntentIso);
    expect(row.expires_at.toISOString()).not.toBe(intentExpiresAt.toISOString());
    expect(reserved.expiresAt).toBe(originalIntentIso);

    // A replay built from fresh Date objects with the ORIGINAL instants is accepted
    // as the same request: the stored idempotency payload really is the original.
    const replay = await tx((client) => reserveFileUpload(client, reserveInput(anchor, {
      policy: policy({
        versionId: snapshot.versionId, sourceRef: snapshot.sourceRef, expiresAt: new Date(originalPolicyIso),
      }),
      bytes: 100, expiresAt: new Date(originalIntentIso), idempotencyKey: key,
    })));
    expect(replay).toMatchObject({ intentId: reserved.intentId, state: 'RESERVED', replayed: true });
  }, 60_000);

  it('rolls the intent, audit and outbox rows back when the audit insert fails', async () => {
    const anchor = await newConsentedAnchor(db);
    const intentsBefore = await intentCount(db);
    const baseline = await auditOutboxCount(db);
    await installFailingAuditTrigger(db);
    let outcome: string;
    try {
      outcome = await db.inTransaction((client) => reserveFileUpload(client, reserveInput(anchor))).then(
        () => 'OK',
        (error: unknown) => error instanceof FileReservationError ? error.code : 'REFUSED');
    } finally {
      await removeFailingAuditTrigger(db);
    }
    // The write is refused (typed or as the underlying database failure), and the
    // caller transaction carries no partial intent/audit/outbox state.
    expect(outcome).not.toBe('OK');
    expect(await intentCount(db)).toBe(intentsBefore);
    expect(await intentCount(db, anchor.sessionId)).toBe(0);
    expect(await auditOutboxCount(db)).toEqual(baseline);
  }, 60_000);
});
