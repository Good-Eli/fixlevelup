/**
 * Unit proofs for the P03-04 slice A file-upload reservation ports that need no
 * database: input/policy narrowing, canonical hashing, the validated audit payload
 * (exactly nine mandatory keys, no free text), driver/legal error translation, and
 * the mandated *order* of the port calls (guarded READ COMMITTED first, session
 * lock before document lock, session lock before the intent row, no INSERT on any
 * refusal).
 *
 * The fake client below answers the exact SQL shapes the ports issue, so a unit
 * run proves:
 *
 * - a missing/invalid policy fails `NOT_CONFIGURED` with *zero* database calls,
 *   i.e. before any intent/audit/outbox write;
 * - a staff-owner request fails `UNSUPPORTED_OWNER` before any database access;
 * - the first statement is always the explicit READ COMMITTED guard, and an
 *   autocommit client is refused `CONFLICT`;
 * - reserve/read/cancel lock the owner session first and the intent row second;
 * - cancel never consults consent or the legal document (no new consent), while
 *   read/replay do;
 * - a replay writes no second intent/audit/outbox row, and a changed payload,
 *   cancelled intent, expired intent or new GIVEN basis never returns success;
 * - the safe DTO contains no token, secret hash, idempotency hash or legal text.
 *
 * These tests use synthetic values only. No real quota, TTL, retention duration or
 * legal text is implied by a number here.
 */
import { describe, expect, it } from 'vitest';
import * as reservationSurface from '../src/files/reservations/index.js';
import {
  FILE_MIME_TYPES, FILE_RESERVATION_PURPOSE, FileReservationError, cancelFileUploadIntent, readFileUploadIntent,
  reserveFileUpload,
} from '../src/files/reservations/index.js';
import type {
  FileReservationErrorCode, FileReservationPolicy, FileReservationSqlClient,
} from '../src/files/reservations/index.js';
import {
  fileIntentBodySha256, filePolicySha256, canonicalFileIntentPayload, canonicalFilePolicy,
} from '../src/files/reservations/hash.js';
import {
  cancelFileUploadIntentInput, fileReservationPolicy, readFileUploadIntentInput, reserveFileUploadInput,
} from '../src/files/reservations/input.js';
// The audit writer and its validator are internal: they are imported from their own
// module here (a unit test of the internal gate), never from the public surface.
import { safeFileIntentAuditDetails, writeFileIntentAudit } from '../src/files/reservations/audit.js';
import type { FileIntentAuditDetails } from '../src/files/reservations/audit.js';
import { mapFileReservationDbError, mapLegalPortError } from '../src/files/reservations/errors.js';
import { LegalPortError } from '../src/settings/legal/legal-contract.js';
import { hashSessionSecret, sha256Hex } from '../src/settings/legal/legal-hash.js';

/* -------------------------------- fixtures -------------------------------- */

const SESSION_ID = '11111111-1111-4111-8111-111111111111';
const TOKEN = 'A'.repeat(43);
const OTHER_SESSION_ID = '22222222-2222-4222-8222-222222222222';
const POLICY_ID = '33333333-3333-4333-8333-333333333333';
const INTENT_ID = '44444444-4444-4444-8444-444444444444';
const FORM_ID = '55555555-5555-4555-8555-555555555555';
const VERSION_ID = '66666666-6666-4666-8666-666666666666';
const EVIDENCE_ID = '77777777-7777-4777-8777-777777777777';
const OTHER_EVIDENCE_ID = '88888888-8888-4888-8888-888888888888';
const IDEMPOTENCY = '99999999-9999-4999-8999-999999999999';
const NOW = new Date('2026-11-21T12:00:00.000Z');

const SESSION_EXPIRES = new Date('2026-11-21T18:00:00.000Z');
const POLICY_EXPIRES = new Date('2026-11-21T17:00:00.000Z');
const INTENT_EXPIRES = new Date('2026-11-21T15:00:00.000Z');

function policy(overrides: Partial<FileReservationPolicy> = {}): FileReservationPolicy {
  return {
    versionId: POLICY_ID,
    sourceRef: 'synthetic/policy/v1',
    allowedMimeTypes: ['image/jpeg', 'image/png'],
    maxFileBytes: 1_000,
    maxOwnerBytes: 5_000,
    maxOwnerFiles: 3,
    expiresAt: POLICY_EXPIRES,
    ...overrides,
  };
}

function reserveInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    session: { sessionId: SESSION_ID, token: TOKEN },
    policy: policy(),
    declaredMime: 'image/jpeg',
    declaredBytes: 500,
    expiresAt: INTENT_EXPIRES,
    idempotencyKey: IDEMPOTENCY,
    ...overrides,
  };
}

function codeOf(run: () => unknown): FileReservationErrorCode {
  try {
    run();
  } catch (error) {
    if (error instanceof FileReservationError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a FileReservationError');
}

async function asyncCodeOf(run: () => Promise<unknown>): Promise<FileReservationErrorCode> {
  try {
    await run();
  } catch (error) {
    if (error instanceof FileReservationError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a FileReservationError');
}

/* --------------------------------- fake SQL -------------------------------- */

interface FakeIntentRow {
  id: string;
  owner_request_session_id: string;
  consent_record_id: string | null;
  consent_document_version_id: string | null;
  consent_purpose: string | null;
  policy_version_id: string;
  policy_source_ref: string;
  policy_sha256: string;
  policy_expires_at: Date | null;
  declared_mime: string;
  declared_bytes: string | number;
  expires_at: Date;
  created_at: Date;
  idempotency_key: string;
  body_sha256: string;
  state: string;
  cancelled_at: Date | null;
  row_version: number;
}

interface FakeAnchorRow {
  id: string;
  secret_hash: string;
  intake_city_id: string;
  intake_city_version_id: string;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  db_now: Date;
}

interface FakeFormRow {
  id: string;
  purpose: string;
  kind: string;
  row_version: number;
  current_version_id: string | null;
  legal_basis: string | null;
}

interface FakeConsentRow {
  id: string;
  session_id: string;
  document_id: string;
  document_version_id: string;
  purpose: string;
  action: string;
  legal_basis: string;
  source: string;
  evidence_ref: string;
  occurred_at: Date;
  supersedes_id: string | null;
}

interface SqlResult {
  rows: unknown[];
  rowCount: number;
}

/**
 * Minimal fake of the caller's transaction. It records every statement, so the
 * tests can assert *order* and absence of writes, and answers the exact SQL shapes
 * the legal and reservation ports issue.
 */
class FakeDatabase {
  readonly statements: { text: string; params: readonly unknown[] }[] = [];
  now = NOW;
  /** `autocommit` makes the transaction-local marker unreadable, like a real PoolClient. */
  transaction: 'explicit' | 'autocommit' = 'explicit';
  anchor: FakeAnchorRow | null;
  form: FakeFormRow | null;
  given: FakeConsentRow | null;
  withdrawn: FakeConsentRow | null = null;
  older: FakeConsentRow | null = null;
  intent: FakeIntentRow | null = null;
  policyVersionConflict = false;
  activeCount = 0;
  activeBytes = 0;
  failAudit = false;
  /** Thrown by an INSERT into the intent table, e.g. to simulate a database guard. */
  insertError: Error | null = null;
  private marker: string | null = null;

  constructor() {
    this.anchor = {
      id: SESSION_ID,
      secret_hash: hashSessionSecret(TOKEN),
      intake_city_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      intake_city_version_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      created_at: new Date('2026-11-21T10:00:00.000Z'),
      expires_at: SESSION_EXPIRES,
      revoked_at: null,
      db_now: NOW,
    };
    this.form = {
      id: FORM_ID, purpose: FILE_RESERVATION_PURPOSE, kind: 'CONSENT_FORM', row_version: 1,
      current_version_id: VERSION_ID, legal_basis: 'synthetic-basis',
    };
    this.given = consent(EVIDENCE_ID);
  }

  get client(): FileReservationSqlClient {
    return {
      query: (text: string, params?: readonly unknown[]) => Promise.resolve(this.run(text, params ?? [])),
    } as unknown as FileReservationSqlClient;
  }

  countOf(fragment: string): number {
    return this.statements.filter((statement) => statement.text.includes(fragment)).length;
  }

  indexOf(fragment: string): number {
    return this.statements.findIndex((statement) => statement.text.includes(fragment));
  }

  get insertsIntoIntents(): number {
    return this.countOf('INSERT INTO foundation.file_upload_intents');
  }

  get writes(): string[] {
    return this.statements.map((statement) => statement.text).filter((text) => /^\s*(INSERT|UPDATE|DELETE)/i.test(text));
  }

  run(text: string, params: readonly unknown[]): SqlResult {
    this.statements.push({ text, params });
    const sql = text.replace(/\s+/g, ' ').trim();
    const rows = (values: unknown[]): SqlResult => ({ rows: values, rowCount: values.length });

    // --- legal transaction guard -------------------------------------------------
    if (sql === 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED') {
      return rows([]);
    }
    if (sql.includes("current_setting('transaction_isolation')")) {
      return rows([{ isolation: 'read committed' }]);
    }
    if (sql.includes('set_config(')) {
      this.marker = typeof params[0] === 'string' ? params[0] : null;
      return rows([{ set_config: this.marker }]);
    }
    if (sql.includes("current_setting('fixlevelup.legal_tx',true)")) {
      return rows([{ marker: this.transaction === 'explicit' ? this.marker : null }]);
    }

    // --- clocks ------------------------------------------------------------------
    if (sql === 'SELECT clock_timestamp() AS db_now') {
      return rows([{ db_now: this.now }]);
    }

    // --- legal: anchor, document, consent ---------------------------------------
    if (sql.includes('FROM foundation.request_sessions')) {
      const anchor = this.anchor;
      return rows(anchor === null ? [] : [{ ...anchor, db_now: this.now }]);
    }
    if (sql.includes('FROM foundation.legal_documents')) {
      return rows(this.form === null ? [] : [{ ...this.form }]);
    }
    if (sql.includes('FROM foundation.consent_records c')) {
      const given = this.given;
      const matches = given !== null && given.session_id === params[0] && given.purpose === params[1]
        && given.document_id === params[2] && given.document_version_id === params[3];
      return rows(matches ? [given] : []);
    }
    if (sql.includes('FROM foundation.consent_records')) {
      const candidate = sql.includes('document_version_id<>$4') ? this.older : this.withdrawn;
      return rows(candidate === null ? [] : [candidate]);
    }

    // --- reservation reads -------------------------------------------------------
    if (sql.includes('SELECT 1 FROM foundation.file_upload_intents')) {
      return rows(this.policyVersionConflict ? [{ '?column?': 1 }] : []);
    }
    if (sql.includes('FROM foundation.file_upload_intents i') && sql.includes('i.idempotency_key=$2')) {
      const intent = this.intent;
      const matches = intent !== null && intent.owner_request_session_id === params[0]
        && intent.idempotency_key === params[1];
      return rows(matches ? [intent] : []);
    }
    if (sql.includes('FROM foundation.file_upload_intents i') && sql.includes('i.id=$1')) {
      const intent = this.intent;
      const matches = intent !== null && intent.id === params[0] && intent.owner_request_session_id === params[1];
      return rows(matches ? [intent] : []);
    }
    if (sql.includes('count(*)::int AS active_count')) {
      return rows([{ active_count: this.activeCount, active_bytes: String(this.activeBytes) }]);
    }

    // --- reservation writes ------------------------------------------------------
    if (sql.startsWith('INSERT INTO foundation.file_upload_intents')) {
      if (this.insertError !== null) {
        throw this.insertError;
      }
      const row: FakeIntentRow = {
        id: String(params[0]),
        owner_request_session_id: String(params[1]),
        consent_record_id: String(params[2]),
        consent_document_version_id: String(params[3]),
        consent_purpose: String(params[4]),
        policy_version_id: String(params[5]),
        policy_source_ref: String(params[6]),
        policy_sha256: String(params[7]),
        allowed_mime_types: params[8],
        policy_expires_at: params[12] as Date,
        declared_mime: String(params[13]),
        declared_bytes: params[14] as number,
        expires_at: params[15] as Date,
        idempotency_key: String(params[16]),
        body_sha256: String(params[17]),
        created_at: this.now,
        state: 'RESERVED',
        cancelled_at: null,
        row_version: 1,
      } as FakeIntentRow;
      this.intent = row;
      return rows([row]);
    }
    if (sql.startsWith('UPDATE foundation.file_upload_intents')) {
      const intent = this.intent;
      if (intent === null || intent.state !== 'RESERVED' || intent.row_version !== params[2]) {
        return rows([]);
      }
      const cancelled: FakeIntentRow = {
        ...intent, state: 'CANCELLED', cancelled_at: this.now, row_version: intent.row_version + 1,
      };
      this.intent = cancelled;
      return rows([cancelled]);
    }
    if (sql.startsWith('INSERT INTO foundation.audit_logs')) {
      if (this.failAudit) {
        throw Object.assign(new Error('audit down'), { code: '57014' });
      }
      return rows([]);
    }
    if (sql.startsWith('INSERT INTO foundation.outbox_events')) {
      return rows([]);
    }
    throw new Error(`Unexpected SQL in unit test: ${sql}`);
  }
}

/** Fixture accessors: a missing fixture row is a test bug, never a silent default. */
function formOf(db: FakeDatabase): FakeFormRow {
  if (db.form === null) {
    throw new Error('fixture: form row missing');
  }
  return db.form;
}

function anchorOf(db: FakeDatabase): FakeAnchorRow {
  if (db.anchor === null) {
    throw new Error('fixture: anchor row missing');
  }
  return db.anchor;
}

function consent(id: string): FakeConsentRow {
  return {
    id,
    session_id: SESSION_ID,
    document_id: FORM_ID,
    document_version_id: VERSION_ID,
    purpose: FILE_RESERVATION_PURPOSE,
    action: 'GIVEN',
    legal_basis: 'synthetic-basis',
    source: 'FORM',
    evidence_ref: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    occurred_at: NOW,
    supersedes_id: null,
  };
}

function intentRow(overrides: Partial<FakeIntentRow> = {}): FakeIntentRow {
  return {
    id: INTENT_ID,
    owner_request_session_id: SESSION_ID,
    consent_record_id: EVIDENCE_ID,
    consent_document_version_id: VERSION_ID,
    consent_purpose: FILE_RESERVATION_PURPOSE,
    policy_version_id: POLICY_ID,
    policy_source_ref: 'synthetic/policy/v1',
    policy_sha256: fileReservationPolicy(policy()).sha256,
    policy_expires_at: POLICY_EXPIRES,
    declared_mime: 'image/jpeg',
    declared_bytes: 500,
    expires_at: INTENT_EXPIRES,
    created_at: NOW,
    idempotency_key: IDEMPOTENCY,
    body_sha256: '',
    state: 'RESERVED',
    cancelled_at: null,
    row_version: 1,
    ...overrides,
  };
}

/** The canonical body hash a successful first reserve of `reserveInput()` writes. */
function expectedBodySha256(): string {
  return fileIntentBodySha256({
    consentDocumentVersionId: VERSION_ID,
    consentEvidenceId: EVIDENCE_ID,
    consentPurpose: FILE_RESERVATION_PURPOSE,
    declaredBytes: 500,
    declaredMime: 'image/jpeg',
    expiresAt: INTENT_EXPIRES.toISOString(),
    idempotencyKey: IDEMPOTENCY,
    policySha256: fileReservationPolicy(policy()).sha256,
    policyVersionId: POLICY_ID,
  });
}

/* ------------------------------ input narrowing ---------------------------- */

describe('file reservation input narrowing', () => {
  it('accepts only the closed MIME vocabulary', () => {
    const allMimes = policy({ allowedMimeTypes: [...FILE_MIME_TYPES] });
    for (const mime of FILE_MIME_TYPES) {
      expect(reserveFileUploadInput(reserveInput({ policy: allMimes, declaredMime: mime })).declaredMime).toBe(mime);
    }
    for (const bad of ['image/svg+xml', 'text/html', 'IMAGE/JPEG', 'image/jpg', 'application/octet-stream', '', 1]) {
      expect(codeOf(() => reserveFileUploadInput(reserveInput({ declaredMime: bad })))).toBe('INVALID_INPUT');
    }
  });

  it('requires a mandatory closed policy and never invents a default', () => {
    expect(codeOf(() => reserveFileUploadInput(reserveInput({ policy: undefined })))).toBe('NOT_CONFIGURED');
    expect(codeOf(() => reserveFileUploadInput(reserveInput({ policy: null })))).toBe('NOT_CONFIGURED');
    const cases: unknown[] = [
      {},
      policy({ allowedMimeTypes: [] }),
      policy({ allowedMimeTypes: ['image/svg+xml' as never] }),
      policy({ allowedMimeTypes: ['image/jpeg', 'image/jpeg'] }),
      policy({ maxFileBytes: 0 }),
      policy({ maxFileBytes: -1 }),
      policy({ maxFileBytes: 1.5 }),
      policy({ maxOwnerBytes: Number.MAX_SAFE_INTEGER + 1 }),
      policy({ maxOwnerFiles: 0 }),
      // `max_owner_files` is a PostgreSQL integer column: above 2^31-1 is refused.
      policy({ maxOwnerFiles: 2_147_483_648 }),
      policy({ maxFileBytes: 2_000, maxOwnerBytes: 1_000 }),
      policy({ versionId: 'not-a-uuid' }),
      policy({ sourceRef: '   ' }),
      policy({ expiresAt: 'tomorrow' }),
      { ...policy(), ttlSeconds: 3600 },
    ];
    for (const bad of cases) {
      expect(codeOf(() => reserveFileUploadInput(reserveInput({ policy: bad })))).toBe('NOT_CONFIGURED');
    }
    // A valid snapshot parses and its canonical hash is 64 lowercase hex characters.
    const parsed = fileReservationPolicy(policy());
    expect(parsed.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(parsed.allowedMimeTypes).toEqual(['image/jpeg', 'image/png']);
  });

  it('bounds declared bytes, MIME membership and the explicit expiry', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 1_001, '500', null]) {
      expect(codeOf(() => reserveFileUploadInput(reserveInput({ declaredBytes: bad })))).toBe('INVALID_INPUT');
    }
    // A MIME inside the vocabulary but outside this policy's allowlist is refused.
    expect(codeOf(() => reserveFileUploadInput(reserveInput({ declaredMime: 'application/pdf' })))).toBe('INVALID_INPUT');
    // A reservation may not outlive its policy.
    expect(codeOf(() => reserveFileUploadInput(reserveInput({ expiresAt: new Date('2026-11-21T17:30:00.000Z') }))))
      .toBe('INVALID_INPUT');
    for (const bad of [undefined, 'tomorrow', new Date(Number.NaN)]) {
      expect(codeOf(() => reserveFileUploadInput(reserveInput({ expiresAt: bad })))).toBe('INVALID_INPUT');
    }
    expect(codeOf(() => reserveFileUploadInput(reserveInput({ idempotencyKey: 'not-a-uuid' })))).toBe('INVALID_INPUT');
    expect(codeOf(() => reserveFileUploadInput(reserveInput({ extra: true })))).toBe('INVALID_INPUT');
  });

  it('copies caller Date inputs, so a later mutation cannot change the parsed snapshot', () => {
    const policyExpiresAt = new Date(POLICY_EXPIRES.getTime());
    const intentExpiresAt = new Date(INTENT_EXPIRES.getTime());
    const parsed = reserveFileUploadInput(reserveInput({
      policy: policy({ expiresAt: policyExpiresAt }), expiresAt: intentExpiresAt,
    }));
    const policyExpiry = parsed.policy.expiresAt.getTime();
    const intentExpiry = parsed.expiresAt.getTime();
    const policySha256 = parsed.policy.sha256;
    // The parsed snapshot does not alias the caller's Date objects.
    expect(parsed.policy.expiresAt).not.toBe(policyExpiresAt);
    expect(parsed.expiresAt).not.toBe(intentExpiresAt);
    policyExpiresAt.setTime(Number.NaN);
    intentExpiresAt.setTime(Number.NaN);
    expect(parsed.policy.expiresAt.getTime()).toBe(policyExpiry);
    expect(parsed.expiresAt.getTime()).toBe(intentExpiry);
    expect(parsed.policy.sha256).toBe(policySha256);
  });

  it('refuses the staff variant before policy parsing and before any database access', async () => {
    // Both a malformed policy and a staff id: the owner refusal must win, because a
    // staff id from a request body is never a credential.
    expect(codeOf(() => reserveFileUploadInput({
      staffId: 'ffffffff-ffff-4fff-8fff-ffffffffffff', policy: null, declaredMime: 'image/jpeg', declaredBytes: 1,
      expiresAt: INTENT_EXPIRES, idempotencyKey: IDEMPOTENCY,
    }))).toBe('UNSUPPORTED_OWNER');
    expect(codeOf(() => reserveFileUploadInput(reserveInput({
      staffId: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
    })))).toBe('UNSUPPORTED_OWNER');

    const db = new FakeDatabase();
    expect(await asyncCodeOf(() => reserveFileUpload(reserveDb(db), {
      staffId: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
    }))).toBe('UNSUPPORTED_OWNER');
    // No transaction guard, no lock, no INSERT: the refusal is pre-database.
    expect(db.statements).toHaveLength(0);
  });

  it('accepts only plain data records: no prototype, accessor, symbol or hidden key', () => {
    const getter = { ...reserveInput() } as Record<string, unknown>;
    Object.defineProperty(getter, 'declaredBytes', { get: () => 500, enumerable: true });
    expect(codeOf(() => reserveFileUploadInput(getter))).toBe('INVALID_INPUT');

    class Payload {
      readonly session = { sessionId: SESSION_ID, token: TOKEN };
      readonly policy = policy();
      readonly declaredMime = 'image/jpeg';
      readonly declaredBytes = 500;
      readonly expiresAt = INTENT_EXPIRES;
      readonly idempotencyKey = IDEMPOTENCY;
    }
    expect(codeOf(() => reserveFileUploadInput(new Payload()))).toBe('INVALID_INPUT');

    const symbolic = { ...reserveInput(), [Symbol('x')]: 1 };
    expect(codeOf(() => reserveFileUploadInput(symbolic))).toBe('INVALID_INPUT');

    const hidden = { ...reserveInput() };
    Object.defineProperty(hidden, 'ttlSeconds', { value: 3600, enumerable: false });
    expect(codeOf(() => reserveFileUploadInput(hidden))).toBe('INVALID_INPUT');

    // A hidden (non-enumerable) staff id is still seen and refused as a staff owner.
    const hiddenStaff = { ...reserveInput() };
    Object.defineProperty(hiddenStaff, 'staffId', { value: 'x', enumerable: false });
    expect(codeOf(() => reserveFileUploadInput(hiddenStaff))).toBe('UNSUPPORTED_OWNER');

    // A null-prototype record is a plain record and is accepted.
    const nullProto = Object.assign(Object.create(null) as Record<string, unknown>, reserveInput());
    expect(reserveFileUploadInput(nullProto).declaredBytes).toBe(500);
  });

  it('requires the raw session proof and refuses a trusted-capability shape', () => {
    for (const bad of [{ sessionId: SESSION_ID }, { sessionId: SESSION_ID, token: 'short' },
      { sessionId: SESSION_ID, token: 'A'.repeat(513) }, { sessionId: 'not-a-uuid', token: TOKEN },
      { sessionId: SESSION_ID, token: 'A'.repeat(43), extra: 1 }]) {
      expect(codeOf(() => reserveFileUploadInput(reserveInput({ session: bad })))).toBe('INVALID_INPUT');
    }
    expect(codeOf(() => readFileUploadIntentInput({ session: { sessionId: SESSION_ID, token: TOKEN } })))
      .toBe('INVALID_INPUT');
    expect(codeOf(() => cancelFileUploadIntentInput({
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID, expectedVersion: 0,
    }))).toBe('INVALID_INPUT');
    // `row_version` is a PostgreSQL integer, so a value above its range cannot match.
    expect(codeOf(() => cancelFileUploadIntentInput({
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID, expectedVersion: 2_147_483_648,
    }))).toBe('INVALID_INPUT');
  });
});

/* ------------------------------- canonical hash ---------------------------- */

describe('canonical policy and idempotency hashing', () => {
  it('hashes the policy snapshot independently of the allowlist order', () => {
    const a = fileReservationPolicy(policy({ allowedMimeTypes: ['image/jpeg', 'image/png'] }));
    const b = fileReservationPolicy(policy({ allowedMimeTypes: ['image/png', 'image/jpeg'] }));
    expect(a.sha256).toBe(b.sha256);
    // The canonical form is the sorted, fixed-order snapshot.
    expect(canonicalFilePolicy({
      versionId: POLICY_ID, sourceRef: 'synthetic/policy/v1', allowedMimeTypes: ['image/png', 'image/jpeg'],
      maxFileBytes: 1_000, maxOwnerBytes: 5_000, maxOwnerFiles: 3, policyExpiresAt: POLICY_EXPIRES.toISOString(),
    })).toBe(canonicalFilePolicy({
      versionId: POLICY_ID, sourceRef: 'synthetic/policy/v1', allowedMimeTypes: ['image/jpeg', 'image/png'],
      maxFileBytes: 1_000, maxOwnerBytes: 5_000, maxOwnerFiles: 3, policyExpiresAt: POLICY_EXPIRES.toISOString(),
    }));
  });

  it('changes the policy hash when any snapshot field changes', () => {
    const base = fileReservationPolicy(policy()).sha256;
    const variants = [
      policy({ sourceRef: 'synthetic/policy/v2' }),
      policy({ maxFileBytes: 999 }),
      policy({ maxOwnerBytes: 4_999 }),
      policy({ maxOwnerFiles: 2 }),
      policy({ allowedMimeTypes: ['image/jpeg'] }),
      policy({ versionId: OTHER_SESSION_ID }),
      policy({ expiresAt: new Date('2026-11-21T16:00:00.000Z') }),
    ];
    const hashes = new Set(variants.map((variant) => fileReservationPolicy(variant).sha256));
    expect(hashes.size).toBe(variants.length);
    expect(hashes.has(base)).toBe(false);
  });

  it('binds the idempotency payload to the exact basis, policy hash, MIME, bytes and expiry', () => {
    const base = canonicalFileIntentPayload({
      consentDocumentVersionId: VERSION_ID, consentEvidenceId: EVIDENCE_ID, consentPurpose: FILE_RESERVATION_PURPOSE,
      declaredBytes: 500, declaredMime: 'image/jpeg', expiresAt: INTENT_EXPIRES.toISOString(),
      idempotencyKey: IDEMPOTENCY, policySha256: fileReservationPolicy(policy()).sha256, policyVersionId: POLICY_ID,
    });
    expect(fileIntentBodySha256(JSON.parse(base) as never)).toMatch(/^[0-9a-f]{64}$/);
    const variants = [
      { declaredBytes: 501 },
      { declaredMime: 'image/png' as const },
      { expiresAt: new Date('2026-11-21T14:00:00.000Z').toISOString() },
      { consentEvidenceId: OTHER_EVIDENCE_ID },
      { consentDocumentVersionId: OTHER_EVIDENCE_ID },
      { policyVersionId: OTHER_SESSION_ID },
      { policySha256: sha256Hex('other-policy') },
      { idempotencyKey: OTHER_SESSION_ID },
    ];
    const hashes = new Set(variants.map((variant) => fileIntentBodySha256({
      consentDocumentVersionId: VERSION_ID, consentEvidenceId: EVIDENCE_ID, consentPurpose: FILE_RESERVATION_PURPOSE,
      declaredBytes: 500, declaredMime: 'image/jpeg', expiresAt: INTENT_EXPIRES.toISOString(),
      idempotencyKey: IDEMPOTENCY, policySha256: fileReservationPolicy(policy()).sha256, policyVersionId: POLICY_ID,
      ...variant,
    })));
    expect(hashes.size).toBe(variants.length);
    // The canonical payload carries no token, no session id and no legal text.
    expect(Object.keys(JSON.parse(base) as Record<string, unknown>).sort()).toEqual([
      'consentDocumentVersionId', 'consentEvidenceId', 'consentPurpose', 'declaredBytes', 'declaredMime',
      'expiresAt', 'idempotencyKey', 'policySha256', 'policyVersionId',
    ]);
    expect(base).not.toContain(TOKEN);
    expect(base).not.toContain(SESSION_ID);
    expect(filePolicySha256({
      versionId: POLICY_ID, sourceRef: 'synthetic/policy/v1', allowedMimeTypes: ['image/jpeg', 'image/png'],
      maxFileBytes: 1_000, maxOwnerBytes: 5_000, maxOwnerFiles: 3, policyExpiresAt: POLICY_EXPIRES.toISOString(),
    })).toMatch(/^[0-9a-f]{64}$/);
  });
});

/* ------------------------------ audit payload ----------------------------- */

/** The exact nine keys of the reviewed payload, sorted. */
const AUDIT_KEYS = [
  'consentEvidenceId', 'declaredBytes', 'declaredMime', 'intentId', 'policyVersionId', 'purpose', 'rowVersion',
  'sessionId', 'state',
];

function auditPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    intentId: INTENT_ID,
    sessionId: SESSION_ID,
    policyVersionId: POLICY_ID,
    declaredMime: 'image/jpeg',
    declaredBytes: 500,
    purpose: FILE_RESERVATION_PURPOSE,
    consentEvidenceId: EVIDENCE_ID,
    state: 'RESERVED',
    rowVersion: 1,
    ...overrides,
  };
}

/** The same payload without one key: a missing key is not the same as `undefined`. */
function withoutKey(key: string): Record<string, unknown> {
  const payload = auditPayload();
  Reflect.deleteProperty(payload, key);
  return payload;
}

function asAuditDetails(value: unknown): FileIntentAuditDetails {
  return value as FileIntentAuditDetails;
}

describe('file reservation audit payload', () => {
  it('accepts exactly the nine required keys and returns a normalized plain record', () => {
    const safe = safeFileIntentAuditDetails(auditPayload());
    expect(Object.keys(safe).sort()).toEqual(AUDIT_KEYS);
    expect(safe).toEqual(auditPayload());
    expect(Object.getPrototypeOf(safe)).toBe(Object.prototype);
    // Identifiers are normalized (lower-case UUID), never stored verbatim.
    expect(safeFileIntentAuditDetails(auditPayload({ intentId: INTENT_ID.toUpperCase() })).intentId).toBe(INTENT_ID);
    // A null-prototype record is still a plain record and is accepted.
    expect(safeFileIntentAuditDetails(Object.assign(Object.create(null) as Record<string, unknown>, auditPayload())))
      .toEqual(auditPayload());
  });

  it('refuses missing, unknown and Partial payloads instead of accepting a subset', () => {
    for (const key of AUDIT_KEYS) {
      expect(codeOf(() => safeFileIntentAuditDetails(withoutKey(key)))).toBe('INVALID_INPUT');
    }
    for (const details of [
      { ...auditPayload(), token: TOKEN },
      { ...auditPayload(), sourceRef: 'synthetic/policy/v1' },
      { ...auditPayload(), bodySha256: sha256Hex('x') },
      { ...auditPayload(), url: 'https://example.invalid/object' },
      { intentId: INTENT_ID, sessionId: SESSION_ID },
      {},
    ]) {
      expect(codeOf(() => safeFileIntentAuditDetails(details))).toBe('INVALID_INPUT');
    }
  });

  it('refuses a short arbitrary string under an allowed key: fields are identifiers, not free text', () => {
    for (const details of [
      auditPayload({ intentId: 'short' }),
      auditPayload({ sessionId: 'x' }),
      auditPayload({ policyVersionId: 'not-a-uuid' }),
      auditPayload({ consentEvidenceId: 'short' }),
      auditPayload({ declaredMime: 'text/html' }),
      auditPayload({ purpose: 'ANALYTICS' }),
      auditPayload({ state: 'READY' }),
    ]) {
      expect(codeOf(() => safeFileIntentAuditDetails(details))).toBe('INVALID_INPUT');
    }
    // The refusal is a bare code and never echoes the submitted value.
    try {
      safeFileIntentAuditDetails(auditPayload({ intentId: 'SECRETSHORTVALUE' }));
      throw new Error('expected an INVALID_INPUT refusal');
    } catch (error) {
      expect(error).toBeInstanceOf(FileReservationError);
      expect((error as FileReservationError).message).toBe('INVALID_INPUT');
    }
  });

  it('refuses string, fractional, zero, unsafe and PostgreSQL-overflow numbers', () => {
    for (const details of [
      auditPayload({ declaredBytes: '500' }),
      auditPayload({ declaredBytes: 0 }),
      auditPayload({ declaredBytes: -1 }),
      auditPayload({ declaredBytes: 1.5 }),
      auditPayload({ declaredBytes: Number.MAX_SAFE_INTEGER + 1 }),
      auditPayload({ declaredBytes: Number.NaN }),
      auditPayload({ rowVersion: 0 }),
      auditPayload({ rowVersion: 1.5 }),
      // `row_version` is a PostgreSQL integer, so 2^31-1 is the inclusive maximum.
      auditPayload({ rowVersion: 2_147_483_648 }),
      auditPayload({ rowVersion: true }),
    ]) {
      expect(codeOf(() => safeFileIntentAuditDetails(details))).toBe('INVALID_INPUT');
    }
    expect(safeFileIntentAuditDetails(auditPayload({ rowVersion: 2_147_483_647 })).rowVersion).toBe(2_147_483_647);
  });

  it('refuses arrays, class instances, custom prototypes, symbols and accessors', () => {
    class AuditShape {
      readonly intentId = INTENT_ID;
      readonly sessionId = SESSION_ID;
      readonly policyVersionId = POLICY_ID;
      readonly declaredMime = 'image/jpeg';
      readonly declaredBytes = 500;
      readonly purpose = FILE_RESERVATION_PURPOSE;
      readonly consentEvidenceId = EVIDENCE_ID;
      readonly state = 'RESERVED';
      readonly rowVersion = 1;
    }
    const accessor = auditPayload();
    Object.defineProperty(accessor, 'declaredBytes', { get: () => 500, enumerable: true });
    const hidden = auditPayload();
    Object.defineProperty(hidden, 'intentId', { value: INTENT_ID, enumerable: false });
    const customPrototype = Object.assign(Object.create({ inherited: true }) as Record<string, unknown>, auditPayload());
    for (const details of [
      Object.assign([], auditPayload()),
      new AuditShape(),
      customPrototype,
      { ...auditPayload(), [Symbol('x')]: 1 },
      accessor,
      new Date(),
      'audit',
      null,
    ]) {
      expect(codeOf(() => safeFileIntentAuditDetails(details))).toBe('INVALID_INPUT');
    }
  });

  it('writes one audit/outbox pair and validates the operation/state pair before any query', async () => {
    const db = new FakeDatabase();
    await writeFileIntentAudit(db.client, 'FILE_UPLOAD_INTENT_RESERVED', asAuditDetails(auditPayload()));
    expect(db.countOf('INSERT INTO foundation.audit_logs')).toBe(1);
    expect(db.countOf('INSERT INTO foundation.outbox_events')).toBe(1);
    const auditStatement = db.statements.find((statement) => statement.text.startsWith('INSERT INTO foundation.audit_logs'));
    expect(auditStatement?.params[1]).toBe('FILE_UPLOAD_INTENT_RESERVED');
    const stored = JSON.parse(String(auditStatement?.params[3])) as Record<string, unknown>;
    expect(Object.keys(stored).sort()).toEqual(AUDIT_KEYS);
    expect(stored['state']).toBe('RESERVED');
    // The persisted payload carries no token, no hash and no free text.
    expect(JSON.stringify(stored)).not.toContain(TOKEN);
    expect(JSON.stringify(stored)).not.toContain('synthetic-basis');

    // A cancel payload is valid only for the cancel operation.
    const cancelled = new FakeDatabase();
    await writeFileIntentAudit(cancelled.client, 'FILE_UPLOAD_INTENT_CANCELLED',
      asAuditDetails(auditPayload({ state: 'CANCELLED', rowVersion: 2 })));
    expect(cancelled.countOf('INSERT INTO foundation.outbox_events')).toBe(1);

    // A mismatched operation/state pair and an unknown operation write nothing.
    for (const operation of ['FILE_UPLOAD_INTENT_RESERVED', 'FILE_UPLOAD_INTENT_CANCELLED'] as const) {
      const mismatch = new FakeDatabase();
      const state = operation === 'FILE_UPLOAD_INTENT_RESERVED' ? 'CANCELLED' : 'RESERVED';
      await expect(writeFileIntentAudit(mismatch.client, operation, asAuditDetails(auditPayload({ state }))))
        .rejects.toThrow(FileReservationError);
      expect(mismatch.statements).toHaveLength(0);
    }
    const unknownOperation = new FakeDatabase();
    await expect(writeFileIntentAudit(unknownOperation.client, 'FILE_UPLOAD_INTENT_READY' as never,
      asAuditDetails(auditPayload()))).rejects.toThrow(FileReservationError);
    expect(unknownOperation.statements).toHaveLength(0);

    // An invalid payload is refused before the first statement, for both operations.
    const invalid = new FakeDatabase();
    for (const operation of ['FILE_UPLOAD_INTENT_RESERVED', 'FILE_UPLOAD_INTENT_CANCELLED'] as const) {
      await expect(writeFileIntentAudit(invalid.client, operation, asAuditDetails(withoutKey('intentId'))))
        .rejects.toThrow(FileReservationError);
      await expect(writeFileIntentAudit(invalid.client, operation, asAuditDetails(auditPayload({ intentId: 'short' }))))
        .rejects.toThrow(FileReservationError);
    }
    expect(invalid.statements).toHaveLength(0);
  });

  it('does not expose the audit writer or its validator on the public reservation surface', () => {
    expect(Object.keys(reservationSurface)).not.toContain('writeFileIntentAudit');
    expect(Object.keys(reservationSurface)).not.toContain('safeFileIntentAuditDetails');
    // The ports and the closed vocabulary stay exported.
    expect(typeof reservationSurface.reserveFileUpload).toBe('function');
    expect(typeof reservationSurface.cancelFileUploadIntent).toBe('function');
    expect(reservationSurface.FILE_MIME_TYPES).toEqual(FILE_MIME_TYPES);
  });
});

/* ----------------------------- error translation --------------------------- */

describe('file reservation error translation', () => {
  it('maps driver integrity failures to typed refusals', () => {
    const expectCode = (error: unknown): FileReservationErrorCode => codeOf(() => mapFileReservationDbError(error));
    expect(expectCode(Object.assign(new Error('dup'), {
      code: '23505', constraint: 'file_upload_intents_session_idempotency_key',
    }))).toBe('IDEMPOTENCY_CONFLICT');
    expect(expectCode(Object.assign(new Error('dup'), { code: '23505', constraint: 'other_key' }))).toBe('ALREADY_EXISTS');
    expect(expectCode(Object.assign(new Error('fk'), { code: '23503' }))).toBe('INVALID_REFERENCE');
    // The composite consent-basis FK is the bypass-path translation of the same
    // "not this session/version/purpose" denial the guard reports as 23514.
    expect(expectCode(Object.assign(new Error('fk'), {
      code: '23503', constraint: 'file_upload_intents_consent_basis_fkey',
    }))).toBe('CONSENT_NOT_CURRENT');
    expect(expectCode(Object.assign(new Error('check'), {
      code: '23514', constraint: 'file_upload_intents_quota',
    }))).toBe('QUOTA_EXCEEDED');
    expect(expectCode(Object.assign(new Error('check'), { code: '23514', constraint: 'x_consent_y' })))
      .toBe('CONSENT_NOT_CURRENT');
    // Migration 014 guard constraint names map to the precise typed denial.
    expect(expectCode(Object.assign(new Error('guard'), {
      code: '23514', constraint: 'file_upload_intents_session',
    }))).toBe('SESSION_EXPIRED');
    expect(expectCode(Object.assign(new Error('guard'), {
      code: '23514', constraint: 'file_upload_intents_expiry',
    }))).toBe('INTENT_EXPIRED');
    expect(expectCode(Object.assign(new Error('guard'), {
      code: '23514', constraint: 'file_upload_intents_policy',
    }))).toBe('NOT_CONFIGURED');
    expect(expectCode(Object.assign(new Error('guard'), {
      code: '23514', constraint: 'file_upload_intents_state_transition',
    }))).toBe('STALE_VERSION');
    expect(expectCode(Object.assign(new Error('check'), { code: '23514', constraint: 'x' }))).toBe('INVALID_INPUT');
    expect(expectCode(Object.assign(new Error('snapshot'), { code: '25001' }))).toBe('CONFLICT');
    expect(expectCode(Object.assign(new Error('deadlock'), { code: '40P01' }))).toBe('CONFLICT');
    // A typed refusal is rethrown unchanged; an unknown driver failure is not hidden.
    const typed = new FileReservationError('QUOTA_EXCEEDED');
    expect(codeOf(() => mapFileReservationDbError(typed))).toBe('QUOTA_EXCEEDED');
    const unknown = Object.assign(new Error('boom'), { code: 'XX000' });
    expect(() => mapFileReservationDbError(unknown)).toThrow(unknown);
  });

  it('translates legal refusals without ever reporting an approval', () => {
    const expectCode = (error: unknown): FileReservationErrorCode => codeOf(() => mapLegalPortError(error));
    expect(expectCode(new LegalPortError('SESSION_EXPIRED'))).toBe('SESSION_EXPIRED');
    expect(expectCode(new LegalPortError('SESSION_REVOKED'))).toBe('SESSION_REVOKED');
    expect(expectCode(new LegalPortError('CONSENT_REVOKED'))).toBe('CONSENT_REVOKED');
    expect(expectCode(new LegalPortError('DOCUMENT_NOT_CURRENT'))).toBe('CONSENT_NOT_CURRENT');
    expect(expectCode(new LegalPortError('DOCUMENT_NOT_PUBLISHED'))).toBe('CONSENT_NOT_PUBLISHED');
    expect(expectCode(new LegalPortError('NOT_FOUND'))).toBe('NOT_FOUND');
    expect(expectCode(new LegalPortError('CONFLICT'))).toBe('CONFLICT');
    expect(expectCode(new LegalPortError('KIND_NOT_CONSENT_FORM'))).toBe('CONFLICT');
  });
});

/* ------------------------------ port behaviour ----------------------------- */

function reserveDb(db: FakeDatabase): FileReservationSqlClient {
  return db.client;
}

describe('reserveFileUpload ordering and guards', () => {
  it('fails NOT_CONFIGURED before any database statement when the policy is missing', async () => {
    const db = new FakeDatabase();
    expect(await asyncCodeOf(() => reserveFileUpload(db.client, reserveInput({ policy: undefined }))))
      .toBe('NOT_CONFIGURED');
    expect(db.statements).toHaveLength(0);
    expect(db.insertsIntoIntents).toBe(0);
  });

  it('runs the READ COMMITTED guard first, then session → document → intent, and writes one audit/outbox pair', async () => {
    const db = new FakeDatabase();
    const result = await reserveFileUpload(db.client, reserveInput());

    expect(db.statements[0]?.text).toBe('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
    const sessionLock = db.indexOf('FROM foundation.request_sessions');
    const documentLock = db.indexOf('FROM foundation.legal_documents');
    const intentInsert = db.indexOf('INSERT INTO foundation.file_upload_intents');
    expect(sessionLock).toBeGreaterThan(0);
    expect(documentLock).toBeGreaterThan(sessionLock);
    expect(intentInsert).toBeGreaterThan(documentLock);
    expect(db.countOf('INSERT INTO foundation.file_upload_intents')).toBe(1);
    expect(db.countOf('INSERT INTO foundation.audit_logs')).toBe(1);
    expect(db.countOf('INSERT INTO foundation.outbox_events')).toBe(1);
    // No destructive or state-changing SQL other than the single intent INSERT.
    expect(db.writes.every((text) => text.startsWith('INSERT'))).toBe(true);

    expect(result.replayed).toBe(false);
    expect(result.state).toBe('RESERVED');
    expect(result.rowVersion).toBe(1);
    expect(result.intentId).toBe(String(db.statements
      .find((statement) => statement.text.startsWith('INSERT INTO foundation.file_upload_intents'))?.params[0]));
    // Safe DTO: identifiers, sizes, MIME, state, policy ids and timestamps only.
    expect(Object.keys(result).sort()).toEqual([
      'cancelledAt', 'consentDocumentVersionId', 'consentEvidenceId', 'consentPurpose', 'createdAt', 'declaredBytes',
      'declaredMime', 'expiresAt', 'intentId', 'policySha256', 'policySourceRef', 'policyVersionId', 'replayed',
      'rowVersion', 'state',
    ]);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(TOKEN);
    expect(serialized).not.toContain(hashSessionSecret(TOKEN));
    expect(serialized).not.toContain('idempotencyKey');
    expect(serialized).not.toContain('bodySha256');
    expect(serialized).not.toContain('synthetic-basis');
    // The raw token never reaches the INSERT parameters.
    const insert = db.statements.find((statement) => statement.text.startsWith('INSERT INTO foundation.file_upload_intents'));
    expect(JSON.stringify(insert?.params)).not.toContain(TOKEN);
  });

  it('refuses an autocommit client with CONFLICT before any domain read', async () => {
    const db = new FakeDatabase();
    db.transaction = 'autocommit';
    expect(await asyncCodeOf(() => reserveFileUpload(db.client, reserveInput()))).toBe('CONFLICT');
    expect(db.countOf('FROM foundation.request_sessions')).toBe(0);
    expect(db.insertsIntoIntents).toBe(0);
  });

  it('returns the stored intent for an identical replay and writes no second row', async () => {
    const db = new FakeDatabase();
    db.intent = intentRow({ body_sha256: expectedBodySha256() });
    const result = await reserveFileUpload(db.client, reserveInput());
    expect(result.replayed).toBe(true);
    expect(result.intentId).toBe(INTENT_ID);
    expect(db.insertsIntoIntents).toBe(0);
    expect(db.countOf('INSERT INTO foundation.audit_logs')).toBe(0);
  });

  it('refuses a changed payload under the same owner/key', async () => {
    const db = new FakeDatabase();
    db.intent = intentRow({ body_sha256: expectedBodySha256() });
    expect(await asyncCodeOf(() => reserveFileUpload(db.client, reserveInput({ declaredBytes: 501 }))))
      .toBe('IDEMPOTENCY_CONFLICT');
    expect(db.insertsIntoIntents).toBe(0);
  });

  it('never revives a cancelled or expired intent on replay', async () => {
    const cancelled = new FakeDatabase();
    cancelled.intent = intentRow({ body_sha256: expectedBodySha256(), state: 'CANCELLED', cancelled_at: NOW });
    expect(await asyncCodeOf(() => reserveFileUpload(cancelled.client, reserveInput()))).toBe('INTENT_CANCELLED');
    expect(cancelled.insertsIntoIntents).toBe(0);

    const expired = new FakeDatabase();
    expired.intent = intentRow({
      body_sha256: expectedBodySha256(), expires_at: new Date('2026-11-21T11:00:00.000Z'),
    });
    expect(await asyncCodeOf(() => reserveFileUpload(expired.client, reserveInput()))).toBe('INTENT_EXPIRED');
    expect(expired.insertsIntoIntents).toBe(0);
  });

  it('refuses a replay whose stored basis is not the exact current GIVEN', async () => {
    const db = new FakeDatabase();
    // A revoke followed by a new GIVEN: the current basis is a different event.
    db.given = consent(OTHER_EVIDENCE_ID);
    db.intent = intentRow({ body_sha256: expectedBodySha256() });
    expect(await asyncCodeOf(() => reserveFileUpload(db.client, reserveInput()))).toBe('CONSENT_NOT_CURRENT');
    expect(db.insertsIntoIntents).toBe(0);
  });

  it('refuses an absent or revoked GIVEN and a stale document', async () => {
    const revoked = new FakeDatabase();
    revoked.given = null;
    revoked.withdrawn = consent(EVIDENCE_ID);
    expect(await asyncCodeOf(() => reserveFileUpload(revoked.client, reserveInput()))).toBe('CONSENT_REVOKED');

    const absent = new FakeDatabase();
    absent.given = null;
    expect(await asyncCodeOf(() => reserveFileUpload(absent.client, reserveInput()))).toBe('CONSENT_NOT_GIVEN');

    const stale = new FakeDatabase();
    stale.form = { ...formOf(stale), current_version_id: OTHER_EVIDENCE_ID };
    stale.given = null;
    stale.older = consent(EVIDENCE_ID);
    expect(await asyncCodeOf(() => reserveFileUpload(stale.client, reserveInput()))).toBe('CONSENT_NOT_CURRENT');

    const unpublished = new FakeDatabase();
    unpublished.form = { ...formOf(unpublished), current_version_id: null, legal_basis: null };
    expect(await asyncCodeOf(() => reserveFileUpload(unpublished.client, reserveInput()))).toBe('CONSENT_NOT_PUBLISHED');
  });

  it('refuses a dead anchor with the precise session code', async () => {
    const expired = new FakeDatabase();
    expired.anchor = { ...anchorOf(expired), expires_at: new Date('2026-11-21T11:00:00.000Z') };
    expect(await asyncCodeOf(() => reserveFileUpload(expired.client, reserveInput()))).toBe('SESSION_EXPIRED');

    const revoked = new FakeDatabase();
    revoked.anchor = { ...anchorOf(revoked), revoked_at: new Date('2026-11-21T11:30:00.000Z') };
    expect(await asyncCodeOf(() => reserveFileUpload(revoked.client, reserveInput()))).toBe('SESSION_REVOKED');

    // A wrong raw token is indistinguishable from a missing anchor.
    const wrongToken = new FakeDatabase();
    expect(await asyncCodeOf(() => reserveFileUpload(wrongToken.client, reserveInput({
      session: { sessionId: SESSION_ID, token: 'B'.repeat(43) },
    })))).toBe('NOT_FOUND');
  });

  it('enforces the owner quota snapshot and the session-expiry ceiling without writing', async () => {
    const quota = new FakeDatabase();
    quota.activeCount = 3;
    expect(await asyncCodeOf(() => reserveFileUpload(quota.client, reserveInput()))).toBe('QUOTA_EXCEEDED');
    expect(quota.insertsIntoIntents).toBe(0);

    const bytes = new FakeDatabase();
    bytes.activeBytes = 4_800;
    expect(await asyncCodeOf(() => reserveFileUpload(bytes.client, reserveInput()))).toBe('QUOTA_EXCEEDED');

    const tooLong = new FakeDatabase();
    expect(await asyncCodeOf(() => reserveFileUpload(tooLong.client, reserveInput({
      expiresAt: new Date('2026-11-21T17:30:00.000Z'),
    })))).toBe('INVALID_INPUT');
    expect(tooLong.insertsIntoIntents).toBe(0);

    // Expiry passed relative to the database clock, after the locks were taken.
    const late = new FakeDatabase();
    late.now = new Date('2026-11-21T15:00:00.000Z');
    expect(await asyncCodeOf(() => reserveFileUpload(late.client, reserveInput()))).toBe('INVALID_INPUT');
    expect(late.insertsIntoIntents).toBe(0);
  });

  it('refuses an expired policy snapshot with NOT_CONFIGURED and no write', async () => {
    const db = new FakeDatabase();
    db.now = new Date('2026-11-21T17:30:00.000Z');
    expect(await asyncCodeOf(() => reserveFileUpload(db.client, reserveInput()))).toBe('NOT_CONFIGURED');
    expect(db.insertsIntoIntents).toBe(0);
    expect(db.countOf('INSERT INTO foundation.audit_logs')).toBe(0);
  });

  it('rejects a contradicting hash for an already stored policy version of this owner', async () => {
    const db = new FakeDatabase();
    db.policyVersionConflict = true;
    expect(await asyncCodeOf(() => reserveFileUpload(db.client, reserveInput()))).toBe('POLICY_VERSION_CONFLICT');
    expect(db.insertsIntoIntents).toBe(0);
  });

  it('rolls the intent back when the audit/outbox write fails', async () => {
    const db = new FakeDatabase();
    db.failAudit = true;
    // The audit failure is not a known constraint error, so it propagates and the
    // caller's transaction (which owns the intent INSERT) rolls back.
    await expect(reserveFileUpload(db.client, reserveInput())).rejects.toThrow('audit down');
    expect(db.insertsIntoIntents).toBe(1);
  });
});

describe('readFileUploadIntent', () => {
  it('locks the session before the intent and returns no secret material', async () => {
    const db = new FakeDatabase();
    db.intent = intentRow({ body_sha256: expectedBodySha256() });
    const view = await readFileUploadIntent(db.client, { session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID });

    expect(db.statements[0]?.text).toBe('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
    expect(db.indexOf('FROM foundation.request_sessions')).toBeLessThan(db.indexOf('FROM foundation.file_upload_intents i'));
    expect(view.intentId).toBe(INTENT_ID);
    expect(view.state).toBe('RESERVED');
    const serialized = JSON.stringify(view);
    expect(serialized).not.toContain(TOKEN);
    expect(serialized).not.toContain(hashSessionSecret(TOKEN));
    expect(serialized).not.toContain('bodySha256');
    expect(serialized).not.toContain('idempotencyKey');
    expect(serialized).not.toContain('synthetic-basis');
    expect(db.writes).toHaveLength(0);
  });

  it('returns one safe NOT_FOUND for a foreign or missing intent', async () => {
    const foreign = new FakeDatabase();
    foreign.intent = intentRow({ owner_request_session_id: OTHER_SESSION_ID, body_sha256: expectedBodySha256() });
    expect(await asyncCodeOf(() => readFileUploadIntent(foreign.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID,
    }))).toBe('NOT_FOUND');

    const missing = new FakeDatabase();
    expect(await asyncCodeOf(() => readFileUploadIntent(missing.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID,
    }))).toBe('NOT_FOUND');
    expect(missing.writes).toHaveLength(0);
  });

  it('denies a read when the stored basis is no longer the exact current GIVEN', async () => {
    const db = new FakeDatabase();
    db.intent = intentRow({ body_sha256: expectedBodySha256() });
    db.given = consent(OTHER_EVIDENCE_ID);
    expect(await asyncCodeOf(() => readFileUploadIntent(db.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID,
    }))).toBe('CONSENT_NOT_CURRENT');
  });

  it('denies a read of an expired intent on the database clock', async () => {
    const db = new FakeDatabase();
    db.intent = intentRow({ body_sha256: expectedBodySha256() });
    db.now = new Date('2026-11-21T15:00:00.000Z');
    expect(await asyncCodeOf(() => readFileUploadIntent(db.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID,
    }))).toBe('INTENT_EXPIRED');
  });
});

describe('cancelFileUploadIntent', () => {
  it('needs no new consent: it cancels after a revoke with a live session, one-way CAS', async () => {
    const db = new FakeDatabase();
    db.intent = intentRow({ body_sha256: expectedBodySha256() });
    // Consent withdrawn: read/replay would now deny, cancel must still work.
    db.given = null;
    db.withdrawn = consent(EVIDENCE_ID);

    const result = await cancelFileUploadIntent(db.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID, expectedVersion: 1,
    });
    expect(result.state).toBe('CANCELLED');
    expect(result.rowVersion).toBe(2);
    expect(result.cancelledAt).toBe(db.now.toISOString());
    expect(result.replayed).toBe(false);
    // The cancel receipt is the minimal cancellation record, not the whole view.
    expect(Object.keys(result).sort()).toEqual(['cancelledAt', 'intentId', 'replayed', 'rowVersion', 'state']);
    expect(JSON.stringify(result)).not.toContain('declaredMime');
    expect(JSON.stringify(result)).not.toContain(TOKEN);
    // No consent/document read on the cancel path: no new consent is required.
    expect(db.countOf('FROM foundation.consent_records')).toBe(0);
    expect(db.countOf('FROM foundation.legal_documents')).toBe(0);
    // Session lock strictly before the intent row lock.
    expect(db.indexOf('FROM foundation.request_sessions'))
      .toBeLessThan(db.indexOf('FROM foundation.file_upload_intents i'));
    // Exactly one UPDATE, and its SET clause only sets state (the DB trigger stamps
    // cancelled_at and row_version; the RETURNING list merely reads them back).
    const updates = db.statements.filter((statement) => statement.text.startsWith('UPDATE foundation.file_upload_intents'));
    expect(updates).toHaveLength(1);
    const setClause = (updates[0]?.text ?? '').replace(/\s+/g, ' ').split(' SET ')[1]?.split(' WHERE ')[0]?.trim();
    expect(setClause).toBe("state='CANCELLED'");
    expect(db.countOf('INSERT INTO foundation.audit_logs')).toBe(1);
    expect(db.countOf('INSERT INTO foundation.outbox_events')).toBe(1);
    expect(db.countOf('DELETE')).toBe(0);
  });

  it('cancels a historical reservation after intent/policy expiry: withdrawal needs no live policy', async () => {
    const db = new FakeDatabase();
    db.intent = intentRow({
      body_sha256: expectedBodySha256(),
      expires_at: new Date('2026-11-21T11:00:00.000Z'),
      policy_expires_at: new Date('2026-11-21T11:30:00.000Z'),
    });
    db.now = new Date('2026-11-21T12:00:00.000Z');
    // Consent also withdrawn: cancel is a pure withdrawal, so neither the expired
    // policy, the expired intent nor the missing consent may deny it.
    db.given = null;
    db.withdrawn = consent(EVIDENCE_ID);
    const result = await cancelFileUploadIntent(db.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID, expectedVersion: 1,
    });
    expect(result.state).toBe('CANCELLED');
    expect(result.rowVersion).toBe(2);
    expect(result.replayed).toBe(false);
    expect(db.countOf('FROM foundation.consent_records')).toBe(0);
  });

  it('refuses a stale version and a foreign intent', async () => {
    const stale = new FakeDatabase();
    stale.intent = intentRow({ body_sha256: expectedBodySha256() });
    expect(await asyncCodeOf(() => cancelFileUploadIntent(stale.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID, expectedVersion: 7,
    }))).toBe('STALE_VERSION');
    expect(stale.countOf('UPDATE foundation.file_upload_intents')).toBe(0);

    const foreign = new FakeDatabase();
    foreign.intent = intentRow({ owner_request_session_id: OTHER_SESSION_ID, body_sha256: expectedBodySha256() });
    expect(await asyncCodeOf(() => cancelFileUploadIntent(foreign.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID, expectedVersion: 1,
    }))).toBe('NOT_FOUND');
    expect(foreign.countOf('UPDATE foundation.file_upload_intents')).toBe(0);
  });

  it('reports an already cancelled intent as a replay only at the current version', async () => {
    const replay = new FakeDatabase();
    replay.intent = intentRow({
      body_sha256: expectedBodySha256(), state: 'CANCELLED', cancelled_at: NOW, row_version: 2,
    });
    const result = await cancelFileUploadIntent(replay.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID, expectedVersion: 2,
    });
    expect(result.replayed).toBe(true);
    expect(result.state).toBe('CANCELLED');
    expect(replay.countOf('UPDATE foundation.file_upload_intents')).toBe(0);
    expect(replay.countOf('INSERT INTO foundation.audit_logs')).toBe(0);

    expect(await asyncCodeOf(() => cancelFileUploadIntent(replay.client, {
      session: { sessionId: SESSION_ID, token: TOKEN }, intentId: INTENT_ID, expectedVersion: 1,
    }))).toBe('STALE_VERSION');
  });
});
