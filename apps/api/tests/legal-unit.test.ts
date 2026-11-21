/**
 * Unit proofs for the P03-03 legal ports that need no database: input narrowing,
 * hashing/secret comparison, error translation and the audit payload allowlist.
 *
 * These run unconditionally (no isolated PostgreSQL needed), so the security
 * shape of the ports — no coercion of `accepted`, no unknown keys, no raw token in
 * an event, constant-time secret comparison — is proved on every `vitest run`.
 */
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  consentGivenInput, consentRevokeInput, currentConsentInput, documentCreateInput, documentVersionInput,
  kindValue, purposeValue, requestSessionInput, sessionProofInput, uuidValue,
} from '../src/settings/legal/legal-input.js';
import { LegalPortError } from '../src/settings/legal/legal-contract.js';
import type { LegalErrorCode } from '../src/settings/legal/legal-contract.js';
import { hashSessionSecret, sessionSecretMatches, sha256Hex } from '../src/settings/legal/legal-hash.js';
import { mapLegalDbError } from '../src/settings/legal/legal-errors.js';
import type { LegalSqlClient } from '../src/settings/legal/legal-contract.js';
import {
  LEGAL_BEGIN_SQL, LEGAL_ISOLATION_PROBE_SQL, LEGAL_ISOLATION_SQL, LEGAL_REQUIRED_ISOLATION, LEGAL_TX_PROBE_SQL,
  LEGAL_TX_SET_SQL, LEGAL_TX_SETTING, assertCallerTransaction, beginLegalTransaction,
} from '../src/settings/legal/legal-tx.js';

const sha = (value: string): string => sha256Hex(value);

function codeOf(run: () => unknown): LegalErrorCode {
  try {
    run();
  } catch (error) {
    if (error instanceof LegalPortError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a LegalPortError');
}

const SESSION_ID = randomUUID();
const TOKEN = 'A'.repeat(43);
const EVIDENCE = randomUUID();
const VERSION = randomUUID();

describe('legal input narrowing', () => {
  it('accepts only the closed purpose and kind vocabulary', () => {
    expect(purposeValue('REQUEST_PROCESSING')).toBe('REQUEST_PROCESSING');
    expect(purposeValue('MARKETING')).toBe('MARKETING');
    expect(kindValue('CONSENT_FORM')).toBe('CONSENT_FORM');
    for (const bad of ['REQUEST', 'request_processing', '', 1, null, undefined, 'ADDRESS_COVERAGE ']) {
      expect(codeOf(() => purposeValue(bad))).toBe('INVALID_INPUT');
    }
    for (const bad of ['POLICY ', 'CONSENT', 'OPT_IN', 0]) {
      expect(codeOf(() => kindValue(bad))).toBe('INVALID_INPUT');
    }
  });

  it('rejects unknown keys instead of ignoring them', () => {
    expect(codeOf(() => documentCreateInput({ purpose: 'MARKETING', kind: 'POLICY', extra: 1 }))).toBe('INVALID_INPUT');
    expect(codeOf(() => consentGivenInput({
      session: { sessionId: SESSION_ID, token: TOKEN }, purpose: 'MARKETING', documentVersionId: VERSION,
      evidenceRef: EVIDENCE, accepted: true, legalBasis: 'synthetic',
    }))).toBe('INVALID_INPUT');
    expect(codeOf(() => requestSessionInput({
      secretHash: sha('x'), intakeCityId: randomUUID(), intakeCityVersionId: randomUUID(),
      expiresAt: '2026-11-22T00:00:00.000Z', ttlSeconds: 3600,
    }))).toBe('INVALID_INPUT');
  });

  it('never coerces acceptance: only the JSON boolean true is accepted', () => {
    const base = {
      session: { sessionId: SESSION_ID, token: TOKEN }, purpose: 'MARKETING', documentVersionId: VERSION,
      evidenceRef: EVIDENCE,
    };
    expect(consentGivenInput({ ...base, accepted: true }).accepted).toBe(true);
    for (const bad of ['true', 1, 1n, 'yes', {}, [], null, undefined]) {
      expect(codeOf(() => consentGivenInput({ ...base, accepted: bad }))).toBe('INVALID_INPUT');
    }
    // A falsy acceptance is refused as invalid input, not recorded as a refusal event.
    expect(codeOf(() => consentGivenInput({ ...base, accepted: false }))).toBe('INVALID_INPUT');
  });

  it('requires the accepted document version explicitly (no silent text upgrade)', () => {
    const base = {
      session: { sessionId: SESSION_ID, token: TOKEN }, purpose: 'MARKETING', evidenceRef: EVIDENCE, accepted: true,
    };
    expect(codeOf(() => consentGivenInput(base))).toBe('INVALID_INPUT');
    expect(codeOf(() => consentGivenInput({ ...base, documentVersionId: 'not-a-uuid' }))).toBe('INVALID_INPUT');
    expect(consentGivenInput({ ...base, documentVersionId: VERSION }).documentVersionId).toBe(VERSION);
  });

  it('bounds every text field and keeps the body verbatim', () => {
    const body = `  reviewed text ${'x'.repeat(10)}  \n`;
    const parsed = documentVersionInput({
      documentId: randomUUID(), expectedVersion: 1, title: 'T', body, legalBasis: 'basis', sourceRef: 'ref',
      reviewedBy: randomUUID(),
    });
    // The checksum is over these exact bytes, so trimming would change reviewed text.
    expect(parsed.body).toBe(body);
    for (const field of ['title', 'body', 'legalBasis', 'sourceRef'] as const) {
      expect(codeOf(() => documentVersionInput({
        documentId: randomUUID(), expectedVersion: 1, title: 'T', body: 'B', legalBasis: 'L', sourceRef: 'S',
        reviewedBy: randomUUID(), [field]: '   ',
      }))).toBe('INVALID_INPUT');
    }
    expect(codeOf(() => documentVersionInput({
      documentId: randomUUID(), expectedVersion: 0, title: 'T', body: 'B', legalBasis: 'L', sourceRef: 'S',
      reviewedBy: randomUUID(),
    }))).toBe('INVALID_INPUT');
    expect(codeOf(() => documentVersionInput({
      documentId: randomUUID(), expectedVersion: 1, title: 'T', body: 'B'.repeat(200_001), legalBasis: 'L',
      sourceRef: 'S', reviewedBy: randomUUID(),
    }))).toBe('INVALID_INPUT');
  });

  it('requires an explicit trusted expiry and never invents a TTL', () => {
    const base = { secretHash: sha('secret'), intakeCityId: randomUUID(), intakeCityVersionId: randomUUID() };
    expect(codeOf(() => requestSessionInput(base))).toBe('INVALID_INPUT');
    expect(codeOf(() => requestSessionInput({ ...base, expiresAt: 'tomorrow' }))).toBe('INVALID_INPUT');
    expect(codeOf(() => requestSessionInput({ ...base, expiresAt: new Date(Number.NaN) }))).toBe('INVALID_INPUT');
    const parsed = requestSessionInput({ ...base, expiresAt: '2026-11-22T00:00:00.000Z' });
    expect(parsed.expiresAt.toISOString()).toBe('2026-11-22T00:00:00.000Z');
    // The port accepts a hash, never a raw secret.
    expect(codeOf(() => requestSessionInput({ ...base, secretHash: 'raw-secret', expiresAt: '2026-11-22T00:00:00Z' })))
      .toBe('INVALID_INPUT');
  });

  it('rejects a session proof that is only a browser-supplied id', () => {
    expect(codeOf(() => sessionProofInput({ sessionId: SESSION_ID }))).toBe('INVALID_INPUT');
    expect(codeOf(() => sessionProofInput({ sessionId: SESSION_ID, token: 'short' }))).toBe('INVALID_INPUT');
    expect(codeOf(() => sessionProofInput({ sessionId: 'not-a-uuid', token: TOKEN }))).toBe('INVALID_INPUT');
    expect(codeOf(() => sessionProofInput({ sessionId: SESSION_ID, token: TOKEN, trusted: true }))).toBe('INVALID_INPUT');
    expect(codeOf(() => sessionProofInput(SESSION_ID))).toBe('INVALID_INPUT');
    expect(codeOf(() => sessionProofInput(null))).toBe('INVALID_INPUT');
    // A plain object can never carry the capability brand.
    expect(codeOf(() => currentConsentInput({ session: { sessionId: SESSION_ID }, purpose: 'MARKETING' })))
      .toBe('INVALID_INPUT');
  });

  it('normalises uuids and rejects non-uuid identifiers', () => {
    const upper = randomUUID().toUpperCase();
    expect(uuidValue(upper)).toBe(upper.toLowerCase());
    for (const bad of ['1', 'x'.repeat(36), randomUUID().slice(1), 42]) {
      expect(codeOf(() => uuidValue(bad))).toBe('INVALID_INPUT');
    }
    expect(codeOf(() => consentRevokeInput({
      session: { sessionId: SESSION_ID, token: TOKEN }, purpose: 'MARKETING', evidenceRef: EVIDENCE,
      supersedesEvidenceId: 'missing',
    }))).toBe('INVALID_INPUT');
  });
});

describe('legal hashing', () => {
  it('hashes the exact UTF-8 body and matches the database CHECK expression', () => {
    // Known SHA-256 of the empty string and of a UTF-8 multi-byte body: the same
    // expression migration 013 evaluates as encode(sha256(convert_to(body,'UTF8')),'hex').
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('Привет')).toBe('dd679c0b9fd408a04148aa7d30c9df393f67b7227f65693fffe0ed6d0f0ade59');
    expect(sha256Hex('Привет')).not.toBe(sha256Hex('привет'));
    // The checksum is over the body bytes only: surrounding whitespace is significant.
    expect(sha256Hex('body ')).not.toBe(sha256Hex('body'));
  });

  it('verifies a raw token against the stored digest in constant time', () => {
    const token = 'B'.repeat(43);
    const stored = hashSessionSecret(token);
    expect(stored).toBe(sha256Hex(token));
    expect(sessionSecretMatches(token, stored)).toBe(true);
    expect(sessionSecretMatches('C'.repeat(43), stored)).toBe(false);
    expect(sessionSecretMatches('', stored)).toBe(false);
    expect(sessionSecretMatches(token, 'not-a-digest')).toBe(false);
    expect(sessionSecretMatches(token, stored.toUpperCase())).toBe(false);
    // The stored value never reveals the token.
    expect(stored).not.toContain(token);
  });
});

describe('legal error translation', () => {
  const driver = (code: string, constraint?: string): Error => Object.assign(new Error('driver text'), { code, constraint });

  it('maps unique, reference and check failures to typed codes without driver text', () => {
    const translated = (error: Error): LegalErrorCode => {
      try {
        mapLegalDbError(error);
      } catch (mapped) {
        expect(mapped).toBeInstanceOf(LegalPortError);
        expect((mapped as Error).message).not.toContain('driver text');
        return (mapped as LegalPortError).code;
      }
      throw new Error('Expected translation');
    };
    expect(translated(driver('23505', 'consent_records_session_evidence_key'))).toBe('ALREADY_EXISTS');
    expect(translated(driver('23505', 'consent_records_supersedes_id_key'))).toBe('CONSENT_REVOKED');
    // The consent guard raises a bare 23505 for a duplicate active GIVEN of a version.
    expect(translated(driver('23505'))).toBe('CONSENT_ALREADY_ACTIVE');
    expect(translated(driver('23505', 'legal_documents_purpose_kind_key'))).toBe('ALREADY_EXISTS');
    expect(translated(driver('23503'))).toBe('INVALID_REFERENCE');
    expect(translated(driver('23514'))).toBe('INVALID_INPUT');
    expect(translated(driver('22001'))).toBe('INVALID_INPUT');
    expect(translated(driver('22P02'))).toBe('INVALID_INPUT');
    expect(translated(driver('40001'))).toBe('CONFLICT');
    expect(translated(driver('40P01'))).toBe('CONFLICT');
    expect(translated(driver('55P03'))).toBe('CONFLICT');
    // A transaction that already pinned a stronger snapshot: the isolation SET is
    // refused, so the call fails closed as a retryable conflict (never a consent answer).
    expect(translated(driver('25001'))).toBe('CONFLICT');
  });

  it('propagates unknown failures unchanged so an infrastructure error is not disguised', () => {
    const unknown = Object.assign(new Error('connection terminated'), { code: '08006' });
    expect(() => mapLegalDbError(unknown)).toThrow(unknown);
    const already = new LegalPortError('NOT_FOUND');
    expect(() => mapLegalDbError(already)).toThrow(already);
    expect(() => mapLegalDbError(new Error('plain'))).toThrow('plain');
  });
});

describe('legal caller-transaction and isolation guard', () => {
  interface RecordedQuery {
    readonly text: string;
    readonly values: readonly unknown[] | undefined;
  }

  /**
   * Minimal recording `LegalSqlClient`. The transaction-local marker is simulated:
   * `set_config` remembers the value for this fake transaction and the probe reports
   * it back, unless `markerVisible` is false (the autocommit case, where the value is
   * discarded with the statement's implicit transaction).
   */
  function fakeClient(options: {
    isolation?: string;
    markerVisible?: boolean;
    failFirst?: Error;
  } = {}): { client: LegalSqlClient; queries: RecordedQuery[] } {
    const queries: RecordedQuery[] = [];
    let marker: string | null = null;
    const query = (text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number }> => {
      queries.push({ text, values });
      if (options.failFirst !== undefined && queries.length === 1) {
        return Promise.reject(options.failFirst);
      }
      if (text === LEGAL_TX_SET_SQL) {
        const value = values?.[0];
        marker = typeof value === 'string' ? value : null;
        return Promise.resolve({ rows: [], rowCount: 1 });
      }
      if (text === LEGAL_TX_PROBE_SQL) {
        return Promise.resolve({ rows: [{ marker: options.markerVisible === false ? null : marker }], rowCount: 1 });
      }
      if (text === LEGAL_ISOLATION_PROBE_SQL) {
        return Promise.resolve({ rows: [{ isolation: options.isolation ?? LEGAL_REQUIRED_ISOLATION }], rowCount: 1 });
      }
      return Promise.resolve({ rows: [], rowCount: 0 });
    };
    return { client: { query } as unknown as LegalSqlClient, queries };
  }

  it('uses a transaction-local custom setting, never a session-wide one', () => {
    expect(LEGAL_TX_SETTING).toContain('.');
    // `set_config(..., is_local => true)` is the whole point: in autocommit it is
    // discarded at the end of that single statement, so the probe cannot pass.
    expect(LEGAL_TX_SET_SQL).toContain("set_config('fixlevelup.legal_tx',$1,true)");
    expect(LEGAL_TX_SET_SQL).not.toContain('false');
    expect(LEGAL_TX_PROBE_SQL).toContain("current_setting('fixlevelup.legal_tx',true)");
  });

  it('opens the transaction with an explicit READ COMMITTED begin', async () => {
    const { client, queries } = fakeClient();
    await beginLegalTransaction(client);
    // A bare BEGIN would inherit a stronger session default; this one cannot.
    expect(LEGAL_BEGIN_SQL).toBe('BEGIN ISOLATION LEVEL READ COMMITTED');
    expect(queries.map((query) => query.text)).toEqual([LEGAL_BEGIN_SQL]);
  });

  it('sets READ COMMITTED before the marker and verifies the level the server reports', async () => {
    const { client, queries } = fakeClient();
    await assertCallerTransaction(client);
    expect(queries.map((query) => query.text)).toEqual([
      LEGAL_ISOLATION_SQL, LEGAL_ISOLATION_PROBE_SQL, LEGAL_TX_SET_SQL, LEGAL_TX_PROBE_SQL,
    ]);
  });

  it('refuses a transaction whose actual isolation is stronger, before touching data', async () => {
    const { client, queries } = fakeClient({ isolation: 'repeatable read' });
    await expect(assertCallerTransaction(client)).rejects.toMatchObject({ code: 'CONFLICT' });
    // The marker is never even attempted: the port must not proceed on a stale level.
    expect(queries.map((query) => query.text)).toEqual([LEGAL_ISOLATION_SQL, LEGAL_ISOLATION_PROBE_SQL]);
  });

  it('fails closed when the isolation SET is refused after a snapshot (PostgreSQL 25001)', async () => {
    const refused = Object.assign(
      new Error('SET TRANSACTION ISOLATION LEVEL must be called before any query'), { code: '25001' });
    const { client, queries } = fakeClient({ failFirst: refused });
    await expect(assertCallerTransaction(client)).rejects.toMatchObject({ code: 'CONFLICT', message: 'CONFLICT' });
    // The raw driver error never surfaces and no data statement follows the refusal.
    expect(queries).toHaveLength(1);
    expect(queries[0]?.text).toBe(LEGAL_ISOLATION_SQL);
  });

  it('still refuses autocommit, where the transaction-local marker cannot survive', async () => {
    const { client } = fakeClient({ markerVisible: false });
    await expect(assertCallerTransaction(client)).rejects.toMatchObject({ code: 'CONFLICT' });
  });
});
