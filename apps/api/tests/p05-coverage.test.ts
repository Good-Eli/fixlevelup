/**
 * P05 §3 / §5.1 targeted defensive tests for the purpose-bound address check and
 * the complete coverage basis.
 *
 * These are pure/unit proofs over a fake `PoolClient`, a fake trusted evidence
 * issuer, a fake audit store and real AEAD crypto from the reviewed payload cipher.
 * They deliberately do NOT claim PostgreSQL behaviour (fences, locks, FK, rollback
 * ordering) — that belongs to the isolated lab run. What they do pin is the cheap
 * to break / expensive to notice part:
 *
 * - the basis is complete and sorted, deterministic under row order, bounded by an
 *   explicit cap that refuses instead of truncating;
 * - the fence must already be held and is never acquired late;
 * - no SQL, no audit and no decrypt happen before the trusted evidence verifies;
 * - the audit attempt is committed exactly once, on its own port, before the
 *   ciphertext row is even selected; duplicate/unconfirmed/lost ACK never decrypt
 *   and are never retried;
 * - the caller's recheck runs after the audit and again after the comparison;
 * - a failed comparison, a tampered cell, a wrong environment/kind and a
 *   non-canonical candidate all produce one safe refusal with no plaintext in the
 *   error, result, or fake-client query log;
 * - the plaintext comparator is not reachable without the module's branded
 *   consumption token;
 * - reproof refuses on any basis drift (zone set, timezone, district version,
 *   address currency) with `COVERAGE_ASSESSMENT_STALE`.
 */
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../src/infrastructure/admission/proof.js';
import { loadKeyring } from '../src/requests/crypto/keyring.js';
import { sealManagedPayload } from '../src/requests/crypto/payload-cipher.js';
import type { PayloadKeyWrap } from '../src/requests/crypto/payload-key-directory.js';
import type { SealedPayload } from '../src/requests/crypto/payload-cipher.js';
import { RequestFailure } from '../src/requests/intake/errors.js';
import type { RequestFailureCode } from '../src/requests/intake/errors.js';
import {
  COVERAGE_BASIS_DEFAULT_CAP, COVERAGE_BASIS_FENCE_HELD_SQL, reproofCoverageBasis,
  readCoverageBasis, recordCoverageAssessment, validateCoverageSelection, verifyAssessmentAddress,
} from '../src/requests/intake/coverage.js';
import type {
  CoverageAuditAttempt, CoverageAuditAttemptStore, CoverageAuditCommit, CoverageReviewEvidence,
  CoverageReviewEvidencePort, CoverageReviewEvidenceRequest, CoverageSelection, RecordCoverageAssessmentInput,
} from '../src/requests/intake/coverage.js';

/* ------------------------------- identities ------------------------------- */

const CITY = '11111111-1111-4111-8111-111111111111';
const CITY_VERSION = '22222222-2222-4222-8222-222222222222';
const OTHER_CITY_VERSION = '33333333-3333-4333-8333-333333333333';
const REQUEST = '44444444-4444-4444-8444-444444444444';
const OTHER_REQUEST = '55555555-5555-4555-8555-555555555555';
const ADDRESS_REVISION = '66666666-6666-4666-8666-666666666666';
const OTHER_ADDRESS_REVISION = '77777777-7777-4777-8777-777777777777';
const PAYLOAD_CELL = '88888888-8888-4888-8888-888888888888';
const DISTRICT = '99999999-9999-4999-8999-999999999999';
const AREA_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const AREA_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const AREA_VERSION_A = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const AREA_VERSION_B = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const STAFF = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const OTHER_STAFF = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const EVIDENCE = '12121212-1212-4212-8212-121212121212';
const TIMEZONE = 'Europe/Moscow';
const ENVIRONMENT = 'test-coverage';

const ADDRESS = Object.freeze({
  street: 'Тестовая улица',
  building: '1',
  districtId: DISTRICT,
  apartment: '42',
});
const ADDRESS_CANONICAL = canonicalJson(ADDRESS);

const RING = loadKeyring({
  kek: [{ keyId: 'kek-1', secretHex: '11'.repeat(32) }],
  hmac: [{ keyId: 'hmac-1', secretHex: '22'.repeat(32) }],
  activeKekId: 'kek-1',
  activeHmacKeyId: 'hmac-1',
});

function seal(address: unknown, revision = 1, environment = ENVIRONMENT, kind: 'ADDRESS' | 'CONTACT' = 'ADDRESS',
  plaintextOverride?: string): SealedPayload {
  return sealManagedPayload({ environment, kind, cellId: PAYLOAD_CELL, requestId: REQUEST, revision }, RING,
    Buffer.from(plaintextOverride ?? canonicalJson(address), 'utf8'));
}

/* --------------------------------- fakes ---------------------------------- */

interface QueryRecord { readonly text: string; readonly values?: readonly unknown[] }

interface Fixture {
  readonly events: string[];
  fenceHeld: boolean;
  cityRow: Record<string, unknown> | undefined;
  addressRows: readonly Record<string, unknown>[];
  districtRows: readonly Record<string, unknown>[];
  zoneRows: readonly Record<string, unknown>[];
  mappingRows: readonly Record<string, unknown>[];
  cellRows: readonly Record<string, unknown>[];
  now: Date;
}

function fixture(overrides: Partial<Fixture> = {}): Fixture {
  const base: Fixture = {
    events: [],
    fenceHeld: true,
    cityRow: { city_id: CITY, lifecycle: 'ACTIVE', current_version_id: CITY_VERSION, timezone: TIMEZONE },
    addressRows: [{
      address_revision_id: ADDRESS_REVISION, address_revision: 1, district_id: DISTRICT,
      district_row_version: 3, payload_cell_id: PAYLOAD_CELL, request_id: REQUEST, type: 'REPAIR',
      status: 'MANAGER_REVIEW', row_version: 7, city_id: CITY, current_address_revision_id: ADDRESS_REVISION,
    }],
    districtRows: [{ district_id: DISTRICT, row_version: 3, archived_at: null }],
    zoneRows: [
      { area_id: AREA_A, area_version_id: AREA_VERSION_A },
      { area_id: AREA_B, area_version_id: AREA_VERSION_B },
    ],
    mappingRows: [
      { area_id: AREA_A, area_version_id: AREA_VERSION_A, district_id: DISTRICT, relation: 'FULL' },
    ],
    cellRows: [cellOf(seal(ADDRESS))],
    now: new Date('2026-11-25T00:00:00.000Z'),
  };
  return { ...base, ...overrides };
}

const wraps = new WeakMap<Record<string, unknown>,PayloadKeyWrap>();
function cellOf(sealed: SealedPayload, kind = 'ADDRESS', revision = 1): Record<string, unknown> {
  const row = { kind, revision, nonce: sealed.nonce, ciphertext: sealed.ciphertext,
    auth_tag: sealed.authTag, aad_context: sealed.aadContext };
  wraps.set(row, { keyId: sealed.keyId, wrappedDek: sealed.wrappedDek });
  return row;
}

function clientFor(state: Fixture): { client: PoolClient; queries: QueryRecord[] } {
  const queries: QueryRecord[] = [];
  const query = async (text: string, values?: readonly unknown[]) => {
    await Promise.resolve();
    queries.push(values === undefined ? { text } : { text, values });
    state.events.push(text.includes('request_payload_cells') ? 'query:payload'
      : text.includes('pg_locks') ? 'query:fence'
        : text.includes('clock_timestamp') ? 'query:clock' : 'query:domain');
    if (text.includes('pg_locks')) { return { rows: [{ held: state.fenceHeld }], rowCount: 1 }; }
    if (text.includes('clock_timestamp')) { return { rows: [{ now: state.now }], rowCount: 1 }; }
    if (text.includes('FROM foundation.service_cities')) {
      return { rows: state.cityRow === undefined ? [] : [state.cityRow], rowCount: state.cityRow === undefined ? 0 : 1 };
    }
    if (text.includes('foundation.request_address_revisions')) { return { rows: state.addressRows, rowCount: state.addressRows.length }; }
    if (text.includes('foundation.administrative_districts')) { return { rows: state.districtRows, rowCount: state.districtRows.length }; }
    if (text.includes('foundation.service_area_district_coverage')) { return { rows: state.mappingRows, rowCount: state.mappingRows.length }; }
    if (text.includes('foundation.service_areas')) { return { rows: state.zoneRows, rowCount: state.zoneRows.length }; }
    if (text.includes('foundation.request_payload_cells')) { return { rows: state.cellRows, rowCount: state.cellRows.length }; }
    return { rows: [], rowCount: 0 };
  };
  return { client: { query } as unknown as PoolClient, queries };
}

class FakeEvidence implements CoverageReviewEvidencePort {
  readonly calls: CoverageReviewEvidenceRequest[] = [];
  result: CoverageReviewEvidence | null = null;
  error: Error | undefined;
  async verify(request: CoverageReviewEvidenceRequest): Promise<CoverageReviewEvidence | null> {
    await Promise.resolve();
    this.calls.push(request);
    if (this.error) { throw this.error; }
    return this.result;
  }
}

function evidenceFor(overrides: Partial<CoverageReviewEvidence> = {}): CoverageReviewEvidence {
  return {
    evidenceId: EVIDENCE, issuer: 'T', purpose: 'COVERAGE_REVIEW', staffId: STAFF, requestId: REQUEST,
    addressRevisionId: ADDRESS_REVISION, candidate: ADDRESS, expiresAt: new Date('2026-11-25T01:00:00.000Z'),
    ...overrides,
  };
}

class FakeAudit implements CoverageAuditAttemptStore {
  readonly attempts: CoverageAuditAttempt[] = [];
  readonly events: string[];
  result: CoverageAuditCommit = 'COMMITTED';
  error: Error | undefined;
  constructor(events: string[]) { this.events = events; }
  async record(attempt: CoverageAuditAttempt): Promise<CoverageAuditCommit> {
    await Promise.resolve();
    this.attempts.push(attempt);
    this.events.push('audit');
    if (this.error) { throw this.error; }
    return this.result;
  }
}

interface Harness {
  readonly state: Fixture;
  readonly client: PoolClient;
  readonly queries: QueryRecord[];
  readonly evidence: FakeEvidence;
  readonly audit: FakeAudit;
  readonly rechecks: number[];
  readonly input: RecordCoverageAssessmentInput;
}

function harness(options: {
  state?: Fixture;
  evidence?: CoverageReviewEvidence | null;
  selection?: CoverageSelection;
  recheckError?: Error;
  audit?: (audit: FakeAudit) => void;
  evidenceError?: Error;
} = {}): Harness {
  const state = options.state ?? fixture();
  const { client, queries } = clientFor(state);
  const evidence = new FakeEvidence();
  evidence.result = options.evidence === undefined ? evidenceFor() : options.evidence;
  evidence.error = options.evidenceError;
  const audit = new FakeAudit(state.events);
  options.audit?.(audit);
  const rechecks: number[] = [];
  const input: RecordCoverageAssessmentInput = {
    client,
    ring: RING,
    environment: ENVIRONMENT,
    keySlots: { environment: ENVIRONMENT,
      create: () => Promise.reject(new Error('Compare cannot write keys')),
      async read(ref) {
        await Promise.resolve();
        state.events.push('key-slot:read');
        expect(ref).toEqual({ environment: ENVIRONMENT, cellId: PAYLOAD_CELL, requestId: REQUEST, kind: 'ADDRESS', revision: 1 });
        const wrap = state.cellRows[0] && wraps.get(state.cellRows[0]);
        if (!wrap) { throw new Error('Missing slot'); }
        return wrap;
      },
    },
    actor: { staffId: STAFF },
    request: { requestId: REQUEST, cityId: CITY, addressRevisionId: ADDRESS_REVISION, expectedVersion: 7 },
    evidenceHandle: EVIDENCE,
    selection: options.selection ?? { outcome: 'IN_ZONE', areaId: AREA_A },
    cap: COVERAGE_BASIS_DEFAULT_CAP,
    evidence,
    audit,
    recheck: async () => {
      await Promise.resolve();
      rechecks.push(rechecks.length + 1);
      if (options.recheckError) { throw options.recheckError; }
      return state.now;
    },
  };
  return { state, client, queries, evidence, audit, rechecks, input };
}

/* ------------------------------- assertions ------------------------------- */

async function expectFailure(promise: Promise<unknown>, code: RequestFailureCode): Promise<RequestFailure> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(RequestFailure);
    expect((error as RequestFailure).code).toBe(code);
    // One safe code, never a per-field or value-bearing diagnostic.
    expect((error as Error).message).toBe(code);
    return error as RequestFailure;
  }
  throw new Error(`expected RequestFailure(${code})`);
}

function expectSyncFailure(run: () => unknown, code: RequestFailureCode): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(RequestFailure);
    expect((error as RequestFailure).code).toBe(code);
    expect((error as Error).message).toBe(code);
    return;
  }
  throw new Error(`expected RequestFailure(${code})`);
}

function payloadQueries(queries: readonly QueryRecord[]): QueryRecord[] {
  return queries.filter((entry) => entry.text.includes('request_payload_cells'));
}

function assertNoPlaintext(value: unknown): void {
  const serialized = JSON.stringify(value);
  expect(serialized).not.toContain(ADDRESS.street);
  expect(serialized).not.toContain('"building"');
}

/* ------------------------------ basis reading ----------------------------- */

describe('readCoverageBasis', () => {
  it('returns the complete sorted basis with a deterministic canonical digest', async () => {
    const first = fixture();
    const a = await readCoverageBasis(clientFor(first).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    expect(a.cityId).toBe(CITY);
    expect(a.cityVersionId).toBe(CITY_VERSION);
    expect(a.timezone).toBe(TIMEZONE);
    expect(a.request.requestId).toBe(REQUEST);
    expect(a.address.current).toBe(true);
    expect(a.address.payloadCellId).toBe(PAYLOAD_CELL);
    expect(a.zones.map((zone) => zone.areaId)).toEqual([AREA_A, AREA_B]);
    expect(a.mappings).toHaveLength(1);
    expect(a.basisDigest).toMatch(/^[a-f0-9]{64}$/);

    // Same facts delivered in a different row order must yield the same digest.
    const shuffled = fixture({ zoneRows: [...first.zoneRows].reverse(), mappingRows: [...first.mappingRows].reverse() });
    const b = await readCoverageBasis(clientFor(shuffled).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    expect(b.basisDigest).toBe(a.basisDigest);
    expect(b.zones.map((zone) => zone.areaId)).toEqual([AREA_A, AREA_B]);
  });

  it('changes the digest when the zone set, timezone or district version changes', async () => {
    const base = await readCoverageBasis(clientFor(fixture()).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    const withoutZone = fixture({ zoneRows: [{ area_id: AREA_A, area_version_id: AREA_VERSION_A }] });
    const oneZone = await readCoverageBasis(clientFor(withoutZone).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    expect(oneZone.basisDigest).not.toBe(base.basisDigest);

    const movedCity = fixture({ cityRow: { city_id: CITY, lifecycle: 'ACTIVE', current_version_id: OTHER_CITY_VERSION, timezone: 'Asia/Tokyo' } });
    const otherCity = await readCoverageBasis(clientFor(movedCity).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    expect(otherCity.basisDigest).not.toBe(base.basisDigest);

    const movedDistrict = fixture({ districtRows: [{ district_id: DISTRICT, row_version: 4, archived_at: null }] });
    const district = await readCoverageBasis(clientFor(movedDistrict).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    expect(district.basisDigest).not.toBe(base.basisDigest);
  });

  it('refuses a basis over the cap instead of returning a truncated set', async () => {
    const state = fixture({ zoneRows: [
      { area_id: AREA_A, area_version_id: AREA_VERSION_A },
      { area_id: AREA_B, area_version_id: AREA_VERSION_B },
      { area_id: 'abababab-abab-4bab-8bab-abababababab', area_version_id: 'acacacac-acac-4cac-8cac-acacacacacac' },
    ] });
    await expectFailure(readCoverageBasis(clientFor(state).client, CITY, ADDRESS_REVISION, 2), 'UNPROCESSABLE');
  });

  it('counts zones and mappings together against the cap', async () => {
    const state = fixture({ mappingRows: [
      { area_id: AREA_A, area_version_id: AREA_VERSION_A, district_id: DISTRICT, relation: 'FULL' },
      { area_id: AREA_B, area_version_id: AREA_VERSION_B, district_id: DISTRICT, relation: 'PARTIAL' },
    ] });
    await expectFailure(readCoverageBasis(clientFor(state).client, CITY, ADDRESS_REVISION, 3), 'UNPROCESSABLE');
  });

  it('requires the caller to already hold the GEO/CFG fence', async () => {
    const state = fixture({ fenceHeld: false });
    const { client, queries } = clientFor(state);
    await expectFailure(readCoverageBasis(client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP), 'NOT_READY');
    // The fence probe is the first statement; the module never acquires the lock itself.
    expect(queries[0]?.text).toBe(COVERAGE_BASIS_FENCE_HELD_SQL);
    expect(queries.some((entry) => entry.text.includes('pg_advisory_xact_lock'))).toBe(false);
  });

  it('refuses a non-ACTIVE or incomplete city with CITY_CONTEXT_STALE', async () => {
    const inactive = fixture({ cityRow: { city_id: CITY, lifecycle: 'INACTIVE', current_version_id: CITY_VERSION, timezone: TIMEZONE } });
    await expectFailure(readCoverageBasis(clientFor(inactive).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP), 'CITY_CONTEXT_STALE');
    const noVersion = fixture({ cityRow: { city_id: CITY, lifecycle: 'ACTIVE', current_version_id: null, timezone: null } });
    await expectFailure(readCoverageBasis(clientFor(noVersion).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP), 'CITY_CONTEXT_STALE');
    const missing = fixture({ cityRow: undefined });
    await expectFailure(readCoverageBasis(clientFor(missing).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP), 'CITY_CONTEXT_STALE');
  });

  it('refuses a foreign or missing address revision with NOT_FOUND', async () => {
    const foreign = fixture({ addressRows: [] });
    await expectFailure(readCoverageBasis(clientFor(foreign).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP), 'NOT_FOUND');
    const otherCity = fixture({ addressRows: [{ ...fixture().addressRows[0], city_id: OTHER_REQUEST }] });
    await expectFailure(readCoverageBasis(clientFor(otherCity).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP), 'NOT_FOUND');
  });

  it('marks a superseded address revision as not current', async () => {
    const state = fixture({ addressRows: [{ ...fixture().addressRows[0], current_address_revision_id: OTHER_ADDRESS_REVISION }] });
    const basis = await readCoverageBasis(clientFor(state).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    expect(basis.address.current).toBe(false);
  });

  it('refuses an archived district mapping shape or a malformed row as a dependency failure', async () => {
    const badRelation = fixture({ mappingRows: [{ area_id: AREA_A, area_version_id: AREA_VERSION_A, district_id: DISTRICT, relation: 'ALL' }] });
    await expectFailure(readCoverageBasis(clientFor(badRelation).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP), 'DEPENDENCY_UNAVAILABLE');
    const badPair = fixture({ addressRows: [{ ...fixture().addressRows[0], district_row_version: null }] });
    await expectFailure(readCoverageBasis(clientFor(badPair).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP), 'DEPENDENCY_UNAVAILABLE');
  });

  it('keeps an archived district visible in the basis but not as a positive authority', async () => {
    const state = fixture({ districtRows: [{ district_id: DISTRICT, row_version: 4, archived_at: new Date() }] });
    const basis = await readCoverageBasis(clientFor(state).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    expect(basis.district).toEqual({ districtId: DISTRICT, rowVersion: 4, archived: true });
  });

  it('supports an address without a district (empty mappings, no district facts)', async () => {
    const state = fixture({ addressRows: [{ ...fixture().addressRows[0], district_id: null, district_row_version: null }] });
    const basis = await readCoverageBasis(clientFor(state).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    expect(basis.district).toBeNull();
    expect(basis.mappings).toEqual([]);
    expect(basis.zones).toHaveLength(2);
  });

  it('rejects a malformed cap and a malformed id without any SQL', async () => {
    const { client, queries } = clientFor(fixture());
    await expectFailure(readCoverageBasis(client, 'not-a-uuid', ADDRESS_REVISION, 10), 'UNPROCESSABLE');
    await expectFailure(readCoverageBasis(client, CITY, ADDRESS_REVISION, 0), 'UNPROCESSABLE');
    await expectFailure(readCoverageBasis(client, CITY, ADDRESS_REVISION, 10_000), 'UNPROCESSABLE');
    expect(queries).toHaveLength(0);
  });
});

/* --------------------------- selection validation -------------------------- */

describe('validateCoverageSelection', () => {
  async function basisOf(overrides: Partial<Fixture> = {}) {
    return await readCoverageBasis(clientFor(fixture(overrides)).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
  }

  it('resolves IN_ZONE only to a current zone of this city', async () => {
    const basis = await basisOf({ mappingRows: [
      { area_id: AREA_A, area_version_id: AREA_VERSION_A, district_id: DISTRICT, relation: 'FULL' },
    ] });
    expect(validateCoverageSelection(basis, { outcome: 'IN_ZONE', areaId: AREA_A }))
      .toEqual({ outcome: 'IN_ZONE', reason: null, areaId: AREA_A, areaVersionId: AREA_VERSION_A });
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'IN_ZONE' }), 'UNPROCESSABLE');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'IN_ZONE', areaId: OTHER_ADDRESS_REVISION }), 'UNPROCESSABLE');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'IN_ZONE', areaId: AREA_A, reason: 'OPERATOR_REVIEW' }), 'UNPROCESSABLE');
  });

  it('refuses IN_ZONE when several current zones overlap on the address district', async () => {
    const basis = await basisOf({ mappingRows: [
      { area_id: AREA_A, area_version_id: AREA_VERSION_A, district_id: DISTRICT, relation: 'FULL' },
      { area_id: AREA_B, area_version_id: AREA_VERSION_B, district_id: DISTRICT, relation: 'PARTIAL' },
    ] });
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'IN_ZONE', areaId: AREA_A }), 'UNPROCESSABLE');
    expect(validateCoverageSelection(basis, { outcome: 'REVIEW', reason: 'OVERLAP_REVIEW' }))
      .toEqual({ outcome: 'REVIEW', reason: 'OVERLAP_REVIEW', areaId: null, areaVersionId: null });
  });

  it('allows IN_ZONE without a district, where overlap cannot be observed', async () => {
    const state = fixture({ addressRows: [{ ...fixture().addressRows[0], district_id: null, district_row_version: null }] });
    const basis = await readCoverageBasis(clientFor(state).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    expect(validateCoverageSelection(basis, { outcome: 'IN_ZONE', areaId: AREA_B }).areaVersionId).toBe(AREA_VERSION_B);
  });

  it('never establishes a positive outcome on an empty zone set', async () => {
    const basis = await basisOf({ zoneRows: [], mappingRows: [] });
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'IN_ZONE', areaId: AREA_A }), 'UNPROCESSABLE');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'EXCEPTION', areaId: AREA_A, reason: 'OPERATOR_REVIEW' }), 'UNPROCESSABLE');
    expect(validateCoverageSelection(basis, { outcome: 'OUTSIDE', reason: 'OUTSIDE_REVIEW' }).outcome).toBe('OUTSIDE');
  });

  it('requires a reason for EXCEPTION (migration 024) and a selected zone', async () => {
    const basis = await basisOf();
    expect(validateCoverageSelection(basis, { outcome: 'EXCEPTION', areaId: AREA_A, reason: 'OPERATOR_REVIEW' }).reason).toBe('OPERATOR_REVIEW');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'EXCEPTION', areaId: AREA_A }), 'UNPROCESSABLE');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'EXCEPTION', reason: 'OPERATOR_REVIEW' }), 'UNPROCESSABLE');
  });

  it('enforces the closed OUTSIDE/REVIEW reason and no-zone rules', async () => {
    const basis = await basisOf();
    expect(validateCoverageSelection(basis, { outcome: 'OUTSIDE', reason: 'OUTSIDE_REVIEW' }).reason).toBe('OUTSIDE_REVIEW');
    expect(validateCoverageSelection(basis, { outcome: 'OUTSIDE', reason: 'OPERATOR_REVIEW' }).reason).toBe('OPERATOR_REVIEW');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'OUTSIDE', reason: 'OUTSIDE_REVIEW', areaId: AREA_A }), 'UNPROCESSABLE');
    expect(validateCoverageSelection(basis, { outcome: 'REVIEW', reason: 'OPERATOR_REVIEW' }).outcome).toBe('REVIEW');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'REVIEW' }), 'UNPROCESSABLE');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'REVIEW', reason: 'OUTSIDE_REVIEW' }), 'UNPROCESSABLE');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'REVIEW', reason: 'OPERATOR_REVIEW', areaId: AREA_A }), 'UNPROCESSABLE');
    expectSyncFailure(() => validateCoverageSelection(basis, { outcome: 'MAYBE' as never }), 'UNPROCESSABLE');
  });
});

/* --------------------------- recordCoverageAssessment ---------------------- */

describe('recordCoverageAssessment', () => {
  it('returns only IDs/digest/outcome after a successful comparison and never plaintext', async () => {
    const h = harness();
    const result = await recordCoverageAssessment(h.input);
    expect(result.requestId).toBe(REQUEST);
    expect(result.addressRevisionId).toBe(ADDRESS_REVISION);
    expect(result.cityId).toBe(CITY);
    expect(result.cityVersionId).toBe(CITY_VERSION);
    expect(result.areaId).toBe(AREA_A);
    expect(result.areaVersionId).toBe(AREA_VERSION_A);
    expect(result.outcome).toBe('IN_ZONE');
    expect(result.reason).toBeNull();
    expect(result.staffId).toBe(STAFF);
    expect(result.evidenceId).toBe(EVIDENCE);
    expect(result.attemptCorrelationId).toMatch(/^[0-9a-f-]{36}$/);
    expect(result.basisDigest).toMatch(/^[a-f0-9]{64}$/);
    assertNoPlaintext(result);

    // Audit commit strictly precedes the ciphertext read; reproof precedes open and follows compare.
    const auditIndex = h.state.events.indexOf('audit');
    const payloadIndex = h.state.events.indexOf('query:payload');
    expect(auditIndex).toBeGreaterThanOrEqual(0);
    expect(payloadIndex).toBeGreaterThan(auditIndex);
    expect(h.state.events.indexOf('key-slot:read')).toBeGreaterThan(payloadIndex);
    expect(h.rechecks).toHaveLength(4);
    expect(h.audit.attempts).toHaveLength(1);
    expect(h.audit.attempts[0]).toMatchObject({
      evidenceId: EVIDENCE, staffId: STAFF, requestId: REQUEST,
      addressRevisionId: ADDRESS_REVISION, purpose: 'COVERAGE_REVIEW',
    });
    expect(h.audit.attempts[0]?.correlationId).toBe(result.attemptCorrelationId);
  });

  it('accepts a candidate given as canonical bytes and ignores any caller-supplied candidate', async () => {
    const h = harness({ evidence: evidenceFor({ candidate: Buffer.from(ADDRESS_CANONICAL, 'utf8') }) });
    const result = await recordCoverageAssessment({
      ...h.input,
      // A forged caller-side candidate must never participate.
      ...({ candidate: { street: 'Подмена', building: '9' } } as object),
    });
    expect(result.outcome).toBe('IN_ZONE');
    expect(h.evidence.calls).toHaveLength(1);
  });

  it('tolerates the store padding of short cells but not arbitrary trailing bytes', async () => {
    const padded = seal(ADDRESS, 1, ENVIRONMENT, 'ADDRESS', `${ADDRESS_CANONICAL}   `);
    const ok = harness({ state: fixture({ cellRows: [cellOf(padded)] }) });
    await expect(recordCoverageAssessment(ok.input)).resolves.toMatchObject({ outcome: 'IN_ZONE' });

    const garbage = seal(ADDRESS, 1, ENVIRONMENT, 'ADDRESS', `${ADDRESS_CANONICAL}x`);
    const bad = harness({ state: fixture({ cellRows: [cellOf(garbage)] }) });
    await expectFailure(recordCoverageAssessment(bad.input), 'DEPENDENCY_UNAVAILABLE');
  });

  it('refuses before any SQL, audit or decrypt when the trusted evidence does not verify', async () => {
    const missing = harness({ evidence: null });
    await expectFailure(recordCoverageAssessment(missing.input), 'FORBIDDEN');
    expect(missing.queries.filter((entry) => !entry.text.includes('pg_locks') && !entry.text.includes('clock_timestamp'))).toHaveLength(0);
    expect(missing.audit.attempts).toHaveLength(0);
    expect(payloadQueries(missing.queries)).toHaveLength(0);

    const wrongActor = harness({ evidence: evidenceFor({ staffId: OTHER_STAFF }) });
    await expectFailure(recordCoverageAssessment(wrongActor.input), 'FORBIDDEN');
    expect(wrongActor.audit.attempts).toHaveLength(0);

    const wrongAddress = harness({ evidence: evidenceFor({ addressRevisionId: OTHER_ADDRESS_REVISION }) });
    await expectFailure(recordCoverageAssessment(wrongAddress.input), 'FORBIDDEN');
    expect(wrongAddress.audit.attempts).toHaveLength(0);

    const expired = harness({ evidence: evidenceFor({ expiresAt: new Date('2026-11-24T00:00:00.000Z') }) });
    await expectFailure(recordCoverageAssessment(expired.input), 'FORBIDDEN');
    expect(expired.audit.attempts).toHaveLength(0);

    const thrown = harness({ evidenceError: new Error('issuer exploded') });
    await expectFailure(recordCoverageAssessment(thrown.input), 'FORBIDDEN');
    expect(thrown.audit.attempts).toHaveLength(0);
  });

  it('refuses a non-canonical, extended, accessor or oversized candidate before opening the cell', async () => {
    const cases: readonly [string, unknown][] = [
      ['extra field', { ...ADDRESS, extra: 'x' }],
      ['missing street', { building: '1' }],
      ['bad district', { street: 'Тестовая улица', building: '1', districtId: 'nope' }],
      ['not an object', 'street'],
      ['oversized', { street: 'a'.repeat(400) + 'b', building: '1' }],
    ];
    for (const [, candidate] of cases) {
      const h = harness({ evidence: evidenceFor({ candidate }) });
      await expectFailure(recordCoverageAssessment(h.input), 'FORBIDDEN');
      expect(payloadQueries(h.queries)).toHaveLength(0);
    }

    const accessor = Object.defineProperty({ building: '1' }, 'street', {
      enumerable: true, get() { return ADDRESS.street; },
    });
    const accessorHarness = harness({ evidence: evidenceFor({ candidate: accessor }) });
    await expectFailure(recordCoverageAssessment(accessorHarness.input), 'FORBIDDEN');
    expect(payloadQueries(accessorHarness.queries)).toHaveLength(0);

    // Bytes that are not exactly the canonical serialization are refused too.
    const pretty = harness({ evidence: evidenceFor({ candidate: Buffer.from(JSON.stringify(ADDRESS, null, 2), 'utf8') }) });
    await expectFailure(recordCoverageAssessment(pretty.input), 'FORBIDDEN');
    expect(payloadQueries(pretty.queries)).toHaveLength(0);
  });

  it('produces one safe refusal for a changed candidate and never a field hint', async () => {
    const changed = harness({ evidence: evidenceFor({ candidate: { ...ADDRESS, apartment: '43' } }) });
    const error = await expectFailure(recordCoverageAssessment(changed.input), 'FORBIDDEN');
    expect(JSON.stringify(error)).not.toContain('43');
    expect(JSON.stringify(error)).not.toContain(ADDRESS.apartment);
    // The audit attempt was committed before the comparison (it must survive rollback).
    expect(changed.audit.attempts).toHaveLength(1);
    expect(payloadQueries(changed.queries)).toHaveLength(1);
  });

  it('maps a tampered cell, a wrong kind/revision and a wrong environment to one dependency refusal', async () => {
    const tampered = seal(ADDRESS);
    tampered.ciphertext[0] = (tampered.ciphertext[0] ?? 0) ^ 0xff;
    const tamperedHarness = harness({ state: fixture({ cellRows: [cellOf(tampered)] }) });
    await expectFailure(recordCoverageAssessment(tamperedHarness.input), 'DEPENDENCY_UNAVAILABLE');
    assertNoPlaintext(tamperedHarness.audit.attempts);

    const wrongKind = harness({ state: fixture({ cellRows: [cellOf(seal(ADDRESS, 1, ENVIRONMENT, 'CONTACT'), 'CONTACT')] }) });
    await expectFailure(recordCoverageAssessment(wrongKind.input), 'DEPENDENCY_UNAVAILABLE');
    expect(payloadQueries(wrongKind.queries)).toHaveLength(1);

    const wrongRevision = harness({ state: fixture({ cellRows: [cellOf(seal(ADDRESS, 2), 'ADDRESS', 2)] }) });
    await expectFailure(recordCoverageAssessment(wrongRevision.input), 'DEPENDENCY_UNAVAILABLE');

    const wrongEnvironment = harness({ state: fixture({ cellRows: [cellOf(seal(ADDRESS, 1, 'test-other'))] }) });
    await expectFailure(recordCoverageAssessment(wrongEnvironment.input), 'DEPENDENCY_UNAVAILABLE');
    expect(wrongEnvironment.audit.attempts).toHaveLength(1);

    const missingCell = harness({ state: fixture({ cellRows: [] }) });
    await expectFailure(recordCoverageAssessment(missingCell.input), 'DEPENDENCY_UNAVAILABLE');
  });

  it('refuses a stored plaintext that is not a normalized address', async () => {
    const notAddress = seal(ADDRESS, 1, ENVIRONMENT, 'ADDRESS', canonicalJson({ name: 'x', phone: '+70000000000' }));
    const h = harness({ state: fixture({ cellRows: [cellOf(notAddress)] }) });
    await expectFailure(recordCoverageAssessment(h.input), 'DEPENDENCY_UNAVAILABLE');
  });

  it('refuses cross-city, stale, wrong-version and wrong-status requests before the audit', async () => {
    const crossCity = harness();
    await expectFailure(recordCoverageAssessment({
      ...crossCity.input, request: { ...crossCity.input.request, cityId: OTHER_REQUEST },
    }), 'NOT_FOUND');
    expect(crossCity.audit.attempts).toHaveLength(0);

    const stale = harness({ state: fixture({ addressRows: [{ ...fixture().addressRows[0], current_address_revision_id: OTHER_ADDRESS_REVISION }] }) });
    await expectFailure(recordCoverageAssessment(stale.input), 'COVERAGE_ASSESSMENT_STALE');
    expect(stale.audit.attempts).toHaveLength(0);

    const version = harness();
    await expectFailure(recordCoverageAssessment({
      ...version.input, request: { ...version.input.request, expectedVersion: 6 },
    }), 'PRECONDITION_FAILED');
    expect(version.audit.attempts).toHaveLength(0);

    const status = harness({ state: fixture({ addressRows: [{ ...fixture().addressRows[0], status: 'NEW' }] }) });
    await expectFailure(recordCoverageAssessment(status.input), 'NOT_READY');
    expect(status.audit.attempts).toHaveLength(0);

    const callback = harness({ state: fixture({ addressRows: [{ ...fixture().addressRows[0], type: 'CALLBACK' }] }) });
    await expectFailure(recordCoverageAssessment(callback.input), 'NOT_READY');
    expect(callback.audit.attempts).toHaveLength(0);
  });

  it('refuses an invalid selection before the audit and the decrypt', async () => {
    const h = harness({ selection: { outcome: 'IN_ZONE' } });
    await expectFailure(recordCoverageAssessment(h.input), 'UNPROCESSABLE');
    expect(h.audit.attempts).toHaveLength(0);
    expect(payloadQueries(h.queries)).toHaveLength(0);

    const overlap = harness({ state: fixture({ mappingRows: [
      { area_id: AREA_A, area_version_id: AREA_VERSION_A, district_id: DISTRICT, relation: 'FULL' },
      { area_id: AREA_B, area_version_id: AREA_VERSION_B, district_id: DISTRICT, relation: 'PARTIAL' },
    ] }) });
    await expectFailure(recordCoverageAssessment(overlap.input), 'UNPROCESSABLE');
    expect(overlap.audit.attempts).toHaveLength(0);
  });

  it('refuses a stale caller snapshot but accepts the exact one', async () => {
    const exact = harness();
    await expect(recordCoverageAssessment({
      ...exact.input,
      snapshot: { addressRevisionId: ADDRESS_REVISION, districtId: DISTRICT, districtRowVersion: 3, cityVersionId: CITY_VERSION },
    })).resolves.toMatchObject({ outcome: 'IN_ZONE' });

    for (const snapshot of [
      { cityVersionId: OTHER_CITY_VERSION },
      { districtId: OTHER_ADDRESS_REVISION },
      { districtRowVersion: 4 },
      { addressRevisionId: OTHER_ADDRESS_REVISION },
    ]) {
      const h = harness();
      await expectFailure(recordCoverageAssessment({ ...h.input, snapshot }), 'COVERAGE_ASSESSMENT_STALE');
      expect(h.audit.attempts).toHaveLength(0);
    }
  });

  it('never decrypts when the audit attempt is duplicate, unconfirmed, lost or thrown, and never retries', async () => {
    const duplicate = harness({ audit: (audit) => { audit.result = 'DUPLICATE'; } });
    await expectFailure(recordCoverageAssessment(duplicate.input), 'CONFLICT');
    expect(duplicate.audit.attempts).toHaveLength(1);
    expect(payloadQueries(duplicate.queries)).toHaveLength(0);

    const unconfirmed = harness({ audit: (audit) => { audit.result = 'UNCONFIRMED'; } });
    await expectFailure(recordCoverageAssessment(unconfirmed.input), 'DEPENDENCY_UNAVAILABLE');
    expect(unconfirmed.audit.attempts).toHaveLength(1);
    expect(payloadQueries(unconfirmed.queries)).toHaveLength(0);

    const lost = harness({ audit: (audit) => { audit.error = new Error('connection lost'); } });
    await expectFailure(recordCoverageAssessment(lost.input), 'DEPENDENCY_UNAVAILABLE');
    expect(lost.audit.attempts).toHaveLength(1);
    expect(payloadQueries(lost.queries)).toHaveLength(0);
  });

  it('refuses after the audit when the caller recheck fails, with no decrypt and no retry', async () => {
    const refusal = new Error('authority revoked');
    const h = harness({ recheckError: refusal });
    // The caller's own refusal propagates unchanged (it is not rewritten into a
    // second opinion by this port) and nothing was decrypted or retried.
    await expect(recordCoverageAssessment(h.input)).rejects.toBe(refusal);
    expect(h.audit.attempts).toHaveLength(1);
    expect(h.rechecks).toHaveLength(1);
    expect(payloadQueries(h.queries)).toHaveLength(0);
  });
});

/* -------------------------- comparator reachability ------------------------ */

describe('verifyAssessmentAddress reachability', () => {
  it('cannot be used without the module branded consumption token', () => {
    const sealed = seal(ADDRESS);
    const forged = { consumed: true } as { readonly consumed: true };
    expectSyncFailure(() => verifyAssessmentAddress({
      consumption: forged, ring: RING,
      ref: { environment: ENVIRONMENT, cellId: PAYLOAD_CELL, requestId: REQUEST, kind: 'ADDRESS', revision: 1 },
      cell: sealed, wrap: sealed, candidate: ADDRESS,
    }), 'FORBIDDEN');
  });
});

/* ------------------------------- reproof ---------------------------------- */

describe('reproofCoverageBasis', () => {
  async function pinned(overrides: Partial<Fixture> = {}) {
    const basis = await readCoverageBasis(clientFor(fixture(overrides)).client, CITY, ADDRESS_REVISION, COVERAGE_BASIS_DEFAULT_CAP);
    return basis;
  }

  it('accepts an unchanged basis', async () => {
    const basis = await pinned();
    const again = await reproofCoverageBasis(clientFor(fixture()).client, CITY, ADDRESS_REVISION, basis.basisDigest, COVERAGE_BASIS_DEFAULT_CAP);
    expect(again.basisDigest).toBe(basis.basisDigest);
  });

  it('refuses on any basis drift with COVERAGE_ASSESSMENT_STALE', async () => {
    const basis = await pinned();
    const drift: readonly Partial<Fixture>[] = [
      { zoneRows: [{ area_id: AREA_A, area_version_id: AREA_VERSION_A }] },
      { zoneRows: [] },
      { mappingRows: [] },
      { mappingRows: [{ area_id: AREA_A, area_version_id: AREA_VERSION_A, district_id: DISTRICT, relation: 'PARTIAL' }] },
      { districtRows: [{ district_id: DISTRICT, row_version: 4, archived_at: null }] },
      { cityRow: { city_id: CITY, lifecycle: 'ACTIVE', current_version_id: OTHER_CITY_VERSION, timezone: 'Asia/Tokyo' } },
      { addressRows: [{ ...fixture().addressRows[0], current_address_revision_id: OTHER_ADDRESS_REVISION }] },
    ];
    for (const overrides of drift) {
      const h = clientFor(fixture(overrides));
      await expectFailure(reproofCoverageBasis(h.client, CITY, ADDRESS_REVISION, basis.basisDigest, COVERAGE_BASIS_DEFAULT_CAP),
        'COVERAGE_ASSESSMENT_STALE');
    }
  });

  it('rejects a malformed pinned digest without SQL', async () => {
    const { client, queries } = clientFor(fixture());
    await expectFailure(reproofCoverageBasis(client, CITY, ADDRESS_REVISION, 'not-a-digest', COVERAGE_BASIS_DEFAULT_CAP), 'UNPROCESSABLE');
    expect(queries).toHaveLength(0);
  });

  it('requires the fence for the live reproof too', async () => {
    const state = fixture({ fenceHeld: false });
    await expectFailure(reproofCoverageBasis(clientFor(state).client, CITY, ADDRESS_REVISION,
      createHash('sha256').update('x').digest('hex'), COVERAGE_BASIS_DEFAULT_CAP), 'NOT_READY');
  });
});
