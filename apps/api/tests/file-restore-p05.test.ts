/**
 * P05-01 slice (g): file-only restore guard extension (docs/P05-PLAN.md §5.3).
 *
 * Real PostgreSQL integration test, opt-in via FIXLEVELUP_FILE_RESTORE_TESTS=1
 * (same gating style as file-restore.test.ts). No S3/Garage is required: these
 * proofs are pure closed-source checks, so the suite runs against the disposable
 * isolated PostgreSQL fixture only (FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1).
 *
 * Covered:
 *  - full S1 chain (through 022): readP05SourceState returns empty=true with
 *    all ten P05 counts zero; one surviving customer row after drain makes
 *    assertP05AbsentAfterDrain refuse activation (P05_ROWS_PRESENT); removing
 *    that row restores P05_EMPTY_AFTER_DRAIN;
 *  - capped S0 chain (capBefore 20261123000100_request_intake_foundation): the
 *    exact pre-P05 source profile attests P05_SCHEMA_ABSENT_AFTER_DRAIN, while
 *    readP05SourceState itself reports SCHEMA_ABSENT;
 *  - partial drift: dropping one P05 relation on the disposable S1 fixture makes
 *    both readP05SourceState and assertP05AbsentAfterDrain refuse with the new
 *    PARTIAL_SCHEMA code — an unknown state never downgrades to a fact;
 *  - attestation build/verify: exact database/profile pass; wrong database,
 *    stale recordedAt (now - 2*maxAgeMs), wrong profile and cross-fact/profile
 *    combinations (S0+EMPTY, S1+ABSENT) or a mismatching expected fact fail;
 *  - round-4 audit finding #9 (docs/P05-PLAN.md §5.3 L129 trace 2): two
 *    individually KNOWN but DIFFERENT schema profiles are never
 *    interchangeable. The real activation gate (requireP05AbsentForActivation,
 *    the exact function both rescrubFileRestore call sites run against the
 *    TARGET) is invoked against real disposable targets whose P05 state does
 *    not match the manifest profile: an S0 manifest over an S1 target and an
 *    S1 manifest over an S0 target both refuse RESTORE_AUTHORITY, the epoch
 *    stays non-ACTIVE and runtime CONNECT stays withheld; the two matching
 *    pairs pass. No S3/Garage is required: only the gate is exercised.
 *
 * No PII: only integer counts, synthetic database names and random UUIDs.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createConfigurationFixture } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';
import { assertP05AbsentAfterDrain, P05_TABLES, P05InventoryError, readP05SourceState } from '../src/files/file-restore/p05-inventory.js';
import { buildP05Attestation, verifyP05Attestation } from '../src/files/file-restore/p05-attestation.js';
import { manifestSourceSchemaProfile, requireP05AbsentForActivation, requireP05ProfileFact } from '../src/files/file-restore/rescrub.js';
import { FileRestoreError } from '../src/files/file-restore/contract.js';

const enabled = process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] === '1';
const live = enabled ? describe : describe.skip;

live('P05-01 file-only restore P05 guard', () => {
  let s1: ConfigurationFixture | undefined;
  let s0: ConfigurationFixture | undefined;

  beforeAll(async () => {
    expect(process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS']).toBe('1');
    // Full chain = schema profile S1 (through 022); capped chain = exact pre-P05 S0.
    s1 = await createConfigurationFixture();
    s0 = await createConfigurationFixture({ capBefore: '20261123000100_request_intake_foundation' });
  }, 300_000);

  afterAll(async () => {
    await s1?.close();
    await s0?.close();
  }, 120_000);

  const requireS1 = (): ConfigurationFixture => {
    if (s1 === undefined) {throw new Error('S1 fixture is not initialized');}
    return s1;
  };
  const requireS0 = (): ConfigurationFixture => {
    if (s0 === undefined) {throw new Error('S0 fixture is not initialized');}
    return s0;
  };

  it('S1: drained source reads empty with all P05 counts zero', { timeout: 60_000 }, async () => {
    const state = await readP05SourceState(requireS1().migrator);
    expect(state.profile).toBe('S1');
    expect(state.empty).toBe(true);
    expect(Object.keys(state.counts)).toHaveLength(P05_TABLES.length);
    for (const table of P05_TABLES) {expect(state.counts[table]).toBe(0);}
    await expect(assertP05AbsentAfterDrain(requireS1().migrator)).resolves.toBe('P05_EMPTY_AFTER_DRAIN');
  });

  it('S1: a surviving P05 row refuses activation; removal restores the empty fact', { timeout: 60_000 }, async () => {
    const db = requireS1();
    await db.migrator.query('INSERT INTO foundation.customers (id) VALUES ($1)', [randomUUID()]);
    await expect(assertP05AbsentAfterDrain(db.migrator)).rejects.toBeInstanceOf(P05InventoryError);
    await expect(assertP05AbsentAfterDrain(db.migrator)).rejects.toMatchObject({ code: 'P05_ROWS_PRESENT' });
    // The migration owner (trusted operator side of the drain) removes the row.
    // The runtime immutability trigger forbids history rewrites, so it is disabled
    // only for this targeted removal on the disposable fixture and re-enabled after.
    await db.migrator.query('ALTER TABLE foundation.customers DISABLE TRIGGER customers_immutable');
    try {
      await db.migrator.query('DELETE FROM foundation.customers');
    } finally {
      await db.migrator.query('ALTER TABLE foundation.customers ENABLE TRIGGER customers_immutable');
    }
    const state = await readP05SourceState(db.migrator);
    expect(state.empty).toBe(true);
    await expect(assertP05AbsentAfterDrain(db.migrator)).resolves.toBe('P05_EMPTY_AFTER_DRAIN');
  });

  it('S0 (capped pre-P05 profile): absent P05 schema attests P05_SCHEMA_ABSENT_AFTER_DRAIN', { timeout: 60_000 }, async () => {
    const db = requireS0();
    await expect(readP05SourceState(db.migrator)).rejects.toMatchObject({ code: 'SCHEMA_ABSENT' });
    await expect(assertP05AbsentAfterDrain(db.migrator)).resolves.toBe('P05_SCHEMA_ABSENT_AFTER_DRAIN');
  });

  // Round-4 audit finding #9 (docs/P05-PLAN.md §5.3 L129, negative trace 2):
  // two individually KNOWN but DIFFERENT schema profiles are never
  // interchangeable on restore. The real activation gate is invoked against
  // real disposable targets whose P05 state does not match the manifest
  // profile. These proofs run BEFORE the partial-drift test below, which drops
  // a P05 table and ends S1-chain reuse in this suite.
  const S0_MANIFEST = { schemaVersion: '20261122000700_catalog_management' };
  const S1_MANIFEST = { schemaVersion: '20261123000100_request_intake_foundation' };

  /** Brings a disposable fixture into the exact state the trusted operator
   * leaves on a fresh restore target (restoreArchives in file-restore.test.ts):
   * one RESTORE_CLOSED epoch singleton and runtime CONNECT withheld. The
   * fixture granted CONNECT at creation; the database owner revokes it here,
   * mirroring the real target's creation-time REVOKE. The epoch row stays as
   * evidentiary state (the reviewed removal trigger forbids DELETE; no later
   * test in this suite reads it). The returned cleanup restores the fixture's
   * original CONNECT grant. The database name is fixture-generated. */
  const closeTargetForActivation = async (db: ConfigurationFixture): Promise<() => Promise<void>> => {
    await db.migrator.query(`INSERT INTO foundation.file_runtime_epochs (singleton,namespace_id,epoch,mode)
      VALUES (true,$1,1,'RESTORE_CLOSED')`, [randomUUID()]);
    const revoked = await db.migrator.query(`REVOKE CONNECT ON DATABASE "${db.database}" FROM fixlevelup_runtime`);
    expect(revoked.command).toBe('REVOKE');
    let restored = false;
    return async () => {
      if (restored) {return;}
      restored = true;
      await db.migrator.query(`GRANT CONNECT ON DATABASE "${db.database}" TO fixlevelup_runtime`);
    };
  };

  /** The closed-target facts rescrub.ts reads at its gate: the singleton mode,
   * the number of ACTIVE epochs, and the runtime role's CONNECT privilege —
   * the exact predicate the ACTIVE CAS re-proves in its WHERE clause. */
  const readClosedTarget = async (db: ConfigurationFixture): Promise<{ readonly mode: string; readonly active: number; readonly connect: boolean }> => {
    const state = (await db.migrator.query<{ mode: string; active: number; connect: boolean }>(`SELECT mode,
      (SELECT count(*)::int FROM foundation.file_runtime_epochs WHERE singleton AND mode='ACTIVE') AS active,
      has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT') AS connect
      FROM foundation.file_runtime_epochs WHERE singleton`)).rows[0];
    if (state === undefined) {throw new Error('Closed target epoch singleton is missing');}
    return state;
  };

  /** Mirrors the second requireP05AbsentForActivation call site in rescrub.ts:
   * the gate runs on a pinned operator client inside the closed pre-ACTIVE
   * transaction, and a FileRestoreError rolls that transaction back, so the
   * ACTIVE CAS below it never executes (this proof never runs the CAS).
   * Returns the refusal, or the fact when the gate passed. */
  const activationGate = async (db: ConfigurationFixture, manifest: { readonly schemaVersion: string }):
    Promise<{ readonly refused: FileRestoreError } | { readonly fact: 'P05_EMPTY_AFTER_DRAIN' | 'P05_SCHEMA_ABSENT_AFTER_DRAIN' }> => {
    const client = await db.migrator.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      try {
        return { fact: await requireP05AbsentForActivation(client, manifest) };
      } catch (error) {
        if (!(error instanceof FileRestoreError)) {throw error;}
        return { refused: error };
      } finally {
        await client.query('ROLLBACK').catch(() => undefined);
      }
    } finally { client.release(); }
  };

  it('target mismatch: S1 target with an S0 manifest refuses activation; epoch stays non-ACTIVE, runtime CONNECT stays withheld', { timeout: 60_000 }, async () => {
    const db = requireS1();
    const reopen = await closeTargetForActivation(db);
    try {
      expect(await readClosedTarget(db)).toMatchObject({ mode: 'RESTORE_CLOSED', active: 0, connect: false });
      // The manifest speaks the pre-P05 S0 profile (expected SCHEMA_ABSENT), but
      // this real target HAS all ten P05 tables, drained empty (fact EMPTY).
      expect(manifestSourceSchemaProfile(S0_MANIFEST)).toBe('S0');
      await expect(assertP05AbsentAfterDrain(db.migrator)).resolves.toBe('P05_EMPTY_AFTER_DRAIN');
      const gate = await activationGate(db, S0_MANIFEST);
      // Regression teeth: with the fact !== expected comparison removed from
      // rescrub.ts the gate resolves { fact: 'P05_EMPTY_AFTER_DRAIN' } instead.
      if (!('refused' in gate)) {throw new Error(`Activation gate passed a mismatched target with ${gate.fact}`);}
      expect(gate.refused).toBeInstanceOf(FileRestoreError);
      expect(gate.refused).toMatchObject({ code: 'RESTORE_AUTHORITY' });
      // Consequence: the refusal fired BEFORE any ACTIVE CAS could run, so the
      // closed epoch singleton is untouched and the runtime role still cannot
      // connect. The runtime pool has never opened a session on this fixture,
      // so its next query needs a fresh connection, which the target refuses.
      expect(await readClosedTarget(db)).toMatchObject({ mode: 'RESTORE_CLOSED', active: 0, connect: false });
      expect(db.runtime.totalCount).toBe(0);
      await expect(db.runtime.query('SELECT 1')).rejects.toMatchObject({ code: '42501' });
    } finally { await reopen(); }
  });

  it('target mismatch: S0 target with an S1 manifest refuses activation; epoch stays non-ACTIVE, runtime CONNECT stays withheld', { timeout: 60_000 }, async () => {
    const db = requireS0();
    const reopen = await closeTargetForActivation(db);
    try {
      expect(await readClosedTarget(db)).toMatchObject({ mode: 'RESTORE_CLOSED', active: 0, connect: false });
      // The manifest speaks the reviewed S1 profile (expected EMPTY), but this
      // capped pre-P05 target has no P05 schema at all (fact SCHEMA_ABSENT).
      expect(manifestSourceSchemaProfile(S1_MANIFEST)).toBe('S1');
      await expect(assertP05AbsentAfterDrain(db.migrator)).resolves.toBe('P05_SCHEMA_ABSENT_AFTER_DRAIN');
      const gate = await activationGate(db, S1_MANIFEST);
      if (!('refused' in gate)) {throw new Error(`Activation gate passed a mismatched target with ${gate.fact}`);}
      expect(gate.refused).toBeInstanceOf(FileRestoreError);
      expect(gate.refused).toMatchObject({ code: 'RESTORE_AUTHORITY' });
      expect(await readClosedTarget(db)).toMatchObject({ mode: 'RESTORE_CLOSED', active: 0, connect: false });
      expect(db.runtime.totalCount).toBe(0);
      await expect(db.runtime.query('SELECT 1')).rejects.toMatchObject({ code: '42501' });
    } finally { await reopen(); }
  });

  it('target match: S1/S1 and S0/S0 pairs pass the activation gate with their own facts and never refuse', { timeout: 60_000 }, async () => {
    // Positive controls: the refusals above come from the profile comparison
    // itself. Each target is acceptable for its own matching manifest, and
    // passing the gate alone flips nothing — only the real ACTIVE CAS would.
    expect(await activationGate(requireS1(), S1_MANIFEST)).toEqual({ fact: 'P05_EMPTY_AFTER_DRAIN' });
    expect(await activationGate(requireS0(), S0_MANIFEST)).toEqual({ fact: 'P05_SCHEMA_ABSENT_AFTER_DRAIN' });
    expect(await readClosedTarget(requireS1())).toMatchObject({ mode: 'RESTORE_CLOSED', active: 0 });
    expect(await readClosedTarget(requireS0())).toMatchObject({ mode: 'RESTORE_CLOSED', active: 0 });
  });

  it('S1 partial drift (one dropped P05 table) refuses with PARTIAL_SCHEMA, never downgrades', { timeout: 60_000 }, async () => {
    const db = requireS1();
    // Half-dropped P05 schema: request_events is gone, the other nine remain.
    // The migrator owner may DDL the disposable S1 fixture, and this suite does
    // not reuse the S1 chain after this test, so no re-CREATE is needed.
    await db.migrator.query('DROP TABLE foundation.request_events');
    await expect(readP05SourceState(db.migrator)).rejects.toBeInstanceOf(P05InventoryError);
    await expect(readP05SourceState(db.migrator)).rejects.toMatchObject({ code: 'PARTIAL_SCHEMA' });
    await expect(assertP05AbsentAfterDrain(db.migrator)).rejects.toBeInstanceOf(P05InventoryError);
    await expect(assertP05AbsentAfterDrain(db.migrator)).rejects.toMatchObject({ code: 'PARTIAL_SCHEMA' });
  });

  it('attestation: exact database/profile and fresh recordedAt verify; stale, wrong database or wrong profile fail', () => {
    const sourceDatabase = `fixlevelup_legal_test_${'0'.repeat(24)}`;
    const now = new Date('2026-11-23T09:00:00.000Z');
    const maxAgeMs = 300_000;
    const attestation = buildP05Attestation({ sourceDatabase, sourceSchemaProfile: 'S1',
      fact: 'P05_EMPTY_AFTER_DRAIN', now });
    expect(attestation).toMatchObject({ kind: 'P05_EMPTY_AFTER_DRAIN', sourceDatabase,
      sourceSchemaProfile: 'S1', recordedAt: now.toISOString() });
    expect(attestation.nonce).toMatch(/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
    expect(verifyP05Attestation(attestation, { sourceDatabase, sourceSchemaProfile: 'S1',
      maxAgeMs, now: new Date(now.getTime() + 60_000) })).toBe(true);
    // Two known profiles attest their own facts, never each other's identity.
    const s0 = buildP05Attestation({ sourceDatabase, sourceSchemaProfile: 'S0',
      fact: 'P05_SCHEMA_ABSENT_AFTER_DRAIN', now });
    expect(verifyP05Attestation(s0, { sourceDatabase, sourceSchemaProfile: 'S0', maxAgeMs, now })).toBe(true);
    expect(verifyP05Attestation(attestation, { sourceDatabase: `fixlevelup_legal_test_${'1'.repeat(24)}`,
      sourceSchemaProfile: 'S1', maxAgeMs, now })).toBe(false);
    const stale = buildP05Attestation({ sourceDatabase, sourceSchemaProfile: 'S1',
      fact: 'P05_EMPTY_AFTER_DRAIN', now: new Date(now.getTime() - 2 * maxAgeMs) });
    expect(verifyP05Attestation(stale, { sourceDatabase, sourceSchemaProfile: 'S1', maxAgeMs, now })).toBe(false);
    expect(verifyP05Attestation(attestation, { sourceDatabase, sourceSchemaProfile: 'S0', maxAgeMs, now })).toBe(false);
    // Cross-fact/profile combinations are inconsistent and never verify: schema
    // absence is only attestable by the pre-P05 S0 source, emptiness only by S1.
    const s0Empty = buildP05Attestation({ sourceDatabase, sourceSchemaProfile: 'S0',
      fact: 'P05_EMPTY_AFTER_DRAIN', now });
    expect(verifyP05Attestation(s0Empty, { sourceDatabase, sourceSchemaProfile: 'S0', maxAgeMs, now })).toBe(false);
    const s1Absent = buildP05Attestation({ sourceDatabase, sourceSchemaProfile: 'S1',
      fact: 'P05_SCHEMA_ABSENT_AFTER_DRAIN', now });
    expect(verifyP05Attestation(s1Absent, { sourceDatabase, sourceSchemaProfile: 'S1', maxAgeMs, now })).toBe(false);
    expect(s1Absent.kind).toBe('P05_SCHEMA_ABSENT_AFTER_DRAIN');
    // An explicitly expected fact must match the attested kind.
    expect(verifyP05Attestation(s0, { sourceDatabase, sourceSchemaProfile: 'S0',
      fact: 'P05_SCHEMA_ABSENT_AFTER_DRAIN', maxAgeMs, now })).toBe(true);
    expect(verifyP05Attestation(s0, { sourceDatabase, sourceSchemaProfile: 'S0',
      fact: 'P05_EMPTY_AFTER_DRAIN', maxAgeMs, now })).toBe(false);
    expect(verifyP05Attestation(attestation, { sourceDatabase, sourceSchemaProfile: 'S1',
      fact: 'P05_SCHEMA_ABSENT_AFTER_DRAIN', maxAgeMs, now })).toBe(false);
  });

  it('activation helper: profile is derived from the exact manifest schemaVersion; unreviewed heads refuse', () => {
    // Only the two reviewed heads resolve: the 021 baseline (S0) and the
    // reviewed P05 act 022 (S1). Everything else refuses.
    expect(manifestSourceSchemaProfile({ schemaVersion: '20261122000700_catalog_management' })).toBe('S0');
    expect(manifestSourceSchemaProfile({ schemaVersion: '20261123000100_request_intake_foundation' })).toBe('S1');
    // A later unknown head is never silently classified as S1...
    expect(() => manifestSourceSchemaProfile({ schemaVersion: '20261123000200_request_lifecycle' })).toThrow(/Unreviewed/);
    // ...and neither is an earlier known-but-unreviewed head (020) nor the
    // early chain head: lexicographic order alone grants no profile.
    expect(() => manifestSourceSchemaProfile({ schemaVersion: '20261122000600_pricing_rules_ranges' })).toThrow(/Unreviewed/);
    expect(() => manifestSourceSchemaProfile({ schemaVersion: '20261120000100_technical_audit_outbox' })).toThrow(/Unreviewed/);
  });

  it('activation helper: fact/profile binding accepts S0+ABSENT and S1+EMPTY, refuses the cross combinations and nonce reuse', () => {
    const db = `fixlevelup_legal_test_${'2'.repeat(24)}`;
    const now = new Date('2026-11-23T10:00:00.000Z');
    const s0 = { schemaVersion: '20261122000700_catalog_management', sourceDatabase: db };
    const s1 = { schemaVersion: '20261123000100_request_intake_foundation', sourceDatabase: db };
    const refusals = (run: () => void): void => {
      let refused: unknown;
      try { run(); } catch (error) {refused = error;}
      expect(refused).toBeInstanceOf(FileRestoreError);
      expect(refused).toMatchObject({ code: 'RESTORE_AUTHORITY' });
    };
    // The two profile-consistent facts pass; each handoff observes its own fact.
    requireP05ProfileFact(s0, { fact: 'P05_SCHEMA_ABSENT_AFTER_DRAIN', profile: 'S0', nonce: randomUUID() }, undefined, now);
    requireP05ProfileFact(s1, { fact: 'P05_EMPTY_AFTER_DRAIN', profile: 'S1', nonce: randomUUID() }, undefined, now);
    // Cross fact/profile combinations refuse: schema absence is only attestable
    // by the pre-P05 S0 source, emptiness only by the S1 source.
    refusals((): void => { requireP05ProfileFact(s0, { fact: 'P05_EMPTY_AFTER_DRAIN', profile: 'S0', nonce: randomUUID() }, undefined, now); });
    refusals((): void => { requireP05ProfileFact(s1, { fact: 'P05_SCHEMA_ABSENT_AFTER_DRAIN', profile: 'S1', nonce: randomUUID() }, undefined, now); });
    // A wrong reported profile refuses even with the otherwise consistent fact.
    refusals((): void => { requireP05ProfileFact(s0, { fact: 'P05_SCHEMA_ABSENT_AFTER_DRAIN', profile: 'S1', nonce: randomUUID() }, undefined, now); });
    refusals((): void => { requireP05ProfileFact(s1, { fact: 'P05_EMPTY_AFTER_DRAIN', profile: 'S0', nonce: randomUUID() }, undefined, now); });
    // Cross-handoff stability: the second handoff must present a DIFFERENT nonce.
    const first = randomUUID();
    requireP05ProfileFact(s1, { fact: 'P05_EMPTY_AFTER_DRAIN', profile: 'S1', nonce: first }, undefined, now);
    requireP05ProfileFact(s1, { fact: 'P05_EMPTY_AFTER_DRAIN', profile: 'S1', nonce: randomUUID() }, first, now);
    refusals((): void => { requireP05ProfileFact(s1, { fact: 'P05_EMPTY_AFTER_DRAIN', profile: 'S1', nonce: first }, first, now); });
    refusals((): void => { requireP05ProfileFact(s1, { fact: 'P05_EMPTY_AFTER_DRAIN', profile: 'S1', nonce: '' }, undefined, now); });
  });
});
