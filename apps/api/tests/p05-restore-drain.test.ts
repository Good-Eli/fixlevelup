/**
 * P05 §5.3 — signed restore authority v2 and the drained-source handoff proof.
 *
 * Scope: finish the S3 wiring of the file-only restore, without touching the
 * reviewed 001–024 SQL and without any production/working restore.
 *
 * ## Part 1 — pure signed-authority proofs (always run)
 *
 * The P03 authority record (challenge/manifest/overlay/inventory/head) is retained
 * for legacy artifacts, but it names no source database, cluster, schema profile,
 * epoch or destination. `requireAuthorityV2` therefore refuses a valid, freshly
 * signed v1 record on its own: legacy artifacts stay restorable only with the new
 * v2 authority, never by the old record alone. Every bound field of v2 is
 * re-serialized from the parsed record and compared to the signed payload, so a
 * partial/renamed/reordered record cannot pass; a second signer cannot either.
 *
 * ## Part 2 — real isolated PostgreSQL: a callback accepted AFTER the empty inventory
 *
 * Plan §5.3 trace 1: the "P05 is empty" fact is taken when the base dump/manifest
 * is created, so it is only PRELIMINARY. This proof commits a real callback
 * (no attachment) after that fact was observed, drains the source exactly like the
 * operator bridge (fenced epoch, runtime CONNECT revoked, `datallowconn=false`,
 * every other backend gone), and shows that the same observation the core makes
 * before activation refuses with RESTORE_AUTHORITY even though the dump itself has
 * no request row.
 *
 * The callback is a REAL committed effect, not a fabricated archive: it is written
 * in one transaction whose deferred `request_effect_complete` and
 * `request_aggregate_complete` triggers validate the exact reviewed completeness
 * (receipt + audit + outbox + principal + staff manual-intake evidence +
 * provenance + contact/preference pointers), and `SET CONSTRAINTS ALL IMMEDIATE`
 * runs those checks before COMMIT. A smoke substitute would fail here.
 *
 * Not covered here (needs the full Garage/ledger contour): the terminal gap between
 * the last source check and the target ACTIVE CAS — `file-restore.test.ts` owns that
 * (it now signs and re-checks the v2 authority on both handoffs).
 */
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { Client } from 'pg';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { canonicalJson } from '../src/infrastructure/admission/proof.js';
import { loadKeyring } from '../src/requests/crypto/keyring.js';
import { idempotencyHmac, sealPayload } from '../src/requests/crypto/payload-cipher.js';
import { validateLimits } from '../src/files/file-restore/records.js';
import {
  readAuthority, readAuthorityV2, readSnapshot, requireAuthorityV2, signAuthority, signAuthorityV2, signSnapshot,
} from '../src/files/file-restore/records.js';
import type { AuthorityRecord, AuthorityRecordV2, ClusterFact, RestoreLimits, SnapshotManifest } from '../src/files/file-restore/contract.js';
import { requireBoundAuthority, requireP05AbsentForActivation } from '../src/files/file-restore/rescrub.js';
import { observeFencedSource, readClusterFact } from '../src/files/file-restore/p05-source-fence.js';
import { P05InventoryError, readP05SourceState, readP05TargetDrainState } from '../src/files/file-restore/p05-inventory.js';
import { readAuthorityInventory } from '../src/files/file-restore/inventory.js';
import { createConfigurationFixture, openConfigurationMaintenanceClient } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';
import { seedRequestFixtures } from './p05-request-fixtures.js';
import type { RequestFixtures } from './p05-request-fixtures.js';
import { dropOwnedTestDatabase, fixtureCredentials, becomeOwner, releaseOwner } from './owned-test-database.js';

/* -------------------------------------------------------------------------- */
/* Part 1 — signed authority v2                                              */
/* -------------------------------------------------------------------------- */

const authorityKeys = generateKeyPairSync('ed25519');
const otherKeys = generateKeyPairSync('ed25519');

const NAMESPACE = '11111111-1111-4111-8111-111111111111';
const INCARNATION = '22222222-2222-4222-8222-222222222222';
const DESTINATION = `fixlevelup_file_restore_${randomBytes(12).toString('hex')}`;
const SOURCE_DB = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
const HEAD = { namespace: NAMESPACE, incarnation: INCARNATION, writerEpoch: 7n, seq: 3n,
  hash: 'a'.repeat(64) } as const;
const CLUSTER: ClusterFact = Object.freeze({ systemIdentifier: '7709991591256236075',
  serverVersionNum: '180007', postmasterStart: '2026-11-24 14:52:59.398011+00' });

function v2Record(overrides: Partial<AuthorityRecordV2> = {}): AuthorityRecordV2 {
  return {
    challenge: 'b'.repeat(64), manifestSha256: 'c'.repeat(64), overlaySha256: 'd'.repeat(64),
    inventorySha256: 'e'.repeat(64), head: HEAD, sourceDatabase: SOURCE_DB, sourceDatabaseOid: 16384,
    cluster: CLUSTER, sourceProfile: 'S3', oldNamespace: NAMESPACE, oldWriterEpoch: '7', destinationDatabase: DESTINATION,
    ...overrides,
  };
}

describe('§5.3 signed authority v2', () => {
  it('round-trips exactly and keeps the legacy v1 record readable for artifacts', () => {
    const signed = signAuthorityV2(v2Record(), authorityKeys.privateKey);
    const { record } = readAuthorityV2(signed, authorityKeys.publicKey);
    expect(record).toEqual(v2Record());
    // The legacy v1 domain still verifies on its own (legacy artifacts remain
    // readable) but never yields a v2 record.
    const legacy: AuthorityRecord = { challenge: 'b'.repeat(64), manifestSha256: 'c'.repeat(64),
      overlaySha256: 'd'.repeat(64), inventorySha256: 'e'.repeat(64), head: HEAD };
    expect(readAuthority(signAuthority(legacy, authorityKeys.privateKey), authorityKeys.publicKey).record).toEqual(legacy);
  });

  it('refuses a valid, freshly signed v1 record as admission (old record alone fails closed)', () => {
    const legacy = signAuthority({ challenge: 'b'.repeat(64), manifestSha256: 'c'.repeat(64),
      overlaySha256: 'd'.repeat(64), inventorySha256: 'e'.repeat(64), head: HEAD }, authorityKeys.privateKey);
    expect(() => readAuthorityV2(legacy, authorityKeys.publicKey)).toThrow(expect.objectContaining({ name: 'FileRestoreError' }));
    expect(() => requireAuthorityV2(legacy, authorityKeys.publicKey)).toThrow(expect.objectContaining({ code: 'RESTORE_AUTHORITY' }));
  });

  it('refuses a foreign signature and a tampered payload; a valid other-fact record is refused by binding', () => {
    const signed = signAuthorityV2(v2Record(), authorityKeys.privateKey);
    // A key this run does not trust.
    expect(() => requireAuthorityV2(signed, otherKeys.publicKey)).toThrow(expect.objectContaining({ code: 'RESTORE_AUTHORITY' }));
    // A signature over another OID is a VALID record (signature/shape layer) but
    // names another source, so the binding layer refuses it. The two layers stay
    // separate: signature validity is never admission by itself.
    const other = signAuthorityV2(v2Record({ sourceDatabaseOid: 16385 }), authorityKeys.privateKey);
    expect(readAuthorityV2(other, authorityKeys.publicKey).record.sourceDatabaseOid).toBe(16385);
    expect(() => {
      requireBoundAuthority(readAuthorityV2(other, authorityKeys.publicKey).record, {
        manifestSha256: 'c'.repeat(64), sourceDatabase: SOURCE_DB, destinationDatabase: DESTINATION,
        sourceDatabaseOid: 16384, sourceProfile: 'S3', oldNamespace: NAMESPACE, oldWriterEpoch: '7',
        observed: { cluster: CLUSTER, inventorySha256: 'e'.repeat(64) },
      });
    }).toThrow(expect.objectContaining({ code: 'RESTORE_AUTHORITY' }));
    // Same signature, mutated payload: the exact re-serialization check refuses.
    const mutated = { ...signed, payload: signed.payload.replace('"S3"', '"S2"') };
    expect(() => requireAuthorityV2(mutated, authorityKeys.publicKey)).toThrow(expect.objectContaining({ code: 'RESTORE_AUTHORITY' }));
    // A truncated tuple cannot be coerced into a record either.
    const truncated = signAuthorityV2(v2Record(), authorityKeys.privateKey);
    expect(() => requireAuthorityV2({ ...truncated, payload: truncated.payload.slice(0, -2) }, authorityKeys.publicKey))
      .toThrow(expect.objectContaining({ code: 'RESTORE_AUTHORITY' }));
  });

  it('refuses a destination/source that does not match the reviewed name patterns', () => {
    for (const bad of [
      { sourceDatabase: 'postgres' },
      { destinationDatabase: 'fixlevelup_dev' },
      { oldNamespace: 'not-a-uuid' },
      { oldWriterEpoch: '0' },
      { sourceDatabaseOid: 0 },
    ]) {
      const signed = signAuthorityV2({ ...v2Record(), ...bad }, authorityKeys.privateKey);
      expect(() => readAuthorityV2(signed, authorityKeys.publicKey), JSON.stringify(bad))
        .toThrow(expect.objectContaining({ name: 'FileRestoreError' }));
    }
  });

  it('binds the observed cluster, database, OID, profile, epoch and destination exactly', () => {
    const observed = { cluster: CLUSTER, inventorySha256: 'e'.repeat(64) };
    const expected = { manifestSha256: 'c'.repeat(64), sourceDatabase: SOURCE_DB, destinationDatabase: DESTINATION,
      sourceDatabaseOid: 16384, sourceProfile: 'S3' as const, oldNamespace: NAMESPACE, oldWriterEpoch: '7', observed };
    expect(() => { requireBoundAuthority(v2Record(), expected); }).not.toThrow();
    const mismatches: Partial<AuthorityRecordV2>[] = [
      { cluster: { ...CLUSTER, systemIdentifier: '7709991591256236076' } },
      { cluster: { ...CLUSTER, serverVersionNum: '180006' } },
      { cluster: { ...CLUSTER, postmasterStart: '2026-11-24 15:52:59.398011+00' } },
      { sourceDatabase: `fixlevelup_legal_test_${'0'.repeat(24)}` },
      { destinationDatabase: `fixlevelup_file_restore_${'0'.repeat(24)}` },
      { sourceDatabaseOid: 16385 },
      { sourceProfile: 'S2' },
      { oldNamespace: INCARNATION },
      { oldWriterEpoch: '8' },
      { manifestSha256: 'f'.repeat(64) },
      { inventorySha256: 'f'.repeat(64) },
    ];
    for (const mismatch of mismatches) {
      expect(() => { requireBoundAuthority({ ...v2Record(), ...mismatch }, expected); }, JSON.stringify(mismatch))
        .toThrow(expect.objectContaining({ code: 'RESTORE_AUTHORITY' }));
    }
  });

  it('keeps the legacy snapshot manifest format unchanged', () => {
    const manifest: SnapshotManifest = { sourceDatabase: SOURCE_DB, destinationDatabase: DESTINATION,
      schemaVersion: '20261125000100_request_intake_effects', dumpSha256: 'a'.repeat(64), base: HEAD, aliases: [], inventory: [] };
    const limits = validateLimits({ maxObjects: 4096, maxIntents: 4096, maxObjectBytes: 16_777_216,
      maxTotalObjectBytes: 268_435_456, maxManifestBytes: 4_194_304, maxDumpBytes: 268_435_456 });
    const signed = signSnapshot(manifest, authorityKeys.privateKey);
    expect(readSnapshot(signed, authorityKeys.publicKey, limits).manifest).toEqual(manifest);
  });
});

/* -------------------------------------------------------------------------- */
/* Part 2 — real isolated PostgreSQL: post-dump callback + drain            */
/* -------------------------------------------------------------------------- */

const enabled = process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] === '1'
  && process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1';
const live = enabled ? describe : describe.skip;

const S3_HEAD_NAME = '20261125000100_request_intake_effects';
const LIMITS: RestoreLimits = validateLimits({ maxObjects: 4096, maxIntents: 4096, maxObjectBytes: 16_777_216,
  maxTotalObjectBytes: 268_435_456, maxManifestBytes: 4_194_304, maxDumpBytes: 268_435_456 });

/**
 * How a negative case tampers with the PHONE facts of an otherwise complete
 * aggregate. Each variant must be REFUSED by the database itself (23514), never by
 * this test's opinion.
 */
type PhoneTamper =
  | 'omit-permission'
  | 'permission-on-foreign-command'
  | 'permission-for-other-contact'
  | 'revoked-without-withdraw'
  | 'evidence-wrong-purpose'
  | 'evidence-other-staff';

/**
 * The EXACT, unmasked refusal each tamper must produce: the reviewed guard's own
 * message at a known stage. Asserting the message — not merely the SQLSTATE — proves
 * the refusal came from the guard under test rather than from an unrelated
 * constraint such as an append-only history trigger or a foreign key.
 */
const PHONE_TAMPER_REFUSAL: Readonly<Record<PhoneTamper,
  { readonly message: string; readonly stage: 'row-guard' | 'event-guard' }>> = {
  'omit-permission': { message: 'Incomplete phone permission for a callback request', stage: 'event-guard' },
  'permission-on-foreign-command': { message: 'Phone permission issued by an unrelated command', stage: 'row-guard' },
  'permission-for-other-contact': { message: 'Phone permission is not for the current contact', stage: 'row-guard' },
  'revoked-without-withdraw': { message: 'Phone permission revoked by an unrelated command', stage: 'row-guard' },
  'evidence-wrong-purpose': { message: 'Incomplete phone permission evidence', stage: 'row-guard' },
  'evidence-other-staff': { message: 'Incomplete phone permission evidence', stage: 'row-guard' },
};

interface PhoneRefusal {
  readonly code: string;
  readonly message: string;
  readonly stage: 'row-guard' | 'event-guard';
}

interface CallbackEffectResult {
  readonly requestId?: string;
  readonly refusal?: PhoneRefusal;
}

interface CommandUnit {
  readonly eventId: string;
  readonly requestId: string;
  readonly correlationId: string;
  readonly command: string;
  readonly actorStaffId: string;
  readonly version: number;
  readonly status: string;
  readonly idempotencyKey: string;
  readonly fingerprint: Buffer;
}

/**
 * Writes one complete command unit — event, audit row, outbox row and receipt — in
 * the reviewed order. History is INSERT-only here: no reviewed history row is ever
 * updated, so a tamper can never be refused by the append-only trigger instead of by
 * the guard under test.
 */
async function insertCommandUnit(client: PoolClient, unit: CommandUnit): Promise<void> {
  const auditId = randomUUID();
  const outboxId = randomUUID();
  const eventType = unit.command === 'CreateCallback' ? 'REQUEST_CALLBACK_INTENT' : 'REQUEST_EFFECT_RECORDED';
  const details = { requestId: unit.requestId, status: unit.status, version: unit.version };
  await client.query(`INSERT INTO foundation.request_events
    (id,request_id,command,principal,operation,idempotency_key,actor_type,actor_session_id,actor_staff_id,
      resulting_version,correlation_id,details)
    VALUES ($1,$2,$3,$4,$3,$5,'STAFF',NULL,$6,$7,$8,$9::jsonb)`,
  [unit.eventId, unit.requestId, unit.command, `STAFF:${unit.actorStaffId}`, unit.idempotencyKey,
    unit.actorStaffId, unit.version, unit.correlationId, JSON.stringify(details)]);
  await client.query(`INSERT INTO foundation.audit_logs(id,operation,correlation_id,details)
    VALUES ($1,$2,$3,$4::jsonb)`,
  [auditId, unit.command, unit.correlationId,
    JSON.stringify({ ...details, actorId: unit.actorStaffId, actorKind: 'STAFF' })]);
  await client.query(`INSERT INTO foundation.outbox_events(id,event_id,event_type,payload)
    VALUES ($1,$2,$3,$4::jsonb)`,
  [outboxId, unit.eventId, eventType, JSON.stringify({ requestId: unit.requestId, version: String(unit.version) })]);
  await client.query(`INSERT INTO foundation.request_command_receipts
    (event_id,request_id,version,correlation_id,command,key_id,fingerprint,resulting_status,audit_id,outbox_id)
    VALUES ($1,$2,$3,$4,$5,'test-hmac-1',$6,$7,$8,$9)`,
  [unit.eventId, unit.requestId, unit.version, unit.correlationId, unit.command, unit.fingerprint,
    unit.status, auditId, outboxId]);
}

/**
 * Writes one REAL committed callback effect (manual staff intake, no attachment) in
 * a single transaction. Every deferred completeness trigger of the reviewed 024 DDL
 * runs before COMMIT via `SET CONSTRAINTS ALL IMMEDIATE`, so the row set is proven
 * complete by the database itself — not by this test's opinion.
 *
 * This is a PHONE-mode manual callback, so completeness includes the exact reviewed
 * phone-permission facts: a `PHONE_GIVE` staff evidence bound to the same staff
 * member, and the `GIVEN` permission row for the current contact issued by this very
 * command. Omitting either must fail the deferred guard.
 *
 * `tamper` builds the same aggregate with one deliberate PHONE defect and returns the
 * exact unmasked refusal (SQLSTATE, reviewed message and stage); nothing is committed
 * in that case. Every defect is built by INSERTing the wrong rows — never by updating
 * append-only history, which would make the history trigger answer instead of the
 * guard under test.
 */
async function buildCallbackEffect(db: ConfigurationFixture, fixture: RequestFixtures,
  tamper?: PhoneTamper): Promise<CallbackEffectResult> {
  const ring = loadKeyring({ activeKekId: 'test-kek-1', activeHmacKeyId: 'test-hmac-1',
    kek: [{ keyId: 'test-kek-1', secretHex: randomBytes(32).toString('hex') }],
    hmac: [{ keyId: 'test-hmac-1', secretHex: randomBytes(32).toString('hex') }] });
  const requestId = randomUUID();
  const customerId = randomUUID();
  const contactId = randomUUID();
  const otherContactId = randomUUID();
  const preferenceId = randomUUID();
  const cellId = randomUUID();
  const otherCellId = randomUUID();
  const eventId = randomUUID();
  const secondEventId = randomUUID();
  const correlationId = randomUUID();
  const secondCorrelationId = randomUUID();
  const manualEvidenceId = randomUUID();
  const phoneEvidenceId = randomUUID();
  const givenPermissionId = randomUUID();
  const permissionId = randomUUID();
  const staffId = fixture.reviewerId;
  const callbackKey = randomUUID();
  const secondKey = randomUUID();
  // A REAL reviewed receipt fingerprint: the same HMAC primitive the intake writes,
  // over a canonical synthetic intent. This test never sends the command over HTTP,
  // so the receipt is structural (late, not sent) — but its fingerprint is genuine,
  // never random bytes.
  const fingerprintOf = (command: string, key: string) => idempotencyHmac({ ring, namespace: `STAFF:${staffId}`,
    canonicalIntent: canonicalJson({ operation: command, key, target: null, ifMatch: null,
      body: { requestId, type: 'CALLBACK' } }) }).digest;
  const seal = (revision: number) => {
    const plaintext = Buffer.from(canonicalJson({ name: 'Synthetic late callback sentinel', phone: '+15550100002' }), 'utf8');
    try {
      return sealPayload({ ring, environment: 'p05-restore-drain', schema: 'foundation', kind: 'CONTACT',
        requestId, revision, plaintext });
    } finally { plaintext.fill(0); }
  };
  const sealed = seal(1);
  const otherSealed = seal(2);
  const client = await db.migrator.connect();
  let atDeferredChecks = false;
  const insertPermission = async (options: { readonly id: string; readonly contact: string;
    readonly action: 'GIVEN' | 'REVOKED'; readonly event: string; readonly evidence: string | null;
    readonly supersedes: string | null }) => {
    await client.query(`INSERT INTO foundation.phone_permission_events
      (id,request_id,contact_revision_id,action,supersedes_given_id,event_id,staff_evidence_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [options.id, requestId, options.contact, options.action, options.supersedes, options.event, options.evidence]);
  };
  try {
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    await client.query('INSERT INTO foundation.customers(id) VALUES ($1)', [customerId]);
    // The aggregate and its history are one unit: the current pointers are
    // DEFERRABLE, so the request row can name revisions inserted a moment later.
    await client.query(`INSERT INTO foundation.requests
      (id,type,status,customer_id,city_id,intake_city_version_id,workflow_package_id,intake_policy_revision_id,
        current_contact_revision_id,current_preference_revision_id)
      VALUES ($1,'CALLBACK','CALLBACK_REQUIRED',$2,$3,$4,$5,$5,$6,$7)`,
    [requestId, customerId, fixture.cityId, fixture.cityVersionId, fixture.policyId, contactId, preferenceId]);
    await client.query(`INSERT INTO foundation.request_payload_cells
      (id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
      VALUES ($1,$2,'CONTACT',1,$3,$4,$5,$6,$7,$8)`,
    [cellId, requestId, sealed.keyId, sealed.wrappedDek, sealed.nonce, sealed.ciphertext, sealed.authTag, sealed.aadContext]);
    await client.query(`INSERT INTO foundation.request_contact_revisions(id,request_id,revision,mode,payload_cell_id)
      VALUES ($1,$2,1,'PHONE',$3)`, [contactId, requestId, cellId]);
    if (tamper === 'permission-for-other-contact') {
      // A second, deliberately NON-current contact revision. It is a COMPLETE row of
      // its own — sealed cell revision 2 plus the matching contact revision — so the
      // refusal cannot be an artefact of reusing revision 1's payload cell.
      await client.query(`INSERT INTO foundation.request_payload_cells
        (id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
        VALUES ($1,$2,'CONTACT',2,$3,$4,$5,$6,$7,$8)`,
      [otherCellId, requestId, otherSealed.keyId, otherSealed.wrappedDek, otherSealed.nonce, otherSealed.ciphertext,
        otherSealed.authTag, otherSealed.aadContext]);
      await client.query(`INSERT INTO foundation.request_contact_revisions(id,request_id,revision,mode,payload_cell_id)
        VALUES ($1,$2,2,'PHONE',$3)`, [otherContactId, requestId, otherCellId]);
    }
    await client.query(`INSERT INTO foundation.request_preference_revisions(id,request_id,revision,urgency,preferred_windows,contact_mode)
      VALUES ($1,$2,1,'FLEXIBLE','[]'::jsonb,'PHONE')`, [preferenceId, requestId]);
    const sourceVersion = (await client.query<{ id: string }>(
      `SELECT id FROM foundation.reference_entry_versions WHERE entry_id=$1 ORDER BY version DESC LIMIT 1`,
      [fixture.formSourceEntryId])).rows[0]?.id;
    if (sourceVersion === undefined) { throw new Error('Missing seeded request source version'); }
    await client.query(`INSERT INTO foundation.request_intake_provenance(request_id,source_entry_id,source_version_id)
      VALUES ($1,$2,$3)`, [requestId, fixture.formSourceEntryId, sourceVersion]);
    await client.query(`INSERT INTO foundation.request_staff_evidence
      (id,request_id,staff_id,purpose,procedure_revision,valid_until)
      VALUES ($1,$2,$3,'MANUAL_INTAKE','p05-manual-intake-v1',clock_timestamp()+interval '1 hour')`,
    [manualEvidenceId, requestId, staffId]);
    // The correct PHONE_GIVE evidence. For the other-staff tamper it is created up
    // front for a DIFFERENT reviewed staff identity — never by updating history.
    const phoneEvidenceStaff = tamper === 'evidence-other-staff' ? db.secondReviewer : staffId;
    await client.query(`INSERT INTO foundation.request_staff_evidence
      (id,request_id,staff_id,purpose,procedure_revision,valid_until)
      VALUES ($1,$2,$3,'PHONE_GIVE','p05-phone-give-v1',clock_timestamp()+interval '1 hour')`,
    [phoneEvidenceId, requestId, phoneEvidenceStaff]);
    // The callback command unit. It is never relabelled afterwards.
    await insertCommandUnit(client, { eventId, requestId, correlationId, command: 'CreateCallback',
      actorStaffId: staffId, version: 1, status: 'CALLBACK_REQUIRED', idempotencyKey: callbackKey,
      fingerprint: fingerprintOf('CreateCallback', callbackKey) });

    // The PHONE facts, written in the reviewed order. Each variant below breaks
    // exactly one reviewed property.
    if (tamper === 'revoked-without-withdraw') {
      // A REAL superseded GIVEN row first (the composite FK of the REVOKED row must
      // resolve), then the request version advances through the reviewed
      // `requests_guard`, and a second command unit is INSERTed. The REVOKED row is
      // then attached to that unrelated command.
      await insertPermission({ id: givenPermissionId, contact: contactId, action: 'GIVEN', event: eventId,
        evidence: phoneEvidenceId, supersedes: null });
      await client.query(`UPDATE foundation.requests SET status='CANCELLED' WHERE id=$1`, [requestId]);
      await insertCommandUnit(client, { eventId: secondEventId, requestId, correlationId: secondCorrelationId,
        command: 'CreateCallback', actorStaffId: staffId, version: 2, status: 'CANCELLED',
        idempotencyKey: secondKey, fingerprint: fingerprintOf('CreateCallback', secondKey) });
      await insertPermission({ id: permissionId, contact: contactId, action: 'REVOKED', event: secondEventId,
        evidence: phoneEvidenceId, supersedes: givenPermissionId });
    } else if (tamper === 'permission-on-foreign-command') {
      // A second, consistent command unit whose command must never issue a phone
      // permission; the permission row names THAT event, so no history row is edited.
      await client.query(`UPDATE foundation.requests SET status='CANCELLED' WHERE id=$1`, [requestId]);
      await insertCommandUnit(client, { eventId: secondEventId, requestId, correlationId: secondCorrelationId,
        command: 'CancelRequest', actorStaffId: staffId, version: 2, status: 'CANCELLED',
        idempotencyKey: secondKey, fingerprint: fingerprintOf('CancelRequest', secondKey) });
      await insertPermission({ id: permissionId, contact: contactId, action: 'GIVEN', event: secondEventId,
        evidence: phoneEvidenceId, supersedes: null });
    } else if (tamper === 'permission-for-other-contact') {
      await insertPermission({ id: permissionId, contact: otherContactId, action: 'GIVEN', event: eventId,
        evidence: phoneEvidenceId, supersedes: null });
    } else if (tamper === 'evidence-wrong-purpose') {
      // The permission names the EXISTING MANUAL_INTAKE evidence of the same staff
      // member, so the purpose mismatch is proven without touching history.
      await insertPermission({ id: permissionId, contact: contactId, action: 'GIVEN', event: eventId,
        evidence: manualEvidenceId, supersedes: null });
    } else if (tamper === 'evidence-other-staff') {
      await insertPermission({ id: permissionId, contact: contactId, action: 'GIVEN', event: eventId,
        evidence: phoneEvidenceId, supersedes: null });
    } else if (tamper === undefined) {
      await insertPermission({ id: permissionId, contact: contactId, action: 'GIVEN', event: eventId,
        evidence: phoneEvidenceId, supersedes: null });
    }
    // 'omit-permission' writes no permission row at all.

    // The reviewed deferred guards run here, before the commit point.
    atDeferredChecks = true;
    await client.query('SET CONSTRAINTS ALL IMMEDIATE');
    await client.query('COMMIT');
    return { requestId };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (tamper === undefined) { throw error; }
    // A tampered aggregate must be refused by the database, and the whole unit must
    // be gone afterwards — nothing is ever committed.
    const code = (error as { code?: unknown }).code;
    const message = (error as { message?: unknown }).message;
    return { refusal: {
      code: typeof code === 'string' ? code : 'UNKNOWN',
      message: typeof message === 'string' ? message : 'UNKNOWN',
      stage: atDeferredChecks ? 'event-guard' : 'row-guard',
    } };
  } finally {
    client.release();
  }
}

/** The positive builder: a complete aggregate, or a hard failure. */
async function commitCallbackEffect(db: ConfigurationFixture, fixture: RequestFixtures): Promise<string> {
  const built = await buildCallbackEffect(db, fixture);
  if (built.requestId === undefined) {
    throw new Error(`Complete callback effect was refused (${built.refusal?.code ?? 'unknown'}: ${built.refusal?.message ?? 'unknown'})`);
  }
  return built.requestId;
}

/**
 * The P1 defect this task closes: a committed staff `CreateCallback` used to be
 * accepted with NO phone permission at all. Each variant below breaks exactly one
 * reviewed property of the PHONE facts and must be refused by the database with
 * `23514` (a guard violation), never silently accepted and never a generic
 * constraint error from somewhere else.
 */
live('024 PHONE completeness guard (real isolated PostgreSQL)', () => {
  it('refuses every incomplete phone fact and accepts the complete one', { timeout: 180_000 }, async () => {
    // Its own disposable database: this proof commits one real aggregate, so it must
    // not share the drained-source fixture below (which starts from an empty P05).
    const db = await createConfigurationFixture();
    try {
      const seeded = await seedRequestFixtures({ db: db.migrator }, { reviewerId: db.reviewer });
      const before = await readP05SourceState(db.migrator, 'S3');
      const cases: readonly PhoneTamper[] = ['omit-permission', 'permission-on-foreign-command',
        'permission-for-other-contact', 'revoked-without-withdraw', 'evidence-wrong-purpose', 'evidence-other-staff'];
      for (const tamper of cases) {
        const refused = await buildCallbackEffect(db, seeded, tamper);
        expect(refused.requestId, `${tamper} must not commit`).toBeUndefined();
        const expected = PHONE_TAMPER_REFUSAL[tamper];
        expect(refused.refusal?.code, `${tamper} must be a guard violation`).toBe('23514');
        // The UNMASKED reviewed message: this is what proves the intended guard
        // answered, not the append-only history trigger or an arbitrary foreign key.
        expect(refused.refusal?.message, `${tamper} must fail inside the intended guard`).toBe(expected.message);
        expect(refused.refusal?.stage, `${tamper} must fail at the intended stage`).toBe(expected.stage);
      }
      // Nothing from the refused attempts leaked into the database.
      expect(await readP05SourceState(db.migrator, 'S3')).toEqual(before);
      expect((await db.migrator.query<{ n: number }>(
        'SELECT count(*)::int AS n FROM foundation.phone_permission_events')).rows[0]?.n).toBe(0);
      expect((await db.migrator.query<{ n: number }>(
        'SELECT count(*)::int AS n FROM foundation.request_staff_evidence')).rows[0]?.n).toBe(0);
      // The complete aggregate is still accepted, which proves the guard is a
      // completeness check and not a blanket refusal.
      const requestId = await commitCallbackEffect(db, seeded);
      expect((await db.migrator.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM foundation.phone_permission_events
          WHERE request_id=$1 AND action='GIVEN'`, [requestId])).rows[0]?.n).toBe(1);
    } finally {
      await db.close();
    }
  });
});

live('§5.3 S3 drained-source handoff (real isolated PostgreSQL)', () => {
  let fixture: ConfigurationFixture | undefined;
  let requests: RequestFixtures | undefined;
  let observer: Client | undefined;
  let poolsEnded = false;

  beforeAll(async () => {
    expect(process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS']).toBe('1');
    fixture = await createConfigurationFixture();
  }, 300_000);

  afterAll(async () => {
    // The observer is the only session this run still owns at teardown; a failure
    // to end it must not hide the cleanup that follows.
    try { await observer?.end(); } catch { /* reported by the drop below if it matters */ }
    if (fixture === undefined) { return; }
    if (poolsEnded) {
      // This test closed the fixture's own pools to install the hard barrier, so
      // the fixture object can no longer dispose them (double end is an error).
      // Drop exactly the disposable database this run created, through the helper
      // that exists for this case: strict name pattern, no force on any other
      // database.
      const maintenance = await openConfigurationMaintenanceClient();
      try { await dropOwnedTestDatabase(maintenance, fixture.database); }
      finally { await maintenance.end(); }
    } else {
      await fixture.close();
    }
  }, 120_000);

  it('a callback committed after the empty inventory makes the fenced source refuse activation', { timeout: 120_000 }, async () => {
    const db = fixture;
    if (db === undefined) { throw new Error('Missing isolated fixture'); }
    // 1. The PRELIMINARY fact: the inventory is taken while P05 is completely empty
    //    (the bare 024 schema, no stand configuration yet). No physical archive is
    //    created here, so this is an inventory fact, not a dump.
    expect(await readP05TargetDrainState(db.migrator, 'S3')).toEqual({ fact: 'P05_EMPTY_AFTER_DRAIN', profile: 'S3' });
    const dumpInventory = await readAuthorityInventory(db.migrator, LIMITS);

    // 2. The stand configuration, then a real callback (no attachment) accepted and
    //    confirmed AFTER that fact.
    requests = await seedRequestFixtures({ db: db.migrator }, { reviewerId: db.reviewer });
    const requestId = await commitCallbackEffect(db, requests);
    expect((await db.migrator.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM foundation.requests WHERE id=$1', [requestId])).rows[0]?.n).toBe(1);
    // A callback without attachment leaves no request_files row at all.
    expect((await db.migrator.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM foundation.request_files')).rows[0]?.n).toBe(0);
    const afterCounts = await readP05SourceState(db.migrator, 'S3');
    expect(afterCounts.profile).toBe('S3');
    // The exact operational rows the callback committed are present; every other
    // P05 table is either the reviewed stand configuration or still empty.
    expect(afterCounts.counts['requests']).toBe(1);
    expect(afterCounts.counts['customers']).toBe(1);
    expect(afterCounts.counts['request_events']).toBe(1);
    expect(afterCounts.counts['request_command_receipts']).toBe(1);
    // Two reviewed staff evidences (MANUAL_INTAKE + PHONE_GIVE) and the single
    // GIVEN phone permission they authorise.
    expect(afterCounts.counts['request_staff_evidence']).toBe(2);
    expect(afterCounts.counts['phone_permission_events']).toBe(1);
    expect(afterCounts.counts['request_intake_provenance']).toBe(1);
    expect(afterCounts.counts['request_payload_cells']).toBe(1);
    expect(afterCounts.counts['request_contact_revisions']).toBe(1);
    expect(afterCounts.counts['request_preference_revisions']).toBe(1);
    expect(afterCounts.counts['request_files']).toBe(0);
    expect(afterCounts.empty).toBe(false);
    await expect(readP05TargetDrainState(db.migrator, 'S3')).rejects.toMatchObject({ code: 'P05_ROWS_PRESENT' });

    // 3. Drain exactly like the operator bridge: fenced epoch, no runtime CONNECT,
    //    no other backend, datallowconn=false. The observer is opened BEFORE the
    //    hard barrier and is the only remaining session.
    const namespace = randomUUID();
    // The reviewed guard accepts only the ACTIVE -> FENCED transition (the same
    // path the file runtime and file-restore.test.ts use).
    await db.migrator.query(`INSERT INTO foundation.file_runtime_epochs (singleton,namespace_id,epoch,mode)
      VALUES (true,$1,1,'ACTIVE')`, [namespace]);
    await db.migrator.query(`UPDATE foundation.file_runtime_epochs SET mode='FENCED'
      WHERE singleton AND namespace_id=$1 AND epoch=1 AND mode='ACTIVE'`, [namespace]);
    await db.migrator.query(`REVOKE CONNECT ON DATABASE "${db.database}" FROM fixlevelup_runtime`);
    await db.runtime.end();
    await db.migrator.end();
    poolsEnded = true;
    const password = fixtureCredentials().migrator;
    // The observer is opened BEFORE the hard barrier, on the same private lab
    // endpoint as the writers, as the reviewed owner role. It remains the only
    // permitted session after PostgreSQL finishes reaping the closed pools.
    observer = new Client({ host: '127.0.0.1', port: 55432, database: db.database, user: 'fixlevelup_migrator',
      password, options: '-c default_transaction_read_only=on' });
    await observer.connect();
    // The hard barrier uses the attested maintenance binding and exact owner;
    // no new source connection is possible while we prove server-side drain.
    const maintenance = await openConfigurationMaintenanceClient();
    try {
      await becomeOwner(maintenance);
      await maintenance.query(`ALTER DATABASE "${db.database}" ALLOW_CONNECTIONS false`);
    } finally {
      try { await releaseOwner(maintenance); } finally { await maintenance.end(); }
    }

    // 4. The barrier itself is real, so the refusal below can only come from the
    //    P05 rows: no new connection is possible and no other backend remains.
    // pg.Client.end() confirms the local socket closed, not that the server
    // has removed its backend from pg_stat_activity. Wait for the actual drain
    // with new statements and a finite deadline, never terminate an observer.
    const source = observer;
    await expect.poll(async () => (await source.query<{ allow: boolean; others: number; mode: string; connect: boolean }>(`SELECT
      d.datallowconn AS allow,
      (SELECT count(*)::int FROM pg_stat_activity a WHERE a.datid=d.oid AND a.pid<>pg_backend_pid()) AS others,
      (SELECT mode FROM foundation.file_runtime_epochs WHERE singleton) AS mode,
      has_database_privilege('fixlevelup_runtime',d.oid,'CONNECT') AS connect
      FROM pg_database d WHERE d.datname=current_database()`)).rows[0], { timeout: 3000, interval: 25 })
      .toEqual({ allow: false, others: 0, mode: 'FENCED', connect: false });
    const rejected = new Client({ host: '127.0.0.1', port: 55432, database: db.database, user: 'fixlevelup_migrator', password });
    try { await expect(rejected.connect()).rejects.toMatchObject({ code: '55000' }); }
    finally { await rejected.end(); }

    // 5. The core's pre-activation observation refuses with RESTORE_AUTHORITY: the
    //    source is not empty even though the dump has no request row.
    const cluster = await readClusterFact(observer);
    expect(cluster).toEqual(await readClusterFact(observer));
    const databaseOid = Number((await observer.query<{ oid: string }>(
      'SELECT oid::text AS oid FROM pg_database WHERE datname=current_database()')).rows[0]?.oid);
    expect(Number.isSafeInteger(databaseOid)).toBe(true);
    const pin = { database: db.database, databaseOid, scope: { namespace, incarnation: randomUUID(), writerEpoch: 1n },
      profile: 'S3' as const, manifestSha256: 'a'.repeat(64), challenge: randomBytes(32).toString('hex') };
    await expect(observeFencedSource(observer, pin, LIMITS)).rejects.toMatchObject({ code: 'RESTORE_AUTHORITY' });
    // The same observation on a profile it is NOT: still a refusal, never a
    // downgrade to an older known profile.
    await expect(observeFencedSource(observer, { ...pin, profile: 'S2' }, LIMITS))
      .rejects.toMatchObject({ code: 'RESTORE_AUTHORITY' });
    // The activation gate answers the same safe code, not a raw inventory error.
    await expect(requireP05AbsentForActivation(observer, { schemaVersion: S3_HEAD_NAME }))
      .rejects.toMatchObject({ code: 'RESTORE_AUTHORITY' });
    // And the inventory digest really changed versus the dump-time fact.
    expect(await readAuthorityInventory(observer, LIMITS)).not.toBe(dumpInventory);
    // The precise cause is the surviving callback row, not a schema drift.
    await expect(readP05TargetDrainState(observer, 'S3')).rejects.toBeInstanceOf(P05InventoryError);
    expect((await observer.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM foundation.requests WHERE id=$1', [requestId])).rows[0]?.n).toBe(1);
  });
});
