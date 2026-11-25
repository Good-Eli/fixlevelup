/**
 * P05 §5.2 targeted defensive tests for the READY attachment admission and the
 * S3 retention interlock.
 *
 * Scope is deliberately narrow: these are not a second P03 audit and they do not
 * pretend to prove PostgreSQL behaviour. They pin the parts that are cheap to get
 * wrong and expensive to notice:
 *
 * - the exact S3 / PRE_S3 / DRIFTED classification boundary (a pure function over
 *   catalog facts, so an intermediate schema can never become a permissive
 *   "legacy" fallback);
 * - the retention query composition per profile (S3 excludes attached intents
 *   before LIMIT and re-checks after the intent/control lock; pre-S3 keeps the
 *   reviewed legacy query; drifted refuses);
 * - the two-call attachment prefix: a forged/absent runtime token is refused before
 *   any SQL, the admission never re-locks the runtime or opens a transaction, the
 *   intents are locked in UUID order, the control must be OPEN, and only
 *   `{fileId, mime, bytes}` is returned;
 * - the refusal paths that must have zero side effects.
 *
 * Real PostgreSQL lock/rollback behaviour, the FK interlock and real bytes belong to
 * the isolated lab run, not here.
 */
import { createHash } from 'node:crypto';
import type { QueryResult, QueryResultRow } from 'pg';
import type { PoolClient } from 'pg';
import { expect, it } from 'vitest';
import type { AttachmentInterlockFacts } from '../src/files/file-lifecycle/authorization.js';
import { classifyAttachmentInterlock } from '../src/files/file-lifecycle/authorization.js';
import { isLifecycleError } from '../src/files/file-lifecycle/errors.js';
import type { FileLifecycleErrorCode } from '../src/files/file-lifecycle/errors.js';
import {
  retentionAttachmentGuardSql, retentionCandidateSql,
} from '../src/files/file-privacy/retention.js';
import { isPrivacyError } from '../src/files/file-privacy/contract.js';
import {
  admitReadyAttachments, lockAttachmentRuntime,
} from '../src/files/file-access/ready-attachment.js';
import type { ReadyAttachmentRuntime } from '../src/files/file-access/ready-attachment.js';

const NAMESPACE = '88888888-8888-4888-8888-888888888888';
const SESSION_ID = '33333333-3333-4333-8333-333333333333';
const REQUEST_ID = '44444444-4444-4444-8444-444444444444';
const CONSENT_ID = '55555555-5555-4555-8555-555555555555';
const DOCUMENT_ID = '77777777-7777-4777-8777-777777777777';
const DOCUMENT_VERSION = '66666666-6666-4666-8666-666666666666';
const CITY_ID = '99999999-9999-4999-8999-999999999999';
const CITY_VERSION = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const INTENT_A = '11111111-1111-4111-8111-111111111111';
const INTENT_B = '22222222-2222-4222-8222-222222222222';
const FILE_A = '00000000-0000-4000-8000-00000000000a';
const FILE_B = '00000000-0000-4000-8000-00000000000b';
const TOKEN = 'tok-tok-tok-tok-tok';
const SECRET_HASH = createHash('sha256').update(TOKEN, 'utf8').digest('hex');
const POLICY = Object.freeze({
  mode: 'local-synthetic' as const, expiresAt: new Date(Date.now() + 600_000), maxAccessAgeMs: 600_000,
  maxFiles: 4, maxBytes: 1_000_000,
});
const CONTEXT = Object.freeze({ epoch: Object.freeze({ namespace: NAMESPACE, epoch: 1n }), policy: POLICY });
const PUBLISHED_AT = new Date().toISOString();

/* ------------------------------- S3 facts --------------------------------- */

function validFacts(): AttachmentInterlockFacts {
  return {
    present: true,
    columns: [
      ['request_id', 'uuid', true, null],
      ['owner_session_id', 'uuid', true, null],
      ['intent_id', 'uuid', true, null],
      ['file_id', 'uuid', true, null],
      ['open_state', 'character varying(24)', true, "'OPEN'::character varying"],
    ],
    constraints: [
      { type: 'p', deferrable: false, validated: true, cols: ['request_id', 'file_id'], ref: null, ref_cols: null,
        upd: null, del: null, def: 'PRIMARY KEY (request_id, file_id)' },
      { type: 'u', deferrable: false, validated: true, cols: ['intent_id'], ref: null, ref_cols: null, upd: null,
        del: null, def: 'UNIQUE (intent_id)' },
      { type: 'u', deferrable: false, validated: true, cols: ['file_id'], ref: null, ref_cols: null, upd: null,
        del: null, def: 'UNIQUE (file_id)' },
      { type: 'c', deferrable: false, validated: true, cols: ['open_state'], ref: null, ref_cols: null, upd: null,
        del: null, def: "CHECK (((open_state)::text = 'OPEN'::text))" },
      { type: 'f', deferrable: false, validated: true, cols: ['request_id', 'owner_session_id'],
        ref: 'foundation.request_session_submits', ref_cols: ['request_id', 'session_id'], upd: 'a', del: 'a',
        def: 'FOREIGN KEY (request_id, owner_session_id) REFERENCES foundation.request_session_submits(request_id, session_id)' },
      { type: 'f', deferrable: false, validated: true, cols: ['intent_id', 'owner_session_id'],
        ref: 'foundation.file_upload_intents', ref_cols: ['id', 'owner_request_session_id'], upd: 'a', del: 'a',
        def: 'FOREIGN KEY (intent_id, owner_session_id) REFERENCES foundation.file_upload_intents(id, owner_request_session_id)' },
      { type: 'f', deferrable: false, validated: true, cols: ['intent_id', 'file_id'],
        ref: 'foundation.file_publications', ref_cols: ['intent_id', 'id'], upd: 'a', del: 'a',
        def: 'FOREIGN KEY (intent_id, file_id) REFERENCES foundation.file_publications(intent_id, id)' },
      { type: 'f', deferrable: false, validated: true, cols: ['intent_id', 'open_state'],
        ref: 'foundation.file_privacy_controls', ref_cols: ['intent_id', 'delete_state'], upd: 'r', del: 'r',
        def: 'FOREIGN KEY (intent_id, open_state) REFERENCES foundation.file_privacy_controls(intent_id, delete_state) ON UPDATE RESTRICT ON DELETE RESTRICT' },
      // PostgreSQL 18 records NOT NULL both on the column and as type 'n' rows.
      ...['file_id', 'intent_id', 'open_state', 'owner_session_id', 'request_id'].map((column) => ({
        type: 'n', deferrable: false, validated: true, cols: [column], ref: null, ref_cols: null, upd: null, del: null,
        def: `NOT NULL ${column}`,
      })),
    ],
    s3_relations: ['request_files', 'request_session_submits'],
    s3_indexes: ['file_privacy_controls_intent_open_key', 'file_publications_intent_file_key'],
  };
}

function mutated(mutate: (facts: AttachmentInterlockFacts & { columns: unknown[]; constraints: unknown[] }) => void) {
  const facts = validFacts() as AttachmentInterlockFacts & { columns: unknown[]; constraints: unknown[] };
  mutate(facts);
  return facts;
}

it('classifies exactly the reviewed S3 interlock as S3', () => {
  expect(classifyAttachmentInterlock(validFacts())).toBe('S3');
  // `regclass::text` drops the schema prefix when the caller's search_path has it.
  const unqualified = mutated((facts) => {
    for (const constraint of facts.constraints) {
      const row = constraint as Record<string, unknown>;
      const ref = row['ref'];
      if (typeof ref === 'string' && ref.startsWith('foundation.')) {
        row['ref'] = ref.slice('foundation.'.length);
      }
    }
  });
  expect(classifyAttachmentInterlock(unqualified)).toBe('S3');
});

it('classifies an absent relation without any S3 artifact as the honest pre-S3 profile', () => {
  expect(classifyAttachmentInterlock({ present: false, columns: [], constraints: [], s3_relations: [], s3_indexes: [] }))
    .toBe('PRE_S3');
});

it('ignores S3 artifacts outside the interlock so a later S3 addition cannot flip the verdict', () => {
  const facts = validFacts() as AttachmentInterlockFacts & { s3_relations: string[]; s3_indexes: string[] };
  facts.s3_relations.push('phone_permission_events');
  facts.s3_indexes.push('request_one_phone_given_key');
  expect(classifyAttachmentInterlock(facts)).toBe('S3');
});

it('never turns an intermediate or drifted schema into a permissive fallback', () => {
  const cases: [string, AttachmentInterlockFacts | undefined][] = [
    ['missing facts row', undefined],
    ['relation absent but an S3 relation present', {
      present: false, columns: [], constraints: [], s3_relations: ['request_session_submits'], s3_indexes: [],
    }],
    ['relation absent but an S3-only unique index present', {
      present: false, columns: [], constraints: [], s3_relations: [],
      s3_indexes: ['file_privacy_controls_intent_open_key'],
    }],
    ['extra column', mutated((facts) => { facts.columns.push(['created_at', 'timestamp with time zone', true, null]); })],
    ['missing open_state default', mutated((facts) => { facts.columns[4] = ['open_state', 'character varying(24)', true, null]; })],
    ['open_state default that is not OPEN', mutated((facts) => { facts.columns[4] = ['open_state', 'character varying(24)', true, "'CLOSED'::character varying"]; })],
    ['deferrable interlock FK', mutated((facts) => { (facts.constraints[7] as Record<string, unknown>)['deferrable'] = true; })],
    ['cascading interlock FK', mutated((facts) => { (facts.constraints[7] as Record<string, unknown>)['del'] = 'c'; })],
    ['missing FK target column pair', mutated((facts) => { (facts.constraints[6] as Record<string, unknown>)['ref_cols'] = ['id']; })],
    ['missing unique(intent_id)', mutated((facts) => { facts.constraints.splice(1, 1); })],
    ['interlock FK to the wrong parent', mutated((facts) => { (facts.constraints[7] as Record<string, unknown>)['ref'] = 'foundation.file_privacy_controls_v2'; })],
    ['missing primary key', mutated((facts) => { facts.constraints.splice(0, 1); })],
    ['extra unexpected constraint', mutated((facts) => { facts.constraints.push({ type: 'c', deferrable: false, validated: true, cols: ['request_id'], ref: null, ref_cols: null, upd: null, del: null, def: 'CHECK (request_id IS NOT NULL)' }); })],
    ['check that allows a non-OPEN state', mutated((facts) => { (facts.constraints[3] as Record<string, unknown>)['def'] = 'CHECK (open_state <> \'CLOSED\')'; })],
    ['weakened CHECK open_state=OPEN OR TRUE', mutated((facts) => { (facts.constraints[3] as Record<string, unknown>)['def'] = "CHECK (((open_state)::text = 'OPEN'::text) OR true)"; })],
    ['weakened CHECK with an extra disjunct', mutated((facts) => { (facts.constraints[3] as Record<string, unknown>)['def'] = "CHECK (((open_state)::text = 'OPEN'::text) OR (open_state)::text = 'CLOSED'::text)"; })],
    ['duplicated interlock FK', mutated((facts) => { facts.constraints.push({ ...(facts.constraints[7] as Record<string, unknown>) }); })],
    ['unvalidated FK', mutated((facts) => { (facts.constraints[7] as Record<string, unknown>)['validated'] = false; })],
    ['malformed catalog payload', { present: true, columns: 'nope', constraints: [], s3_relations: [], s3_indexes: [] }],
  ];
  for (const [label, facts] of cases) {
    expect(classifyAttachmentInterlock(facts), label).toBe('DRIFTED');
  }
});

/* --------------------------- retention composition -------------------------- */

it('excludes attached intents before LIMIT only on the exact S3 profile', () => {
  const s3 = retentionCandidateSql('S3');
  expect(s3).toContain('NOT EXISTS (SELECT 1 FROM foundation.request_files rf WHERE rf.intent_id=i.id)');
  expect(s3.indexOf('request_files')).toBeLessThan(s3.indexOf('LIMIT $6'));
  const preS3 = retentionCandidateSql('PRE_S3');
  expect(preS3).not.toContain('request_files');
  expect(preS3).toContain('ORDER BY i.id LIMIT $6');
});

it('re-checks the attachment interlock after the intent/control lock, and refuses a drifted schema', () => {
  expect(retentionAttachmentGuardSql('S3'))
    .toBe('SELECT rf.intent_id FROM foundation.request_files rf WHERE rf.intent_id=$1 LIMIT 1');
  expect(retentionAttachmentGuardSql('PRE_S3')).toBeUndefined();
  for (const build of [() => retentionCandidateSql('DRIFTED'), () => retentionAttachmentGuardSql('DRIFTED')]) {
    let code: string | undefined;
    try {
      build();
    } catch (error) {
      expect(isPrivacyError(error)).toBe(true);
      code = (error as { code?: string }).code;
    }
    expect(code).toBe('NOT_CONFIGURED');
  }
});

/* ------------------------------ fake PoolClient ----------------------------- */

interface FakeControl {
  intent_id: string; row_version: string; access_epoch: string; processing_generation: number;
  processing_lease_id: string | null; processing_expires_at: string | null; read_generation: number;
  read_lease_id: string | null; read_expires_at: string | null; delete_state: string;
}

interface FakePublication { fileId: string; intentId: string; mime: string; bytes: number }

class AttachmentDb {
  readonly statements: { readonly text: string; readonly params: readonly unknown[] }[] = [];
  readonly lockedIntents: string[] = [];
  readonly inserted: { requestId: string; owner: string; intentId: string; fileId: string }[] = [];
  marker = '';
  runtime = { namespace_id: NAMESPACE, epoch: '1', mode: 'ACTIVE' };
  anchor: { id: string; secret_hash: string; intake_city_id: string; intake_city_version_id: string;
    revoked: boolean; live: boolean } | null = {
    id: SESSION_ID, secret_hash: SECRET_HASH, intake_city_id: CITY_ID, intake_city_version_id: CITY_VERSION,
    revoked: false, live: true,
  };
  consent: { evidence_id: string; document_id: string; document_version_id: string; occurred_at: string;
    unrevoked: boolean; current: boolean; published: boolean } | null = {
    evidence_id: CONSENT_ID, document_id: DOCUMENT_ID, document_version_id: DOCUMENT_VERSION,
    occurred_at: PUBLISHED_AT, unrevoked: true, current: true, published: true,
  };
  request: { id: string; type: string; city_id: string; intake_city_version_id: string;
    edge_session_id: string | null; edge_consent_id: string | null; edge_document_version_id: string | null;
    edge_command: string | null } | null = {
    id: REQUEST_ID, type: 'REPAIR', city_id: CITY_ID, intake_city_version_id: CITY_VERSION,
    edge_session_id: SESSION_ID, edge_consent_id: CONSENT_ID, edge_document_version_id: DOCUMENT_VERSION,
    edge_command: 'CreateRepair',
  };
  control: FakeControl | null = {
    intent_id: '', row_version: '1', access_epoch: '1', processing_generation: 0, processing_lease_id: null,
    processing_expires_at: null, read_generation: 0, read_lease_id: null, read_expires_at: null, delete_state: 'OPEN',
  };
  publications = new Map<string, FakePublication>();
  intentState = 'RESERVED';
  intentOwner = SESSION_ID;
  links: unknown[] = [];
  interlock: AttachmentInterlockFacts = validFacts();
  /** The reviewed S3 fingerprint answers (must track `S3_PINS` in p05-profile-catalog.ts). */
  fingerprint = 'S3' as 'S3' | 'DRIFTED';
  preS3Absent = false;
  deferrableConstraints: { conname: string }[] = [];
  insertRowCount = 2;
  proof = { session_live: true, session_revoked: false, intent_live: true, policy_live: true, within_quota: true,
    extra_policy_live: true, lease_live: true, db_now: PUBLISHED_AT };
  gate = { policy_live: true, ready_live: true, lease_live: true, remaining_ms: 0, session_live: true,
    intent_live: true, original_policy_live: true, expires_at_ms: Date.parse(PUBLISHED_AT) + 300_000 };
  windowProofs = 0;

  constructor() {
    this.control = this.control === null ? null : { ...this.control };
    this.add(FILE_A, INTENT_A);
    this.add(FILE_B, INTENT_B);
  }

  private add(fileId: string, intentId: string): void {
    this.publications.set(fileId, { fileId, intentId, mime: 'image/png', bytes: 64 });
  }

  private publicationRow(intentId: string) {
    const publication = [...this.publications.values()].find((candidate) => candidate.intentId === intentId);
    if (publication === undefined) {
      return undefined;
    }
    return {
      id: publication.fileId, intent_id: publication.intentId, quarantine_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      raw_bytes: String(publication.bytes), raw_sha256: 'a'.repeat(64),
      sanitized_attempt_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', mime: publication.mime,
      served_bytes: String(publication.bytes), served_sha256: 'b'.repeat(64), published_at: PUBLISHED_AT,
      object_key: 'sanitized/key', storage_endpoint: 'http://127.0.0.1:3900', storage_bucket: 'bucket',
      storage_region: 'local',
    };
  }

  query<T extends QueryResultRow = QueryResultRow>(text: string, params: readonly unknown[] = []):
  Promise<QueryResult<T>> {
    return Promise.resolve(this.execute<T>(text, params));
  }

  private execute<T extends QueryResultRow>(text: string, params: readonly unknown[]): QueryResult<T> {
    this.statements.push({ text, params });
    const sql = text.replace(/\s+/gu, ' ').trim();
    const result = (rows: unknown[], rowCount = rows.length) => ({ rows, rowCount, command: '', oid: 0, fields: [] }) as QueryResult<T>;
    const one = (rows: unknown[]) => result(rows);

    // legal transaction guard (idempotent, no transaction control)
    if (sql === 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED') { return result([]); }
    if (sql.includes("current_setting('transaction_isolation')")) { return result([{ isolation: 'read committed' }]); }
    if (sql.includes('set_config(')) { this.marker = String(params[0]); return result([{ set_config: this.marker }]); }
    if (sql.includes("current_setting('fixlevelup.legal_tx',true)")) { return result([{ marker: this.marker }]); }
    // runtime
    if (sql.includes('FROM foundation.file_runtime_epochs')) { return one([this.runtime]); }
    // interlock probe: presence → freeze → facts → (fingerprint | pre-S3 absence)
    if (sql.includes("to_regclass('foundation.request_files') IS NOT NULL AS present")) {
      return one([{ present: this.interlock.present }]);
    }
    if (sql === 'SELECT 1 FROM foundation.request_files WHERE false') { return result([]); }
    if (sql.includes('WITH target AS')) { return one([this.interlock]); }
    if (sql.includes('NOT pg_is_in_recovery()')) { return one([{ absent: this.preS3Absent }]); }
    if (sql.includes('FROM foundation.permissions WHERE code=ANY')) { return one([{ absent: this.preS3Absent }]); }
    // shared reviewed S3 fingerprint (probeP05Layer('S3')): namespace exactness, the
    // combined S1 metadata+enforcement read, then the S3 metadata and enforcement.
    if (sql.includes('objects(name, allowed)')) { return one([{ exact: this.fingerprint === 'S3' }]); }
    if (sql.includes('b.metadata')) {
      return one([{ metadata: this.fingerprint === 'S3'
        ? 'fdb0e4bfd8554af5d4a3b96dc87ee855f3dd2e1ce051124de0e81f6c4e353d4d' : 'f'.repeat(64),
      compatible: this.fingerprint === 'S3',
      enforcement: this.fingerprint === 'S3'
        ? '967e5798d23f2c138a5de44feaf83fb992feafd1ccd87319aee4ac53dc51334f' : 'f'.repeat(64) }]);
    }
    if (sql.includes("'permission',p.code")) {
      return one([{ metadata: this.fingerprint === 'S3'
        ? '8f2ac462c39d2bcf9bfc99896d8b563778e41b495e6f77b213413f8673ee2158' : 'f'.repeat(64) }]);
    }
    if (sql.includes("'rel_acl'")) {
      return one([{ enforcement: this.fingerprint === 'S3'
        ? '0dd83e1dad3593b0db50b268ce51cef0586b5d499cef5aff0dd72e24efd07723' : 'f'.repeat(64) }]);
    }
    // anchor / consent / request binding
    if (sql.includes('FROM foundation.request_sessions WHERE id=$1')) { return one(this.anchor === null ? [] : [this.anchor]); }
    if (sql.includes('AS evidence_id')) { return one(this.consent === null ? [] : [this.consent]); }
    if (sql.includes('LEFT JOIN foundation.request_session_submits')) { return one(this.request === null ? [] : [this.request]); }
    // publication resolution (no lock)
    if (sql.includes('FROM foundation.file_publications p JOIN foundation.file_upload_intents i')) {
      const requested = params[0] as readonly string[];
      const owner = params[1];
      const rows = requested.map((fileId) => this.publications.get(fileId))
        .filter((publication): publication is FakePublication => publication !== undefined
          && (owner === undefined || this.intentOwner === owner))
        .map((publication) => ({ id: publication.fileId, intent_id: publication.intentId, mime: publication.mime,
          served_bytes: String(publication.bytes) }));
      return one(rows);
    }
    // intent lock
    if (sql.includes('FROM foundation.file_upload_intents WHERE id=$1')) {
      const intentId = String(params[0]);
      if (params[1] !== this.intentOwner || ![...this.publications.values()].some((p) => p.intentId === intentId)) {
        return one([]);
      }
      this.lockedIntents.push(intentId);
      return one([{ id: intentId, state: this.intentState, row_version: 1, consent_record_id: CONSENT_ID,
        consent_document_version_id: DOCUMENT_VERSION, consent_purpose: 'REQUEST_PROCESSING',
        declared_mime: 'image/png', declared_bytes: '64', max_file_bytes: '1000', allowed: true }]);
    }
    // control lock / lazy create
    if (sql.includes('FROM foundation.file_privacy_controls WHERE intent_id=$1 FOR UPDATE')) {
      return one(this.control === null ? [] : [this.control]);
    }
    if (sql.startsWith('INSERT INTO foundation.file_privacy_controls')) {
      this.control = { intent_id: String(params[0]), row_version: '1', access_epoch: '1', processing_generation: 0,
        processing_lease_id: null, processing_expires_at: null, read_generation: 0, read_lease_id: null,
        read_expires_at: null, delete_state: 'OPEN' };
      return one([this.control]);
    }
    // publication evidence under the intent lock
    if (sql.includes('FROM foundation.file_publications p JOIN foundation.file_sanitized_attempts a')) {
      const row = this.publicationRow(String(params[0]));
      return one(row === undefined ? [] : [row]);
    }
    // exact P03 authorization proof
    if (sql.includes('session_revoked')) { return one([this.proof]); }
    // READY access window
    if (sql.includes('AS policy_live')) { this.windowProofs += 1; return one([this.gate]); }
    // existing links
    if (sql.includes('FROM foundation.request_files rf WHERE rf.request_id=$1')) { return one(this.links); }
    // insert
    if (sql.startsWith('INSERT INTO foundation.request_files')) {
      const rows = JSON.parse(String(params[2])) as { intent_id: string; file_id: string }[];
      for (const row of rows) {
        this.inserted.push({ requestId: String(params[0]), owner: String(params[1]), intentId: row.intent_id, fileId: row.file_id });
      }
      return result([], this.insertRowCount);
    }
    // deferrable constraints
    if (sql.includes('FROM pg_constraint')) { return one(this.deferrableConstraints); }
    if (sql.startsWith('SET CONSTRAINTS')) { return result([]); }
    throw new Error(`Unexpected statement in attachment fake: ${sql.slice(0, 80)}`);
  }
}

function clientOf(db: AttachmentDb): PoolClient {
  return db as unknown as PoolClient;
}

function runtimeToken(db: AttachmentDb): Promise<ReadyAttachmentRuntime> {
  return lockAttachmentRuntime(clientOf(db), CONTEXT);
}

async function admission(db: AttachmentDb, token: ReadyAttachmentRuntime, input: unknown = command()) {
  return await admitReadyAttachments(clientOf(db), token, input);
}

/** One full two-call attempt with a fresh, client-bound, single-use runtime token. */
async function attempt(db: AttachmentDb, input: unknown = command()) {
  return await admission(db, await runtimeToken(db), input);
}

function command(overrides: Partial<{ requestId: string; session: unknown; consentEvidenceId: string;
  consentDocumentVersionId: string; fileIds: readonly string[] }> = {}) {
  return {
    requestId: REQUEST_ID,
    session: { sessionId: SESSION_ID, token: TOKEN },
    consentEvidenceId: CONSENT_ID,
    consentDocumentVersionId: DOCUMENT_VERSION,
    fileIds: [FILE_B, FILE_A],
    ...overrides,
  };
}

async function refusal(action: Promise<unknown>, code: FileLifecycleErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await action;
  } catch (error) {
    caught = error;
  }
  expect(caught, `expected ${code}`).toBeDefined();
  expect(isLifecycleError(caught)).toBe(true);
  expect((caught as { code: string }).code).toBe(code);
  expect((caught as Error).message).toBe(code);
}

/* --------------------------- attachment admission -------------------------- */

it('requires a runtime token from the first call, bound to the same client', async () => {
  const db = new AttachmentDb();
  for (const forged of [undefined, {}, { ready: true }, Object.freeze({ ready: true })]) {
    await refusal(admitReadyAttachments(clientOf(db), forged as ReadyAttachmentRuntime, command()), 'NOT_CONFIGURED');
  }
  expect(db.statements).toHaveLength(0);
  // A real token minted on ANOTHER client must not authorize this transaction.
  const foreign = await runtimeToken(new AttachmentDb());
  await refusal(admitReadyAttachments(clientOf(db), foreign, command()), 'NOT_CONFIGURED');
  expect(db.statements).toHaveLength(0);
});

it('is single-use: a replayed token is refused before any SQL', async () => {
  const db = new AttachmentDb();
  const token = await runtimeToken(db);
  await admission(db, token);
  const before = db.statements.length;
  await refusal(admission(db, token), 'NOT_CONFIGURED');
  expect(db.statements).toHaveLength(before);
});

it('never re-locks the runtime and never opens a transaction', async () => {
  const db = new AttachmentDb();
  const token = await runtimeToken(db);
  // Only the admission half is inspected: the first call legitimately locks the runtime.
  const before = db.statements.length;
  await admission(db, token);
  const admissionSql = db.statements.slice(before).map(({ text }) => text);
  expect(admissionSql.some((sql) => /file_runtime_epochs[^;]*FOR SHARE/iu.test(sql))).toBe(false);
  expect(admissionSql.some((sql) => /^\s*(BEGIN|COMMIT|ROLLBACK)\b/iu.test(sql))).toBe(false);
  expect(admissionSql[0]).toBe('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
});

it('rejects a pre-S3 profile and a drifted interlock before touching any file or request row', async () => {
  const preS3 = new AttachmentDb();
  preS3.interlock = { present: false, columns: [], constraints: [], s3_relations: [], s3_indexes: [] };
  preS3.preS3Absent = true;
  await refusal(attempt(preS3), 'NOT_CONFIGURED');

  const drifted = new AttachmentDb();
  // Relation present, but a weakened CHECK and a missing reviewed fingerprint.
  drifted.interlock = mutated((facts) => {
    (facts.constraints[3] as Record<string, unknown>)['def'] = "CHECK (((open_state)::text = 'OPEN'::text) OR true)";
  });
  await refusal(attempt(drifted), 'NOT_CONFIGURED');

  const noFingerprint = new AttachmentDb();
  noFingerprint.fingerprint = 'DRIFTED';
  await refusal(attempt(noFingerprint), 'NOT_CONFIGURED');

  for (const db of [preS3, drifted, noFingerprint]) {
    expect(db.statements.some(({ text }) => text.includes('FROM foundation.request_sessions'))).toBe(false);
    expect(db.inserted).toHaveLength(0);
  }
});

it('validates the exact input shape, bounds and duplicate file ids before any file work', async () => {
  const db = new AttachmentDb();
  const cases: unknown[] = [
    command({ fileIds: [] }),
    command({ fileIds: [FILE_A, FILE_A] }),
    command({ fileIds: [FILE_A, FILE_B, FILE_A] }),
    command({ fileIds: ['not-a-uuid'] }),
    { ...command(), extra: true },
    command({ fileIds: Array.from({ length: POLICY.maxFiles + 1 }, (_, index) =>
      `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`) }),
    command({ session: { sessionId: SESSION_ID, token: 'short' } }),
  ];
  for (const input of cases) {
    await refusal(attempt(db, input), 'INVALID_INPUT');
  }
  expect(db.inserted).toHaveLength(0);
});

it('refuses a runtime that is no longer the exact locked ACTIVE epoch', async () => {
  const fenced = new AttachmentDb();
  const fencedToken = await runtimeToken(fenced);
  fenced.runtime = { ...fenced.runtime, mode: 'FENCED' };
  await refusal(admission(fenced, fencedToken), 'NOT_CONFIGURED');

  const moved = new AttachmentDb();
  const movedToken = await runtimeToken(moved);
  moved.runtime = { ...moved.runtime, epoch: '2' };
  await refusal(admission(moved, movedToken), 'NOT_CONFIGURED');
});

it('refuses a foreign/revoked/expired anchor and a non-current consent with no side effects', async () => {
  const db = new AttachmentDb();
  db.anchor = db.anchor === null ? null : { ...db.anchor, secret_hash: 'c'.repeat(64) };
  await refusal(attempt(db), 'NOT_FOUND');
  db.anchor = db.anchor === null ? null : { ...db.anchor, secret_hash: SECRET_HASH, revoked: true };
  await refusal(attempt(db), 'SESSION_REVOKED');
  db.anchor = db.anchor === null ? null : { ...db.anchor, revoked: false, live: false };
  await refusal(attempt(db), 'SESSION_EXPIRED');
  db.anchor = db.anchor === null ? null : { ...db.anchor, live: true };
  db.consent = db.consent === null ? null : { ...db.consent, unrevoked: false };
  await refusal(attempt(db), 'CONSENT_REVOKED');
  db.consent = db.consent === null ? null : { ...db.consent, unrevoked: true, current: false };
  await refusal(attempt(db), 'CONSENT_NOT_CURRENT');
  db.consent = db.consent === null ? null : { ...db.consent, current: true };
  await refusal(attempt(db, command({ consentDocumentVersionId: DOCUMENT_ID })), 'CONSENT_NOT_CURRENT');
  expect(db.inserted).toHaveLength(0);
});

it('refuses a request that is not the anchor own committed repair submit edge', async () => {
  const db = new AttachmentDb();
  db.request = db.request === null ? null : { ...db.request, type: 'CALLBACK' };
  await refusal(attempt(db), 'NOT_FOUND');
  db.request = db.request === null ? null : { ...db.request, type: 'REPAIR', edge_consent_id: DOCUMENT_ID };
  await refusal(attempt(db), 'CONFLICT');
  db.request = db.request === null ? null : { ...db.request, edge_consent_id: CONSENT_ID, edge_command: 'CreateCallback' };
  await refusal(attempt(db), 'CONFLICT');
  db.request = db.request === null ? null : { ...db.request, edge_command: 'CreateRepair', edge_session_id: DOCUMENT_ID };
  await refusal(attempt(db), 'CONFLICT');
  expect(db.inserted).toHaveLength(0);
});

it('refuses non-image, unowned, over-budget and frozen files before inserting a link', async () => {
  const db = new AttachmentDb();
  db.publications.set(FILE_A, { fileId: FILE_A, intentId: INTENT_A, mime: 'application/pdf', bytes: 64 });
  await refusal(attempt(db), 'NOT_READY');
  db.publications.set(FILE_A, { fileId: FILE_A, intentId: INTENT_A, mime: 'image/png', bytes: 64 });
  db.publications.delete(FILE_B);
  await refusal(attempt(db), 'NOT_FOUND');
  db.publications.set(FILE_B, { fileId: FILE_B, intentId: INTENT_B, mime: 'image/png', bytes: POLICY.maxBytes });
  await refusal(attempt(db), 'QUOTA_EXCEEDED');
  db.publications.set(FILE_B, { fileId: FILE_B, intentId: INTENT_B, mime: 'image/png', bytes: 64 });
  db.control = db.control === null ? null : { ...db.control, delete_state: 'PENDING_LEDGER', access_epoch: '2' };
  await refusal(attempt(db), 'NOT_FOUND');
  expect(db.inserted).toHaveLength(0);
});

it('refuses when the publication evidence is not the requested READY revision', async () => {
  const db = new AttachmentDb();
  const publication = db.publications.get(FILE_A);
  db.publications.set(FILE_A, { ...(publication as FakePublication), fileId: FILE_A, intentId: INTENT_B });
  await refusal(attempt(db), 'NOT_READY');
  expect(db.inserted).toHaveLength(0);
});

it('refuses an already linked file/intent/request instead of replaying the admission', async () => {
  const db = new AttachmentDb();
  db.links = [{ '?column?': 1 }];
  await refusal(attempt(db), 'CONFLICT');
  expect(db.inserted).toHaveLength(0);
});

it('locks intents in UUID order, creates the missing OPEN control, and returns only safe metadata', async () => {
  const db = new AttachmentDb();
  db.control = null;
  const { attachments: views, expiresAtMs } = await attempt(db);
  expect(expiresAtMs).toBe(db.gate.expires_at_ms);
  // Input order is B,A; the mandated lock order is the intent UUID order.
  expect(db.lockedIntents).toEqual([INTENT_A, INTENT_B]);
  expect(db.statements.some(({ text }) => text.startsWith('INSERT INTO foundation.file_privacy_controls'))).toBe(true);
  expect(db.inserted).toEqual([
    { requestId: REQUEST_ID, owner: SESSION_ID, intentId: INTENT_A, fileId: FILE_A },
    { requestId: REQUEST_ID, owner: SESSION_ID, intentId: INTENT_B, fileId: FILE_B },
  ]);
  expect(views).toEqual([
    { fileId: FILE_B, mime: 'image/png', bytes: 64 },
    { fileId: FILE_A, mime: 'image/png', bytes: 64 },
  ]);
  for (const view of views) {
    expect(Object.keys(view).sort()).toEqual(['bytes', 'fileId', 'mime']);
  }
  const text = JSON.stringify(views);
  for (const forbidden of ['object_key', 'storage_endpoint', 'storage_bucket', 'storage_region', 'sanitized/key']) {
    expect(text).not.toContain(forbidden);
  }
});

it('freezes the reviewed relation before reading its definition', async () => {
  const db = new AttachmentDb();
  await attempt(db);
  const texts = db.statements.map(({ text }) => text);
  const presence = texts.findIndex((text) => text.includes("to_regclass('foundation.request_files') IS NOT NULL AS present"));
  const freeze = texts.indexOf('SELECT 1 FROM foundation.request_files WHERE false');
  const facts = texts.findIndex((text) => text.includes('WITH target AS'));
  const fingerprint = texts.findIndex((text) => text.includes('objects(name, allowed)'));
  expect(presence).toBeGreaterThanOrEqual(0);
  expect(freeze).toBeGreaterThan(presence);
  expect(facts).toBeGreaterThan(freeze);
  expect(fingerprint).toBeGreaterThan(facts);
});

it('proves every READY window again after the insert and the forced deferred constraints', async () => {
  const db = new AttachmentDb();
  db.deferrableConstraints = [{ conname: 'request_files_example_fkey' }];
  await attempt(db);
  const insertIndex = db.statements.findIndex(({ text }) => text.startsWith('INSERT INTO foundation.request_files'));
  const setIndex = db.statements.findIndex(({ text }) => text.startsWith('SET CONSTRAINTS'));
  const windowIndexes = db.statements
    .map(({ text }, index) => ({ text, index }))
    .filter(({ text }) => text.includes('remaining_ms'))
    .map(({ index }) => index);
  expect(insertIndex).toBeGreaterThan(0);
  expect(setIndex).toBeGreaterThan(insertIndex);
  expect(windowIndexes.filter((index) => index > setIndex)).toHaveLength(2);
  expect(db.windowProofs).toBe(4);
});

it('hands the submit decision the earliest deadline of all locked READY files', async () => {
  const db = new AttachmentDb();
  const earliest = Date.parse(PUBLISHED_AT) + 25_000;
  const later = earliest + 10_000;
  const original = db.query.bind(db);
  db.query = async <T extends QueryResultRow = QueryResultRow>(text: string, params?: readonly unknown[]) => {
    if (text.includes('AS policy_live')) {
      db.gate = { ...db.gate, expires_at_ms: params?.[0] === INTENT_A ? earliest : later };
    }
    return await original<T>(text, params ?? []);
  };
  const result = await attempt(db);
  expect(db.windowProofs).toBe(4);
  expect(result.attachments.map(({ fileId }) => fileId)).toEqual([FILE_B, FILE_A]);
  expect(result.expiresAtMs).toBe(earliest);
});

it('fails closed when the final window re-proof no longer holds', async () => {
  const db = new AttachmentDb();
  // The first proof (before the insert) succeeds, the post-insert one does not.
  let calls = 0;
  const original = db.query.bind(db);
  db.query = async <T extends QueryResultRow = QueryResultRow>(text: string, params?: readonly unknown[]) => {
    if (text.includes('AS policy_live')) {
      calls += 1;
      if (calls > 2) {
        db.gate = { ...db.gate, ready_live: false };
      }
    }
    return await original<T>(text, params ?? []);
  };
  await refusal(attempt(db), 'NOT_READY');
});
