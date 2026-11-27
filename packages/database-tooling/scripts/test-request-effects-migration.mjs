import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

/** P05-03/P05-04 (024, schema profile S3) migration proof: request intake effects.
 *
 * Proves on the disposable isolated PostgreSQL databases of the migration
 * orchestrator, as a SEPARATE cap from the historical P05-01 (022) and P05-02
 * (023) numbers:
 *  - the ten new S3 tables exist, start inert on a populated upgrade, and their
 *    history triggers refuse UPDATE/DELETE/TRUNCATE with SQLSTATE 23514;
 *  - the exact column grants for `fixlevelup_runtime` on all ten new tables and
 *    on the three modified tables (requests, request_payload_cells,
 *    request_preference_revisions): a missing, extra or elevated privilege fails;
 *  - no PUBLIC access, no table-level privilege, no grant option, and the three
 *    024 guard functions are not callable by the runtime;
 *  - the new CHECKs are present, validated and enforced where a row can be
 *    created without a full request aggregate (request_address_review_attempts),
 *    plus the aggregate-level pair CHECKs are present and validated.
 *
 * Deliberately NOT exercised here: inserting a whole request aggregate
 * (request + contact/address/appliance revisions + event + receipt + audit +
 * outbox + submit/evidence/provenance rows). That is the command path's own
 * proof, not migration wiring, and fabricating it here would duplicate it.
 */
export const requestEffectsMigration = '20261125000100_request_intake_effects';

/**
 * The seven `requests.*` capability codes 024 provisions. They are catalog-only:
 * 024 never grants them to a role, so they appear in the fresh-database catalog
 * inventory as extra codes with no grants. Exported for the RBAC cutover check,
 * which asserts the whole catalog and therefore must know about them.
 */
export const requestEffectsCodes = [
  'requests.cancel',
  'requests.contact.manage',
  'requests.coverage.assess',
  'requests.create',
  'requests.read',
  'requests.ready',
  'requests.review',
];

// 024 CHECK inventory, deliberately independent of the DDL text: a dropped,
// renamed or unvalidated guard must fail this proof. Measured on a disposable
// 001…024 database as the exact delta against the same chain capped at 023.
export const requestEffectsChecks = [
  'phone_permission_events_action_check',
  'phone_permission_events_check',
  'phone_permission_events_given_action_check',
  'phone_permission_events_purpose_check',
  'request_address_review_attempts_purpose_check',
  'request_appliance_brands_brand_kind_check',
  'request_channel_choices_provider_check',
  'request_command_receipts_fingerprint_check',
  'request_command_receipts_key_id_check',
  'request_command_receipts_resulting_status_check',
  'request_command_receipts_version_check',
  'request_coverage_assessments_basis_digest_check',
  'request_coverage_assessments_check',
  'request_coverage_assessments_check1',
  'request_coverage_assessments_check2',
  'request_coverage_assessments_outcome_check',
  'request_coverage_assessments_reason_check',
  'request_files_open_state_check',
  'request_intake_provenance_callback_type_check',
  'request_intake_provenance_check',
  'request_intake_provenance_source_type_check',
  'request_preference_contact_mode_check',
  'request_session_submits_action_check',
  'request_session_submits_purpose_check',
  'request_session_submits_submit_command_check',
  'request_staff_evidence_procedure_revision_check',
  'request_staff_evidence_purpose_check',
  'request_staff_evidence_valid_until_check',
  'requests_assessment_requires_address_check',
  'requests_package_pair_check',
];

const requestEffectsTables = ['request_staff_evidence', 'request_command_receipts', 'request_session_submits',
  'phone_permission_events', 'request_files', 'request_appliance_brands', 'request_channel_choices',
  'request_address_review_attempts', 'request_coverage_assessments', 'request_intake_provenance'];

// Exact runtime column ACL of 024, measured as the delta 023 -> 024. Tables that
// receive no grant at all are listed with empty arrays so an accidental GRANT
// fails instead of passing silently.
const requestEffectsAcl = {
  request_staff_evidence: {
    select: ['id', 'request_id', 'staff_id', 'purpose', 'procedure_revision', 'valid_until', 'declared_at'],
    insert: ['id', 'request_id', 'staff_id', 'purpose', 'procedure_revision', 'valid_until'],
    update: [],
  },
  request_command_receipts: {
    select: ['event_id', 'request_id', 'version', 'correlation_id', 'command', 'key_id', 'fingerprint',
      'resulting_status', 'audit_id', 'outbox_id'],
    insert: ['event_id', 'request_id', 'version', 'correlation_id', 'command', 'key_id', 'fingerprint',
      'resulting_status', 'audit_id', 'outbox_id'],
    update: [],
  },
  request_session_submits: {
    select: ['session_id', 'request_id', 'customer_id', 'intake_city_id', 'intake_city_version_id', 'consent_id',
      'document_id', 'document_version_id', 'purpose', 'action', 'event_id', 'submit_command'],
    insert: ['session_id', 'request_id', 'customer_id', 'intake_city_id', 'intake_city_version_id', 'consent_id',
      'document_id', 'document_version_id', 'event_id', 'submit_command'],
    update: [],
  },
  phone_permission_events: {
    select: ['id', 'request_id', 'contact_revision_id', 'purpose', 'action', 'supersedes_given_id', 'event_id',
      'staff_evidence_id', 'occurred_at'],
    insert: ['id', 'request_id', 'contact_revision_id', 'action', 'supersedes_given_id', 'event_id',
      'staff_evidence_id'],
    update: [],
  },
  request_files: {
    select: ['request_id', 'owner_session_id', 'intent_id', 'file_id'],
    insert: ['request_id', 'owner_session_id', 'intent_id', 'file_id'],
    update: [],
  },
  request_appliance_brands: {
    select: ['appliance_revision_id', 'request_id', 'brand_id', 'brand_kind', 'brand_version_id'],
    insert: ['appliance_revision_id', 'request_id', 'brand_id', 'brand_version_id'],
    update: [],
  },
  request_channel_choices: {
    select: ['request_id', 'provider', 'catalog_version_id', 'option_version_id', 'readiness_basis_id', 'checked_at'],
    insert: ['request_id', 'provider', 'catalog_version_id', 'option_version_id', 'readiness_basis_id'],
    update: [],
  },
  // Write-only evidence: the runtime may insert an attempt but never read it back.
  request_address_review_attempts: {
    select: [],
    insert: ['evidence_id', 'staff_id', 'request_id', 'address_revision_id', 'purpose', 'correlation_id'],
    update: [],
  },
  request_coverage_assessments: {
    select: ['id', 'request_id', 'address_revision_id', 'city_id', 'city_version_id', 'area_id', 'area_version_id',
      'basis_digest', 'outcome', 'reason', 'staff_id', 'attempt_correlation_id', 'event_id', 'created_at'],
    insert: ['id', 'request_id', 'address_revision_id', 'city_id', 'city_version_id', 'area_id', 'area_version_id',
      'basis_digest', 'outcome', 'reason', 'staff_id', 'attempt_correlation_id', 'event_id'],
    update: [],
  },
  request_intake_provenance: {
    select: ['request_id', 'source_entry_id', 'source_version_id', 'source_type', 'callback_entry_id',
      'callback_version_id', 'callback_type'],
    insert: ['request_id', 'source_entry_id', 'source_version_id', 'callback_entry_id', 'callback_version_id'],
    update: [],
  },
};

/**
 * The three tables 024 *modifies*. Their ACL is not owned by 024 as a whole: 022
 * already granted a wider surface (for `requests` even a wider UPDATE surface),
 * so the proof asserts the 024 delta plus negative controls — the new privilege
 * must be present, and identity/history columns must stay unwritable. Restating
 * the pre-024 surface here would duplicate an earlier cap and would silently
 * re-assert numbers this task is not allowed to rewrite.
 */
const modifiedAcl = {
  requests: {
    select: ['current_assessment_id'],
    insert: [],
    update: ['type', 'current_assessment_id'],
    mustNotUpdate: ['id', 'public_number', 'customer_id', 'city_id', 'created_at'],
  },
  request_payload_cells: {
    select: ['wrapped_dek', 'nonce', 'ciphertext', 'auth_tag', 'aad_context'],
    insert: [],
    update: [],
    mustNotUpdate: ['id', 'request_id', 'kind', 'revision'],
  },
  request_preference_revisions: {
    select: ['contact_mode'],
    insert: ['contact_mode'],
    update: [],
    mustNotUpdate: ['id', 'request_id', 'revision'],
  },
};

const requestEffectsFunctions = ['request_role_grant_guard', 'request_effect_guard', 'request_aggregate_guard',
  'request_phone_permission_guard'];

async function denied(query, sqlState, label) {
  await assert.rejects(query, (error) => error.code === sqlState, `Expected SQLSTATE ${sqlState}: ${label}`);
}

/**
 * TRUNCATE refusal. Every 024 history table carries the statement-level
 * `catalog_reject_history_change` trigger (SQLSTATE 23514), but a table that is
 * the target of a foreign key is refused earlier by PostgreSQL itself with
 * 0A000 ("cannot truncate a table referenced in a foreign key constraint").
 * Both are a refusal; which one fires depends on the FK graph, so the proof
 * accepts exactly those two codes and nothing else.
 */
async function truncateDenied(query, label) {
  await assert.rejects(query, (error) => error.code === '23514' || error.code === '0A000',
    `Expected a TRUNCATE refusal (23514 or 0A000): ${label}`);
}

async function columnPrivileges(reader, target) {
  return reader.query(`SELECT attname,
    has_column_privilege(current_user,attrelid,attnum,'SELECT') AS readable,
    has_column_privilege(current_user,attrelid,attnum,'INSERT') AS insertable,
    has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS updatable,
    has_column_privilege(current_user,attrelid,attnum,'REFERENCES') AS referencable,
    has_column_privilege(current_user,attrelid,attnum,'SELECT WITH GRANT OPTION') AS grantable
    FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped`, [target]);
}

/** Exact column ACL, no PUBLIC access and no table-level privilege on one table. */
export async function proveRequestEffectsAcl(runtime, spec = requestEffectsAcl, label = '') {
  for (const [table, grants] of Object.entries(spec)) {
    const target = `foundation.${table}`;
    const columns = await columnPrivileges(runtime, target);
    const pick = (flag) => columns.rows.filter((column) => column[flag]).map((column) => column.attname).sort();
    const readable = pick('readable');
    const insertable = pick('insertable');
    const updatable = pick('updatable');
    if (label === '') {
      // Tables owned by 024: the whole column surface must match exactly.
      assert.deepEqual(readable, [...grants.select].sort(), `Runtime SELECT columns on ${table}`);
      assert.deepEqual(insertable, [...grants.insert].sort(), `Runtime INSERT columns on ${table}`);
      assert.deepEqual(updatable, [...grants.update].sort(), `Runtime UPDATE columns on ${table}${label}`);
    } else {
      // Tables modified by 024: the 024 delta must be present and the negative
      // controls must stay unwritable; the pre-024 surface belongs to earlier caps.
      for (const column of grants.select) {
        assert.ok(readable.includes(column), `Runtime SELECT must include ${table}.${column}`);
      }
      for (const column of grants.insert) {
        assert.ok(insertable.includes(column), `Runtime INSERT must include ${table}.${column}`);
      }
      for (const column of grants.update) {
        assert.ok(updatable.includes(column), `Runtime UPDATE must include ${table}.${column}`);
      }
      for (const column of grants.mustNotUpdate ?? []) {
        assert.ok(!updatable.includes(column), `Runtime UPDATE must not include ${table}.${column}`);
      }
    }
    assert.equal(pick('referencable').length, 0, `Runtime REFERENCES on ${table}${label}`);
    assert.equal(pick('grantable').length, 0, `Runtime grant option on ${table}${label}`);
    const broad = await runtime.query(`SELECT has_table_privilege(current_user,$1,
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS elevated`, [target]);
    assert.equal(broad.rows[0].elevated, false, `Runtime table-level privilege on ${table}${label}`);
    // No PUBLIC grant may exist on any column of the table.
    const publicGrants = await runtime.query(`SELECT count(*)::int AS n FROM pg_attribute a
      WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
      AND EXISTS (SELECT FROM aclexplode(a.attacl) x WHERE x.grantee=0)`, [target]);
    assert.equal(publicGrants.rows[0].n, 0, `PUBLIC column grant on ${table}${label}`);
  }
}

/** The 024 triggers exist exactly once per table and the guard functions stay unreachable. */
export async function proveRequestEffectsTriggers(owner, runtime) {
  const triggers = await owner.query(`SELECT c.relname AS table_name, t.tgname, p.proname AS function_name
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_proc p ON p.oid=t.tgfoid
    WHERE n.nspname='foundation' AND NOT t.tgisinternal AND c.relname = ANY($1::text[]) ORDER BY 1,2`,
  [requestEffectsTables]);
  const seen = triggers.rows.map((row) => `${row.table_name}.${row.tgname}`);
  for (const table of requestEffectsTables) {
    // Every 024 table carries exactly one history trigger. Other reviewed guards
    // may sit on the same table (phone_permission_events has the PHONE
    // completeness trigger too), so the history trigger is matched by its
    // function, not by "the only trigger".
    const history = triggers.rows.filter((row) => row.table_name === table
      && row.function_name === 'catalog_reject_history_change');
    assert.equal(history.length, 1, `Expected exactly one history trigger on ${table}`);
    assert.equal(history[0]?.tgname, `${table}_immutable`, `History trigger name on ${table}`);
    assert.ok(seen.includes(`${table}.${table}_immutable`), `History trigger presence on ${table}`);
  }
  // The exact PHONE completeness trigger: row-level BEFORE INSERT, non-deferrable,
  // so an unauthorised permission row cannot even reach the transaction's end.
  const phoneTrigger = triggers.rows.filter((row) => row.function_name === 'request_phone_permission_guard');
  assert.equal(phoneTrigger.length, 1, 'Expected exactly one PHONE completeness trigger');
  assert.equal(phoneTrigger[0]?.table_name, 'phone_permission_events', 'PHONE trigger table');
  const phoneTriggerShape = (await owner.query(`SELECT tgtype, tgdeferrable, tginitdeferred, tgenabled
    FROM pg_trigger WHERE tgrelid='foundation.phone_permission_events'::regclass
      AND tgname='phone_permission_complete'`)).rows[0];
  assert.equal(phoneTriggerShape?.tgdeferrable, false, 'PHONE trigger must be non-deferrable');
  assert.equal(phoneTriggerShape?.tginitdeferred, false, 'PHONE trigger must not be initially deferred');
  assert.equal(phoneTriggerShape?.tgenabled, 'O', 'PHONE trigger must be enabled in origin mode');
  // BEFORE INSERT, ROW: tgtype bit 0 (ROW) and bit 2 (BEFORE) set, bit 4 (INSERT) set.
  assert.equal((phoneTriggerShape?.tgtype ?? 0) & 1, 1, 'PHONE trigger must be FOR EACH ROW');
  assert.equal((phoneTriggerShape?.tgtype ?? 0) & 2, 2, 'PHONE trigger must be BEFORE');
  assert.equal((phoneTriggerShape?.tgtype ?? 0) & 4, 4, 'PHONE trigger must fire on INSERT');
  // No SECOND guard is added on this table: provenance is enforced by the row-level
  // guard (command shape + current request version + exact evidence) together with
  // the UNIQUE(event_id) index, so no extra trigger and no extra ACL is needed.
  assert.equal(triggers.rows.filter((row) => row.table_name === 'phone_permission_events').length, 2,
    'phone_permission_events carries exactly the history and PHONE triggers');
  // The three 024 guard functions are SECURITY INVOKER, fixed search_path, owned by
  // the migrator and not executable by the runtime: a trigger is their only path.
  const functions = await owner.query(`SELECT p.proname, pg_get_userbyid(p.proowner) AS owner, p.prosecdef,
    p.proconfig, has_function_privilege('fixlevelup_runtime',p.oid,'EXECUTE') AS runtime_execute,
    EXISTS (SELECT FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
      WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') AS public_execute
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='foundation' AND p.proname = ANY($1::text[]) ORDER BY p.proname`, [requestEffectsFunctions]);
  assert.equal(functions.rowCount, requestEffectsFunctions.length, '024 guard function inventory');
  for (const fn of functions.rows) {
    assert.equal(fn.owner, 'fixlevelup_migrator', `Owner of ${fn.proname}`);
    assert.equal(fn.prosecdef, false, `${fn.proname} must be SECURITY INVOKER`);
    assert.ok(fn.proconfig?.includes('search_path=pg_catalog'), `${fn.proname} must pin search_path`);
    assert.equal(fn.runtime_execute, false, `Runtime EXECUTE on ${fn.proname}`);
    assert.equal(fn.public_execute, false, `PUBLIC EXECUTE on ${fn.proname}`);
  }
  // A direct call is refused even if some future grant appears.
  await denied(runtime.query('SELECT foundation.request_effect_guard()'), '42501', 'runtime guard call');
  await denied(runtime.query('SELECT foundation.request_phone_permission_guard()'), '42501',
    'runtime PHONE guard call');
}

/** Populated upgrade: S3 starts inert, history is immutable, new CHECKs are enforced. */
export async function proveRequestEffectsUpgrade(owner, runtime) {
  // Inert start: 024 provisions capability codes and structure, never request rows.
  for (const table of requestEffectsTables) {
    assert.equal((await owner.query(`SELECT FROM foundation.${table}`)).rowCount, 0,
      `Unexpected seed in ${table}`);
  }
  // 024 provisions codes only; it must not grant them to any role.
  const granted = await owner.query(`SELECT count(*)::int AS n FROM foundation.role_permissions
    WHERE permission_code LIKE 'requests.%' AND enabled`);
  assert.equal(granted.rows[0].n, 0, '024 must provision request codes without granting them');
  const codes = await owner.query(`SELECT code, module FROM foundation.permissions
    WHERE code LIKE 'requests.%' ORDER BY code`);
  assert.deepEqual(codes.rows.map((row) => row.code),
    ['requests.cancel', 'requests.contact.manage', 'requests.coverage.assess', 'requests.create',
      'requests.read', 'requests.ready', 'requests.review']);
  assert.ok(codes.rows.every((row) => row.module === 'requests'), '024 permission module must be requests');

  // request_address_review_attempts has no FK by design (it is committed before the
  // plaintext comparison), so a real row can be created here without an aggregate.
  const evidenceId = randomUUID();
  const correlationId = randomUUID();
  await owner.query(`INSERT INTO foundation.request_address_review_attempts
    (evidence_id,staff_id,request_id,address_revision_id,purpose,correlation_id)
    VALUES($1,$2,$3,$4,'COVERAGE_REVIEW',$5)`,
  [evidenceId, randomUUID(), randomUUID(), randomUUID(), correlationId]);
  const attempt = (await owner.query(`SELECT purpose, occurred_at, evidence_id
    FROM foundation.request_address_review_attempts WHERE evidence_id=$1`, [evidenceId])).rows[0];
  assert.equal(attempt.purpose, 'COVERAGE_REVIEW', 'Review attempt purpose');
  assert.ok(Date.now() - attempt.occurred_at.getTime() < 60_000, 'Review attempt must use the database clock');
  // The correlation id is unique: a second attempt cannot reuse it.
  await assert.rejects(owner.query(`INSERT INTO foundation.request_address_review_attempts
    (evidence_id,staff_id,request_id,address_revision_id,purpose,correlation_id)
    VALUES($1,$2,$3,$4,'COVERAGE_REVIEW',$5)`,
  [randomUUID(), randomUUID(), randomUUID(), randomUUID(), correlationId]),
  (error) => error.code === '23505', 'Expected a unique violation on the review attempt correlation');
  // purpose vocabulary is closed.
  await assert.rejects(owner.query(`INSERT INTO foundation.request_address_review_attempts
    (evidence_id,staff_id,request_id,address_revision_id,purpose,correlation_id)
    VALUES($1,$2,$3,$4,'OTHER',$5)`,
  [randomUUID(), randomUUID(), randomUUID(), randomUUID(), randomUUID()]),
  (error) => error.code === '23514', 'Expected the review attempt purpose CHECK');

  // Immutability of the new history tables: UPDATE/DELETE/TRUNCATE refused.
  await denied(owner.query(`UPDATE foundation.request_address_review_attempts SET purpose='COVERAGE_REVIEW'`),
    '23514', 'review attempt UPDATE');
  await denied(owner.query('DELETE FROM foundation.request_address_review_attempts'), '23514',
    'review attempt DELETE');
  await truncateDenied(owner.query('TRUNCATE foundation.request_address_review_attempts'),
    'review attempt TRUNCATE');
  for (const table of requestEffectsTables.filter((name) => name !== 'request_address_review_attempts')) {
    await truncateDenied(owner.query(`TRUNCATE foundation.${table}`), `${table} TRUNCATE`);
  }

  // The two aggregate-level pair CHECKs of 024 are present and validated.
  const pairChecks = await owner.query(`SELECT conname, convalidated FROM pg_constraint
    WHERE connamespace='foundation'::regnamespace AND conname = ANY($1::text[]) ORDER BY conname`,
  [['requests_package_pair_check', 'requests_assessment_requires_address_check']]);
  assert.equal(pairChecks.rowCount, 2, '024 aggregate pair CHECK inventory');
  assert.ok(pairChecks.rows.every((row) => row.convalidated), '024 aggregate pair CHECKs must be validated');

  // Runtime half: exact ACL on the ten new and three modified tables.
  await proveRequestEffectsAcl(runtime);
  await proveRequestEffectsAcl(runtime, modifiedAcl, ' (024 delta)');
  // Runtime cannot write where it has no privilege, cannot read write-only
  // evidence, and cannot rewrite history.
  await denied(runtime.query('SELECT evidence_id FROM foundation.request_address_review_attempts'), '42501',
    'runtime read of write-only review attempts');
  for (const table of requestEffectsTables) {
    await denied(runtime.query(`UPDATE foundation.${table} SET request_id=request_id`), '42501',
      `runtime UPDATE on ${table}`);
    await denied(runtime.query(`DELETE FROM foundation.${table}`), '42501', `runtime DELETE on ${table}`);
    // TRUNCATE may be refused by the FK graph (0A000) before the privilege
    // check runs, so a runtime TRUNCATE must fail with one of those two codes.
    await assert.rejects(runtime.query(`TRUNCATE foundation.${table}`),
      (error) => error.code === '42501' || error.code === '0A000',
      `runtime TRUNCATE on ${table}`);
  }
  // A guarded column of a new table cannot be written by the runtime.
  await denied(runtime.query(`INSERT INTO foundation.request_files(request_id,owner_session_id,intent_id,file_id,open_state)
    VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'OPEN')`), '42501',
  'runtime INSERT of request_files.open_state');
  await denied(runtime.query(`INSERT INTO foundation.request_appliance_brands
    (appliance_revision_id,request_id,brand_id,brand_version_id,brand_kind)
    VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'BRAND')`), '42501',
  'runtime INSERT of request_appliance_brands.brand_kind');
  await denied(runtime.query(`INSERT INTO foundation.request_session_submits
    (session_id,request_id,customer_id,intake_city_id,intake_city_version_id,consent_id,document_id,
     document_version_id,event_id,submit_command,purpose)
    VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),
     gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'SubmitForm','REQUEST_PROCESSING')`),
  '42501', 'runtime INSERT of request_session_submits.purpose');
  // The new `requests` grants are additive: 022 already lets the runtime move the
  // status/pointers, so the negative control is an identity column, which neither
  // 022 nor 024 ever grants.
  await denied(runtime.query(`UPDATE foundation.requests SET public_number=public_number+1`), '42501',
    'runtime UPDATE of requests.public_number');
  await denied(runtime.query(`UPDATE foundation.requests SET customer_id=customer_id`), '42501',
    'runtime UPDATE of requests.customer_id');
  return { tables: requestEffectsTables.length, checks: requestEffectsChecks.length };
}
