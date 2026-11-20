import { randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, cpSync } from 'node:fs';
import { resolve } from 'node:path';
import { admin, credentials, connection, prepareDatabase, runPrisma, root } from './migration-local.mjs';

function assert(condition, label) { if (!condition) { throw new Error(label); } }
function command(args, database, expected = 0, shadow, history) {
  const result = runPrisma(args, database, shadow, history);
  if (result.status !== expected) { process.stdout.write(result.output); throw new Error(`Prisma command expected ${String(expected)}, got ${String(result.status)}`); }
  return result.output;
}
async function denied(client, sql) {
  try { await client.query(sql); }
  catch (error) { assert(error.code === '42501', `Expected insufficient_privilege, got ${error.code}`); return; }
  throw new Error('Runtime privilege unexpectedly allowed');
}
let checkDenials = 0;
async function checkViolation(client, sql, values = []) {
  try { await client.query(sql, values); }
  catch (error) { assert(error.code === '23514', `Expected custom CHECK violation, got ${error.code}`); checkDenials += 1; return; }
  throw new Error('Invalid CHECK input accepted');
}
const migrations = ['20261120000100_technical_audit_outbox', '20261120000200_technical_outbox_attempts', '20261120000300_technical_outbox_leases', '20261120000400_staff_identity', '20261120000500_web_auth'];
const expectedChecks = [
  'audit_logs_operation_check', 'outbox_events_status_check', 'outbox_events_type_check', 'outbox_events_attempt_count_check',
  'outbox_events_lease_generation_check', 'outbox_events_lease_pair_check', 'outbox_events_lease_pending_check', 'outbox_events_last_error_code_check',
  'staff_role_check', 'staff_employment_state_check', 'staff_auth_version_check',
  'staff_web_credentials_login_check', 'staff_web_credentials_password_hash_check', 'staff_bootstrap_marker_singleton_check',
  'web_sessions_token_hash_check', 'web_sessions_auth_version_check', 'web_sessions_expiry_check', 'web_sessions_revoked_at_check',
  'web_auth_throttles_key_hash_check', 'web_auth_attempts_expiry_check', 'web_auth_attempts_completion_check',
];
const client = await admin();
const passwords = credentials();
const suffix = randomBytes(6).toString('hex');
const fresh = `fixlevelup_p017a_fresh_${suffix}`;
const upgrade = `fixlevelup_p017a_upgrade_${suffix}`;
const upgradeSecond = `fixlevelup_p017a_upgrade_${randomBytes(6).toString('hex')}`;
const upgradeThird = `fixlevelup_p017a_upgrade_${randomBytes(6).toString('hex')}`;
const upgradeFourth = `fixlevelup_p017a_upgrade_${randomBytes(6).toString('hex')}`;
const shadow = `fixlevelup_p017a_shadow_${suffix}`;
const historyRoot = resolve(root, `node_modules/.cache/p017a-${suffix}`);
const firstHistory = resolve(historyRoot, 'first/migrations');
const secondHistory = resolve(historyRoot, 'second/migrations');
const thirdHistory = resolve(historyRoot, 'third/migrations');
const fourthHistory = resolve(historyRoot, 'fourth/migrations');
try {
  for (const database of [fresh, upgrade, upgradeSecond, upgradeThird, upgradeFourth, shadow]) { await prepareDatabase(client, database, true); }
  console.log(`Isolated test databases: ${fresh}, ${upgrade}, ${upgradeSecond}, ${upgradeThird}, ${upgradeFourth}, ${shadow}`);
  for (const [history, names] of [[firstHistory, migrations.slice(0, 1)], [secondHistory, migrations.slice(0, 2)], [thirdHistory, migrations.slice(0, 3)], [fourthHistory, migrations.slice(0, 4)]]) {
    mkdirSync(history, { recursive: true });
    cpSync(resolve(root, 'prisma/migrations/migration_lock.toml'), resolve(history, 'migration_lock.toml'));
    for (const name of names) { cpSync(resolve(root, 'prisma/migrations', name), resolve(history, name), { recursive: true }); }
  }
  command(['migrate', 'deploy'], fresh);
  command(['migrate', 'deploy'], upgrade, 0, undefined, firstHistory);
  const upgraded = connection('fixlevelup_runtime', passwords.fixlevelup_runtime, upgrade);
  await upgraded.connect();
  const upgradeId = randomUUID();
  try {
    await upgraded.query('INSERT INTO foundation.outbox_events(id,event_id,event_type) VALUES($1,$2,$3)', [upgradeId, randomUUID(), 'TECHNICAL_UPGRADE']);
  } finally { await upgraded.end(); }
  command(['migrate', 'deploy'], upgrade);
  const reader = connection('fixlevelup_migrator', passwords.fixlevelup_migrator, upgrade);
  await reader.connect();
  try {
    const row = await reader.query('SELECT event_type,status,attempt_count,lease_owner,lease_generation,lease_expires_at,next_attempt_at,last_error_code FROM foundation.outbox_events WHERE id=$1', [upgradeId]);
    const event = row.rows[0];
    assert(event?.event_type === 'TECHNICAL_UPGRADE' && event.status === 'PENDING' && event.attempt_count === 0
      && event.lease_owner === null && event.lease_generation === '0' && event.lease_expires_at === null
      && event.next_attempt_at instanceof Date && event.last_error_code === null, 'First-to-latest upgrade lost data/defaults');
    const before = await reader.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    command(['migrate', 'deploy'], upgrade);
    const after = await reader.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    assert(JSON.stringify(before.rows) === JSON.stringify(after.rows) && after.rowCount === migrations.length
      && JSON.stringify(after.rows.map((entry) => entry.migration_name)) === JSON.stringify(migrations), 'Replay changed migration history');
  } finally { await reader.end(); }

  // Explicit second-to-latest upgrade preserves existing statuses, attempts and payloads.
  command(['migrate', 'deploy'], upgradeSecond, 0, undefined, secondHistory);
  const secondWriter = connection('fixlevelup_runtime', passwords.fixlevelup_runtime, upgradeSecond);
  await secondWriter.connect();
  const priorEvents = ['PENDING', 'EXPANDED', 'FAILED'].map((status, index) => ({
    id: randomUUID(), eventId: randomUUID(), status, attempts: index + 2, payload: { technical: true, index },
  }));
  let beforeRows;
  try {
    for (const event of priorEvents) {
      await secondWriter.query('INSERT INTO foundation.outbox_events(id,event_id,event_type,status,attempt_count,payload) VALUES($1,$2,$3,$4,$5,$6)',
        [event.id, event.eventId, 'TECHNICAL_SECOND_UPGRADE', event.status, event.attempts, event.payload]);
    }
    beforeRows = (await secondWriter.query('SELECT id,event_id,event_type,created_at,status,attempt_count,payload FROM foundation.outbox_events ORDER BY id')).rows;
  } finally { await secondWriter.end(); }
  command(['migrate', 'deploy'], upgradeSecond);
  const secondReader = connection('fixlevelup_migrator', passwords.fixlevelup_migrator, upgradeSecond);
  await secondReader.connect();
  try {
    const preserved = await secondReader.query('SELECT id,event_id,event_type,created_at,status,attempt_count,payload FROM foundation.outbox_events ORDER BY id');
    assert(JSON.stringify(preserved.rows) === JSON.stringify(beforeRows), 'Second-to-latest upgrade changed existing data');
    const defaults = await secondReader.query('SELECT lease_owner,lease_generation,lease_expires_at,next_attempt_at,last_error_code FROM foundation.outbox_events');
    assert(defaults.rowCount === priorEvents.length && defaults.rows.every((event) => event.lease_owner === null && event.lease_generation === '0'
      && event.lease_expires_at === null && event.next_attempt_at instanceof Date && event.last_error_code === null), 'Second-to-latest lease defaults missing');
    const applied = await secondReader.query('SELECT migration_name FROM foundation._prisma_migrations WHERE finished_at IS NOT NULL ORDER BY migration_name');
    assert(applied.rowCount === migrations.length && JSON.stringify(applied.rows.map((entry) => entry.migration_name)) === JSON.stringify(migrations), 'Second-to-latest history mismatch');
  } finally { await secondReader.end(); }
  // Upgrade the third history with populated audit and leased outbox data.
  command(['migrate', 'deploy'], upgradeThird, 0, undefined, thirdHistory);
  const thirdWriter = connection('fixlevelup_runtime', passwords.fixlevelup_runtime, upgradeThird);
  await thirdWriter.connect();
  const thirdId = randomUUID(), thirdEventId = randomUUID(), thirdOwner = randomUUID();
  let thirdAuditBefore, thirdOutboxBefore;
  try {
    await thirdWriter.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES($1,$2,$3)', [thirdId, 'TECHNICAL_THIRD_UPGRADE', randomUUID()]);
    await thirdWriter.query("INSERT INTO foundation.outbox_events(id,event_id,event_type,status,attempt_count,payload,lease_owner,lease_generation,lease_expires_at,next_attempt_at,last_error_code) VALUES($1,$2,$3,'PENDING',4,$4,$5,2147483648,CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '30 minutes','HANDLER_FAILED')",
      [thirdId, thirdEventId, 'TECHNICAL_THIRD_UPGRADE', { technical: true }, thirdOwner]);
    thirdAuditBefore = (await thirdWriter.query('SELECT * FROM foundation.audit_logs ORDER BY id')).rows;
    thirdOutboxBefore = (await thirdWriter.query('SELECT * FROM foundation.outbox_events ORDER BY id')).rows;
  } finally { await thirdWriter.end(); }
  command(['migrate', 'deploy'], upgradeThird);
  const thirdReader = connection('fixlevelup_migrator', passwords.fixlevelup_migrator, upgradeThird);
  await thirdReader.connect();
  try {
    const auditAfter = (await thirdReader.query('SELECT * FROM foundation.audit_logs ORDER BY id')).rows;
    const outboxAfter = (await thirdReader.query('SELECT * FROM foundation.outbox_events ORDER BY id')).rows;
    assert(JSON.stringify(auditAfter) === JSON.stringify(thirdAuditBefore) && JSON.stringify(outboxAfter) === JSON.stringify(thirdOutboxBefore), 'Third-to-latest upgrade changed existing synthetic data');
    const beforeReplay = await thirdReader.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    assert(beforeReplay.rowCount === migrations.length && JSON.stringify(beforeReplay.rows.map((entry) => entry.migration_name)) === JSON.stringify(migrations)
      && beforeReplay.rows.every((entry) => entry.finished_at !== null), 'Third-to-latest history mismatch');
    command(['migrate', 'deploy'], upgradeThird);
    const afterReplay = await thirdReader.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    assert(JSON.stringify(afterReplay.rows) === JSON.stringify(beforeReplay.rows), 'Third-to-latest replay changed history');
    command(['migrate', 'diff', '--from-migrations', '../../prisma/migrations', '--to-config-datasource', '--exit-code'], upgradeThird, 0, shadow);
    command(['migrate', 'diff', '--from-schema', '../../prisma/schema.prisma', '--to-config-datasource', '--exit-code'], upgradeThird);
  } finally { await thirdReader.end(); }
  // Preserve synthetic staff, credentials, marker, audit and outbox across web auth migration.
  command(['migrate', 'deploy'], upgradeFourth, 0, undefined, fourthHistory);
  const fourthReader = connection('fixlevelup_migrator', passwords.fixlevelup_migrator, upgradeFourth);
  await fourthReader.connect();
  try {
    const staffId = randomUUID(), eventId = randomUUID();
    await fourthReader.query("INSERT INTO foundation.staff(id,role,employment_state,auth_version) VALUES($1,'ADMIN','ACTIVE',7)", [staffId]);
    await fourthReader.query("INSERT INTO foundation.staff_web_credentials(staff_id,login,password_hash) VALUES($1,'synthetic-login','synthetic-hash')", [staffId]);
    await fourthReader.query('INSERT INTO foundation.staff_bootstrap_marker(id,staff_id) VALUES(1,$1)', [staffId]);
    await fourthReader.query("INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES($1,'TECHNICAL_FOURTH_UPGRADE',$2)", [eventId, randomUUID()]);
    await fourthReader.query("INSERT INTO foundation.outbox_events(id,event_id,event_type,payload) VALUES($1,$2,'TECHNICAL_FOURTH_UPGRADE',$3)", [eventId, randomUUID(), { synthetic: true }]);
    const tables = ['staff', 'staff_web_credentials', 'staff_bootstrap_marker', 'audit_logs', 'outbox_events'];
    const before = [];
    for (const table of tables) { before.push((await fourthReader.query(`SELECT * FROM foundation.${table} ORDER BY 1`)).rows); }
    command(['migrate', 'deploy'], upgradeFourth);
    for (const [index, table] of tables.entries()) {
      const after = (await fourthReader.query(`SELECT * FROM foundation.${table} ORDER BY 1`)).rows;
      assert(JSON.stringify(after) === JSON.stringify(before[index]), `Fourth-to-latest upgrade changed ${table} data`);
    }
    const history = await fourthReader.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    assert(history.rowCount === migrations.length && JSON.stringify(history.rows.map((entry) => entry.migration_name)) === JSON.stringify(migrations)
      && history.rows.every((entry) => entry.finished_at !== null), 'Fourth-to-latest history mismatch');
    command(['migrate', 'deploy'], upgradeFourth);
    const replay = await fourthReader.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    assert(JSON.stringify(replay.rows) === JSON.stringify(history.rows), 'Fourth-to-latest replay changed history');
    command(['migrate', 'diff', '--from-migrations', '../../prisma/migrations', '--to-config-datasource', '--exit-code'], upgradeFourth, 0, shadow);
    command(['migrate', 'diff', '--from-schema', '../../prisma/schema.prisma', '--to-config-datasource', '--exit-code'], upgradeFourth);
  } finally { await fourthReader.end(); }
  console.log(`Fresh/first-to-latest/second-to-latest/third-to-latest/fourth-to-latest/data preservation/replay (${migrations.length} migrations): PASS`);
  command(['migrate', 'diff', '--from-migrations', '../../prisma/migrations', '--to-config-datasource', '--exit-code'], fresh, 0, shadow);
  command(['migrate', 'diff', '--from-schema', '../../prisma/schema.prisma', '--to-config-datasource', '--exit-code'], fresh);
  const runtimeStaffId = randomUUID();
  const migration = connection('fixlevelup_migrator', passwords.fixlevelup_migrator, fresh);
  await migration.connect();
  try {
    const freshBefore = await migration.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    assert(freshBefore.rowCount === migrations.length && JSON.stringify(freshBefore.rows.map((entry) => entry.migration_name)) === JSON.stringify(migrations)
      && freshBefore.rows.every((entry) => entry.finished_at !== null), 'Fresh migration history mismatch');
    command(['migrate', 'deploy'], fresh);
    const freshAfter = await migration.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    assert(JSON.stringify(freshAfter.rows) === JSON.stringify(freshBefore.rows), 'Fresh replay changed migration history');
    await migration.query("INSERT INTO foundation.staff(id,role,employment_state,auth_version) VALUES($1,'ADMIN','ACTIVE',1)", [runtimeStaffId]);
    await migration.query("INSERT INTO foundation.staff_web_credentials(staff_id,login,password_hash) VALUES($1,'runtime-synthetic','initial-synthetic-hash')", [runtimeStaffId]);
    const owner = await migration.query("SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname='foundation'");
    assert(owner.rows[0]?.owner === 'fixlevelup_migrator', 'Schema owner mismatch');
    const checks = await migration.query("SELECT conname,convalidated FROM pg_constraint WHERE connamespace='foundation'::regnamespace AND contype='c' ORDER BY conname");
    assert(checks.rowCount === expectedChecks.length && checks.rows.every((check) => check.convalidated)
      && JSON.stringify(checks.rows.map((check) => check.conname)) === JSON.stringify([...expectedChecks].sort()), 'Custom CHECK constraints mismatch');
    const functions = await migration.query("SELECT p.proname, pg_get_userbyid(p.proowner) AS owner, p.prosecdef, p.proconfig, has_function_privilege('fixlevelup_runtime',p.oid,'EXECUTE') AS runtime_execute, EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') AS public_execute FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='foundation' AND p.proname = ANY($1::text[]) ORDER BY p.proname", [['cleanup_web_auth_attempts', 'cleanup_web_auth_throttles', 'cleanup_web_sessions']]);
    assert(functions.rowCount === 3 && functions.rows.every((fn) => fn.owner === 'fixlevelup_migrator' && fn.prosecdef
      && fn.proconfig?.includes('search_path=pg_catalog') && fn.runtime_execute && !fn.public_execute), 'Cleanup function security mismatch');
    const dueIndex = await migration.query("SELECT pg_get_indexdef(indexrelid) AS definition,indisvalid FROM pg_index WHERE indexrelid='foundation.outbox_events_due_idx'::regclass");
    assert(dueIndex.rows[0]?.indisvalid && dueIndex.rows[0].definition === 'CREATE INDEX outbox_events_due_idx ON foundation.outbox_events USING btree (status, next_attempt_at, created_at, id)', 'Due index mismatch');
    await migration.query('ALTER TABLE foundation.audit_logs ADD COLUMN p017a_drift_probe integer');
    command(['migrate', 'diff', '--from-schema', '../../prisma/schema.prisma', '--to-config-datasource', '--exit-code'], fresh, 2);
    await migration.query('ALTER TABLE foundation.audit_logs DROP COLUMN p017a_drift_probe');
    command(['migrate', 'diff', '--from-schema', '../../prisma/schema.prisma', '--to-config-datasource', '--exit-code'], fresh);
  } finally { await migration.end(); }
  console.log(`Migration-history diff/schema drift detection/restoration/catalog checks (${expectedChecks.length} CHECKs): PASS`);
  const runtime = connection('fixlevelup_runtime', passwords.fixlevelup_runtime, fresh);
  await runtime.connect();
  try {
    const role = await runtime.query("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit FROM pg_roles WHERE rolname IN ('fixlevelup_runtime','fixlevelup_migrator')");
    assert(role.rowCount === 2 && role.rows.every((row) => Object.values(row).every((value) => value === false)), 'Unsafe technical role flags');
    const memberships = await runtime.query("SELECT 1 FROM pg_auth_members WHERE member IN (SELECT oid FROM pg_roles WHERE rolname IN ('fixlevelup_runtime','fixlevelup_migrator'))");
    assert(memberships.rowCount === 0, 'Technical role membership');
    const workerColumns = ['status', 'attempt_count', 'lease_owner', 'lease_generation', 'lease_expires_at', 'next_attempt_at', 'last_error_code'];
    const grants = await runtime.query("SELECT a.attname,has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE') AS writable FROM pg_attribute a WHERE a.attrelid='foundation.outbox_events'::regclass AND a.attnum>0 AND NOT a.attisdropped");
    assert(grants.rows.filter((column) => column.writable).length === workerColumns.length
      && grants.rows.every((column) => column.writable === workerColumns.includes(column.attname)), 'Runtime outbox column grants mismatch');
    const tableGrant = await runtime.query("SELECT has_table_privilege(current_user,'foundation.outbox_events','UPDATE') AS writable, has_any_column_privilege(current_user,'foundation.audit_logs','UPDATE') AS audit_writable");
    assert(!tableGrant.rows[0].writable && !tableGrant.rows[0].audit_writable, 'Runtime broad UPDATE/audit UPDATE unexpectedly allowed');
    for (const [table, allowed] of [['staff', ['auth_version']], ['staff_web_credentials', ['password_hash']]]) {
      const columns = await runtime.query("SELECT a.attname,has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE') AS writable FROM pg_attribute a WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped", [`foundation.${table}`]);
      assert(columns.rows.filter((column) => column.writable).length === allowed.length
        && columns.rows.every((column) => column.writable === allowed.includes(column.attname)), `Runtime ${table} column grants mismatch`);
      const broad = await runtime.query("SELECT has_table_privilege(current_user,$1,'UPDATE') AS writable", [`foundation.${table}`]);
      assert(!broad.rows[0].writable, `Runtime ${table} broad UPDATE unexpectedly allowed`);
    }
    await runtime.query('UPDATE foundation.staff SET auth_version=auth_version+1 WHERE id=$1', [runtimeStaffId]);
    await runtime.query("UPDATE foundation.staff_web_credentials SET password_hash='updated-synthetic-hash' WHERE staff_id=$1", [runtimeStaffId]);
    const staff = await runtime.query('SELECT s.id,s.role,s.employment_state,s.auth_version,c.login,c.password_hash FROM foundation.staff s JOIN foundation.staff_web_credentials c ON c.staff_id=s.id WHERE s.id=$1', [runtimeStaffId]);
    assert(staff.rows[0]?.auth_version === 2 && staff.rows[0].role === 'ADMIN' && staff.rows[0].employment_state === 'ACTIVE'
      && staff.rows[0].login === 'runtime-synthetic' && staff.rows[0].password_hash === 'updated-synthetic-hash', 'Runtime scoped staff reads/writes failed');
    const webGrants = [
      ['web_sessions', ['id', 'staff_id', 'token_hash', 'auth_version', 'created_at', 'idle_expires_at', 'absolute_expires_at', 'revoked_at'], ['token_hash', 'auth_version', 'idle_expires_at', 'revoked_at']],
      ['web_auth_throttles', ['key_hash'], ['key_hash']],
      ['web_auth_attempts', ['id', 'key_hash', 'reserved_at', 'expires_at', 'failed_at', 'completed_at'], ['expires_at', 'failed_at', 'completed_at']],
    ];
    for (const [table, readable, writable] of webGrants) {
      const columns = await runtime.query("SELECT a.attname,has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT') AS readable,has_column_privilege(current_user,a.attrelid,a.attnum,'INSERT') AS insertable,has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE') AS writable FROM pg_attribute a WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped", [`foundation.${table}`]);
      assert(columns.rows.length === readable.length && columns.rows.every((column) => column.readable === readable.includes(column.attname)
        && column.insertable === readable.includes(column.attname) && column.writable === writable.includes(column.attname)), `Runtime ${table} column grants mismatch`);
      const broad = await runtime.query("SELECT has_table_privilege(current_user,$1,'UPDATE') AS writable,has_table_privilege(current_user,$1,'DELETE') AS deletable", [`foundation.${table}`]);
      assert(!broad.rows[0].writable && !broad.rows[0].deletable, `Runtime ${table} broad grants unexpectedly allowed`);
    }
    const expiredKey = 'a'.repeat(64), activeKey = 'b'.repeat(64), orphanKey = 'c'.repeat(64);
    await runtime.query('INSERT INTO foundation.web_auth_throttles(key_hash) VALUES($1),($2),($3)', [expiredKey, activeKey, orphanKey]);
    await runtime.query("INSERT INTO foundation.web_auth_attempts(id,key_hash,reserved_at,expires_at) SELECT gen_random_uuid(),$1,CURRENT_TIMESTAMP-INTERVAL '2 hours',CURRENT_TIMESTAMP-INTERVAL '1 hour' FROM generate_series(1,101)", [expiredKey]);
    await runtime.query("INSERT INTO foundation.web_auth_attempts(id,key_hash,reserved_at,expires_at) VALUES(gen_random_uuid(),$1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '1 hour')", [activeKey]);
    let cleaned = await runtime.query('SELECT foundation.cleanup_web_auth_throttles() AS count');
    assert(cleaned.rows[0].count === 1, 'Throttle cleanup failed to preserve referenced keys');
    cleaned = await runtime.query('SELECT foundation.cleanup_web_auth_attempts() AS count');
    assert(cleaned.rows[0].count === 100, 'Attempt cleanup batch limit mismatch');
    cleaned = await runtime.query('SELECT foundation.cleanup_web_auth_attempts() AS count');
    assert(cleaned.rows[0].count === 1, 'Attempt cleanup remainder mismatch');
    cleaned = await runtime.query('SELECT foundation.cleanup_web_auth_throttles() AS count');
    assert(cleaned.rows[0].count === 1, 'Throttle cleanup did not remove unreferenced key');
    const remainingAttempts = await runtime.query('SELECT key_hash FROM foundation.web_auth_attempts');
    const remainingKeys = await runtime.query('SELECT key_hash FROM foundation.web_auth_throttles');
    assert(remainingAttempts.rowCount === 1 && remainingAttempts.rows[0].key_hash === activeKey
      && remainingKeys.rowCount === 1 && remainingKeys.rows[0].key_hash === activeKey, 'Cleanup removed live authentication data');
    await runtime.query("INSERT INTO foundation.web_sessions(id,staff_id,token_hash,auth_version,created_at,idle_expires_at,absolute_expires_at) SELECT gen_random_uuid(),$1,lpad(to_hex(n),64,'0'),1,CURRENT_TIMESTAMP-INTERVAL '60 days',CURRENT_TIMESTAMP-INTERVAL '40 days',CURRENT_TIMESTAMP-INTERVAL '31 days' FROM generate_series(1,101) n", [runtimeStaffId]);
    await runtime.query("INSERT INTO foundation.web_sessions(id,staff_id,token_hash,auth_version,created_at,idle_expires_at,absolute_expires_at) VALUES(gen_random_uuid(),$1,$2,1,CURRENT_TIMESTAMP-INTERVAL '10 days',CURRENT_TIMESTAMP-INTERVAL '5 days',CURRENT_TIMESTAMP-INTERVAL '1 day')", [runtimeStaffId, 'f'.repeat(64)]);
    cleaned = await runtime.query('SELECT foundation.cleanup_web_sessions() AS count');
    assert(cleaned.rows[0].count === 100, 'Session cleanup batch limit mismatch');
    cleaned = await runtime.query('SELECT foundation.cleanup_web_sessions() AS count');
    assert(cleaned.rows[0].count === 1, 'Session cleanup remainder mismatch');
    const remainingSessions = await runtime.query('SELECT token_hash FROM foundation.web_sessions');
    assert(remainingSessions.rowCount === 1 && remainingSessions.rows[0].token_hash === 'f'.repeat(64), 'Session cleanup removed retained session');
    const event = randomUUID(), correlation = randomUUID();
    await runtime.query('BEGIN');
    await runtime.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES($1,$2,$3)', [event, 'TECHNICAL_COMMIT', correlation]);
    await runtime.query('INSERT INTO foundation.outbox_events(id,event_id,event_type) VALUES($1,$2,$3)', [event, event, 'TECHNICAL_COMMIT']);
    await runtime.query('COMMIT');
    const committed = await runtime.query('SELECT (SELECT count(*)::int FROM foundation.audit_logs WHERE id=$1) AS audit, (SELECT count(*)::int FROM foundation.outbox_events WHERE id=$1) AS outbox', [event]);
    assert(committed.rows[0].audit === 1 && committed.rows[0].outbox === 1, 'Committed pair missing');
    await runtime.query("UPDATE foundation.outbox_events SET status='EXPANDED',attempt_count=1 WHERE id=$1", [event]);
    const rolledBack = randomUUID();
    await runtime.query('BEGIN');
    await runtime.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES($1,$2,$3)', [rolledBack, 'TECHNICAL_ROLLBACK', correlation]);
    await runtime.query('INSERT INTO foundation.outbox_events(id,event_id,event_type) VALUES($1,$2,$3)', [rolledBack, rolledBack, 'TECHNICAL_ROLLBACK']);
    await runtime.query('ROLLBACK');
    const counts = await runtime.query('SELECT (SELECT count(*)::int FROM foundation.audit_logs WHERE id=$1) AS audit, (SELECT count(*)::int FROM foundation.outbox_events WHERE id=$1) AS outbox', [rolledBack]);
    assert(counts.rows[0].audit === 0 && counts.rows[0].outbox === 0, 'Rollback not atomic');
    const failed = randomUUID();
    await runtime.query('BEGIN');
    await runtime.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES($1,$2,$3)', [failed, 'TECHNICAL_FAILURE', correlation]);
    await checkViolation(runtime, "INSERT INTO foundation.outbox_events(id,event_id,event_type,status) VALUES($1,$2,'TECHNICAL_FAILURE','INVALID')", [failed, failed]);
    await runtime.query('ROLLBACK');
    assert((await runtime.query('SELECT 1 FROM foundation.audit_logs WHERE id=$1', [failed])).rowCount === 0, 'Error rollback retained audit');
    const invalidChecks = [
      "UPDATE foundation.outbox_events SET attempt_count=-1", "UPDATE foundation.outbox_events SET status='INVALID'",
      "INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES(gen_random_uuid(),'',gen_random_uuid())",
      "INSERT INTO foundation.outbox_events(id,event_id,event_type) VALUES(gen_random_uuid(),gen_random_uuid(),'')",
      'UPDATE foundation.outbox_events SET lease_generation=-1',
      'UPDATE foundation.outbox_events SET lease_owner=gen_random_uuid(),lease_expires_at=NULL',
      'UPDATE foundation.outbox_events SET lease_owner=NULL,lease_expires_at=CURRENT_TIMESTAMP',
      "UPDATE foundation.outbox_events SET lease_owner=gen_random_uuid(),lease_expires_at=CURRENT_TIMESTAMP,status='EXPANDED'",
      "UPDATE foundation.outbox_events SET lease_owner=gen_random_uuid(),lease_expires_at=CURRENT_TIMESTAMP,status='FAILED'",
      "UPDATE foundation.outbox_events SET last_error_code='UNSAFE_DRIVER_ERROR'",
    ];
    for (const sql of invalidChecks) { await checkViolation(runtime, sql); }

    const leased = randomUUID(), leaseOwner = randomUUID();
    await runtime.query('INSERT INTO foundation.outbox_events(id,event_id,event_type) VALUES($1,$1,$2)', [leased, 'TECHNICAL_LEASE']);
    // The repository owns maxAttempts=3. The database only requires nonnegative independent counters.
    await runtime.query('UPDATE foundation.outbox_events SET attempt_count=4,lease_generation=0 WHERE id=$1', [leased]);
    await runtime.query("UPDATE foundation.outbox_events SET lease_owner=$2,lease_generation=2147483648,lease_expires_at=CURRENT_TIMESTAMP+INTERVAL '30 seconds',next_attempt_at=CURRENT_TIMESTAMP+INTERVAL '1 minute',last_error_code='HANDLER_FAILED' WHERE id=$1", [leased, leaseOwner]);
    const lease = (await runtime.query('SELECT lease_owner,lease_generation,lease_expires_at,next_attempt_at,last_error_code,attempt_count FROM foundation.outbox_events WHERE id=$1', [leased])).rows[0];
    assert(lease.lease_owner === leaseOwner && lease.lease_generation === '2147483648' && lease.lease_expires_at instanceof Date
      && lease.next_attempt_at instanceof Date && lease.last_error_code === 'HANDLER_FAILED' && lease.attempt_count === 4, 'Runtime lease writes/BIGINT failed');
    for (const status of ['EXPANDED', 'FAILED']) {
      await checkViolation(runtime, 'UPDATE foundation.outbox_events SET status=$2 WHERE id=$1', [leased, status]);
      await runtime.query('UPDATE foundation.outbox_events SET status=$2,lease_owner=NULL,lease_expires_at=NULL,last_error_code=$3 WHERE id=$1', [leased, status, status === 'FAILED' ? 'ATTEMPTS_EXHAUSTED' : null]);
      const terminal = (await runtime.query('SELECT status,lease_owner,lease_expires_at,last_error_code FROM foundation.outbox_events WHERE id=$1', [leased])).rows[0];
      assert(terminal.status === status && terminal.lease_owner === null && terminal.lease_expires_at === null
        && terminal.last_error_code === (status === 'FAILED' ? 'ATTEMPTS_EXHAUSTED' : null), 'Terminal lease/error cleanup failed');
      if (status === 'EXPANDED') {
        await runtime.query("UPDATE foundation.outbox_events SET status='PENDING',lease_owner=$2,lease_expires_at=CURRENT_TIMESTAMP+INTERVAL '30 seconds' WHERE id=$1", [leased, leaseOwner]);
      }
    }
    const privilegeDenials = [
      "UPDATE foundation.audit_logs SET operation='FORBIDDEN'", 'DELETE FROM foundation.audit_logs',
      'TRUNCATE foundation.audit_logs', 'ALTER TABLE foundation.audit_logs ADD COLUMN forbidden integer',
      'DROP TABLE foundation.audit_logs', 'SELECT * FROM foundation._prisma_migrations',
      'CREATE TABLE foundation.forbidden(id integer)', 'CREATE SCHEMA forbidden', 'CREATE TEMP TABLE forbidden(id integer)',
      'SET ROLE fixlevelup_migrator', "UPDATE foundation.outbox_events SET payload='{}'", 'DELETE FROM foundation.outbox_events',
      "UPDATE foundation.outbox_events SET event_id='00000000-0000-0000-0000-000000000000'", 'CREATE TABLE public.forbidden(id integer)',
      "UPDATE foundation.staff SET role='MANAGER'", "UPDATE foundation.staff SET employment_state='INACTIVE'",
      "UPDATE foundation.staff_web_credentials SET login='forbidden'", 'UPDATE foundation.staff SET id=id',
      'UPDATE foundation.staff_web_credentials SET staff_id=staff_id',
      ...['staff', 'staff_web_credentials', 'staff_bootstrap_marker'].flatMap((table) => [
        `INSERT INTO foundation.${table} DEFAULT VALUES`, `DELETE FROM foundation.${table}`,
      ]),
      'SELECT * FROM foundation.staff_bootstrap_marker', 'UPDATE foundation.staff_bootstrap_marker SET id=id',
      ...['web_sessions', 'web_auth_throttles', 'web_auth_attempts'].map((table) => `DELETE FROM foundation.${table}`),
      'UPDATE foundation.web_sessions SET staff_id=staff_id', 'UPDATE foundation.web_sessions SET absolute_expires_at=absolute_expires_at',
      'UPDATE foundation.web_auth_attempts SET key_hash=key_hash', 'UPDATE foundation.web_auth_attempts SET reserved_at=reserved_at',
    ];
    for (const sql of privilegeDenials) { await denied(runtime, sql); }
    console.log(`Runtime committed writes/rollback/leases, ${checkDenials} CHECK denials and ${privilegeDenials.length} privilege denials: PASS`);
  } finally { await runtime.end(); }
  console.log('P01-01.9A migration integration proofs: PASS. Test databases retained; no dev data reset.');
} catch (error) {
  console.error(`Migration proof failed: ${error.message}`);
  process.exitCode = 1;
} finally { await client.end(); }
