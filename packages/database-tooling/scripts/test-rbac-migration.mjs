import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { argon2, randomBytes, randomUUID } from 'node:crypto';

// Ephemeral synthetic values: never depend on, print or store production secrets.
export async function syntheticVerifier() {
  const salt = randomBytes(16);
  const tag = await new Promise((resolve, reject) => argon2('argon2id',{message:randomBytes(40),nonce:salt,parallelism:1,memory:19456,passes:2,tagLength:32},(error,value) => error ? reject(error) : resolve(value)));
  return ['$argon2id','v=19','m=19456,t=2,p=1',salt.toString('base64').replace(/=+$/,''),tag.toString('base64').replace(/=+$/,'')].join('$');
}

const self = ['staff.self.read', 'staff.self.update', 'staff.self.deactivate'];
const ordinary = ['staff.read', 'staff.create', 'staff.update', 'staff.deactivate'];
const protectedCodes = ['roles.create', 'roles.update', 'roles.archive', 'roles.permissions.manage', 'staff.role.assign'];

// Deliberately separate from the seed SQL: a missing, extra or mis-scoped seed fails.
export async function proveRbacCutover(client, extraCatalogOnly = []) {
  const catalog = await client.query('SELECT code,protected,active FROM foundation.permissions ORDER BY code');
  const original = [...self,...ordinary,...protectedCodes,'roles.read'];
  assert.deepEqual(catalog.rows.map((p) => p.code), [...original,...extraCatalogOnly].sort());
  assert(catalog.rows.every((p) => p.active && p.protected === protectedCodes.includes(p.code)));
  const grants = await client.query(`SELECT r.code,rp.permission_code,rp.scope_type,rp.enabled FROM foundation.roles r
    JOIN foundation.role_permissions rp ON rp.role_id=r.id WHERE r.role_type='SYSTEM' ORDER BY rp.permission_code`);
  for (const [role, codes] of [['TECHNICIAN',self], ['MANAGER',[...self,...ordinary]], ['ADMIN',original]]) {
    const rows = grants.rows.filter((row) => row.code === role);
    assert.deepEqual(rows.map((row) => row.permission_code), [...codes].sort());
    assert(rows.every((row) => row.enabled && row.scope_type === (self.includes(row.permission_code) ? 'SELF' : 'GLOBAL')));
  }
  const missing = await client.query(`SELECT s.id FROM foundation.staff s LEFT JOIN foundation.staff_role_assignments a
    ON a.staff_id=s.id AND a.revoked_at IS NULL WHERE a.id IS NULL`);
  assert.equal(missing.rowCount, 0);
  const acl = await client.query(`SELECT has_any_column_privilege('fixlevelup_runtime','foundation.user_permissions','SELECT,UPDATE,INSERT,REFERENCES') OR
    has_table_privilege('fixlevelup_runtime','foundation.user_permissions','DELETE,TRUNCATE,TRIGGER') AS allowed`);
  assert.equal(acl.rows[0].allowed,false);
  const broad = await client.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='foundation' AND c.relname IN ('roles','permissions','role_permissions','staff_role_assignments') AND
    (has_table_privilege('fixlevelup_runtime',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') OR
     has_any_column_privilege('fixlevelup_runtime',c.oid,'SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION'))`);
  assert.equal(broad.rowCount,0);
}

export async function proveRbacInvariants(client) {
  const result = await client.query(`SELECT t.tgname,t.tgenabled,t.tgdeferrable,t.tginitdeferred,p.prosecdef,p.proconfig,
    has_function_privilege('fixlevelup_runtime',p.oid,'EXECUTE') AS callable
    FROM pg_trigger t JOIN pg_proc p ON t.tgfoid=p.oid WHERE p.pronamespace='foundation'::regnamespace AND t.tgname LIKE 'rbac_%'`);
  assert.deepEqual(result.rows.map((r) => r.tgname).sort(), [
    'rbac_assignment_current','rbac_assignment_write','rbac_catalog_write','rbac_guard_catalog','rbac_credential_current','rbac_credential_removal',
    'rbac_grant_write','rbac_guard_assignment','rbac_guard_grant','rbac_guard_role','rbac_role_write','rbac_staff_current','rbac_staff_write',
  ].sort());
  assert(result.rows.every((r) => r.tgenabled === 'O' && !r.prosecdef && !r.callable && r.proconfig?.includes('search_path=pg_catalog')
    && (!r.tgname.endsWith('_current') || (r.tgdeferrable && r.tginitdeferred))));
}

// Execute the actual migration in an existing transaction on a pristine isolated
// 008 DB. A guard failure must roll back BOTH the proof fixtures and all attempted
// DDL, keeping the database at 008 so the subsequent successful cutover is real.
export async function proveRejectedUpgrade(client) {
  const actual = (await client.query('SELECT current_database() AS db')).rows[0].db;
  assert.match(actual, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  const sql = readFileSync(new URL('../../../prisma/migrations/20261120000900_rbac/migration.sql',import.meta.url),'utf8');
  for (const reason of ['missing marker','unsupported verifier','unsupported login']) {
    await client.query('BEGIN');
    const id = randomUUID();
    await client.query("INSERT INTO foundation.staff(id,role,employment_state) VALUES($1,'ADMIN','ACTIVE')",[id]);
    if (reason !== 'missing marker') {
      await client.query('INSERT INTO foundation.staff_bootstrap_marker(id,staff_id) VALUES(1,$1)',[id]);
      await client.query('INSERT INTO foundation.staff_web_credentials(staff_id,login,password_hash) VALUES($1,$2,$3)',
        [id,reason === 'unsupported login' ? 'not usable' : 'synthetic',reason === 'unsupported verifier' ? 'unsupported' : await syntheticVerifier()]);
    }
    await assert.rejects(client.query(sql), (error) => error.code === '23514' && error.message === (reason === 'missing marker'
      ? 'RBAC cutover requires verified active bootstrap administrator with web credential' : 'RBAC cutover requires supported staff web credentials'));
    await client.query('ROLLBACK');
    const after = await client.query("SELECT to_regclass('foundation.permissions') IS NULL AS clean, (SELECT count(*)::int FROM foundation.staff) AS staff");
    assert.deepEqual(after.rows[0],{clean:true,staff:0});
  }
  console.log('008→009 rejected cutovers: missing root, unsupported login/verifier; atomic rollback: PASS');
}

/** Populate an isolated pre-009 database, never a real application database. */
export async function proveEighthUpgrade(client, deploy) {
  const actual = (await client.query('SELECT current_database() AS db')).rows[0].db;
  assert.match(actual, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  const ids = Array.from({length: 7}, () => randomUUID());
  const [root,reader,manager,dual,dormant,formerAdmin,tech] = ids;
  for (const [id,role] of [[root,'ADMIN'],[reader,'MANAGER'],[manager,'MANAGER'],[dual,'MANAGER'],[dormant,'MANAGER'],[formerAdmin,'ADMIN'],[tech,'TECHNICIAN']]) {
    await client.query("INSERT INTO foundation.staff(id,role,employment_state,auth_version) VALUES($1,$2,'ACTIVE',4)", [id,role]);
  }
  await client.query("INSERT INTO foundation.staff_web_credentials(staff_id,login,password_hash) VALUES($1,'synthetic-root',$2)", [root,await syntheticVerifier()]);
  await client.query('INSERT INTO foundation.staff_bootstrap_marker(id,staff_id) VALUES(1,$1)', [root]);
  const plain = `INSERT INTO foundation.user_permissions(id,staff_id,capability,scope) VALUES(gen_random_uuid(),$1,$2,'GLOBAL')`;
  for (const id of [reader,dual,formerAdmin]) {await client.query(plain,[id,'staff.read']);}
  for (const id of [manager,dual,tech]) {await client.query(plain,[id,'staff.manage']);}
  await client.query(plain,[dormant,'roles.create']);
  await client.query(`INSERT INTO foundation.user_permissions(id,staff_id,capability,scope,valid_from,valid_until,revoked_at) VALUES
    (gen_random_uuid(),$1,'staff.read','GLOBAL',now()-interval '1 day',NULL,now()),
    (gen_random_uuid(),$1,'staff.read','GLOBAL',now()+interval '1 day',NULL,NULL),
    (gen_random_uuid(),$1,'staff.manage','GLOBAL',now()-interval '1 day',now()+interval '1 day',NULL)`, [dormant]);
  const link = randomUUID();
  await client.query('INSERT INTO foundation.staff_telegram_links(id,staff_id,telegram_user_id) VALUES($1,$2,117)',[link,tech]);
  await client.query(`INSERT INTO foundation.web_sessions(id,staff_id,auth_version,token_hash,idle_expires_at,absolute_expires_at) VALUES
    (gen_random_uuid(),$1,4,$2,now()+interval '1 hour',now()+interval '1 day')`, [root,randomBytes(32).toString('hex')]);
  await client.query(`INSERT INTO foundation.web_sessions(id,staff_id,auth_version,token_hash,idle_expires_at,absolute_expires_at,
    channel,initdata_digest,initdata_exchanged_at,telegram_link_id) VALUES
    (gen_random_uuid(),$1,4,$2,now()+interval '1 hour',now()+interval '1 day','STAFF_TELEGRAM',$3,now(),$4)`,
    [tech,randomBytes(32).toString('hex'),randomBytes(32).toString('hex'),link]);
  const legacy = await client.query('SELECT * FROM foundation.user_permissions ORDER BY id');
  deploy();
  const sessions = await client.query(`SELECT ws.channel,ws.auth_version<>s.auth_version AS stale FROM foundation.web_sessions ws JOIN foundation.staff s ON s.id=ws.staff_id ORDER BY ws.channel`);
  assert.deepEqual(sessions.rows,[{channel:'CRM',stale:true},{channel:'STAFF_TELEGRAM',stale:true}]);
  await proveRbacCutover(client);
  const staff = await client.query(`SELECT s.id,s.role,s.auth_version,r.code,r.id AS role_id FROM foundation.staff s JOIN
    foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL JOIN foundation.roles r ON r.id=a.role_id`);
  assert.equal(staff.rowCount, ids.length);
  for (const [id,expected] of [[root,'ADMIN'],[reader,1],[manager,2],[dual,3],[dormant,0],[formerAdmin,1],[tech,'TECHNICIAN']]) {
    const row = staff.rows.find((r) => r.id === id);
    const custom = typeof expected === 'number';
    assert.equal(row.code, custom ? `LEGACY_OPERATIONS_${expected}` : expected);
    assert.equal(row.role, custom ? 'MANAGER' : expected);
    assert.equal(row.auth_version,5);
    const cutoverAudit = await client.query(`SELECT details FROM foundation.audit_logs WHERE operation='RBAC_CUTOVER_ASSIGNMENT' AND details->>'staffId'=$1`, [id]);
    assert.equal(cutoverAudit.rowCount,1);
    assert.deepEqual(cutoverAudit.rows[0].details,{actor:'SYSTEM_MIGRATION_009',staffId:id,roleId:row.role_id,
      before:{channelRole:[root,formerAdmin].includes(id) ? 'ADMIN' : (id === tech ? 'TECHNICIAN' : 'MANAGER'),authVersion:4},
      after:{roleCode:row.code,channelRole:row.role,authVersion:5}});
    if (!custom) {continue;}
    const assigned = await client.query('SELECT permission_code FROM foundation.role_permissions WHERE role_id=$1 AND enabled ORDER BY permission_code', [row.role_id]);
    assert.deepEqual(assigned.rows.map((p) => p.permission_code), [...(expected & 1 ? ['staff.read'] : []),...(expected & 2 ? ['staff.create','staff.deactivate'] : [])].sort());
  }
  assert.deepEqual((await client.query('SELECT * FROM foundation.user_permissions ORDER BY id')).rows, legacy.rows);
  deploy();
  assert.equal((await client.query("SELECT FROM foundation.audit_logs WHERE operation='RBAC_CUTOVER_ASSIGNMENT'")).rowCount, ids.length);
  console.log('008→009 populated RBAC cutover: 7 explicit assignments, grants/CRM projection, audit, invalidation, replay: PASS');
}
