import { createRequire } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { win32 } from 'node:path';
import { spawnSync } from 'node:child_process';
import { admin, credentials } from './migration-local.mjs';

const { Client } = createRequire(new URL('../../../apps/api/package.json', import.meta.url))('pg');
const container = 'fixlevelup-dev-postgres';
const migrator = 'fixlevelup_migrator';
const runtime = 'fixlevelup_runtime';
const image = 'postgres:18.7-bookworm@sha256:1757c628698dd1ca67ff7a5fc386bfd91040afc62a45484c346c788b0cbe5402';
// These are the reviewed repository SQL files, not fabricated Prisma history.
const migrations = [
  ['20261120000100_technical_audit_outbox', '24d0020e30e38230a905c1fec9e8a8bf272ceb6c32ad50433a28751f389a148d'],
  ['20261120000200_technical_outbox_attempts', '44e300b03f73be0a62ad542ff787b8de93ddcb620d83d33e454e7c83cd042244'],
  ['20261120000300_technical_outbox_leases', 'ffc57bc2b4accb5a34aca2603569064c3862815d143e65a91154738e6b1f6a6d'],
];
const schemas = ['foundation', 'public', 'restore_proof'];
const tables = [
  ['foundation', 'audit_logs', 'id'], ['foundation', 'outbox_events', 'id'],
  ['restore_proof', 'object_manifest', 'key'], ['restore_proof', 'migration_evidence', 'migration_name'],
];
function assert(condition, message) { if (!condition) { throw new Error(message); } }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function canonical(value) {
  if (value instanceof Date) { return value.toISOString(); }
  if (typeof value === 'bigint') { return value.toString(); }
  if (Array.isArray(value)) { return value.map(canonical); }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}
function serialize(value) { return JSON.stringify(canonical(value)); }
function identifier(value) { return `"${value.replaceAll('"', '""')}"`; }

function validate({ suffix, directory, objects } = {}) {
  assert(typeof suffix === 'string' && /^[a-f0-9]{12}$/.test(suffix), 'Invalid drill suffix');
  const expected = `C:\\LocalAI\\fixlevelup\\backups\\p0110b-${suffix}`;
  assert(typeof directory === 'string' && win32.isAbsolute(directory) && directory === expected,
    'Drill directory must be the exact isolated Windows backup path');
  // Reject junctions/symlinks at every ancestor, including backups and the drill directory.
  let path = win32.parse(expected).root;
  for (const part of expected.slice(path.length).split('\\')) {
    path = win32.join(path, part);
    const stat = lstatSync(path);
    assert(stat.isDirectory() && !stat.isSymbolicLink(), 'Unsafe backup directory ancestor');
  }
  assert(realpathSync.native(directory).toLowerCase() === expected.toLowerCase(), 'Backup directory resolves elsewhere');
  assert(!existsSync(win32.join(directory, 'database.dump'))
    && !existsSync(win32.join(directory, 'database-evidence.json')), 'Refusing existing database artifacts');
  assert(Array.isArray(objects) && objects.length > 0 && objects.length <= 10, 'Expected 1..10 synthetic objects');
  const seen = new Set();
  const normalized = objects.map((object) => {
    assert(object !== null && typeof object === 'object' && !Array.isArray(object), 'Invalid object descriptor');
    const { key, bytes, sha256: digest, contentType, metadata } = object;
    assert(typeof key === 'string' && key.startsWith(`synthetic/restore/${suffix}/`)
      && key.length <= 512 && /^[a-zA-Z0-9/_.-]+$/.test(key)
      && key.split('/').every((part) => part !== '' && part !== '.' && part !== '..') && !seen.has(key), 'Invalid synthetic object key');
    seen.add(key);
    assert(Number.isSafeInteger(bytes) && bytes >= 0 && bytes <= 1024 * 1024, 'Invalid synthetic object size');
    assert(typeof digest === 'string' && /^[a-f0-9]{64}$/.test(digest), 'Invalid object SHA256');
    assert(typeof contentType === 'string' && contentType.length <= 128 && /^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/.test(contentType), 'Invalid content type');
    assert(metadata !== null && typeof metadata === 'object' && !Array.isArray(metadata)
      && Object.getPrototypeOf(metadata) === Object.prototype, 'Invalid object metadata');
    assert(Object.entries(metadata).length <= 20 && Object.entries(metadata).every(([keyName, value]) =>
      /^[a-z0-9][a-z0-9_-]{0,63}$/.test(keyName) && typeof value === 'string'
      && value.length <= 1024 && [...value].every((character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127)), 'Invalid synthetic metadata');
    return { key, bytes, sha256: digest, contentType, metadata: { ...metadata } };
  });
  return { suffix, directory, objects: normalized.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0) };
}

function docker(args) {
  const env = { ...process.env };
  // Use only the container's trusted local socket; never pass or inherit libpq credentials.
  for (const key of Object.keys(env)) { if (key.toUpperCase().startsWith('PG')) { delete env[key]; } }
  const result = spawnSync('docker', args, {
    encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 16 * 1024 * 1024, env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Never include raw stdout/stderr/error objects in an exception or evidence.
  assert(!result.error && result.status === 0 && !result.signal, 'Docker subprocess failed (details suppressed)');
  return result.stdout;
}
function exec(tool, args) {
  return docker(['exec', container, tool, '--host=/var/run/postgresql', '--port=5432', '-U', 'fixlevelup_dev', ...args]);
}
function verifyContainer() {
  const format = ['{{json .Name}}', '{{json .Config.Image}}', '{{json .Config.Labels}}',
    '{{json .NetworkSettings.Ports}}', '{{json .State.Running}}'].join('\n');
  const rows = docker(['inspect', '--type', 'container', '--format', format, container]).trim().split(/\r?\n/).map((row) => JSON.parse(row));
  assert(rows.length === 5 && rows[0] === `/${container}` && rows[1] === image && rows[4] === true,
    'Unexpected PostgreSQL container/image/state');
  assert(rows[2]?.['com.docker.compose.project'] === container && rows[2]?.['com.docker.compose.service'] === 'postgres',
    'Unexpected Compose identity');
  const binding = rows[3]?.['5432/tcp'];
  assert(Array.isArray(binding) && binding.length === 1 && binding[0].HostIp === '127.0.0.1'
    && binding[0].HostPort === '55432', 'Unexpected PostgreSQL port binding');
}
function connection(user, password, database, allowed) {
  assert(allowed.includes(database) && /^fixlevelup_p0110b_(?:source|restore)_[a-f0-9]{12}$/.test(database), 'Unsafe drill database');
  assert([migrator, runtime].includes(user) && /^[a-f0-9]{64}$/.test(password), 'Unsafe drill role');
  return new Client({ host: '127.0.0.1', port: 55432, user, password, database,
    connectionTimeoutMillis: 5000, statement_timeout: 15000, application_name: 'fixlevelup-p0110b-restore-proof',
    options: '-c timezone=UTC -c datestyle=ISO,YMD',
  });
}
async function open(user, password, database, allowed) {
  const client = connection(user, password, database, allowed);
  try {
    await client.connect();
    const { rows } = await client.query("SELECT current_database() AS db,current_user AS role,current_setting('server_version_num')::int AS version");
    assert(rows[0].db === database && rows[0].role === user && rows[0].version === 180007, 'Unexpected drill connection identity');
    return client;
  } catch (error) { await client.end().catch(() => {}); throw error; }
}
async function transaction(client, body, commit = true) {
  await client.query('BEGIN');
  try {
    const result = await body();
    await client.query(commit ? 'COMMIT' : 'ROLLBACK');
    return result;
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
}

async function prepare(adminClient, database, passwords, allowed) {
  await adminClient.query(`CREATE DATABASE ${identifier(database)} OWNER ${migrator} TEMPLATE template0`);
  await adminClient.query(`REVOKE ALL ON DATABASE ${identifier(database)} FROM PUBLIC`);
  await adminClient.query(`GRANT CONNECT ON DATABASE ${identifier(database)} TO ${migrator}, ${runtime}`);
  const client = await open(migrator, passwords[migrator], database, allowed);
  try { await client.query('REVOKE CREATE ON SCHEMA public FROM PUBLIC'); }
  finally { await client.end(); }
}
async function applyMigrations(client, reviewed) {
  for (const entry of reviewed) { await client.query(entry.sql); }
  await transaction(client, async () => {
    await client.query(`CREATE SCHEMA restore_proof AUTHORIZATION ${migrator}`);
    await client.query('REVOKE ALL ON SCHEMA restore_proof FROM PUBLIC');
    await client.query(`CREATE TABLE restore_proof.migration_evidence (
      migration_name text PRIMARY KEY, source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
      application_method text NOT NULL CHECK (application_method = 'reviewed_sql_not_prisma_deploy')
    )`);
    for (const entry of reviewed) {
      await client.query('INSERT INTO restore_proof.migration_evidence VALUES($1,$2,$3)',
        [entry.name, entry.sha256, 'reviewed_sql_not_prisma_deploy']);
    }
    await client.query(`CREATE TABLE restore_proof.object_manifest (
      key text PRIMARY KEY, size bigint NOT NULL CHECK (size BETWEEN 0 AND 1048576),
      sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'), content_type text NOT NULL, metadata jsonb NOT NULL
    )`);
    await client.query('REVOKE ALL ON ALL TABLES IN SCHEMA restore_proof FROM PUBLIC');
    await client.query(`GRANT USAGE ON SCHEMA restore_proof TO ${runtime}`);
    await client.query(`GRANT SELECT ON restore_proof.object_manifest TO ${runtime}`);
  });
}
async function seed(owner, writer, objects) {
  await transaction(owner, async () => {
    for (const object of objects) {
      await owner.query('INSERT INTO restore_proof.object_manifest(key,size,sha256,content_type,metadata) VALUES($1,$2,$3,$4,$5)',
        [object.key, object.bytes, object.sha256, object.contentType, object.metadata]);
    }
  });
  const references = objects.map(({ key, bytes, sha256: digest }) => ({ key, bytes, sha256: digest }));
  const committed = [];
  async function pair(id, status, index) {
    const payload = { synthetic: true, objects: references, fixture: index };
    await writer.query(`INSERT INTO foundation.audit_logs(id,operation,correlation_id,occurred_at,details)
      VALUES($1,'SYNTHETIC_RESTORE',$1,'2000-01-02T03:04:05.123456Z',$2)`, [id, payload]);
    await writer.query(`INSERT INTO foundation.outbox_events
      (id,event_id,event_type,created_at,status,payload,attempt_count,lease_generation,next_attempt_at,last_error_code)
      VALUES($1,$1,'SYNTHETIC_RESTORE','2000-01-02T03:04:05.654321Z',$2,$3,$4,$5,'2099-01-01T00:00:00Z',$6)`,
    [id, status, payload, index, index === 3 ? '9007199254740993' : String(index), status === 'FAILED' ? 'ATTEMPTS_EXHAUSTED' : null]);
    if (index === 3) {
      // Deliberately expired, never an active/future recovered claim. Due time remains in the future.
      await writer.query("UPDATE foundation.outbox_events SET lease_owner=$2,lease_expires_at='2000-01-01T00:00:00.000001Z' WHERE id=$1", [id, randomUUID()]);
    }
  }
  await transaction(writer, async () => {
    for (const [index, status] of ['PENDING', 'EXPANDED', 'FAILED', 'PENDING'].entries()) {
      const id = randomUUID(); committed.push(id); await pair(id, status, index);
    }
  });
  const rolledBack = randomUUID();
  await transaction(writer, () => pair(rolledBack, 'PENDING', 0), false);
  const result = await writer.query(`SELECT (SELECT count(*)::int FROM foundation.audit_logs WHERE id=$1) AS audit,
    (SELECT count(*)::int FROM foundation.outbox_events WHERE id=$1) AS outbox,
    (SELECT count(*)::int FROM foundation.audit_logs) AS total_audit,
    (SELECT count(*)::int FROM foundation.outbox_events) AS total_outbox`, [rolledBack]);
  assert(result.rows[0].audit === 0 && result.rows[0].outbox === 0
    && result.rows[0].total_audit === 4 && result.rows[0].total_outbox === 4, 'Synthetic commit/rollback fixture mismatch');
  return { committed, rolledBack };
}

async function snapshot(client) {
  const result = {};
  for (const [schema, table, key] of tables) {
    const qualified = `${identifier(schema)}.${identifier(table)}`;
    const { rows } = await client.query(`SELECT a.attname, t.typname FROM pg_attribute a
      JOIN pg_type t ON t.oid=a.atttypid WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`, [qualified]);
    assert(rows.length > 0, 'Missing snapshot table');
    // Read every column. Preserve TIMESTAMPTZ(6) microseconds and BIGINT beyond JS safe integers.
    const columns = rows.map(({ attname, typname }) => {
      const name = identifier(attname);
      if (typname === 'timestamptz') { return `to_char(${name} AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ${name}`; }
      if (typname === 'int8') { return `${name}::text AS ${name}`; }
      return name;
    });
    const order = key === 'id' ? identifier(key) : `${identifier(key)} COLLATE "C"`;
    result[`${schema}.${table}`] = (await client.query(`SELECT ${columns.join(',')} FROM ${qualified} ORDER BY ${order}`)).rows;
  }
  return canonical(result);
}

async function catalog(client) {
  const queries = {
    schemas: `SELECT nspname AS name,pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname=ANY($1) ORDER BY nspname`,
    tables: `SELECT n.nspname AS schema,c.relname AS name,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,
      c.reloptions,pg_get_userbyid(c.relowner) AS owner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname=ANY($1) ORDER BY n.nspname,c.relname`,
    columns: `SELECT n.nspname AS schema,c.relname AS table_name,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod) AS type,
      a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid) AS default_expression,co.collname AS collation
      FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum LEFT JOIN pg_collation co ON co.oid=a.attcollation
      WHERE n.nspname=ANY($1) AND a.attnum>0 AND NOT a.attisdropped ORDER BY n.nspname,c.relname,a.attnum`,
    constraints: `SELECT n.nspname AS schema,c.relname AS table_name,k.conname,k.contype,k.convalidated,k.condeferrable,k.condeferred,
      pg_get_constraintdef(k.oid,true) AS definition FROM pg_constraint k JOIN pg_namespace n ON n.oid=k.connamespace
      LEFT JOIN pg_class c ON c.oid=k.conrelid WHERE n.nspname=ANY($1) ORDER BY n.nspname,c.relname,k.conname`,
    indexes: `SELECT n.nspname AS schema,c.relname AS name,i.indisvalid,i.indisready,i.indisunique,i.indisprimary,
      pg_get_indexdef(i.indexrelid) AS definition FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
      JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($1) ORDER BY n.nspname,c.relname`,
    grants: `SELECT * FROM (
      SELECT 'schema' AS kind,n.nspname AS schema,n.nspname AS object_name,'' AS column_name,
        pg_get_userbyid(x.grantor) AS grantor,CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END AS grantee,x.privilege_type,x.is_grantable
        FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) x WHERE n.nspname=ANY($1)
      UNION ALL SELECT 'relation',n.nspname,c.relname,'',pg_get_userbyid(x.grantor),
        CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,x.privilege_type,x.is_grantable
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) x
        WHERE n.nspname=ANY($1) AND c.relkind IN ('r','p','v','m','S','f')
      UNION ALL SELECT 'column',n.nspname,c.relname,a.attname,pg_get_userbyid(x.grantor),
        CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,x.privilege_type,x.is_grantable
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE n.nspname=ANY($1) AND a.attnum>0 AND NOT a.attisdropped
      ) g ORDER BY kind,schema,object_name,column_name,grantor,grantee,privilege_type,is_grantable`,
    default_grants: `SELECT pg_get_userbyid(d.defaclrole) AS owner,coalesce(n.nspname,'') AS schema,d.defaclobjtype,
      pg_get_userbyid(x.grantor) AS grantor,CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END AS grantee,
      x.privilege_type,x.is_grantable FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
      CROSS JOIN LATERAL aclexplode(d.defaclacl) x WHERE n.nspname=ANY($1) OR d.defaclnamespace=0
      ORDER BY owner,schema,d.defaclobjtype,grantor,grantee,x.privilege_type,x.is_grantable`,
  };
  const result = {};
  for (const [name, sql] of Object.entries(queries)) { result[name] = (await client.query(sql, [schemas])).rows; }
  // Database names/OIDs deliberately excluded: compare semantic identity/ACL, not their different names.
  result.database = (await client.query(`SELECT pg_get_userbyid(datdba) AS owner,pg_encoding_to_char(encoding) AS encoding,
    datlocprovider,datcollate,datctype,datlocale,datallowconn,datconnlimit FROM pg_database WHERE datname=current_database()`)).rows;
  result.database_grants = (await client.query(`SELECT pg_get_userbyid(x.grantor) AS grantor,
    CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END AS grantee,x.privilege_type,x.is_grantable
    FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) x
    WHERE d.datname=current_database() ORDER BY grantor,grantee,x.privilege_type,x.is_grantable`)).rows;
  return canonical(result);
}
function schemaDump(database) {
  const raw = exec('pg_dump', ['-d', database, '--schema-only']);
  // pg_dump 18 emits random \restrict tokens. Comments/empty lines are not schema semantics.
  return raw.split(/\r?\n/).filter((line) => !line.startsWith('--') && !/^\\(?:un)?restrict(?:\s|$)/.test(line)
    && line.trim() !== '').join('\n') + '\n';
}
// PostgreSQL 18.7's dump/reparse moves an ARRAY::text[] coercion onto each
// varchar literal. Restore only these two reviewed CHECKs to their exact original
// expression form; do not normalize arbitrary expressions or weaken comparison.
async function restoreReviewedChecks(client, target, sourceCatalog) {
  assert(/^fixlevelup_p0110b_restore_[a-f0-9]{12}$/.test(target), 'Unsafe constraint repair target');
  const specs = [
    { name: 'outbox_events_status_check', column: 'status', values: ['PENDING', 'EXPANDED', 'FAILED'] },
    { name: 'outbox_events_last_error_code_check', column: 'last_error_code', values: ['HANDLER_FAILED', 'ATTEMPTS_EXHAUSTED'] },
  ].map((spec) => ({ ...spec,
    original: `CHECK (${spec.column}::text = ANY (ARRAY[${spec.values.map((value) => `'${value}'::character varying`).join(', ')}]::text[]))`,
    roundtrip: `CHECK (${spec.column}::text = ANY (ARRAY[${spec.values.map((value) => `'${value}'::character varying::text`).join(', ')}]))`,
    expression: `"${spec.column}" IN (${spec.values.map((value) => `'${value}'`).join(', ')})`,
  }));
  const restoredBefore = await catalog(client);
  const guardedCatalog = structuredClone(restoredBefore);
  for (const spec of specs) {
    const sourceRow = sourceCatalog.constraints.find((row) => row.schema === 'foundation'
      && row.table_name === 'outbox_events' && row.conname === spec.name);
    const targetRow = guardedCatalog.constraints.find((row) => row.schema === 'foundation'
      && row.table_name === 'outbox_events' && row.conname === spec.name);
    assert(sourceRow?.definition === spec.original && targetRow?.definition === spec.roundtrip,
      'Unexpected reviewed constraint definition before repair');
    targetRow.definition = spec.original;
  }
  assert(serialize(sourceCatalog) === serialize(guardedCatalog), 'Unexpected catalog drift before reviewed constraint repair');
  await transaction(client, async () => {
    const identity = (await client.query('SELECT current_database() AS db,current_user AS role')).rows[0];
    assert(identity.db === target && identity.role === migrator, 'Unexpected constraint repair connection');
    await client.query('LOCK TABLE foundation.outbox_events IN ACCESS EXCLUSIVE MODE');
    for (const spec of specs) {
      const current = (await client.query(`SELECT pg_get_constraintdef(oid,true) AS definition
        FROM pg_constraint WHERE conrelid='foundation.outbox_events'::regclass AND conname=$1`, [spec.name])).rows;
      assert(current.length === 1 && current[0].definition === spec.roundtrip, 'Constraint changed before reviewed repair');
      // Narrow target-only replacement: no database/table cleanup, no CASCADE, and
      // validated ADD must accept every restored row before this transaction commits.
      await client.query(`ALTER TABLE foundation.outbox_events DROP CONSTRAINT ${identifier(spec.name)},
        ADD CONSTRAINT ${identifier(spec.name)} CHECK (${spec.expression})`);
    }
    assert(serialize(sourceCatalog) === serialize(await catalog(client)), 'Reviewed constraint repair did not restore exact catalog');
  });
  return { names: specs.map(({ name }) => name), beforeCatalogSha256: sha256(serialize(restoredBefore)),
    afterCatalogSha256: sha256(serialize(sourceCatalog)),
    reason: 'PostgreSQL 18.7 pg_dump reparse changes varchar-array cast representation; exact reviewed CHECK definitions reapplied transactionally on isolated target only' };
}
async function denied(client, sql) {
  let code;
  await transaction(client, async () => {
    try { await client.query(sql); } catch (error) { code = error.code; }
  }, false);
  assert(code === '42501', 'Runtime privilege denial was not insufficient_privilege');
}
async function proveRuntime(client, fixtures, expectedObjects) {
  const audit = await client.query('SELECT * FROM foundation.audit_logs ORDER BY id');
  const outbox = await client.query('SELECT * FROM foundation.outbox_events ORDER BY id');
  const manifest = await client.query('SELECT key,size::text,sha256,content_type,metadata FROM restore_proof.object_manifest ORDER BY key COLLATE "C"');
  assert(audit.rowCount === 4 && outbox.rowCount === 4 && manifest.rowCount === expectedObjects.length,
    'Runtime restored SELECT/count mismatch');
  assert(fixtures.committed.every((id) => audit.rows.some((row) => row.id === id) && outbox.rows.some((row) => row.id === id))
    && !audit.rows.some((row) => row.id === fixtures.rolledBack) && !outbox.rows.some((row) => row.id === fixtures.rolledBack),
    'Runtime commit/rollback evidence mismatch');
  assert(serialize(manifest.rows) === serialize(expectedObjects.map((object) => ({ key: object.key, size: String(object.bytes),
    sha256: object.sha256, content_type: object.contentType, metadata: object.metadata }))), 'Runtime object manifest differs');
  const id = fixtures.committed[0];
  const before = (await client.query('SELECT * FROM foundation.outbox_events WHERE id=$1', [id])).rows;
  await transaction(client, async () => {
    const changed = await client.query(`UPDATE foundation.outbox_events SET status='PENDING',attempt_count=2,
      lease_owner=$2,lease_generation=9007199254740994,lease_expires_at='2001-01-01T00:00:00Z',
      next_attempt_at='2099-02-01T00:00:00Z',last_error_code='HANDLER_FAILED' WHERE id=$1
      RETURNING status,attempt_count,lease_owner,lease_generation::text,lease_expires_at,next_attempt_at,last_error_code`, [id, randomUUID()]);
    assert(changed.rowCount === 1 && changed.rows[0].lease_generation === '9007199254740994'
      && changed.rows[0].last_error_code === 'HANDLER_FAILED', 'Runtime worker-field UPDATE failed');
  }, false);
  assert(serialize(before) === serialize((await client.query('SELECT * FROM foundation.outbox_events WHERE id=$1', [id])).rows),
    'Runtime worker UPDATE rollback failed');
  // Both re-applied CHECKs must still reject invalid rows, including on restore.
  for (const [field, invalid] of [['status', 'INVALID'], ['last_error_code', 'INVALID']]) {
    let code;
    await transaction(client, async () => {
      try { await client.query(`UPDATE foundation.outbox_events SET ${identifier(field)}=$2 WHERE id=$1`, [id, invalid]); }
      catch (error) { code = error.code; }
    }, false);
    assert(code === '23514', 'Reviewed outbox CHECK did not reject invalid runtime row');
  }
  const attempts = [
    "UPDATE foundation.audit_logs SET operation='FORBIDDEN'", 'DELETE FROM foundation.audit_logs',
    'ALTER TABLE foundation.audit_logs ADD COLUMN forbidden integer', 'CREATE TABLE foundation.forbidden(id integer)',
    'CREATE TABLE public.forbidden(id integer)', 'CREATE SCHEMA forbidden', 'CREATE TEMP TABLE forbidden(id integer)',
    'SELECT * FROM restore_proof.migration_evidence', `SET ROLE ${migrator}`, 'SET ROLE fixlevelup_dev',
    "UPDATE foundation.outbox_events SET payload='{}'", 'DELETE FROM foundation.outbox_events',
    "UPDATE restore_proof.object_manifest SET metadata='{}'",
  ];
  for (const sql of attempts) { await denied(client, sql); }
  return attempts.length;
}

/** Synthetic-only, retained-database backup/restore drill. Importing this module performs no work. */
export async function databaseDrill(input) {
  // Validation is outside the redaction boundary so callers can correct safe input errors.
  const { suffix, directory, objects } = validate(input);
  const source = `fixlevelup_p0110b_source_${suffix}`;
  const target = `fixlevelup_p0110b_restore_${suffix}`;
  const allowed = [source, target];
  const dumpPath = win32.join(directory, 'database.dump');
  const containerDump = `/tmp/fixlevelup-p0110b-${suffix}.dump`;
  const clients = [];
  let stage = 'preflight';
  try {
    const reviewed = migrations.map(([name, digest]) => {
      const sqlBytes = readFileSync(new URL(`../../../prisma/migrations/${name}/migration.sql`, import.meta.url));
      assert(sha256(sqlBytes) === digest, 'Reviewed migration checksum changed');
      return { name, sha256: digest, sql: sqlBytes.toString('utf8') };
    });
    const passwords = credentials(); // ignored local role env; never create/rotate credentials
    verifyContainer();
    docker(['exec', container, 'test', '!', '-e', containerDump]);
    docker(['exec', container, 'test', '!', '-e', `/tmp/fixlevelup-p0110b-${suffix}-restore.dump`]);
    const adminClient = await admin(); clients.push(adminClient);
    const identity = (await adminClient.query('SELECT system_identifier::text AS id FROM pg_control_system()')).rows[0].id;
    const socketIdentity = exec('psql', ['-d', 'fixlevelup_dev', '-X', '-A', '-t', '--set=ON_ERROR_STOP=1', '-c',
      "SELECT current_setting('server_version_num') || ':' || system_identifier::text FROM pg_control_system()"] ).trim();
    assert(socketIdentity === `180007:${identity}`, 'Docker socket and TCP server identities differ');
    const roles = (await adminClient.query(`SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit
      FROM pg_roles WHERE rolname=ANY($1) ORDER BY rolname`, [[migrator, runtime]])).rows;
    assert(roles.length === 2 && roles.every((role) => role.rolcanlogin && !role.rolsuper && !role.rolcreatedb
      && !role.rolcreaterole && !role.rolreplication && !role.rolbypassrls && !role.rolinherit), 'Unsafe technical role flags');
    assert((await adminClient.query('SELECT 1 FROM pg_auth_members WHERE member IN (SELECT oid FROM pg_roles WHERE rolname=ANY($1))',
      [[migrator, runtime]])).rowCount === 0, 'Unexpected technical role memberships');
    assert((await adminClient.query('SELECT 1 FROM pg_database WHERE datname=ANY($1)', [allowed])).rowCount === 0,
      'Refusing preexisting drill databases');
    // No dev DDL/data changes: admin's dev connection only creates these two fresh databases and their ACLs.
    stage = 'create-isolated-databases';
    for (const database of allowed) { await prepare(adminClient, database, passwords, allowed); }
    const sourceOwner = await open(migrator, passwords[migrator], source, allowed); clients.push(sourceOwner);
    const sourceRuntime = await open(runtime, passwords[runtime], source, allowed); clients.push(sourceRuntime);
    stage = 'reviewed-migrations-and-synthetic-fixtures';
    await applyMigrations(sourceOwner, reviewed);
    const fixtures = await seed(sourceOwner, sourceRuntime, objects);
    let denials = await proveRuntime(sourceRuntime, fixtures, objects);
    const beforeData = await snapshot(sourceOwner);
    const beforeCatalog = await catalog(sourceOwner);
    const beforeSchema = schemaDump(source);
    stage = 'custom-dump-and-copy';
    exec('pg_dump', ['-d', source, '-Fc', '-f', containerDump]);
    docker(['cp', `${container}:${containerDump}`, dumpPath]);
    const dumpStat = lstatSync(dumpPath);
    assert(dumpStat.isFile() && !dumpStat.isSymbolicLink() && dumpStat.size > 0 && dumpStat.size <= 64 * 1024 * 1024, 'Invalid dump artifact');
    const dumpSha256 = sha256(readFileSync(dumpPath));
    stage = 'restore-preserving-owners-and-acls';
    // Restore the actual host backup artifact, not the original container-side source dump.
    const restoreDump = `/tmp/fixlevelup-p0110b-${suffix}-restore.dump`;
    assert(sha256(readFileSync(dumpPath)) === dumpSha256, 'Host backup checksum changed before restore');
    docker(['cp', dumpPath, `${container}:${restoreDump}`]);
    const copiedDigest = docker(['exec', container, 'sha256sum', restoreDump]).trim().split(/\s+/)[0];
    assert(copiedDigest === dumpSha256 && sha256(readFileSync(dumpPath)) === dumpSha256,
      'Copied restore artifact checksum differs');
    // No --clean, --no-owner, --no-acl, role rewrites, globals, or password arguments.
    exec('pg_restore', ['-d', target, '--exit-on-error', restoreDump]);
    const targetOwner = await open(migrator, passwords[migrator], target, allowed); clients.push(targetOwner);
    stage = 'restore-exact-reviewed-check-definitions';
    const constraintCanonicalization = await restoreReviewedChecks(targetOwner, target, beforeCatalog);
    const targetRuntime = await open(runtime, passwords[runtime], target, allowed); clients.push(targetRuntime);
    stage = 'canonical-comparison-and-runtime-proof';
    const restoredData = await snapshot(targetOwner);
    const restoredCatalog = await catalog(targetOwner);
    const restoredSchema = schemaDump(target);
    assert(serialize(beforeData) === serialize(restoredData), 'Complete restored table snapshots differ');
    assert(serialize(beforeCatalog) === serialize(restoredCatalog), 'Restored owner/ACL/schema catalog differs');
    assert(beforeSchema === restoredSchema, 'Normalized schema-only dumps differ');
    denials += await proveRuntime(targetRuntime, fixtures, objects);
    assert(serialize(beforeData) === serialize(await snapshot(sourceOwner))
      && serialize(restoredData) === serialize(await snapshot(targetOwner)), 'Runtime proofs changed fixture data');
    const result = { source, target, dumpSha256, dataSha256: sha256(serialize(beforeData)),
      catalogSha256: sha256(serialize(beforeCatalog)), objects: objects.length, denials };
    stage = 'write-redacted-evidence';
    writeFileSync(win32.join(directory, 'database-evidence.json'), JSON.stringify({
      ...result, protocol: 'P01-01.10B', syntheticOnly: true, databasesRetained: true,
      serverVersion: '18.7', container, composeProject: container,
      applicationMethod: 'reviewed_sql_not_prisma_deploy',
      migrations: reviewed.map(({ name, sha256: digest }) => ({ name, sourceSha256: digest })),
      constraintCanonicalization,
      schemaSha256: sha256(beforeSchema), comparisons: { completeData: true, catalogAndAcls: true,
        normalizedSchemaOnly: true, databaseAclSemantic: true },
      fixtures: { committedPairs: fixtures.committed.length, rollbackPairsAbsent: true,
        statuses: ['PENDING', 'EXPANDED', 'FAILED'], bigintAboveSafeInteger: true,
        expiredSyntheticLeaseOnly: true, futureNextAttempt: true, workerUpdateRolledBack: true,
        reviewedCheckInvalidRowsRejected: { sqlstate: '23514', checksPerDatabase: 2, databases: 2 } },
      tableRows: Object.fromEntries(Object.entries(beforeData).map(([name, rows]) => [name, rows.length])),
    }, null, 2) + '\n', { flag: 'wx' });
    return result;
  } catch (error) {
    const safeReasons = ['Complete restored table snapshots differ', 'Restored owner/ACL/schema catalog differs', 'Normalized schema-only dumps differ', 'Runtime object manifest differs', 'Runtime proofs changed fixture data', 'Docker subprocess failed (details suppressed)'];
    if (safeReasons.includes(error?.message)) { console.error(`Database restore diagnostic: ${error.message}`); }
    // Raw driver/CLI causes may contain local credentials; emit only safe stage.
    // eslint-disable-next-line preserve-caught-error
    throw new Error(`Database restore drill failed at ${stage}; details suppressed; isolated databases/artifacts retained (${source}, ${target})`);
  } finally {
    for (const client of clients.reverse()) { await client.query('ROLLBACK').catch(() => {}); await client.end().catch(() => {}); }
  }
}
