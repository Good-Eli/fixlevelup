/**
 * Shared isolated operator/launcher fixture for the P03-05 and P04-04 HTTPS
 * browser proofs (docs/P05-PLAN.md §7, S0 launch contract).
 *
 * It provides three things to both smoke runners and nothing else:
 *  1. the pinned S0 cap: the reviewed 21-migration prefix of the current chain
 *     (the 022–024 P05 migrations are excluded and reported, never hidden);
 *  2. a disposable control contour (separate database + narrow launcher role)
 *     created by the reviewed `ensureLaunchRegistry` module;
 *  3. one real guarded launch: a witness held on the application database, a
 *     signed one-time proof issued into the control registry, the production
 *     `superviseLaunch` owning the child's private IPC channel, and the real
 *     CAS consumption. No launch algorithm is reimplemented here — the launcher,
 *     registry, control-contour, proof and witness modules are the reviewed
 *     production sources, compiled from this image's own tree into an ephemeral
 *     scratch output because the release build deliberately excludes them.
 */
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const apiPackage = new URL('../../apps/api/package.json', import.meta.url);
const apiRequire = createRequire(apiPackage);
export const { Client, Pool } = apiRequire('pg');

export const host = '127.0.0.1';
export const pgPort = 55432;
export const token = () => randomBytes(32).toString('hex');
export const isToken = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);
export const isUuid = (value) => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(value);

/** The S0 launch contract: no P05 migration is applied, so no P05 grant exists. */
export const PROOF_PROFILE = 'S0';
/** The exact pinned PostgreSQL version the isolated cluster must report. */
export const SERVER_VERSION_NUM = '180007';
export const CONTROL_DATABASE = /^fixlevelup_p05_control_[a-f0-9]{12}$/u;
export const LAUNCHER_ROLE = /^fixlevelup_p05_launcher_[a-f0-9]{12}$/u;

const migrationsRoot = new URL('../../prisma/migrations/', import.meta.url);
const pinManifest = new URL('../p0404-browser-smoke/SHA256SUMS', import.meta.url);
const apiRoot = new URL('../../apps/api/', import.meta.url);

/** Reviewed S0 physical-profile predicates (apps/api/tests/admission-fixture.ts). */
const S0_PREDICATES = Object.freeze(['legacy.ready', 'catalog.management.ready',
  'preIntakeProfileAbsent', 'formSessionProfileAbsent']);

/**
 * The reviewed P05 migrations the S0 cap excludes. They must be present in the
 * tree and must be EXACTLY these three: an unknown, renamed or reordered layer
 * is not something this smoke is allowed to skip silently.
 */
export const EXCLUDED_P05_MIGRATIONS = Object.freeze([
  '20261123000100_request_intake_foundation',
  '20261124000100_form_session_foundation',
  '20261125000100_request_intake_effects',
]);
const PINNED_COUNT = 21;
const EXACT_CHAIN_LENGTH = PINNED_COUNT + EXCLUDED_P05_MIGRATIONS.length;
const migrationName = /^\d{14}_[a-z0-9_]+$/u;

/**
 * Pure validation of the migration inventory. Refuses any chain that is not
 * EXACTLY the pinned 21-migration S0 prefix followed by EXACTLY the three
 * reviewed P05 migrations, in order. No filesystem access, so the regression
 * check can exercise it with synthetic chains.
 */
export function validateInventory(chain, pins) {
  if (!Array.isArray(pins) || pins.length !== PINNED_COUNT) {
    throw new Error('Invalid pinned S0 migration manifest');
  }
  for (const pin of pins) {
    if (typeof pin?.name !== 'string' || !migrationName.test(pin.name)
      || typeof pin?.checksum !== 'string' || !/^[a-f0-9]{64}$/u.test(pin.checksum)) {
      throw new Error('Invalid pinned S0 migration entry');
    }
  }
  if (!Array.isArray(chain) || chain.length !== EXACT_CHAIN_LENGTH) {
    throw new Error(`Migration chain must be exactly ${String(EXACT_CHAIN_LENGTH)} directories`);
  }
  for (const name of chain) {
    if (typeof name !== 'string' || !migrationName.test(name)) {
      throw new Error('Unexpected migration directory in the chain');
    }
  }
  const sorted = [...chain].sort();
  if (sorted.join() !== chain.join()) { throw new Error('Migration chain is not sorted'); }
  for (const [index, pin] of pins.entries()) {
    if (chain[index] !== pin.name) { throw new Error('Pinned S0 prefix does not match the migration chain'); }
  }
  const excluded = chain.slice(PINNED_COUNT);
  if (excluded.join() !== EXCLUDED_P05_MIGRATIONS.join()) {
    throw new Error('Migration chain suffix is not exactly the reviewed P05 migrations');
  }
  return Object.freeze({ pins: Object.freeze([...pins]), chain: Object.freeze([...chain]),
    excluded: Object.freeze(excluded) });
}

let inventory;

/**
 * The exact migration inventory: the real chain, the pinned 21-entry S0 prefix
 * with its byte checksums, and the explicitly excluded reviewed P05 suffix.
 * Any prefix, length, ordering or checksum drift refuses before a database is
 * touched.
 */
export function migrationInventory() {
  inventory ??= (async () => {
    const manifest = await readFile(pinManifest, 'utf8');
    const lines = manifest.replaceAll('\r\n', '\n').split('\n');
    if (lines.pop() !== '') { throw new Error('Invalid pinned S0 migration manifest'); }
    const pins = lines.map((line) => {
      const match = /^([a-f0-9]{64}) {2}(\d{14}_[a-z0-9_]+)\/migration\.sql$/u.exec(line);
      if (!match || match[0] !== line) { throw new Error('Invalid pinned S0 migration entry'); }
      return Object.freeze({ name: match[2], checksum: match[1] });
    });
    const chain = (await readdir(migrationsRoot, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    const plan = validateInventory(chain, pins);
    const scripts = [];
    for (const pin of plan.pins) {
      const sql = await readFile(new URL(`${pin.name}/migration.sql`, migrationsRoot), 'utf8');
      if (createHash('sha256').update(sql.replaceAll('\r\n', '\n')).digest('hex') !== pin.checksum) {
        throw new Error('Pinned S0 migration digest drift');
      }
      scripts.push(sql);
    }
    return Object.freeze({ pins: plan.pins, chain: plan.chain, excluded: plan.excluded,
      scripts: Object.freeze(scripts) });
  })();
  return inventory;
}

/**
 * Pure validation of REAL `foundation._prisma_migrations` rows against the
 * pinned S0 manifest: exactly one completed, non-rolled-back, single-step row
 * per pinned migration, in sorted order, with the pinned checksum. Returns the
 * ordered history digest the proof carries. Any deviation throws — the digest
 * is never produced for an unverified history. Shared by the provisioning
 * apply and by the witness-backend re-proof so both use one validator.
 */
export function historyDigestOf(rows, pins) {
  if (!Array.isArray(pins) || pins.length !== PINNED_COUNT) { throw new Error('Invalid pinned S0 migration manifest'); }
  if (!Array.isArray(rows) || rows.length !== pins.length) { throw new Error('Unexpected migration history length'); }
  const entries = [];
  for (const [index, pin] of pins.entries()) {
    const row = rows[index];
    if (row === undefined || row === null
      || row.migration_name !== pin.name || row.checksum !== pin.checksum
      || !(row.finished_at instanceof Date) || row.rolled_back_at !== null
      || row.applied_steps_count !== 1) {
      throw new Error('Unexpected migration history');
    }
    entries.push(`${String(row.migration_name)}:${String(row.checksum)}`);
  }
  return createHash('sha256').update(entries.join('\n'), 'utf8').digest('hex');
}

/**
 * Applies exactly the pinned prefix as the migrator and writes the real Prisma
 * history rows (one completed, non-rolled-back record per migration with the
 * pinned checksum). `prisma migrate deploy` cannot be used: it would apply the
 * whole chain, including the excluded P05 migrations.
 */
export async function applyCappedMigrations(migrator, pinned = undefined) {
  const plan = pinned ?? await migrationInventory();
  await migrator.query(`CREATE TABLE IF NOT EXISTS foundation._prisma_migrations (
    id text PRIMARY KEY,
    checksum varchar(64) NOT NULL,
    finished_at timestamptz,
    migration_name varchar(255) NOT NULL,
    logs text,
    rolled_back_at timestamptz,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    applied_steps_count integer NOT NULL DEFAULT 1
  )`);
  for (const [index, pin] of plan.pins.entries()) {
    // Each reviewed migration script carries its own BEGIN;...COMMIT; block,
    // exactly as the Prisma runner executes it.
    await migrator.query(plan.scripts[index]);
    await migrator.query(`INSERT INTO foundation._prisma_migrations
      (id, checksum, finished_at, migration_name, rolled_back_at, applied_steps_count)
      VALUES ($1, $2, clock_timestamp(), $3, NULL, 1)`, [randomUUID(), pin.checksum, pin.name]);
  }
  const rows = (await migrator.query(`SELECT migration_name, checksum, finished_at, rolled_back_at,
    applied_steps_count FROM foundation._prisma_migrations ORDER BY migration_name ASC`)).rows;
  return Object.freeze({ applied: plan.pins.length, chain: plan.chain.length, excluded: plan.excluded,
    historyManifestDigest: historyDigestOf(rows, plan.pins) });
}

/**
 * Pure verdict for the witness-backend identity facts. Split out so the exact
 * refusal rules can be regression-checked with synthetic rows (no database):
 * a single mismatched fact refuses, and nothing is signed or spawned.
 */
export function witnessBoundaryVerdict(identity, expected) {
  const mismatch = (reason) => ({ ok: false, reason });
  if (typeof identity !== 'object' || identity === null) { return mismatch('IDENTITY_MISSING'); }
  if (identity.database_ok !== true) { return mismatch('DATABASE'); }
  if (identity.database_oid !== String(expected.databaseOid)) { return mismatch('DATABASE_OID'); }
  if (identity.user_ok !== true || identity.session_ok !== true) { return mismatch('ROLE'); }
  if (identity.schema !== expected.schema) { return mismatch('SCHEMA'); }
  if (identity.backend_pid !== String(expected.witnessPid)) { return mismatch('BACKEND_PID'); }
  if (identity.server_addr !== expected.host || identity.client_addr !== expected.host
    || identity.server_port !== expected.port) { return mismatch('LOOPBACK'); }
  if (identity.listen_addresses !== expected.host) { return mismatch('LISTEN'); }
  if (identity.server_version_num !== expected.serverVersionNum) { return mismatch('SERVER_VERSION'); }
  if (identity.primary !== true) { return mismatch('NOT_PRIMARY'); }
  if (identity.own_witness_lock !== 1) { return mismatch('WITNESS_LOCK'); }
  return { ok: true, reason: undefined };
}

/**
 * Re-proves, ON THE WITNESS BACKEND ITSELF, the exact facts the proof is about
 * to assert: this is the same connection that holds the session advisory lock,
 * so the database/OID/role/loopback/primary identity and the pinned S0 history
 * digest are read from the backend whose pid the child will be pinned to. Runs
 * BEFORE signing/issuing the proof and before the child is spawned; on any
 * mismatch nothing is signed, nothing is registered and nothing is spawned.
 *
 * It grants no extra authority: it is the launcher's own operator connection
 * and it only reads catalog/data it already owns.
 */
export async function reproveWitnessBoundary({ witness, appOperator, appDatabase, databaseOid,
  expectedHistoryDigest, pins }) {
  if (!isToken(expectedHistoryDigest)) { throw new Error('Invalid expected history digest'); }
  if (!Number.isSafeInteger(databaseOid) || databaseOid <= 0) { throw new Error('Invalid application database OID'); }
  const witnessKey = witness.key;
  const identity = (await witness.client.query(`SELECT
      current_database() = $1 AS database_ok,
      (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())::text AS database_oid,
      current_user = $2 AS user_ok,
      session_user = $2 AS session_ok,
      current_schema() AS schema,
      pg_catalog.pg_backend_pid()::text AS backend_pid,
      -- inet-to-text adds a netmask suffix (127.0.0.1/32); the canonical
      -- fixture identity probes compare the bare host, so use host() here too.
      pg_catalog.host(inet_server_addr()) AS server_addr,
      pg_catalog.host(inet_client_addr()) AS client_addr,
      inet_server_port() AS server_port,
      current_setting('listen_addresses') AS listen_addresses,
      current_setting('server_version_num') AS server_version_num,
      NOT pg_catalog.pg_is_in_recovery() AS primary,
      (SELECT count(*)::int FROM pg_catalog.pg_locks
        WHERE locktype = 'advisory' AND granted AND mode = 'ExclusiveLock'
          AND classid = $3::int::oid AND objid = $4::int::oid AND objsubid = 2
          AND pid = pg_catalog.pg_backend_pid()) AS own_witness_lock`,
  [appDatabase.database, appOperator.user, witnessKey.classId, witnessKey.objectId])).rows[0];
  const verdict = witnessBoundaryVerdict(identity, { databaseOid, witnessPid: witness.pid,
    schema: 'public', host, port: pgPort, serverVersionNum: SERVER_VERSION_NUM });
  if (!verdict.ok) {
    throw new Error(`Witness backend does not match the proof target identity (${String(verdict.reason)})`);
  }
  const rows = (await witness.client.query(`SELECT migration_name, checksum, finished_at, rolled_back_at,
    applied_steps_count FROM foundation._prisma_migrations ORDER BY migration_name ASC`)).rows;
  const digest = historyDigestOf(rows, pins ?? await migrationInventory().then((plan) => plan.pins));
  if (digest !== expectedHistoryDigest) { throw new Error('Witness backend history digest differs from the pinned manifest'); }
  return Object.freeze({ backendPid: witness.pid, databaseOid, historyManifestDigest: digest,
    rows: rows.length, database: appDatabase.database, operatorRole: appOperator.user });
}

/**
 * Deterministic S0 physical-contract digest. The reviewed predicate list is
 * read back from the test admission fixture and compared, so a changed S0
 * contract refuses instead of silently minting a stale fact.
 */
export async function physicalContractDigest() {
  const source = await readFile(new URL('../../apps/api/tests/admission-fixture.ts', import.meta.url), 'utf8');
  const block = /S0: \[([^\]]*)\]/u.exec(source)?.[1] ?? '';
  const listed = [...block.matchAll(/'([^']+)'/gu)].map((match) => match[1]);
  if (listed.join() !== S0_PREDICATES.join()) { throw new Error('Reviewed S0 physical predicate contract changed'); }
  return createHash('sha256')
    .update(`p05/physical-contract/v1/${PROOF_PROFILE}\n${S0_PREDICATES.join('\n')}`, 'utf8').digest('hex');
}

/** SHA-256 over the exact compiled API release tree (relative path + file digest). */
export async function artifactDigest() {
  const root = new URL('../../apps/api/dist/', import.meta.url);
  const lines = [];
  const visit = async (directory, prefix) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = `${prefix}${entry.name}`;
      if (entry.isSymbolicLink()) { throw new Error('Unexpected symlink in the compiled artifact'); }
      if (entry.isDirectory()) { await visit(new URL(`${entry.name}/`, directory), `${path}/`); continue; }
      if (!entry.isFile()) { throw new Error('Unexpected compiled artifact entry'); }
      lines.push(`${path}:${createHash('sha256').update(await readFile(new URL(entry.name, directory))).digest('hex')}`);
    }
  };
  await visit(root, '');
  return createHash('sha256').update(lines.sort().join('\n'), 'utf8').digest('hex');
}

let launcherModules;

/**
 * Compiles the three reviewed launcher-side admission modules (excluded from
 * the release build on purpose) from this image's own sources into a UNIQUE
 * ephemeral scratch output created with `mkdtemp` directly under `apps/api`
 * (so the emitted tree keeps the `apps/api` depth the modules' own relative
 * `createRequire` paths expect). A preexisting directory is never reused and
 * nothing is written into `dist` or the release graph.
 */
export function compileLauncherModules() {
  launcherModules ??= (async () => {
    const scratch = await mkdtemp(fileURLToPath(new URL('.p0305-launcher-', apiRoot)));
    const scratchConfig = join(scratch, 'tsconfig.scratch.json');
    await writeFile(scratchConfig, `${JSON.stringify({
      extends: join(fileURLToPath(apiRoot), 'tsconfig.build.json'),
      compilerOptions: { outDir: scratch, rootDir: join(fileURLToPath(apiRoot), 'src'),
        noEmit: false, incremental: false, composite: false },
      include: [join(fileURLToPath(apiRoot), 'src/infrastructure/admission/launcher.ts'),
        join(fileURLToPath(apiRoot), 'src/infrastructure/admission/registry.ts'),
        join(fileURLToPath(apiRoot), 'src/infrastructure/admission/control-contour.ts')],
      exclude: [join(fileURLToPath(apiRoot), 'node_modules')],
    }, null, 2)}\n`);
    const tsc = apiRequire.resolve('typescript/bin/tsc');
    const built = spawnSync(process.execPath, [tsc, '-p', scratchConfig],
      { cwd: fileURLToPath(apiRoot), stdio: 'ignore', timeout: 240_000 });
    if (built.status !== 0) { throw new Error('Scratch launcher compile failed'); }
    const [launcher, registry, control] = await Promise.all([
      import(pathToFileURL(join(scratch, 'infrastructure/admission/launcher.js')).href),
      import(pathToFileURL(join(scratch, 'infrastructure/admission/registry.js')).href),
      import(pathToFileURL(join(scratch, 'infrastructure/admission/control-contour.js')).href),
    ]);
    const [proof, witness, runtimeAdmission] = await Promise.all([
      import(new URL('../../apps/api/dist/infrastructure/admission/proof.js', import.meta.url).href),
      import(new URL('../../apps/api/dist/infrastructure/admission/witness.js', import.meta.url).href),
      import(new URL('../../apps/api/dist/infrastructure/admission/runtime-admission.js', import.meta.url).href),
    ]);
    for (const [name, value] of [['superviseLaunch', launcher.superviseLaunch], ['decideLaunch', launcher.decideLaunch],
      ['ensureLaunchRegistry', registry.ensureLaunchRegistry], ['issueProof', registry.issueProof],
      ['readRegistryState', registry.readRegistryState], ['loadControlContour', control.loadControlContour],
      ['signProof', proof.signProof], ['proofDigestOf', proof.proofDigestOf], ['holdWitness', witness.holdWitness],
      ['releaseWitness', witness.releaseWitness], ['witnessKeyForInstance', runtimeAdmission.witnessKeyForInstance]]) {
      if (typeof value !== 'function') { throw new Error(`Reviewed launcher module export missing: ${name}`); }
    }
    return Object.freeze({ launcher, registry, control, proof, witness, runtimeAdmission, scratch });
  })();
  return launcherModules;
}

/**
 * Creates the disposable control contour: one separate database owned by the
 * cluster operator, one narrow launcher role, the reviewed registry, and the
 * exact narrow grants. Every property is read back before it is used.
 */
export async function createControlContour({ admin, owner, marker, modules }) {
  if (!/^[a-f0-9]{24}$/u.test(marker ?? '')) { throw new Error('Disposable control namespace marker missing'); }
  const suffix = marker.slice(0, 12);
  const database = `fixlevelup_p05_control_${suffix}`;
  const role = `fixlevelup_p05_launcher_${suffix}`;
  const password = token();
  if (!CONTROL_DATABASE.test(database) || !LAUNCHER_ROLE.test(role)) { throw new Error('Invalid control contour identity'); }
  const existing = await admin.query(`SELECT (SELECT count(*)::int FROM pg_database WHERE datname=$1) AS databases,
    (SELECT count(*)::int FROM pg_roles WHERE rolname=$2) AS roles`, [database, role]);
  if (existing.rows[0]?.databases !== 0 || existing.rows[0]?.roles !== 0) {
    throw new Error('Control contour already exists; refusing to reuse it');
  }
  // Identifier and password interpolation is confined to fixed generated names
  // and a 64-hex synthetic secret.
  await admin.query(`CREATE ROLE "${role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    NOBYPASSRLS NOINHERIT PASSWORD '${password}'`);
  await admin.query(`CREATE DATABASE "${database}" OWNER "${owner.user}" TEMPLATE template0`);
  await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
  await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO "${role}"`);
  const control = new Client({ host, port: pgPort, database, user: owner.user, password: owner.password,
    ssl: false, connectionTimeoutMillis: 1000, statement_timeout: 10_000, query_timeout: 12_000, max: 1 });
  try {
    await control.connect();
    await modules.registry.ensureLaunchRegistry(control);
    await control.query(`GRANT USAGE ON SCHEMA launch_control TO "${role}"`);
    await control.query(`GRANT SELECT, INSERT ON launch_control.launch_proofs TO "${role}"`);
    await control.query(`GRANT UPDATE (state, consumed_at) ON launch_control.launch_proofs TO "${role}"`);
    // Narrow shape read back from the catalog: the launcher holds column-level
    // UPDATE on exactly state/consumed_at, so table-level UPDATE must be FALSE.
    // The role OID is read as text: pg returns oid/bigint as a string, and an
    // OID is unsigned 32-bit, so it is validated as digits rather than coerced.
    const shape = (await control.query(`SELECT
      (SELECT oid FROM pg_roles WHERE rolname=$1)::text AS role_oid,
      has_schema_privilege($1,'launch_control','CREATE') AS launcher_creates,
      has_schema_privilege($1,'launch_control','USAGE') AS launcher_uses_schema,
      has_table_privilege($1,'launch_control.launch_proofs','SELECT') AS launcher_selects,
      has_table_privilege($1,'launch_control.launch_proofs','INSERT') AS launcher_inserts,
      has_table_privilege($1,'launch_control.launch_proofs','DELETE') AS launcher_deletes,
      has_table_privilege($1,'launch_control.launch_proofs','TRUNCATE') AS launcher_truncates,
      has_table_privilege($1,'launch_control.launch_proofs','UPDATE') AS launcher_updates_table,
      has_column_privilege($1,'launch_control.launch_proofs','state','UPDATE') AS launcher_updates_state,
      has_column_privilege($1,'launch_control.launch_proofs','consumed_at','UPDATE') AS launcher_updates_consumed,
      has_column_privilege($1,'launch_control.launch_proofs','proof_digest','UPDATE') AS launcher_updates_digest,
      has_column_privilege($1,'launch_control.launch_proofs','expires_at','UPDATE') AS launcher_updates_expiry,
      has_column_privilege($1,'launch_control.launch_proofs','instance_id','UPDATE') AS launcher_updates_instance,
      has_column_privilege($1,'launch_control.launch_proofs','state','SELECT') AS launcher_selects_state,
      (SELECT count(*)::int FROM information_schema.column_privileges
        WHERE grantee=$1 AND table_schema='launch_control' AND table_name='launch_proofs'
          AND privilege_type='UPDATE') AS launcher_update_columns,
      has_database_privilege('fixlevelup_runtime',$2,'CONNECT') AS runtime_connect,
      has_database_privilege('fixlevelup_migrator',$2,'CONNECT') AS migrator_connect,
      has_database_privilege($1,$2,'CREATE') AS launcher_creates_database,
      (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$2) AS owner_name,
      (SELECT pg_get_userbyid(relowner) FROM pg_class
        WHERE oid='launch_control.launch_proofs'::regclass) AS table_owner`,
    [role, database])).rows[0];
    const roleOid = typeof shape?.role_oid === 'string' && /^[1-9]\d{0,9}$/u.test(shape.role_oid)
      ? Number(shape.role_oid) : NaN;
    if (!Number.isSafeInteger(roleOid) || roleOid <= 0
      || shape.launcher_creates !== false || shape.launcher_uses_schema !== true
      || shape.launcher_selects !== true || shape.launcher_inserts !== true
      || shape.launcher_deletes !== false || shape.launcher_truncates !== false
      || shape.launcher_updates_table !== false
      || shape.launcher_updates_state !== true || shape.launcher_updates_consumed !== true
      || shape.launcher_updates_digest !== false || shape.launcher_updates_expiry !== false
      || shape.launcher_updates_instance !== false || shape.launcher_selects_state !== true
      || shape.launcher_update_columns !== 2
      || shape.runtime_connect !== false || shape.migrator_connect !== false
      || shape.launcher_creates_database !== false
      || shape.owner_name !== owner.user || shape.table_owner !== owner.user) {
      throw new Error('Unexpected control contour privileges');
    }
  } finally { await control.end().catch(() => undefined); }
  const facts = Object.freeze({ host, port: pgPort, database, user: role, password });
  const probe = new Client({ ...facts, ssl: false, connectionTimeoutMillis: 1000, statement_timeout: 5000, max: 1 });
  try {
    await probe.connect();
    const identity = (await probe.query(`SELECT current_database()=$1 AS database, current_user=$2 AS role,
      has_table_privilege(current_user,'launch_control.launch_proofs','DELETE') AS deletes,
      has_table_privilege(current_user,'launch_control.launch_proofs','UPDATE') AS updates_table,
      has_column_privilege(current_user,'launch_control.launch_proofs','consumed_at','UPDATE') AS updates_consumed,
      (SELECT count(*)::int FROM launch_control.launch_proofs) AS rows`, [database, role])).rows[0];
    if (identity?.database !== true || identity.role !== true || identity.deletes !== false
      || identity.updates_table !== false || identity.updates_consumed !== true || identity.rows !== 0) {
      throw new Error('Launcher role cannot reach its own control registry');
    }
  } finally { await probe.end().catch(() => undefined); }
  return Object.freeze({ database, role, facts });
}

/**
 * One real guarded launch of `startChild`. The witness is held on the
 * application database, the proof is signed and registered once, the production
 * supervisor owns the private IPC channel and performs the single CAS
 * consumption; `stop()` releases the witness and the control connection.
 */
export async function launchGuarded(options) {
  const { modules, consumerKind, appDatabase, appOperator, control, databaseOid,
    artifact, history, physical, startChild, startupTimeoutMs = 30_000, ackTimeoutMs = 5000,
    instanceId = randomUUID(), launchNonce = randomUUID(), channelId = randomUUID(),
    issuerGeneration = 1, expiresInMs = 300_000 } = options;
  if (consumerKind !== 'API' && consumerKind !== 'WORKER') { throw new Error('Invalid guarded consumer kind'); }
  if (!Number.isSafeInteger(databaseOid) || databaseOid <= 0) { throw new Error('Invalid application database OID'); }
  for (const [name, value] of [['artifact', artifact], ['history', history], ['physical', physical]]) {
    if (!isToken(value)) { throw new Error(`Invalid ${name} digest`); }
  }
  const witnessKey = modules.runtimeAdmission.witnessKeyForInstance(instanceId);
  const witnessClient = new Client({ ...appOperator, ssl: false, connectionTimeoutMillis: 1000,
    statement_timeout: 5000, query_timeout: 5000, application_name: 'p0305-launcher-witness' });
  await witnessClient.connect();
  let stopped = false;
  const controlClient = new Client({ ...control, ssl: false, connectionTimeoutMillis: 1000,
    statement_timeout: 5000, query_timeout: 5000, application_name: 'p0305-launcher-control' });
  const release = async () => {
    if (stopped) { return; }
    stopped = true;
    await modules.witness.releaseWitness(witnessClient, witnessKey).catch(() => undefined);
    await witnessClient.end().catch(() => undefined);
    await controlClient.end().catch(() => undefined);
  };
  try {
    await modules.witness.holdWitness(witnessClient, witnessKey);
    const witnessPid = (await witnessClient.query('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
    if (!Number.isSafeInteger(witnessPid) || witnessPid <= 0) { throw new Error('Launcher witness pid missing'); }
    // Same-backend re-proof: the exact database/OID/role/loopback/primary facts
    // and the pinned S0 history digest are re-validated ON the connection that
    // holds the witness, before anything is signed, registered or spawned. The
    // value proven here is the value carried in the proof.
    const boundary = await reproveWitnessBoundary({
      witness: { client: witnessClient, pid: witnessPid, key: witnessKey },
      appOperator, appDatabase, databaseOid, expectedHistoryDigest: history,
      pins: options.pins ?? await migrationInventory().then((plan) => plan.pins),
    });
    const keyPair = generateKeyPairSync('ed25519');
    const publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const payload = {
      issuerGeneration,
      launchNonce,
      consumerKind,
      instanceId,
      channelId,
      artifactDigest: artifact,
      endpoint: `${appDatabase.host}:${String(appDatabase.port)}`,
      targetIdentity: { database: appDatabase.database, databaseOid,
        runtimeRole: appDatabase.user, schema: 'public' },
      profile: PROOF_PROFILE,
      // The proven value, read on the witness backend, is what the proof carries.
      historyManifestDigest: boundary.historyManifestDigest,
      physicalContractDigest: physical,
      witness: { classId: witnessKey.classId, objectId: witnessKey.objectId, mode: 'SESSION' },
      expiresAt: new Date(Date.now() + expiresInMs).toISOString(),
    };
    const proofToken = modules.proof.signProof(payload,
      keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
    const proofDigest = modules.proof.proofDigestOf(payload);
    await controlClient.connect();
    await modules.registry.issueProof(controlClient, { issuerGeneration, launchNonce, proofDigest,
      consumerKind, instanceId, channelId, expiresAt: new Date(payload.expiresAt) });
    const child = startChild({
      LAUNCH_DATABASE: appDatabase.database,
      LAUNCH_DATABASE_OID: String(databaseOid),
      LAUNCH_ROLE: appDatabase.user,
      LAUNCH_SCHEMA: 'public',
      LAUNCH_PROFILE: PROOF_PROFILE,
      LAUNCH_ENDPOINT: payload.endpoint,
      LAUNCH_ISSUER_GENERATION: String(issuerGeneration),
      LAUNCH_NONCE: launchNonce,
      LAUNCH_CONSUMER_KIND: consumerKind,
      LAUNCH_INSTANCE_ID: instanceId,
      LAUNCH_CHANNEL_ID: channelId,
      LAUNCH_ARTIFACT_DIGEST: artifact,
      LAUNCH_HISTORY_MANIFEST_DIGEST: boundary.historyManifestDigest,
      LAUNCH_PHYSICAL_CONTRACT_DIGEST: physical,
      LAUNCH_PROOF_TOKEN: proofToken,
      LAUNCHER_WITNESS_PID: String(witnessPid),
      LAUNCHER_PUBLIC_KEY_PEM: publicKeyPem,
      LAUNCH_APPROVAL_TIMEOUT_MS: String(ackTimeoutMs),
    });
    const expected = Object.freeze({ consumerKind, instanceId, launchNonce, channelId, issuerGeneration,
      proofDigest, witnessHolderPid: witnessPid, database: appDatabase.database, databaseOid,
      role: appDatabase.user, profile: PROOF_PROFILE });
    const supervisor = modules.launcher.superviseLaunch({
      app: appOperator, control, ackTimeoutMs,
      witnessKeyOf: (id) => modules.runtimeAdmission.witnessKeyForInstance(id),
    }, expected, child, { startupTimeoutMs, drainTimeoutMs: 5000 });
    const activation = await supervisor.activation;
    if (activation.approved !== true) {
      await supervisor.stop();
      await release();
      throw new Error(`Guarded launch refused (${activation.reason})`);
    }
    const stop = async () => {
      await supervisor.stop();
      await release();
    };
    return Object.freeze({ child, activation, proofDigest, launchNonce, instanceId, witnessPid,
      witnessBoundary: boundary,
      registryState: () => modules.registry.readRegistryState(controlClient, issuerGeneration, launchNonce), stop });
  } catch (error) {
    await release();
    throw error;
  }
}
