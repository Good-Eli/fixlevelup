import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// PostgreSQL 18.7 logical dump/reparse can change the expression tree of IN
// and BETWEEN. Reapply only affected expressions, never import SQL from the
// observed database. These pins cover ordered names + LF-normalised SQL. The S2
// pin (001-023) is historical and stays byte-for-byte; S3 is the same reviewed
// chain extended with 024, so a 001-024 database is accepted only against its own
// digest. A length outside the map is refused, never inferred.
const MANIFESTS = new Map([
  [23, 'd93a19c4a6d013a9796412aec2c1f9d0c59630d99d77cc523808dbe17783708e'],
  // Re-pinned after the reviewed 024 PHONE-completeness guard was added. Measured
  // as the exact digest of the ordered names + LF-normalised SQL, never guessed.
  [24, '4aee698201b5955496fffab5c402d9d499c3e332a3db9eb51fc1536e09a608e8'],
]);
// Evidence-only S0 prefix, pinned independently of the full checkout manifest.
const S0_COUNT = 21;
const S0_HEAD = '20261122000700_catalog_management';
const S0_MANIFEST = '2b62d7ff18dd7e869c5080f033f42d09d51951707d538a941bb62e7e8bee49f9';
const digest = input => createHash('sha256').update(input).digest('hex');
const dir = fileURLToPath(new URL('../../prisma/migrations/', import.meta.url));
const identifier = value => /^[a-z_][a-z0-9_]{0,62}$/u.test(value);
let denyStage = 'unknown';
const deny = (stage = denyStage) => {
  if (process.env['FIXLEVELUP_LAB_DEBUG_EXPRESSIONS'] === '1') { process.stderr.write('EXPR-DENY ' + stage + String.fromCharCode(10)); }
  throw new Error('Unrecognised reviewed restore expression: ' + stage);
};

// The inputs are an immutable reviewed SQL set, not arbitrary PostgreSQL SQL.
// Handle nested parentheses and doubled SQL quote escapes; refuse ambiguity.
function parenthesized(sql, start) {
  if (sql[start] !== '(') { return deny(); }
  let depth = 0;
  let quote = '';
  for (let i = start; i < sql.length; i++) {
    const ch = sql[i];
    if (quote) {
      if (ch === quote && sql[i + 1] === quote) { i++; }
      else if (ch === quote) { quote = ''; }
    } else if (ch === "'" || ch === '"') { quote = ch; }
    else if (ch === '(') { depth++; }
    else if (ch === ')' && --depth === 0) { return sql.slice(start, i + 1); }
  }
  return deny();
}

export async function restoreReviewedExpressions(source, destination, expectedDatabase, legacyProfile, rehearsal) {
  const slots = rehearsal === 'synthetic-key-rehearsal';
  const cluster = process.env['FIXLEVELUP_CLUSTER_NAME'];
  if (slots ? (!/^fixlevelup_configuration_test_[a-f0-9]{24}$/u.test(expectedDatabase)
    || legacyProfile !== undefined || process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1'
    || process.env['FIXLEVELUP_P05_KEY_SLOT_RECOVERY_TESTS'] !== '1' || process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1'
    || !/^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/u.test(cluster ?? ''))
    : (rehearsal !== undefined || !/^fixlevelup_file_restore_[a-f0-9]{24}$/u.test(expectedDatabase))) {
    deny('restore-expression-target');
  }
  const legacy = legacyProfile === 'S0';
  if (legacyProfile !== undefined && (!legacy || process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1'
    || process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] !== '1')) { deny('legacy-evidence-opt-in'); }
  const migrations = readdirSync(dir).filter(name => /^\d{14}_[a-z_]+$/u.test(name)).sort();
  const allFiles = migrations.map(name => readFileSync(resolve(dir, name, 'migration.sql'), 'utf8').replaceAll('\r\n','\n'));
  const manifest = migrations.map((name, i) => `${name}:${digest(allFiles[i])}`);
  const pinned = MANIFESTS.get(migrations.length);
  if (pinned === undefined || digest(manifest.join('\n')) !== pinned) { deny(); }
  if (legacy && (migrations[S0_COUNT - 1] !== S0_HEAD || digest(manifest.slice(0, S0_COUNT).join('\n')) !== S0_MANIFEST)) {
    deny('legacy-evidence-pin');
  }
  const files = legacy ? allFiles.slice(0, S0_COUNT) : allFiles;
  const reviewed = new Map();
  // Unnamed CHECKs get an automatic PostgreSQL name, so they cannot be looked up
  // by name. They are kept as PER-TABLE candidates instead and are only accepted
  // when re-applying one reproduces the source definition byte-for-byte.
  const candidates = new Map();
  const addCandidate = (table, expression) => {
    const list = candidates.get(table) ?? [];
    if (!list.includes(expression)) { list.push(expression); }
    candidates.set(table, list);
  };
  for (const sql of files) {
    for (const m of sql.matchAll(/\bCONSTRAINT\s+"?([a-z_][a-z0-9_]*)"?\s+CHECK\s*\(/giu)) {
      // Later reviewed migrations replace certain named CHECKs (notably role_permissions_scope_check).
      reviewed.set(m[1], parenthesized(sql, m.index + m[0].length - 1));
    }
    // Associate every CHECK(...) in the reviewed SQL with the nearest preceding
    // CREATE TABLE / ALTER TABLE target; that is the table whose constraint list
    // it belongs to.
    const statements = [...sql.matchAll(/\b(?:CREATE|ALTER)\s+TABLE\s+(?:ONLY\s+)?foundation\.([a-z_][a-z0-9_]*)/giu)];
    for (const [index, statement] of statements.entries()) {
      const from = statement.index + statement[0].length;
      const to = statements[index + 1]?.index ?? sql.length;
      const body = sql.slice(from, to);
      for (const check of body.matchAll(/\bCHECK\s*(\()/gu)) {
        try {
          addCandidate(statement[1], parenthesized(body, check.index + check[0].length - 1));
        } catch { /* not a plain parenthesised expression: ignored as a candidate */ }
      }
    }
  }
  const checks = `SELECT c.relname AS table,k.conname AS name,pg_catalog.pg_get_constraintdef(k.oid) AS definition
    FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid
    WHERE c.relnamespace='foundation'::regnamespace AND k.contype='c' ORDER BY c.relname,k.conname`;
  const before = (await source.query(checks)).rows;
  const after = (await destination.query(checks)).rows;
  if (!before.length || before.length !== after.length) { deny('constraint-count ' + before.length + '/' + after.length); }
  // The generated expression must be located by its own definition, not by
  // position: with 024 appended, `files.at(-2)` no longer names the migration
  // that creates `is_waiting_link`. Exactly one reviewed migration may define it.
  const waitingSql = files.filter(sql => /is_waiting_link boolean GENERATED ALWAYS AS\s*\(/u.test(sql));
  if (waitingSql.length !== (legacy ? 0 : 1)) { deny('waiting-sql-count ' + waitingSql.length); }
  let expression;
  if (!legacy) {
    const waiting = waitingSql[0].match(/is_waiting_link boolean GENERATED ALWAYS AS\s*(\()/u);
    if (!waiting) { deny('waiting-expression'); }
    expression = parenthesized(waitingSql[0], waiting.index + waiting[0].length - 1);
  }
  // This extra contour repairs PostgreSQL's logical-restore deparse drift
  // on one closed synthetic rehearsal DB. It cannot open a file-restore target
  // with requests; the file-only branch still requires an empty relation.
  const requestsClosed = slots ? `current_setting('cluster_name')=$1 AND current_setting('server_version_num')='180007'
      AND host(inet_server_addr())='127.0.0.1' AND inet_server_port()=55432
      AND session_user=current_user AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT')
      AND NOT EXISTS(SELECT FROM pg_stat_activity a WHERE a.datname=current_database()
        AND a.pid<>pg_backend_pid() AND a.backend_type='client backend')
      AND NOT EXISTS(SELECT FROM pg_prepared_xacts WHERE database=current_database())`
    : legacy ? `to_regclass('foundation.requests') IS NULL` : 'NOT EXISTS(SELECT FROM foundation.requests)';
  await destination.query('BEGIN');
  try {
    const bindingSql = `SELECT current_database() AS database,current_user AS role,
      NOT has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT') AND NOT pg_is_in_recovery()
      AND NOT EXISTS(SELECT FROM foundation.file_runtime_epochs) AND ${requestsClosed} AS closed`;
    const closed = slots ? await destination.query(bindingSql,[cluster]) : await destination.query(bindingSql);
    const binding = closed.rows[0];
    if (!binding?.closed || binding.role !== 'fixlevelup_migrator' || binding.database !== expectedDatabase) { deny('closed-binding ' + JSON.stringify(binding ?? null)); }
    for (const [i, entry] of before.entries()) {
      const peer = after[i];
      if (!identifier(entry.table) || !identifier(entry.name) || peer.table !== entry.table || peer.name !== entry.name) { deny('identifier ' + entry.table + '.' + entry.name); }
      if (entry.definition === peer.definition) { continue; }
      const known = reviewed.get(entry.name);
      if (known !== undefined) {
        await destination.query(`ALTER TABLE foundation."${entry.table}" DROP CONSTRAINT "${entry.name}",
          ADD CONSTRAINT "${entry.name}" CHECK ${known}`);
        continue;
      }
      // Unnamed reviewed CHECK: probe every candidate for this table inside a
      // savepoint and keep exactly the one whose re-parse reproduces the SOURCE
      // definition. Zero or several matches is a refusal, never a guess.
      const tableCandidates = candidates.get(entry.table) ?? [];
      const matched = [];
      for (const candidate of tableCandidates) {
        await destination.query('SAVEPOINT probe');
        try {
          await destination.query(`ALTER TABLE foundation."${entry.table}" DROP CONSTRAINT "${entry.name}",
            ADD CONSTRAINT "${entry.name}" CHECK ${candidate}`);
          const { rows: [probe] } = await destination.query(`SELECT pg_catalog.pg_get_constraintdef(k.oid) AS definition
            FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid
            WHERE c.relnamespace='foundation'::regnamespace AND c.relname=$1 AND k.conname=$2`,
          [entry.table, entry.name]);
          await destination.query('ROLLBACK TO SAVEPOINT probe');
          if (probe?.definition === entry.definition) { matched.push(candidate); }
        } catch {
          await destination.query('ROLLBACK TO SAVEPOINT probe');
        }
      }
      if (matched.length !== 1) {
        deny('unnamed-constraint ' + entry.table + '.' + entry.name + ' matches=' + matched.length);
      }
      await destination.query(`ALTER TABLE foundation."${entry.table}" DROP CONSTRAINT "${entry.name}",
        ADD CONSTRAINT "${entry.name}" CHECK ${matched[0]}`);
    }
    // The reviewed expanded target must have empty requests; S0 has no requests
    // relation or generated request expression to reapply.
    if (!legacy) {
      await destination.query(`ALTER TABLE foundation.requests ALTER COLUMN is_waiting_link SET EXPRESSION AS ${expression}`);
    }
    const verified = (await destination.query(checks)).rows;
    if (JSON.stringify(verified) !== JSON.stringify(before)) {
      if (process.env['FIXLEVELUP_LAB_DEBUG_EXPRESSIONS'] === '1') {
        for (const [i, entry] of before.entries()) {
          const peer = verified[i];
          if (JSON.stringify(peer) !== JSON.stringify(entry)) {
            process.stderr.write(`EXPR-DIFF ${JSON.stringify({ before: entry, after: peer })}\n`);
          }
        }
      }
      deny();
    }
    await destination.query('COMMIT');
  } catch (error) { await destination.query('ROLLBACK'); throw error; }
}
