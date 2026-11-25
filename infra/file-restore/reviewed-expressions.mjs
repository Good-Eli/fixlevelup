import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// PostgreSQL 18.7 logical dump/reparse can change the expression tree of IN
// and BETWEEN. Reapply only affected expressions, never import SQL from the
// observed database. This pin covers ordered names + LF-normalised SQL 001-023.
const S2_MANIFEST = 'd93a19c4a6d013a9796412aec2c1f9d0c59630d99d77cc523808dbe17783708e';
const digest = input => createHash('sha256').update(input).digest('hex');
const dir = fileURLToPath(new URL('../../prisma/migrations/', import.meta.url));
const identifier = value => /^[a-z_][a-z0-9_]{0,62}$/u.test(value);
const deny = () => { throw new Error('Unrecognised reviewed restore expression'); };

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

export async function restoreReviewedExpressions(source, destination, expectedDatabase) {
  if (!/^fixlevelup_file_restore_[a-f0-9]{24}$/u.test(expectedDatabase)) { deny(); }
  const migrations = readdirSync(dir).filter(name => /^\d{14}_[a-z_]+$/u.test(name)).sort();
  const files = migrations.map(name => readFileSync(resolve(dir, name, 'migration.sql'), 'utf8').replaceAll('\r\n','\n'));
  if (migrations.length !== 23 || digest(migrations.map((name, i) => `${name}:${digest(files[i])}`).join('\n')) !== S2_MANIFEST) { deny(); }
  const reviewed = new Map();
  for (const sql of files) {
    for (const m of sql.matchAll(/\bCONSTRAINT\s+"?([a-z_][a-z0-9_]*)"?\s+CHECK\s*\(/giu)) {
      // Later reviewed migrations replace certain named CHECKs (notably role_permissions_scope_check).
      reviewed.set(m[1], parenthesized(sql, m.index + m[0].length - 1));
    }
  }
  const checks = `SELECT c.relname AS table,k.conname AS name,pg_catalog.pg_get_constraintdef(k.oid) AS definition
    FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid
    WHERE c.relnamespace='foundation'::regnamespace AND k.contype='c' ORDER BY c.relname,k.conname`;
  const before = (await source.query(checks)).rows;
  const after = (await destination.query(checks)).rows;
  if (!before.length || before.length !== after.length) { deny(); }
  const waiting = files.at(-2).match(/is_waiting_link boolean GENERATED ALWAYS AS\s*(\()/u);
  if (!waiting) { deny(); }
  const expression = parenthesized(files.at(-2), waiting.index + waiting[0].length - 1);
  await destination.query('BEGIN');
  try {
    const closed = await destination.query(`SELECT current_database() AS database,current_user AS role,
      NOT has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT') AND NOT pg_is_in_recovery()
      AND NOT EXISTS(SELECT FROM foundation.file_runtime_epochs) AND NOT EXISTS(SELECT FROM foundation.requests) AS closed`);
    const binding = closed.rows[0];
    if (!binding?.closed || binding.role !== 'fixlevelup_migrator' || binding.database !== expectedDatabase) { deny(); }
    for (const [i, entry] of before.entries()) {
      const peer = after[i];
      if (!identifier(entry.table) || !identifier(entry.name) || peer.table !== entry.table || peer.name !== entry.name) { deny(); }
      if (entry.definition === peer.definition) { continue; }
      const known = reviewed.get(entry.name);
      if (!known) { deny(); }
      await destination.query(`ALTER TABLE foundation."${entry.table}" DROP CONSTRAINT "${entry.name}",
        ADD CONSTRAINT "${entry.name}" CHECK ${known}`);
    }
    // This is the ONLY generated expression on reviewed S1/S2 request rows;
    // the closed source and the fresh target must both have no P05 data.
    await destination.query(`ALTER TABLE foundation.requests ALTER COLUMN is_waiting_link SET EXPRESSION AS ${expression}`);
    const verified = (await destination.query(checks)).rows;
    if (JSON.stringify(verified) !== JSON.stringify(before)) { deny(); }
    await destination.query('COMMIT');
  } catch (error) { await destination.query('ROLLBACK'); throw error; }
}
